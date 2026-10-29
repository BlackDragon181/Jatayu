"""
Vulnerability-scanner connectors for JATAYU.

Two ingestion paths:
  • File import  — parse Nessus (.nessus XML), Qualys (XML/CSV), or generic CSV
                   scan exports into a normalized finding schema.
  • Live API     — pull findings directly from Tenable.io / Qualys cloud APIs
                   when credentials are configured.

Ingested findings + connector credentials are persisted to disk (this app is
run self-hosted/stateful). Credentials are stored locally in plaintext — the
files are git-ignored; see .gitignore.

Normalized finding schema (one dict per host×vuln):
  {
    "source":     "nessus" | "qualys" | "csv" | "tenable" | ...,
    "asset":      str,         # hostname or IP — best available label
    "ip":         str,
    "hostname":   str,
    "cve_ids":    [str, ...],  # upper-cased CVE IDs
    "plugin_name":str,         # vuln / plugin / QID title
    "severity":   "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO",
    "cvss":       float | None,
    "port":       str,
    "first_seen": str,         # ISO-ish date when available
    "description":str,         # short, optional
  }
"""

import csv
import io
import json
import logging
import os
import re
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ─────────────────────────────────────────────────────────────────────────────
# Storage location (mirrors fetcher._writable_base pattern)
# ─────────────────────────────────────────────────────────────────────────────
def _writable_base() -> Path:
    candidates = []
    if os.environ.get("DATA_DIR"):
        candidates.append(Path(os.environ["DATA_DIR"]))
    candidates.append(Path(__file__).resolve().parent)
    candidates.append(Path(tempfile.gettempdir()) / "jatayu_data")
    for base in candidates:
        try:
            (base / "ingested").mkdir(parents=True, exist_ok=True)
            return base
        except Exception:
            continue
    return Path(tempfile.gettempdir())


_BASE_DIR = _writable_base()
INGEST_DIR = _BASE_DIR / "ingested"
FINDINGS_FILE = INGEST_DIR / "findings.json"
CONFIG_FILE = INGEST_DIR / "connectors_config.json"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def normalize_severity(value, cvss=None) -> str:
    """Map heterogeneous severity inputs to a fixed scale.

    Handles Nessus 0-4, Qualys 1-5, plain strings, and CVSS-based fallback.
    """
    if value is not None and value != "":
        s = str(value).strip().upper()
        if s in SEVERITIES:
            return s
        if s in ("CRIT",):
            return "CRITICAL"
        if s in ("INFORMATIONAL", "NONE", "INFO"):
            return "INFO"
        # numeric severity codes
        if s.isdigit():
            n = int(s)
            # Nessus uses 0-4, Qualys uses 1-5; treat 5 and 4(when max not seen)
            mapping = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL", 5: "CRITICAL"}
            if n in mapping:
                return mapping[n]
    # Fall back to CVSS banding
    try:
        c = float(cvss)
        if c >= 9.0:
            return "CRITICAL"
        if c >= 7.0:
            return "HIGH"
        if c >= 4.0:
            return "MEDIUM"
        if c > 0:
            return "LOW"
    except (TypeError, ValueError):
        pass
    return "INFO"


def _to_float(value):
    try:
        f = float(value)
        return f if f > 0 else None
    except (TypeError, ValueError):
        return None


def _extract_cves(*texts) -> list:
    found = []
    for t in texts:
        if not t:
            continue
        for m in _CVE_RE.findall(str(t)):
            cve = m.upper()
            if cve not in found:
                found.append(cve)
    return found


_AV_RE = re.compile(r"AV:([NALP])", re.I)
_AV_MAP = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}


def _av_from_vector(vec) -> str:
    """Parse the attack-vector (AV:) component from a CVSS vector string."""
    if not vec:
        return ""
    m = _AV_RE.search(str(vec))
    return _AV_MAP.get(m.group(1).upper(), "") if m else ""


def _finding(source, asset="", ip="", hostname="", cve_ids=None, plugin_name="",
             severity="INFO", cvss=None, port="", first_seen="", description="",
             cvss_vector="", attack_vector=""):
    asset = asset or hostname or ip or "unknown"
    return {
        "source": source,
        "asset": asset,
        "ip": ip,
        "hostname": hostname,
        "cve_ids": cve_ids or [],
        "plugin_name": plugin_name or "",
        "severity": severity,
        "cvss": cvss,
        "cvss_vector": cvss_vector or "",
        "attack_vector": attack_vector or _av_from_vector(cvss_vector),
        "port": str(port or ""),
        "first_seen": first_seen or _now_iso(),
        "description": (description or "")[:300],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Parsers
# ─────────────────────────────────────────────────────────────────────────────
def parse_nessus(content: bytes) -> list:
    """Parse a Nessus v2 (.nessus) XML export into normalized findings."""
    findings = []
    text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    root = ET.fromstring(text)
    for host in root.iter("ReportHost"):
        hostname = host.get("name", "") or ""
        ip = hostname
        for tag in host.iter("tag"):
            if tag.get("name") == "host-ip" and tag.text:
                ip = tag.text.strip()
            elif tag.get("name") in ("host-fqdn", "netbios-name") and tag.text and not hostname:
                hostname = tag.text.strip()
        for item in host.iter("ReportItem"):
            sev = item.get("severity")
            plugin = item.get("pluginName", "") or ""
            port = item.get("port", "") or ""
            cves = [e.text.strip().upper() for e in item.findall("cve") if e.text]
            cvss = None
            for tagname in ("cvss3_base_score", "cvss_base_score"):
                el = item.find(tagname)
                if el is not None and el.text:
                    cvss = _to_float(el.text)
                    if cvss:
                        break
            desc_el = item.find("description")
            desc = desc_el.text if desc_el is not None else ""
            vec = ""
            for tagname in ("cvss3_vector", "cvss_vector"):
                el = item.find(tagname)
                if el is not None and el.text:
                    vec = el.text.strip()
                    break
            cves = cves or _extract_cves(plugin, desc)
            # Skip pure-informational items with no CVE to keep ingest meaningful
            if not cves and normalize_severity(sev, cvss) == "INFO":
                continue
            findings.append(_finding(
                "nessus", asset=hostname or ip, ip=ip, hostname=hostname,
                cve_ids=cves, plugin_name=plugin,
                severity=normalize_severity(sev, cvss), cvss=cvss, port=port,
                description=desc, cvss_vector=vec,
            ))
    return findings


def parse_csv(content: bytes, source: str = "csv") -> list:
    """Parse a generic vulnerability CSV with flexible column mapping.

    Recognizes common column names from Nessus/Qualys/OpenVAS CSV exports.
    """
    findings = []
    text = content.decode("utf-8-sig", errors="replace") if isinstance(content, bytes) else content
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return findings

    # Build a case-insensitive header lookup
    cols = {h.lower().strip(): h for h in reader.fieldnames if h}

    def pick(*names):
        for n in names:
            if n in cols:
                return cols[n]
        return None

    c_ip = pick("ip", "ip address", "host", "host-ip", "asset ip", "ip_address")
    c_host = pick("dns", "hostname", "fqdn", "host name", "netbios", "asset name", "name")
    c_cve = pick("cve", "cve id", "cve_id", "cves", "cve ids")
    c_sev = pick("severity", "risk", "risk factor", "threat")
    c_cvss = pick("cvss", "cvss base", "cvss base score", "cvss3 base score", "cvss_base_score", "score")
    c_name = pick("name", "plugin name", "title", "vulnerability", "qid title", "synopsis")
    c_port = pick("port", "protocol/port")
    c_date = pick("first seen", "first_seen", "first detected", "last seen", "date")
    c_desc = pick("description", "synopsis", "details")
    c_vec = pick("cvss vector", "cvss3 vector", "cvss_vector", "cvss3_vector",
                 "cvss v3 vector", "vector", "cvss vector string")

    for row in reader:
        ip = (row.get(c_ip) or "").strip() if c_ip else ""
        host = (row.get(c_host) or "").strip() if c_host else ""
        name = (row.get(c_name) or "").strip() if c_name else ""
        desc = (row.get(c_desc) or "").strip() if c_desc else ""
        cve_raw = (row.get(c_cve) or "") if c_cve else ""
        cves = _extract_cves(cve_raw) or _extract_cves(name, desc)
        cvss = _to_float(row.get(c_cvss)) if c_cvss else None
        sev = (row.get(c_sev) or "") if c_sev else ""
        port = (row.get(c_port) or "") if c_port else ""
        date = (row.get(c_date) or "") if c_date else ""
        vec = (row.get(c_vec) or "") if c_vec else ""
        if not (ip or host or cves):
            continue
        if not cves and normalize_severity(sev, cvss) == "INFO":
            continue
        findings.append(_finding(
            source, asset=host or ip, ip=ip, hostname=host, cve_ids=cves,
            plugin_name=name, severity=normalize_severity(sev, cvss),
            cvss=cvss, port=port, first_seen=date, description=desc, cvss_vector=vec,
        ))
    return findings


def parse_qualys(content: bytes) -> list:
    """Parse a Qualys export. Supports the VM detection XML and CSV exports."""
    raw = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    stripped = raw.lstrip()
    if not stripped.startswith("<"):
        return parse_csv(content, source="qualys")

    findings = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return parse_csv(content, source="qualys")

    # Qualys host detection list: HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST
    for host in root.iter("HOST"):
        ip = (host.findtext("IP") or "").strip()
        dns = (host.findtext("DNS") or host.findtext("NETBIOS") or "").strip()
        det_list = host.find("DETECTION_LIST")
        if det_list is None:
            continue
        for det in det_list.iter("DETECTION"):
            qid = (det.findtext("QID") or "").strip()
            sev = (det.findtext("SEVERITY") or "").strip()
            port = (det.findtext("PORT") or "").strip()
            cvss = _to_float(det.findtext("CVSS_BASE") or det.findtext("CVSS3_BASE"))
            results = det.findtext("RESULTS") or ""
            first = (det.findtext("FIRST_FOUND_DATETIME") or "")[:10]
            # Parse CVEs from the dedicated XML element first, then supplement
            # with regex extraction from freeform RESULTS text as fallback.
            xml_cves = [
                n.text.strip().upper() for n in det.findall(".//CVE_ID_LIST/CVE_ID")
                if n.text and n.text.strip()
            ]
            regex_cves = _extract_cves(results)
            cves = list(dict.fromkeys(xml_cves + [c for c in regex_cves if c not in xml_cves]))
            findings.append(_finding(
                "qualys", asset=dns or ip, ip=ip, hostname=dns, cve_ids=cves,
                plugin_name=f"QID {qid}" if qid else "Qualys Detection",
                severity=normalize_severity(sev, cvss), cvss=cvss, port=port,
                first_seen=first, description=results,
            ))
    return findings


def parse_file(filename: str, content: bytes) -> tuple:
    """Dispatch to the right parser by extension/content. Returns (source, findings)."""
    name = (filename or "").lower()
    if name.endswith(".nessus"):
        return "nessus", parse_nessus(content)
    if name.endswith(".csv"):
        # Qualys CSVs have a recognizable preamble; otherwise treat as generic
        head = content[:2000].decode("utf-8", errors="replace").lower() if isinstance(content, bytes) else content[:2000].lower()
        source = "qualys" if "qualys" in head or '"qid"' in head else "csv"
        return source, parse_csv(content, source=source)
    if name.endswith(".xml"):
        head = content[:400].decode("utf-8", errors="replace").lower() if isinstance(content, bytes) else content[:400].lower()
        if "nessus" in head:
            return "nessus", parse_nessus(content)
        return "qualys", parse_qualys(content)
    # Unknown extension — sniff content
    head = content[:400].decode("utf-8", errors="replace").lower() if isinstance(content, bytes) else content[:400].lower()
    if "nessusclientdata" in head:
        return "nessus", parse_nessus(content)
    if head.lstrip().startswith("<"):
        return "qualys", parse_qualys(content)
    return "csv", parse_csv(content)


# ─────────────────────────────────────────────────────────────────────────────
# Live API clients
# ─────────────────────────────────────────────────────────────────────────────
class ConnectorError(Exception):
    pass


# Tenable severity_id → normalized scale (matches Nessus 0-4 banding).
_TENABLE_SEV = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


class TenableClient:
    """Tenable.io client (API-key auth).

    Vulnerabilities are pulled via the **vulnerability export API**
    (`/vulns/export`), which returns one record per *asset × plugin* with the
    real asset identity (hostname / IPv4 / FQDN), the plugin's CVE list, and
    CVSS/severity. The older `/workbenches/vulnerabilities` rollup only returns
    plugin-level aggregates with no per-asset identity and no CVE list, which
    collapsed the ingested asset count and dropped vulnerabilities downstream.
    """

    def __init__(self, access_key: str, secret_key: str, base_url: str = "https://cloud.tenable.com"):
        if not access_key or not secret_key:
            raise ConnectorError("Tenable requires both an Access Key and a Secret Key.")
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "JATAYU-Connector/1.0",
        })

    def test(self) -> dict:
        r = self.session.get(f"{self.base}/server/properties", timeout=20)
        if r.status_code in (401, 403):
            raise ConnectorError("Authentication failed — check your Tenable API keys.")
        r.raise_for_status()
        props = r.json()
        return {"ok": True, "server_version": props.get("server_version", "unknown")}

    # ── export helpers ────────────────────────────────────────────────────────
    def _start_export(self, days: int, num_assets: int) -> str:
        payload = {
            "num_assets": max(50, min(num_assets, 5000)),
            "filters": {
                # Ingest everything actionable; drop pure INFO (severity "info").
                "severity": ["low", "medium", "high", "critical"],
            },
        }
        if days:
            since = int(time.time()) - days * 86400
            payload["filters"]["since"] = since
        r = self.session.post(f"{self.base}/vulns/export",
                              data=json.dumps(payload), timeout=30)
        if r.status_code in (401, 403):
            raise ConnectorError(
                "Authentication failed or the API keys lack the 'CAN VIEW' / export "
                "permission required for vulnerability export. Check your Tenable keys.")
        r.raise_for_status()
        uuid = r.json().get("export_uuid")
        if not uuid:
            raise ConnectorError("Tenable did not return an export_uuid.")
        return uuid

    def _wait_for_chunks(self, uuid: str, max_wait: int, poll: float) -> list:
        deadline = time.time() + max_wait
        chunks: list = []
        while time.time() < deadline:
            r = self.session.get(f"{self.base}/vulns/export/{uuid}/status", timeout=30)
            r.raise_for_status()
            body = r.json()
            status = (body.get("status") or "").upper()
            if status == "FINISHED":
                return body.get("chunks_available", []) or []
            if status in ("ERROR", "CANCELLED"):
                raise ConnectorError(f"Tenable export {status.lower()} before completion.")
            # QUEUED / PROCESSING — accumulate any chunks already available so a
            # slow/large export still yields partial data within the time budget.
            chunks = body.get("chunks_available", []) or chunks
            time.sleep(poll)
        if chunks:
            logger.warning("Tenable export timed out; ingesting %d partial chunk(s).", len(chunks))
            return chunks
        raise ConnectorError(
            f"Tenable export did not finish within {max_wait}s. Try a smaller date "
            "range, or re-run the sync — large exports can take several minutes.")

    @staticmethod
    def _map_vuln(v: dict) -> dict:
        asset = v.get("asset") or {}
        plugin = v.get("plugin") or {}
        port = v.get("port") or {}
        ip = (asset.get("ipv4") or asset.get("ipv6") or "").strip()
        host = (asset.get("hostname") or asset.get("fqdn")
                or asset.get("netbios_name") or "").strip()
        label = host or ip or asset.get("uuid") or "unknown"
        cves = [c.upper() for c in (plugin.get("cve") or []) if c]
        if not cves:
            cves = _extract_cves(plugin.get("name", ""))
        cvss = _to_float(plugin.get("cvss3_base_score") or plugin.get("cvss_base_score"))
        sev = _TENABLE_SEV.get(v.get("severity_id"))
        if sev is None:
            sev = normalize_severity(v.get("severity"), cvss)
        # Tenable carries the CVSS vector as a string or a {raw:...} object.
        def _vec(val):
            if isinstance(val, dict):
                return val.get("raw") or ""
            return val or ""
        cvss_vector = (_vec(plugin.get("cvss3_vector")) or _vec(plugin.get("cvss_vector")) or "")
        return _finding(
            "tenable", asset=label, ip=ip, hostname=host, cve_ids=cves,
            plugin_name=plugin.get("name", "") or (f"Plugin {plugin.get('id')}" if plugin.get("id") else ""),
            severity=sev, cvss=cvss, port=str(port.get("port") or ""),
            first_seen=(v.get("first_found") or "")[:10],
            description=plugin.get("description", "") or plugin.get("synopsis", ""),
            cvss_vector=cvss_vector,
        )

    def sync(self, days: int = 90, num_assets: int = 500,
             max_wait: int = 240, poll: float = 3.0) -> list:
        """Export per-asset vulnerability findings from Tenable.io."""
        uuid = self._start_export(days, num_assets)
        chunk_ids = self._wait_for_chunks(uuid, max_wait, poll)
        findings = []
        for cid in chunk_ids:
            r = self.session.get(f"{self.base}/vulns/export/{uuid}/chunks/{cid}", timeout=120)
            r.raise_for_status()
            for v in (r.json() or []):
                try:
                    findings.append(self._map_vuln(v))
                except Exception as e:  # never let one malformed record abort the sync
                    logger.warning("Skipped a malformed Tenable vuln record: %s", e)
        return findings


class QualysClient:
    """Minimal Qualys VM client (basic-auth, XML API)."""

    def __init__(self, username: str, password: str, base_url: str = "https://qualysapi.qualys.com"):
        if not username or not password:
            raise ConnectorError("Qualys requires a username and password.")
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({
            "X-Requested-With": "JATAYU-Connector",
            "User-Agent": "JATAYU-Connector/1.0",
        })

    def test(self) -> dict:
        r = self.session.get(f"{self.base}/msp/about.php", timeout=20)
        if r.status_code in (401, 403):
            raise ConnectorError("Authentication failed — check your Qualys credentials.")
        r.raise_for_status()
        return {"ok": True}

    def sync(self) -> list:
        r = self.session.post(
            f"{self.base}/api/2.0/fo/asset/host/vm/detection/",
            data={"action": "list", "show_results": "1", "status": "Active"},
            timeout=120,
        )
        if r.status_code in (401, 403):
            raise ConnectorError("Authentication failed — check your Qualys credentials.")
        r.raise_for_status()
        return parse_qualys(r.content)


def make_client(vendor: str, config: dict):
    vendor = (vendor or "").lower()
    if vendor == "tenable":
        return TenableClient(
            config.get("access_key", ""), config.get("secret_key", ""),
            config.get("base_url") or "https://cloud.tenable.com",
        )
    if vendor == "qualys":
        return QualysClient(
            config.get("username", ""), config.get("password", ""),
            config.get("base_url") or "https://qualysapi.qualys.com",
        )
    raise ConnectorError(f"Unknown connector vendor: {vendor}")


# ─────────────────────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────────────────────
class IngestStore:
    """Disk-backed store for ingested findings and connector configs."""

    def __init__(self):
        self._lock = threading.Lock()
        try:
            INGEST_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    # ── findings ──────────────────────────────────────────────────────────────
    def load_findings(self) -> list:
        try:
            if FINDINGS_FILE.exists():
                return json.loads(FINDINGS_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"Failed to read findings: {e}")
        return []

    def _save_findings(self, findings: list):
        FINDINGS_FILE.write_text(json.dumps(findings, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _key(f: dict) -> tuple:
        return (
            f.get("source", ""), (f.get("ip") or f.get("asset") or "").lower(),
            ",".join(sorted(f.get("cve_ids") or [])), f.get("plugin_name", ""), f.get("port", ""),
        )

    def add_findings(self, new_findings: list) -> dict:
        """Merge new findings (dedup by source+asset+cve+plugin+port). Returns summary."""
        with self._lock:
            existing = self.load_findings()
            seen = {self._key(f) for f in existing}
            added = 0
            for f in new_findings:
                k = self._key(f)
                if k not in seen:
                    existing.append(f)
                    seen.add(k)
                    added += 1
            self._save_findings(existing)
            return {"added": added, "skipped": len(new_findings) - added, "total": len(existing)}

    def clear(self) -> None:
        with self._lock:
            self._save_findings([])

    def stats(self) -> dict:
        with self._lock:
            findings = self.load_findings()
        by_source, by_sev, assets, cves = {}, {}, set(), set()
        for f in findings:
            by_source[f.get("source","")] = by_source.get(f.get("source",""), 0) + 1
            by_sev[f.get("severity","")] = by_sev.get(f.get("severity",""), 0) + 1
            assets.add((f.get("ip") or f.get("asset") or "").lower())
            for c in f.get("cve_ids") or []:
                cves.add(c)
        return {
            "total": len(findings),
            "assets": len(assets),
            "unique_cves": len(cves),
            "by_source": by_source,
            "by_severity": by_sev,
        }

    # ── connector config ──────────────────────────────────────────────────────
    def get_config(self) -> dict:
        try:
            if CONFIG_FILE.exists():
                return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"Failed to read connector config: {e}")
        return {}

    def get_vendor_config(self, vendor: str) -> dict:
        return self.get_config().get((vendor or "").lower(), {})

    def set_vendor_config(self, vendor: str, cfg: dict) -> None:
        with self._lock:
            cfg_all = self.get_config()
            entry = {k: v for k, v in cfg.items() if v not in (None, "")}
            entry["configured_at"] = _now_iso()
            cfg_all[(vendor or "").lower()] = entry
            CONFIG_FILE.write_text(json.dumps(cfg_all, ensure_ascii=False, indent=2), encoding="utf-8")

    def public_config(self) -> dict:
        """Connector config with secrets masked — safe to send to the UI."""
        secret_keys = {"secret_key", "password", "access_key"}
        out = {}
        for vendor, cfg in self.get_config().items():
            out[vendor] = {
                k: ("••••••••" if k in secret_keys and v else v)
                for k, v in cfg.items()
            }
        return out


# Module-level singleton used by app.py
store = IngestStore()
