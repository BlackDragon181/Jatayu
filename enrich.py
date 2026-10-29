"""
enrich.py — per-CVE enrichment via the Shodan CVEDB API (https://cvedb.shodan.io).

CVEDB returns EPSS, CVSS v2/v3/v4 (+ which version is authoritative), CISA-KEV
membership, ransomware-campaign association, and the EUVD id for a single CVE —
in one unauthenticated call. We use it to enrich the risk-prioritization engine
(see risk.py) with exploit-probability (EPSS) and CVSS 4.0 scoring.

Results are cached to disk (cache/cvedb/<cve>.json, ~24h TTL) and fetched with a
bounded thread pool so a refresh over hundreds of CVEs stays fast and polite.

Normalized record (one per CVE):
  {
    "cve": str, "epss": float|None, "percentile": float|None,
    "cvss": float|None, "cvss_v2": float|None, "cvss_v3": float|None,
    "cvss_v4": float|None, "cvss_version": str, "kev": bool,
    "ransomware": bool, "euvd": str, "source": "cvedb",
  }
"""

import json
import logging
import os
import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
CVEDB_URL = "https://cvedb.shodan.io/cve/{cve}"
# CIRCL Vulnerability-Lookup API — free, no key — used only to recover the CVSS
# vector (hence attack vector), which Shodan CVEDB does not expose. The modern
# vulnerability.circl.lu endpoint covers recent CVEs (the legacy cve.circl.lu
# one returned errors for 2024+ CVEs).
CIRCL_URL = "https://vulnerability.circl.lu/api/vulnerability/{cve}"

_AV_RE = re.compile(r"AV:([NALP])", re.I)
_AV_MAP = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}


def attack_vector_from_vector(vec: str) -> str:
    """Parse the attack-vector (AV:) component out of a CVSS vector string."""
    if not vec:
        return ""
    m = _AV_RE.search(str(vec))
    return _AV_MAP.get(m.group(1).upper(), "") if m else ""

# Cache location — mirror fetcher._writable_base() so we share the same writable
# root and degrade gracefully on read-only filesystems.
def _writable_base() -> Path:
    candidates = []
    if os.environ.get("DATA_DIR"):
        candidates.append(Path(os.environ["DATA_DIR"]))
    candidates.append(Path(__file__).resolve().parent)
    candidates.append(Path(tempfile.gettempdir()) / "jatayu_data")
    for base in candidates:
        try:
            (base / "cache" / "cvedb").mkdir(parents=True, exist_ok=True)
            return base
        except Exception:
            continue
    return Path(tempfile.gettempdir())


_CACHE_DIR = _writable_base() / "cache" / "cvedb"
_TTL = 86_400              # 24h — EPSS/KEV move slowly day-to-day
_MAX_WORKERS = 8
_TIMEOUT = 20

_session = requests.Session()
_session.headers.update({"User-Agent": "JATAYU-Enrich/1.0", "Accept": "application/json"})


def _to_float(v):
    try:
        f = float(v)
        return f if f >= 0 else None
    except (TypeError, ValueError):
        return None


def _normalize(cve: str, d: dict) -> dict:
    """Map a raw CVEDB response into our normalized enrichment record."""
    cvss_v4 = _to_float(d.get("cvss_v4"))
    cvss_v3 = _to_float(d.get("cvss_v3"))
    # CVEDB tells us which version its top-level `cvss` reflects; prefer v4 when present.
    if cvss_v4 is not None:
        version = "4.0"
    elif cvss_v3 is not None:
        version = "3.x"
    else:
        version = str(d.get("cvss_version") or "") or "—"
    return {
        "cve": cve,
        "epss": _to_float(d.get("epss")),
        "percentile": _to_float(d.get("ranking_epss")),
        "cvss": _to_float(d.get("cvss")),
        "cvss_v2": _to_float(d.get("cvss_v2")),
        "cvss_v3": cvss_v3,
        "cvss_v4": cvss_v4,
        "cvss_version": version,
        "kev": bool(d.get("kev")),
        "ransomware": str(d.get("ransomware_campaign") or "").lower() == "known",
        "euvd": _euvd_id(d.get("euvd")),
        # CVEDB's own short remediation hint — used by risk.build_remediation.
        "propose_action": (d.get("propose_action") or "").strip(),
        "references": [r for r in (d.get("references") or []) if r][:5],
        "cvss_vector": "",       # filled by _fetch_one via CIRCL
        "attack_vector": "",     # parsed from cvss_vector
        "source": "cvedb",
    }


def _euvd_id(euvd) -> str:
    """CVEDB returns euvd as either a bare id string or a nested object; we only
    keep the id to avoid bloating the snapshot."""
    if isinstance(euvd, dict):
        return euvd.get("id", "") or ""
    return str(euvd or "")


def _cache_path(cve: str) -> Path:
    # v3: records carry attack_vector/cvss_vector sourced from the modern CIRCL
    # endpoint — bump so older/empty cached records are ignored and refilled.
    return _CACHE_DIR / f"{cve.upper()}.v3.json"


_VEC_DIR = _CACHE_DIR.parent / "cvss_vector"
try:
    _VEC_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass


def _fetch_cvss_vector(cve: str) -> str:
    """CVSS vector string from CIRCL (CVEDB doesn't expose one), with retry/backoff.

    Returns '' on failure — callers MUST NOT cache empty results so they retry on a
    later refresh (CIRCL rate-limits bulk bursts, so coverage fills progressively).
    """
    for attempt in range(3):
        try:
            r = _session.get(CIRCL_URL.format(cve=cve), timeout=_TIMEOUT)
            if r.status_code == 429:           # rate-limited — back off and retry
                time.sleep(0.6 * (attempt + 1))
                continue
            if r.status_code != 200:
                return ""
            blob = r.text
            m = (re.search(r"CVSS:[34]\.\d/[A-Z:/.]*AV:[NALP][A-Z:/.]*", blob)
                 or re.search(r"AV:[NALP]/[A-Za-z:/]+", blob)
                 or _AV_RE.search(blob))
            return m.group(0) if m else ""
        except Exception:
            time.sleep(0.4 * (attempt + 1))
    return ""


def _vector_cached(cve: str) -> str:
    """Return the CVSS vector for a CVE, from a success-only disk cache or a
    throttled live fetch. Empty results are never cached (so they retry)."""
    p = _VEC_DIR / f"{cve.upper()}.txt"
    try:
        if p.exists():
            v = p.read_text(encoding="utf-8").strip()
            if v:
                return v
    except Exception:
        pass
    vec = _fetch_cvss_vector(cve)
    if vec:
        try:
            p.write_text(vec, encoding="utf-8")
        except Exception:
            pass
    return vec


def _read_cache(cve: str):
    p = _cache_path(cve)
    try:
        if p.exists() and (time.time() - p.stat().st_mtime) < _TTL:
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _write_cache(cve: str, rec: dict):
    try:
        _cache_path(cve).write_text(json.dumps(rec), encoding="utf-8")
    except Exception as e:
        logger.debug("cvedb cache write failed for %s: %s", cve, e)


def _fetch_one(cve: str):
    cve = cve.upper()
    cached = _read_cache(cve)
    if cached is not None:
        return cve, cached
    try:
        r = _session.get(CVEDB_URL.format(cve=cve), timeout=_TIMEOUT)
        if r.status_code == 404:
            rec = _normalize(cve, {})        # unknown CVE — cache an empty record
            _write_cache(cve, rec)
            return cve, rec
        r.raise_for_status()
        rec = _normalize(cve, r.json() or {})
        _write_cache(cve, rec)
        return cve, rec
    except Exception as e:
        logger.debug("cvedb fetch failed for %s: %s", cve, e)
        return cve, None


def enrich_cves(cve_ids, max_workers: int = _MAX_WORKERS) -> dict:
    """Return {CVE: enrichment_record} for the given iterable of CVE ids.

    De-duplicates and validates input, serves from cache where fresh, and fetches
    the rest concurrently. CVEs that fail to resolve are omitted (partial result),
    so a flaky network never aborts the whole refresh.
    """
    uniq = sorted({c.upper() for c in (cve_ids or []) if c and _CVE_RE.match(c)})
    if not uniq:
        return {}
    out = {}
    # Serve cache hits first to shrink the network fan-out.
    to_fetch = []
    for cve in uniq:
        cached = _read_cache(cve)
        if cached is not None:
            out[cve] = cached
        else:
            to_fetch.append(cve)
    if to_fetch:
        workers = max(1, min(max_workers, len(to_fetch)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for cve, rec in ex.map(_fetch_one, to_fetch):
                if rec is not None:
                    out[cve] = rec

    # CVSS vector / attack vector overlay (CIRCL — gentle, success-only cache).
    # Decoupled from the CVEDB cache and run at low concurrency so CIRCL doesn't
    # rate-limit; coverage fills progressively across refreshes and is never
    # cached empty. The scanner-provided vector (connectors.py) remains the
    # authoritative source when present.
    need_vec = [c for c in out if not out[c].get("attack_vector")]
    if need_vec:
        vworkers = max(1, min(3, len(need_vec)))
        with ThreadPoolExecutor(max_workers=vworkers) as ex:
            for cve, vec in zip(need_vec, ex.map(_vector_cached, need_vec)):
                if vec:
                    out[cve]["cvss_vector"] = vec
                    out[cve]["attack_vector"] = attack_vector_from_vector(vec)
    return out
