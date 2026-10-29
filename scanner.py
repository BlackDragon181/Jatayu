"""
scanner.py — Active Threat Intelligence / Attack Surface Scanner
Fetches data from multiple FREE public APIs concurrently.
No paid keys required for base functionality; OTX_API_KEY, VT_API_KEY,
and ABUSEIPDB_KEY are used when present.
"""

import os
import re
import ssl
import socket
import json
import hashlib
import logging
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

import requests

try:
    import dns.resolver as _dns_resolver
except Exception:  # pragma: no cover - dnspython optional at import time
    _dns_resolver = None

logger = logging.getLogger(__name__)

# ── Shared session ─────────────────────────────────────────────────────────────
_session = requests.Session()
_session.headers.update({"User-Agent": "JATAYU-ThreatScanner/1.0"})
TIMEOUT = 12  # seconds per individual HTTP request

# Live web probing intentionally ignores cert validation (we report cert problems
# ourselves), so silence the noisy urllib3 warning.
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

# Lightweight session for live web probing (shorter timeout, browser-like UA)
_probe_session = requests.Session()
_probe_session.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; JATAYU-ASM/1.0; +attack-surface-scan)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
})
PROBE_TIMEOUT = 7  # seconds per live web request

# Attack-surface tuning
MAX_SUBDOMAINS_RESOLVE = 150   # cap passive subdomains we attempt to resolve/probe
MAX_HOSTS_DEEP_SCAN    = 40    # cap live hosts we deep-scan (ports + web checks)

# ── Constants ──────────────────────────────────────────────────────────────────
RISKY_PORTS = {21, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}

# Severity ordering (higher = worse) for sorting findings/remediation
SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# Security headers we evaluate, with the finding raised when missing
SECURITY_HEADERS = {
    "strict-transport-security": ("HIGH", "HSTS (Strict-Transport-Security) header missing",
        "Without HSTS, browsers may connect over plaintext HTTP, enabling SSL-strip / downgrade attacks.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses."),
    "content-security-policy": ("MEDIUM", "Content-Security-Policy header missing",
        "No CSP means the browser has no defence-in-depth against cross-site scripting and content injection.",
        "Define a restrictive Content-Security-Policy (start with 'default-src \\'self\\'' and tighten)."),
    "x-frame-options": ("MEDIUM", "X-Frame-Options / frame-ancestors not set",
        "The page can be embedded in a frame on a malicious site, enabling clickjacking.",
        "Set 'X-Frame-Options: DENY' (or a CSP 'frame-ancestors' directive)."),
    "x-content-type-options": ("LOW", "X-Content-Type-Options header missing",
        "Browsers may MIME-sniff responses, which can turn benign files into executable content.",
        "Set 'X-Content-Type-Options: nosniff' on all responses."),
    "referrer-policy": ("LOW", "Referrer-Policy header missing",
        "Full referrer URLs (which may contain sensitive data) can leak to third-party sites.",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter)."),
    "permissions-policy": ("LOW", "Permissions-Policy header missing",
        "Powerful browser features (camera, geolocation, etc.) are not explicitly restricted.",
        "Set a 'Permissions-Policy' header disabling features the app does not use."),
}

# Sensitive paths probed with safe GET requests (no payloads).
#   path, severity, signatures (any-match), html_ok, regex (optional strong proof)
# html_ok=False means a text/html response is rejected — real secret files
# (.env, .git/config, .DS_Store, backups) are NOT served as HTML, so an HTML body
# is almost always an SPA/soft-404 catch-all, not the file. A soft-404 baseline
# (see _probe_paths) plus these constraints eliminate the classic ".env exposed"
# false positives on SPA / wildcard sites.
SENSITIVE_PATHS = [
    {"path": "/.git/config",     "sev": "CRITICAL", "sigs": ["repositoryformatversion"],
     "html_ok": False, "regex": r"\[core\]"},
    {"path": "/.env",            "sev": "CRITICAL",
     "sigs": ["DB_", "APP_", "SECRET", "API_KEY", "AWS_", "DATABASE_URL"],
     "html_ok": False, "regex": r"(?m)^[A-Z][A-Z0-9_]{2,}\s*="},
    {"path": "/.svn/entries",    "sev": "HIGH", "sigs": ["svn://", "dir\n"], "html_ok": False},
    {"path": "/.DS_Store",       "sev": "LOW",  "sigs": ["Bud1"], "html_ok": False},
    {"path": "/phpinfo.php",     "sev": "HIGH", "sigs": ["phpinfo()", "PHP Version"], "html_ok": True,
     "regex": r"PHP Version\s*</td>|<title>phpinfo"},
    {"path": "/server-status",   "sev": "MEDIUM", "sigs": ["Apache Server Status"], "html_ok": True,
     "regex": r"Apache Server Status for"},
    {"path": "/backup.zip",      "sev": "HIGH", "sigs": ["PK\x03\x04"], "html_ok": False},
    {"path": "/config.php.bak",  "sev": "HIGH", "sigs": ["<?php"], "html_ok": False,
     "regex": r"DB_PASSWORD|define\(|mysqli?_connect"},
    {"path": "/.well-known/security.txt", "sev": "INFO", "sigs": ["Contact:"], "html_ok": False,
     "regex": r"(?mi)^Contact:\s*\S"},
    {"path": "/robots.txt",      "sev": "INFO", "sigs": ["Disallow:", "User-agent:"], "html_ok": False,
     "regex": r"(?mi)^(User-agent|Disallow|Allow|Sitemap)\s*:"},
]

PORT_LABELS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 2375: "Docker", 3000: "Dev HTTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB",
}


# ── Type detection ─────────────────────────────────────────────────────────────
def detect_type(query: str) -> str:
    """Return 'domain', 'ip', 'asn', or 'unknown'."""
    q = query.strip()
    # ASN
    if re.match(r'^[Aa][Ss]\d{1,10}$', q):
        return "asn"
    # IPv4
    try:
        ipaddress.IPv4Address(q)
        return "ip"
    except ValueError:
        pass
    # IPv6
    try:
        ipaddress.IPv6Address(q)
        return "ip"
    except ValueError:
        pass
    # Domain / hostname
    domain_re = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if domain_re.match(q):
        return "domain"
    return "unknown"


# ── Individual fetchers ────────────────────────────────────────────────────────

def _fetch_shodan_internetdb(ip: str) -> dict:
    """Shodan InternetDB — open ports, services, CVEs, tags. FREE, no key."""
    try:
        r = _session.get(f"https://internetdb.shodan.io/{ip}", timeout=TIMEOUT)
        if r.status_code == 404:
            return {"ip": ip, "ports": [], "cpes": [], "vulns": [], "tags": [], "hostnames": []}
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.debug(f"Shodan InternetDB error for {ip}: {e}")
        return {}


def _fetch_dns(domain: str) -> dict:
    """Cloudflare DNS-over-HTTPS for A, AAAA, MX, NS, TXT, CNAME records."""
    records = {}
    rtypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in rtypes:
        try:
            r = _session.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": rtype},
                headers={"Accept": "application/dns-json"},
                timeout=TIMEOUT,
            )
            r.raise_for_status()
            data = r.json()
            answers = data.get("Answer", [])
            if answers:
                records[rtype] = [a.get("data", "") for a in answers]
        except Exception as e:
            logger.debug(f"DNS {rtype} lookup error for {domain}: {e}")
    return records


def _fetch_crtsh(domain: str) -> list:
    """Certificate Transparency logs via crt.sh. Returns list of cert/subdomain records.

    crt.sh is frequently overloaded (502/timeout); retry briefly before giving up.
    """
    for attempt in range(2):
        try:
            r = _session.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=TIMEOUT,
            )
            if r.status_code >= 500:
                logger.debug(f"crt.sh {r.status_code} for {domain} (attempt {attempt+1})")
                continue
            r.raise_for_status()
            entries = r.json()
            seen = set()
            results = []
            for e in entries:
                names = e.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.").lower()
                    if name and name not in seen and name.endswith(domain):
                        seen.add(name)
                        results.append({
                            "name": name,
                            "issuer": e.get("issuer_ca_id"),
                            "not_before": e.get("not_before", "")[:10],
                            "not_after": e.get("not_after", "")[:10],
                            "cert_id": e.get("id"),
                        })
            # Sort: shortest (apex) first, then alphabetical
            results.sort(key=lambda x: (x["name"].count("."), x["name"]))
            return results[:200]
        except Exception as e:
            logger.debug(f"crt.sh error for {domain} (attempt {attempt+1}): {e}")
    return []


def _fetch_certspotter_subs(domain: str) -> set:
    """SSLMate certspotter issuances — free, reliable subdomain source."""
    out = set()
    try:
        r = _session.get(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            for issuance in r.json():
                for name in issuance.get("dns_names", []):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain):
                        out.add(name)
    except Exception as e:
        logger.debug(f"certspotter error for {domain}: {e}")
    return out


def _fetch_anubis_subs(domain: str) -> set:
    """jldc.me Anubis subdomain DB — free JSON list."""
    out = set()
    try:
        r = _session.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=TIMEOUT)
        if r.status_code == 200:
            for name in r.json():
                name = str(name).strip().lstrip("*.").lower()
                if name.endswith(domain):
                    out.add(name)
    except Exception as e:
        logger.debug(f"anubis error for {domain}: {e}")
    return out


def _fetch_hackertarget_subs(domain: str) -> set:
    """HackerTarget hostsearch — free CSV (host,ip), rate-limited."""
    out = set()
    try:
        r = _session.get("https://api.hackertarget.com/hostsearch/",
                         params={"q": domain}, timeout=TIMEOUT)
        if r.status_code == 200 and "," in r.text and "API count exceeded" not in r.text:
            for line in r.text.splitlines():
                host = line.split(",")[0].strip().lower()
                if host.endswith(domain):
                    out.add(host)
    except Exception as e:
        logger.debug(f"hackertarget error for {domain}: {e}")
    return out


def _enumerate_subdomains(domain: str) -> dict:
    """Merge subdomains from several free sources; return {names, certs}.

    crt.sh additionally provides certificate metadata for display.
    """
    certs = []
    names = set()
    sources = {
        "crtsh": lambda: _fetch_crtsh(domain),
        "certspotter": lambda: _fetch_certspotter_subs(domain),
        "anubis": lambda: _fetch_anubis_subs(domain),
        "hackertarget": lambda: _fetch_hackertarget_subs(domain),
    }
    ex = ThreadPoolExecutor(max_workers=4)
    fut = {ex.submit(fn): name for name, fn in sources.items()}
    try:
        for f in as_completed(fut, timeout=TIMEOUT + 8):
            name = fut[f]
            try:
                data = f.result()
            except Exception as e:
                logger.debug(f"subdomain source '{name}' failed: {e}")
                continue
            if name == "crtsh":
                certs = data or []
                names.update(c["name"] for c in certs)
            else:
                names.update(data or set())
    except FuturesTimeout:
        logger.debug("subdomain enumeration timed out; using partial results")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    names.add(domain)  # always include the apex
    ordered = sorted(names, key=lambda n: (n.count("."), n))
    return {"names": ordered, "certs": certs}


def _fetch_email_security(domain: str) -> dict:
    """Check SPF, DMARC, MTA-STS via DNS TXT lookups."""
    result = {
        "spf": None, "spf_strict": False,
        "dmarc": None, "dmarc_policy": None, "dmarc_enforce": False,
        "mta_sts": False,
        "issues": [],
        "grade": "F",
        "score": 0,
    }
    # SPF
    try:
        r = _session.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": "TXT"},
            headers={"Accept": "application/dns-json"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        txts = [a.get("data", "") for a in r.json().get("Answer", [])]
        for txt in txts:
            txt_clean = txt.strip('"')
            if txt_clean.startswith("v=spf1"):
                result["spf"] = txt_clean
                if "-all" in txt_clean:
                    result["spf_strict"] = True
                break
    except Exception as e:
        logger.debug(f"SPF lookup error for {domain}: {e}")

    # DMARC
    try:
        r = _session.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": f"_dmarc.{domain}", "type": "TXT"},
            headers={"Accept": "application/dns-json"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        txts = [a.get("data", "") for a in r.json().get("Answer", [])]
        for txt in txts:
            txt_clean = txt.strip('"')
            if txt_clean.startswith("v=DMARC1"):
                result["dmarc"] = txt_clean
                m = re.search(r'p=(\w+)', txt_clean)
                if m:
                    result["dmarc_policy"] = m.group(1)
                    if m.group(1) in ("quarantine", "reject"):
                        result["dmarc_enforce"] = True
                break
    except Exception as e:
        logger.debug(f"DMARC lookup error for {domain}: {e}")

    # MTA-STS
    try:
        r = _session.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": f"_mta-sts.{domain}", "type": "TXT"},
            headers={"Accept": "application/dns-json"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        txts = [a.get("data", "") for a in r.json().get("Answer", [])]
        for txt in txts:
            if "v=STSv1" in txt.strip('"'):
                result["mta_sts"] = True
                break
    except Exception as e:
        logger.debug(f"MTA-STS lookup error for {domain}: {e}")

    # Score + grade
    score = 0
    if result["spf"]:
        score += 25
    if result["spf_strict"]:
        score += 15
    if result["dmarc"]:
        score += 35
    if result["dmarc_enforce"]:
        score += 20
    if result["mta_sts"]:
        score += 5
    result["score"] = score
    if score >= 90:
        result["grade"] = "A"
    elif score >= 75:
        result["grade"] = "B"
    elif score >= 50:
        result["grade"] = "C"
    elif score >= 25:
        result["grade"] = "D"
    else:
        result["grade"] = "F"

    # Issues list
    if not result["spf"]:
        result["issues"].append("No SPF record found")
    elif not result["spf_strict"]:
        result["issues"].append("SPF policy not strict (-all missing)")
    if not result["dmarc"]:
        result["issues"].append("No DMARC record found")
    elif not result["dmarc_enforce"]:
        result["issues"].append(f"DMARC policy not enforced (p={result['dmarc_policy'] or 'none'})")
    if not result["mta_sts"]:
        result["issues"].append("MTA-STS not configured")

    return result


def _fetch_ipinfo(ip_or_domain: str) -> dict:
    """ipinfo.io — IP geolocation, ASN, org. FREE tier."""
    try:
        r = _session.get(f"https://ipinfo.io/{ip_or_domain}/json", timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.debug(f"ipinfo.io error for {ip_or_domain}: {e}")
        return {}


def _fetch_greynoise(ip: str) -> dict:
    """GreyNoise Community API — IP noise/reputation. FREE."""
    try:
        r = _session.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": ""},  # anonymous community tier
            timeout=TIMEOUT,
        )
        if r.status_code in (400, 404):
            return {"ip": ip, "noise": False, "riot": False, "classification": "unknown", "message": "not found"}
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.debug(f"GreyNoise error for {ip}: {e}")
        return {}


def _fetch_rdap(query: str, qtype: str) -> dict:
    """RDAP (rdap.org) — WHOIS/registration data. FREE."""
    try:
        if qtype == "ip":
            url = f"https://rdap.org/ip/{query}"
        elif qtype == "asn":
            asn_num = re.sub(r'^[Aa][Ss]', '', query)
            url = f"https://rdap.org/autnum/{asn_num}"
        elif qtype == "domain":
            url = f"https://rdap.org/domain/{query}"
        else:
            return {}
        r = _session.get(url, timeout=TIMEOUT)
        if r.status_code in (400, 404, 422):
            return {"error": f"RDAP: not found ({r.status_code})"}
        r.raise_for_status()
        data = r.json()
        # Extract useful fields
        result = {
            "handle": data.get("handle"),
            "type": data.get("type"),
            "name": data.get("name"),
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "ip_version": data.get("ipVersion"),
            "country": data.get("country"),
            "parent_handle": data.get("parentHandle"),
        }
        # Entities (registrar, registrant, etc.)
        entities = []
        for ent in data.get("entities", []):
            vcard = ent.get("vcardArray", [])
            name = ""
            email = ""
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        name = field[3]
                    elif field[0] == "email":
                        email = field[3]
            roles = ent.get("roles", [])
            if name or roles:
                entities.append({"name": name, "email": email, "roles": roles})
        result["entities"] = entities[:6]
        # Events (registration, expiry, last changed)
        events = []
        for ev in data.get("events", []):
            events.append({
                "action": ev.get("eventAction"),
                "date": ev.get("eventDate", "")[:10],
            })
        result["events"] = events
        # Remarks
        remarks = []
        for rem in data.get("remarks", [])[:3]:
            desc = " ".join(rem.get("description", []))
            if desc:
                remarks.append(desc[:200])
        result["remarks"] = remarks
        # Prefixes (ASN)
        if "networks" in data:
            result["prefixes"] = [n.get("handle", "") for n in data["networks"][:20]]
        return {k: v for k, v in result.items() if v is not None}
    except Exception as e:
        logger.debug(f"RDAP error for {query}: {e}")
        return {}


def _fetch_urlscan(domain_or_ip: str) -> dict:
    """URLScan.io — recent scans. FREE read access."""
    try:
        r = _session.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain_or_ip}", "size": 10},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        results = []
        for res in data.get("results", [])[:10]:
            page = res.get("page", {})
            results.append({
                "url": page.get("url", ""),
                "ip": page.get("ip", ""),
                "country": page.get("country", ""),
                "status": page.get("status", ""),
                "task_time": res.get("task", {}).get("time", "")[:10],
                "screenshot": res.get("screenshot", ""),
                "verdict": res.get("verdicts", {}).get("overall", {}).get("malicious", False),
            })
        return {
            "total": data.get("total", 0),
            "results": results,
            "malicious_count": sum(1 for r in results if r.get("verdict")),
        }
    except Exception as e:
        logger.debug(f"URLScan error for {domain_or_ip}: {e}")
        return {}


def _fetch_otx(query: str, qtype: str) -> dict:
    """AlienVault OTX — threat pulses. Requires OTX_API_KEY env var."""
    key = os.environ.get("OTX_API_KEY", "")
    if not key:
        return {"available": False, "reason": "OTX_API_KEY not configured"}
    try:
        headers = {"X-OTX-API-KEY": key}
        if qtype == "ip":
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{query}/general"
        elif qtype == "domain":
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{query}/general"
        else:
            return {"available": False, "reason": "ASN not supported by OTX"}
        r = _session.get(url, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        return {
            "available": True,
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "pulses": [
                {
                    "name": p.get("name", ""),
                    "tags": p.get("tags", [])[:5],
                    "created": p.get("created", "")[:10],
                    "tlp": p.get("tlp", ""),
                }
                for p in data.get("pulse_info", {}).get("pulses", [])[:8]
            ],
            "reputation": data.get("reputation", 0),
            "country": data.get("country_name", ""),
        }
    except Exception as e:
        logger.debug(f"OTX error for {query}: {e}")
        return {"available": False, "error": str(e)}


def _fetch_virustotal(query: str, qtype: str) -> dict:
    """VirusTotal — requires VT_API_KEY env var."""
    key = os.environ.get("VT_API_KEY", "")
    if not key:
        return {"available": False, "reason": "VT_API_KEY not configured"}
    try:
        headers = {"x-apikey": key}
        if qtype == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
        elif qtype == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{query}"
        else:
            return {"available": False, "reason": "ASN not supported by VirusTotal"}
        r = _session.get(url, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data.get("reputation", 0),
            "categories": data.get("categories", {}),
            "last_analysis_date": data.get("last_analysis_date"),
            "tags": data.get("tags", [])[:10],
        }
    except Exception as e:
        logger.debug(f"VirusTotal error for {query}: {e}")
        return {"available": False, "error": str(e)}


def _fetch_abuseipdb(ip: str) -> dict:
    """AbuseIPDB — requires ABUSEIPDB_KEY env var."""
    key = os.environ.get("ABUSEIPDB_KEY", "")
    if not key:
        return {"available": False, "reason": "ABUSEIPDB_KEY not configured"}
    try:
        r = _session.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            headers={"Key": key, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "available": True,
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "last_reported_at": (d.get("lastReportedAt") or "")[:10],
            "isp": d.get("isp", ""),
            "usage_type": d.get("usageType", ""),
            "domain": d.get("domain", ""),
            "country_code": d.get("countryCode", ""),
        }
    except Exception as e:
        logger.debug(f"AbuseIPDB error for {ip}: {e}")
        return {"available": False, "error": str(e)}


# ── Active host discovery & web-application checks ───────────────────────────────

def _mk_finding(severity, category, asset, title, description, remediation,
                evidence="", cve=None, cvss=None, unverified=False,
                confidence="Confirmed", owasp="") -> dict:
    """Build a normalised finding record.

    confidence: "Confirmed" (directly validated), "Likely" (strong signal),
    or "Informational". The UI/report can surface only Confirmed/Likely to keep
    the signal-to-noise enterprise-grade. owasp: OWASP Top-10 tag, e.g. "A03:2021 Injection".
    """
    f = {
        "severity": severity,
        "category": category,
        "asset": asset,
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
        "confidence": confidence,
    }
    if owasp:
        f["owasp"] = owasp
    if cve:
        f["cve"] = cve
    if cvss is not None:
        f["cvss"] = cvss
    if unverified:
        # Inferred (e.g. version-based) rather than directly validated — drives
        # a lower confidence rating in the ASM assessment and reduces FP noise.
        f["unverified"] = True
    return f


def _resolve_host(host: str) -> list:
    """Resolve a hostname to a list of IPv4/IPv6 addresses."""
    ips = []
    if _dns_resolver is not None:
        for rtype in ("A", "AAAA"):
            try:
                ans = _dns_resolver.resolve(host, rtype, lifetime=5)
                ips.extend(str(r) for r in ans)
            except Exception:
                pass
    if not ips:
        try:
            info = socket.getaddrinfo(host, None)
            ips = list({i[4][0] for i in info})
        except Exception:
            pass
    return list(dict.fromkeys(ips))


def _probe_http(host: str) -> dict:
    """Probe https:// then http:// for a live web service. Non-intrusive GET."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = _probe_session.get(url, timeout=PROBE_TIMEOUT, allow_redirects=True,
                                   verify=False, stream=True)
            # Read a bounded slice of the body for fingerprinting / signatures
            body = ""
            try:
                raw = r.raw.read(20000, decode_content=True) or b""
                body = raw.decode(r.encoding or "utf-8", errors="replace")
            except Exception:
                body = (r.text or "")[:20000]
            finally:
                r.close()
            final_url = r.url or url
            return {
                "alive": True,
                "scheme": scheme,
                "status": r.status_code,
                "final_url": final_url,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": body,
                "redirect_to_https": final_url.startswith("https://"),
                "probed_scheme": scheme,
            }
        except Exception as e:
            logger.debug(f"HTTP probe {url} failed: {e}")
            continue
    return {"alive": False}


def _check_security_headers(headers: dict, asset: str, status: int = 200, content_type: str = "") -> list:
    """Flag missing/weak HTTP security headers.

    Only evaluated on a 200 HTML page response — checking headers on redirects,
    JSON/API endpoints, or error pages produces noisy false positives.
    """
    findings = []
    if status != 200 or "html" not in (content_type or "").lower():
        return findings
    for hdr, (sev, title, desc, fix) in SECURITY_HEADERS.items():
        val = headers.get(hdr, "")
        if not val:
            # X-Frame-Options can be satisfied by CSP frame-ancestors
            if hdr == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", "").lower():
                continue
            findings.append(_mk_finding(sev, "Security Headers", asset, title, desc, fix,
                owasp="A05:2021 Security Misconfiguration"))
        elif hdr == "strict-transport-security":
            m = re.search(r"max-age=(\d+)", val)
            if m and int(m.group(1)) < 15552000:  # < 180 days
                findings.append(_mk_finding("LOW", "Security Headers", asset,
                    "HSTS max-age is short",
                    f"HSTS max-age is {m.group(1)}s; short windows weaken downgrade protection.",
                    "Use a max-age of at least 31536000 (1 year).", evidence=val,
                    owasp="A05:2021 Security Misconfiguration"))
    return findings


def _check_tls(host: str, asset: str) -> list:
    """Inspect the TLS certificate: expiry, issuer, protocol version."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                der = ssock.getpeercert(binary_form=True)
                proto = ssock.version()
        # Protocol version
        if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(_mk_finding("MEDIUM", "TLS/SSL", asset,
                f"Obsolete TLS protocol supported ({proto})",
                "Legacy TLS/SSL versions have known cryptographic weaknesses.",
                "Disable TLS 1.1 and below; require TLS 1.2+.", evidence=proto))
        # Validate against trust store separately to detect self-signed / chain issues
        try:
            vctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=PROBE_TIMEOUT) as s2:
                with vctx.wrap_socket(s2, server_hostname=host) as vs:
                    cert = vs.getpeercert() or cert
        except ssl.SSLCertVerificationError as ve:
            reason = str(ve)
            sev = "HIGH"
            if "self signed" in reason.lower() or "self-signed" in reason.lower():
                title = "Self-signed / untrusted TLS certificate"
            elif "hostname mismatch" in reason.lower() or "doesn't match" in reason.lower():
                title = "TLS certificate hostname mismatch"
            else:
                title = "TLS certificate failed validation"
            findings.append(_mk_finding(sev, "TLS/SSL", asset, title,
                "The certificate is not trusted by standard CAs, enabling MITM risk.",
                "Install a valid certificate from a trusted CA matching the hostname.",
                evidence=reason[:160]))
        # Expiry
        not_after = cert.get("notAfter") if isinstance(cert, dict) else None
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    findings.append(_mk_finding("HIGH", "TLS/SSL", asset,
                        "TLS certificate has expired",
                        f"The certificate expired {abs(days)} day(s) ago; clients will see errors.",
                        "Renew the TLS certificate immediately.", evidence=not_after))
                elif days < 21:
                    findings.append(_mk_finding("MEDIUM", "TLS/SSL", asset,
                        "TLS certificate expiring soon",
                        f"The certificate expires in {days} day(s).",
                        "Renew the certificate before expiry and automate renewal.", evidence=not_after))
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"TLS check {host} failed: {e}")
    return findings


def _check_cookies(headers: dict, asset: str) -> list:
    """Check Set-Cookie flags (Secure, HttpOnly, SameSite) per individual cookie."""
    findings = []
    raw = headers.get("set-cookie", "")
    if not raw:
        return findings
    # Split on cookie boundaries (commas not inside quoted values or date fields).
    # Use a conservative split: each Set-Cookie header value ends before a new token=value pair.
    # requests joins multiple Set-Cookie headers with ', '; split only on ', ' followed by a name= pattern.
    import re as _re
    cookie_parts = _re.split(r",\s*(?=[A-Za-z_][A-Za-z0-9_\-]*=)", raw)
    for part in cookie_parts:
        name = part.split("=", 1)[0].strip()[:40]
        low = part.lower()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            findings.append(_mk_finding("LOW", "Cookies", asset,
                f"Cookie '{name}' missing flags: {', '.join(missing)}",
                "Cookies without Secure/HttpOnly/SameSite are exposed to theft via XSS or plaintext transport.",
                "Set Secure, HttpOnly, and SameSite=Lax/Strict on session cookies.",
                evidence=f"{name} -> missing {', '.join(missing)}"))
    return findings


def _fingerprint_tech(headers: dict, body: str, asset: str) -> tuple:
    """Detect server / framework / CMS. Returns (tech_list, findings)."""
    tech = []
    findings = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    generator = headers.get("x-generator", "")
    if server:
        tech.append(server)
    if powered:
        tech.append(powered)
    if generator:
        tech.append(generator)

    # Version disclosure (a digit in the Server / X-Powered-By banner)
    disclosed = [v for v in (server, powered) if re.search(r"\d+\.\d+", v)]
    if disclosed:
        findings.append(_mk_finding("INFO", "Information Disclosure", asset,
            "Software version disclosed in HTTP headers",
            "Exact product versions help attackers match known exploits to the target.",
            "Suppress version banners (e.g. ServerTokens Prod / expose_php Off).",
            evidence="; ".join(disclosed)[:160]))

    # CMS / framework signatures from body + cookies
    blow = (body or "").lower()
    cookie = headers.get("set-cookie", "").lower()
    sigs = {
        "WordPress": ("wp-content" in blow or "wp-includes" in blow or "wordpress" in generator.lower()),
        "Drupal": ("drupal" in blow or "drupal" in generator.lower()),
        "Joomla": ("joomla" in blow or "joomla" in generator.lower()),
        "Django": ("csrftoken" in cookie or "django" in powered.lower()),
        "Laravel": ("laravel_session" in cookie),
        "PHP": ("phpsessid" in cookie or "php" in powered.lower()),
        "ASP.NET": ("asp.net" in powered.lower() or "aspxauth" in cookie),
    }
    meta = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body or "", re.I)
    if meta:
        tech.append(meta.group(1).strip())
    for name, present in sigs.items():
        if present and name not in tech:
            tech.append(name)
    return list(dict.fromkeys([t for t in tech if t])), findings


def _check_dir_listing(body: str, status: int, asset: str) -> list:
    """Detect autoindex / directory listing."""
    if status == 200 and body and ("Index of /" in body or "<title>Index of" in body):
        return [_mk_finding("MEDIUM", "Information Disclosure", asset,
            "Directory listing enabled",
            "Autoindex exposes the full file listing of a directory to anyone.",
            "Disable directory autoindex (Options -Indexes / autoindex off).")]
    return []


def _check_https_redirect(probe: dict, asset: str) -> list:
    """Flag a site that serves over HTTP without redirecting to HTTPS."""
    if probe.get("alive") and probe.get("probed_scheme") == "http" and not probe.get("redirect_to_https"):
        return [_mk_finding("MEDIUM", "Transport Security", asset,
            "No HTTP-to-HTTPS redirect",
            "The site serves content over plaintext HTTP without forcing HTTPS, exposing traffic to interception.",
            "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.")]
    return []


# Improbable paths used to fingerprint catch-all / soft-404 servers (SPAs, wildcard
# routers) that return 200 + an HTML page for *every* URL — the #1 cause of bogus
# "/.env exposed" findings.
_SOFT404_PROBES = ["/jatayu-baseline-7f3a9q.html", "/zzq-not-real-1b8x2", "/.well-known/jatayu-404x"]


def _fetch_path(base: str, path: str):
    """GET a path; return (status, content_type, text, length) or None on error."""
    try:
        r = _probe_session.get(base + path, timeout=PROBE_TIMEOUT,
                               allow_redirects=False, verify=False, stream=True)
        status = r.status_code
        ctype = (r.headers.get("content-type", "") or "").lower()
        clen = r.headers.get("content-length")
        try:
            chunk = (r.raw.read(6000, decode_content=True) or b"")
            text = chunk.decode("utf-8", errors="replace")
        except Exception:
            text = (r.text or "")[:6000]
        finally:
            r.close()
        length = int(clen) if (clen and clen.isdigit()) else len(text)
        return (status, ctype, text, length)
    except Exception as e:
        logger.debug(f"Path fetch {base+path} failed: {e}")
        return None


def _soft404_baseline(base: str) -> dict:
    """Probe improbable paths to learn how the server answers non-existent URLs."""
    statuses, hashes, html_catchall = set(), set(), False
    for p in _SOFT404_PROBES:
        res = _fetch_path(base, p)
        if not res:
            continue
        status, ctype, text, _ = res
        statuses.add(status)
        hashes.add(hashlib.md5(text.encode("utf-8", "replace")).hexdigest())
        if status == 200:                      # 200 for a path that cannot exist
            if "html" in ctype or "<html" in text[:400].lower():
                html_catchall = True
    return {"statuses": statuses, "hashes": hashes, "html_catchall": html_catchall}


def _looks_like_soft404(res, baseline) -> bool:
    """True if a probe response is indistinguishable from the server's 404 page."""
    status, ctype, text, _ = res
    if hashlib.md5(text.encode("utf-8", "replace")).hexdigest() in baseline["hashes"]:
        return True                             # byte-identical to a known 404 body
    # Catch-all serving HTML for everything: an HTML response to a "file" path is bogus.
    if baseline["html_catchall"] and ("html" in ctype or "<html" in text[:400].lower()):
        return True
    return False


def _probe_paths(base_url: str, asset: str, baseline: dict = None) -> list:
    """Safe GET probes for exposed sensitive files/paths. No payloads.

    Eliminates false positives by (1) learning the server's soft-404 behaviour,
    (2) rejecting catch-all/SPA HTML responses for non-HTML file paths, and
    (3) requiring a strong content signature (and an optional regex proof) — not
    just a 200 status and a weak keyword.
    """
    findings = []
    base = base_url.rstrip("/")
    if baseline is None:
        baseline = _soft404_baseline(base)

    def _probe(entry):
        path = entry["path"]
        res = _fetch_path(base, path)
        if not res:
            return None
        status, ctype, text, length = res
        if status != 200 or not text:
            return None
        if _looks_like_soft404(res, baseline):
            return None
        is_html = "html" in ctype or "<html" in text[:400].lower()
        # Real secret files are not served as HTML — reject SPA/error pages.
        if not entry.get("html_ok", True) and is_html:
            return None
        if not any(s in text for s in entry["sigs"]):
            return None
        rx = entry.get("regex")
        if rx and not re.search(rx, text):
            return None                         # strong proof required, not present
        sev = entry["sev"]
        title = (f"Exposed path: {path}" if sev == "INFO"
                 else f"Sensitive path exposed: {path}")
        return _mk_finding(sev, "Exposed Path", asset, title,
            f"{path} is publicly accessible and returned matching content "
            f"(content-type: {ctype or 'unknown'}).",
            f"Restrict or remove public access to {path}.",
            evidence=f"GET {path} -> 200 ({length}B)",
            confidence="Confirmed", owasp="A05:2021 Security Misconfiguration")

    with ThreadPoolExecutor(max_workers=8) as ex:
        for fnd in ex.map(_probe, SENSITIVE_PATHS):
            if fnd:
                findings.append(fnd)
    return findings


# ── Rogue / look-alike domain detection (homograph + typosquat) ─────────────────
# Confusable characters that render like an ASCII letter (the basis of homograph
# attacks). Includes high-value Cyrillic/Greek homoglyphs valid in IDN domains.
_HOMOGLYPHS = {
    "a": ["а", "ɑ"], "c": ["с", "ϲ"], "e": ["е", "ё"], "o": ["о", "ο", "0"],
    "p": ["р"], "x": ["х"], "y": ["у"], "i": ["і", "ı", "1", "l"], "s": ["ѕ"],
    "j": ["ј"], "h": ["һ"], "d": ["ԁ"], "g": ["ɡ", "9"], "l": ["1", "i", "ӏ"],
    "m": ["rn"], "n": ["ո"], "w": ["vv", "ѡ"], "b": ["Ь", "6"], "k": ["κ"],
    "t": ["т"], "u": ["υ", "ս"], "z": ["ᴢ"],
}
# Adjacent QWERTY keys for typo generation.
_QWERTY = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}
_ALT_TLDS = ["com", "net", "org", "io", "co", "app", "xyz", "online", "site",
             "info", "biz", "live", "icu", "top", "vip", "cc", "store"]
_COMBO_SUFFIX = ["-login", "-secure", "-support", "-account", "-verify", "-pay",
                 "-help", "-mail", "-portal", "-app", "secure", "login"]
_COMBO_PREFIX = ["login-", "secure-", "my-", "account-", "portal-", "www-"]
_MULTI_TLDS = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "co.za", "org.uk", "com.sg"}


def _split_domain(domain: str):
    """Split into (sld, tld) handling a few common multi-part TLDs."""
    domain = domain.lower().strip().strip(".")
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_TLDS:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    if len(parts) >= 2:
        return ".".join(parts[:-1]), parts[-1]
    return domain, ""


def _to_ace(domain: str) -> str:
    """Unicode domain → ASCII (punycode/A-label). '' if it can't be encoded."""
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        try:
            return ".".join(
                lbl.encode("idna").decode("ascii") if any(ord(c) > 127 for c in lbl) else lbl
                for lbl in domain.split("."))
        except Exception:
            return ""


def _generate_lookalikes(domain: str) -> dict:
    """Generate candidate look-alike domains → {candidate: technique}. Apex SLD only."""
    sld, tld = _split_domain(domain)
    if not sld or not tld:
        return {}
    cand = {}

    def add(name, tech):
        name = name.lower()
        if name and name != domain and "." in name:
            cand.setdefault(name, tech)

    # 1) Homograph substitutions (one char at a time).
    for i, ch in enumerate(sld):
        for gl in _HOMOGLYPHS.get(ch, []):
            add(sld[:i] + gl + sld[i + 1:] + "." + tld, "homograph")
    # 2) Typos: omission, repetition, transposition, adjacent-key replacement.
    for i in range(len(sld)):
        add(sld[:i] + sld[i + 1:] + "." + tld, "typo-omission")
        add(sld[:i] + sld[i] + sld[i:] + "." + tld, "typo-repetition")
        if i + 1 < len(sld):
            add(sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:] + "." + tld, "typo-transposition")
        for k in _QWERTY.get(sld[i], ""):
            add(sld[:i] + k + sld[i + 1:] + "." + tld, "typo-adjacent")
    # 3) Hyphenation / dot removal.
    if "-" not in sld and len(sld) > 4:
        mid = len(sld) // 2
        add(sld[:mid] + "-" + sld[mid:] + "." + tld, "hyphenation")
    # 4) TLD swap.
    for t in _ALT_TLDS:
        if t != tld:
            add(sld + "." + t, "tld-swap")
    # 5) Combosquatting.
    for s in _COMBO_SUFFIX:
        add(sld + s + "." + tld, "combosquat")
    for p in _COMBO_PREFIX:
        add(p + sld + "." + tld, "combosquat")
    return cand


def detect_lookalikes(domain: str, max_candidates: int = 600) -> list:
    """Return DNS-CONFIRMED look-alike domains only (registered + resolving).

    Unregistered theoretical variants are never reported — per the requirement to
    only surface look-alikes once their existence is confirmed.
    """
    cand = _generate_lookalikes(domain)
    if not cand:
        return []
    items = list(cand.items())[:max_candidates]

    def _check(item):
        name, tech = item
        ace = _to_ace(name) or name
        ips = _resolve_host(ace)
        if not ips:
            return None
        return {"domain": name, "punycode": ace if ace != name else "",
                "technique": tech, "ips": ips[:3],
                "homograph": tech == "homograph" or ace.startswith("xn--") or "xn--" in ace,
                "confidence": "Confirmed"}

    out = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        try:
            for r in ex.map(_check, items, timeout=35):
                if r:
                    out.append(r)
        except Exception:
            pass
    # Most deceptive first: homographs, then typos, then combosquat/tld-swap.
    rank = {"homograph": 0, "typo-transposition": 1, "typo-omission": 1,
            "typo-adjacent": 1, "typo-repetition": 1, "hyphenation": 2,
            "combosquat": 3, "tld-swap": 4}
    out.sort(key=lambda x: rank.get(x["technique"], 5))
    return out


# ── OWASP safe web-vuln detection (non-intrusive) ───────────────────────────────
# DB error signatures — presence after a single benign quote indicates the input
# reaches a SQL query unsanitised (OWASP A03). Read-only; no data is modified.
_SQL_ERRORS = re.compile(
    r"(SQL syntax.*?MySQL|Warning.*?\bmysqli?_|valid MySQL result|MySqlException|"
    r"PostgreSQL.*?ERROR|pg_query\(\)|PG::\w*Error|"
    r"Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark after the character string|"
    r"System\.Data\.SqlClient\.SqlException|"
    r"ORA-\d{5}|Oracle error|quoted string not properly terminated|"
    r"SQLite3?::|sqlite3\.OperationalError|SQLSTATE\[)", re.I | re.S)

# Verbose error / stack-trace signatures (OWASP A05 misconfig). Strong, low-FP only.
_STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|java\.lang\.[A-Za-z.]+Exception|"
    r"at System\.[A-Za-z.]+\(|Stack trace:|Microsoft\.AspNetCore\.Diagnostics|"
    r"Whoops\\?, looks like something went wrong|Werkzeug Debugger|"
    r"<b>Fatal error</b>:|<b>Warning</b>:.*?on line)", re.I | re.S)

_REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_uri", "return", "returnurl",
                    "dest", "destination", "continue", "r", "u"]
_COMMON_PARAMS = ["id", "q", "search", "page", "file", "cat", "item"]
_XSS_MARKER = "jx9z3q'\"<svg/onload=1>"


def _extract_param_urls(body: str, base_url: str, cap: int = 4) -> list:
    """Same-origin URLs that carry query parameters, parsed from the page."""
    from urllib.parse import urlparse, urljoin, parse_qs
    out, seen = [], set()
    base_host = urlparse(base_url).hostname or ""
    for m in re.finditer(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', body, re.I):
        raw = m.group(1)
        if raw.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            continue
        u = urljoin(base_url, raw)
        p = urlparse(u)
        if p.scheme not in ("http", "https") or (p.hostname and base_host and p.hostname != base_host):
            continue
        if not p.query:
            continue
        params = list(parse_qs(p.query).keys())
        if not params:
            continue
        key = (p.path, tuple(sorted(params)))
        if key in seen:
            continue
        seen.add(key)
        out.append((u, params))
        if len(out) >= cap:
            break
    return out


def _set_param(url: str, param: str, value: str) -> str:
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[param] = [value]
    flat = {k: v[0] for k, v in qs.items()}
    return urlunparse(p._replace(query=urlencode(flat)))


def _get(url: str, allow_redirects=False):
    try:
        r = _probe_session.get(url, timeout=PROBE_TIMEOUT, allow_redirects=allow_redirects,
                               verify=False, stream=True)
        try:
            text = (r.raw.read(8000, decode_content=True) or b"").decode("utf-8", "replace")
        except Exception:
            text = (r.text or "")[:8000]
        finally:
            r.close()
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, text
    except Exception:
        return None


def _check_web_vulns(probe: dict, asset: str) -> list:
    """Non-intrusive OWASP-style checks: SQLi (error-based), reflected XSS, open
    redirect, and verbose-error misconfiguration. Read-only single probes."""
    findings = []
    base = probe.get("final_url") or ""
    body = probe.get("body", "") or ""
    if not base:
        return findings

    # Verbose error / stack trace already visible on the landing page (A05).
    if _STACK_TRACE.search(body):
        findings.append(_mk_finding("MEDIUM", "Security Misconfiguration", asset,
            "Verbose error / stack trace exposed",
            "The application returns framework stack traces or debug output, leaking "
            "internal paths, versions, and logic useful to attackers.",
            "Disable debug mode in production and return generic error pages.",
            evidence=_STACK_TRACE.search(body).group(0)[:120],
            confidence="Confirmed", owasp="A05:2021 Security Misconfiguration"))

    # Candidate (url, params): discovered param URLs + common params on the base.
    candidates = _extract_param_urls(body, base)
    base_params = [(base, _COMMON_PARAMS)] if "?" not in base else []
    targets = candidates + base_params
    tested = 0
    seen_sqli = seen_xss = False

    for url, params in targets:
        for param in params[:3]:
            if tested >= 12:
                break
            tested += 1
            # SQLi — single benign quote; look for a DB error that wasn't there before.
            if not seen_sqli:
                res = _get(_set_param(url, param, "1'\""))
                if res and res[2] and _SQL_ERRORS.search(res[2]) and not _SQL_ERRORS.search(body):
                    seen_sqli = True
                    findings.append(_mk_finding("HIGH", "SQL Injection", asset,
                        f"Possible SQL injection via '{param}'",
                        "A single-quote probe elicited a database error, indicating user "
                        "input reaches a SQL query without proper parameterisation.",
                        "Use parameterised queries / prepared statements; validate and "
                        "escape input; deploy a WAF as defence-in-depth.",
                        evidence=f"{param}=1'\" -> {_SQL_ERRORS.search(res[2]).group(0)[:80]}",
                        confidence="Confirmed", owasp="A03:2021 Injection"))
            # Reflected XSS — benign marker reflected unencoded.
            if not seen_xss:
                res = _get(_set_param(url, param, _XSS_MARKER))
                if res and res[2] and _XSS_MARKER in res[2]:
                    ctype = (res[1].get("content-type", "") or "").lower()
                    if "html" in ctype:
                        seen_xss = True
                        findings.append(_mk_finding("HIGH", "Cross-Site Scripting", asset,
                            f"Possible reflected XSS via '{param}'",
                            "User input is reflected into the HTML response without output "
                            "encoding, allowing script injection in a victim's browser.",
                            "Context-aware output encoding; a strict Content-Security-Policy; "
                            "validate input.",
                            evidence=f"{param} reflected unencoded",
                            confidence="Likely", owasp="A03:2021 Injection"))
            # Open redirect — redirect-ish param echoed into Location.
            if param.lower() in _REDIRECT_PARAMS:
                res = _get(_set_param(url, param, "https://jatayu-redirect.example/x"),
                           allow_redirects=False)
                if res and res[0] in (301, 302, 303, 307, 308):
                    loc = res[1].get("location", "")
                    if "jatayu-redirect.example" in loc:
                        findings.append(_mk_finding("MEDIUM", "Open Redirect", asset,
                            f"Open redirect via '{param}'",
                            "The application redirects to an attacker-controlled URL, aiding "
                            "phishing and OAuth token theft.",
                            "Allow-list redirect targets; avoid user-controlled redirects.",
                            evidence=f"{param} -> {loc[:80]}",
                            confidence="Confirmed", owasp="A01:2021 Broken Access Control"))
        if tested >= 12:
            break
    return findings


# ── Default-credential exposure (detect-only — NO login attempts) ───────────────
# Admin/management interfaces for products that ship with well-known default
# credentials. We only fingerprint exposure and flag the risk; we never submit
# credentials. default = documented vendor default (for the analyst's message).
_DEFAULT_CRED_PANELS = [
    {"path": "/manager/html",        "product": "Apache Tomcat Manager", "default": "tomcat/tomcat",
     "sigs": ["Tomcat", "manager-gui"], "realm": "tomcat", "sev": "HIGH"},
    {"path": "/jenkins/login",       "product": "Jenkins",        "default": "admin/admin",
     "sigs": ["Jenkins", "j_username"], "sev": "HIGH"},
    {"path": "/login",               "product": "Grafana",        "default": "admin/admin",
     "sigs": ["Grafana", "grafana-app"], "sev": "HIGH"},
    {"path": "/phpmyadmin/",         "product": "phpMyAdmin",     "default": "root/(blank)",
     "sigs": ["phpMyAdmin", "pma_username"], "sev": "HIGH"},
    {"path": "/wp-login.php",        "product": "WordPress admin", "default": "(no default — brute-force target)",
     "sigs": ["user_login", "wp-submit"], "sev": "MEDIUM"},
    {"path": "/administrator/",      "product": "Joomla admin",   "default": "admin/admin",
     "sigs": ["Joomla", "mod-login"], "sev": "MEDIUM"},
    {"path": "/solr/",               "product": "Apache Solr",    "default": "(no auth by default)",
     "sigs": ["Solr Admin", "solr-admin"], "sev": "HIGH"},
    {"path": "/actuator",            "product": "Spring Boot Actuator", "default": "(exposed management endpoints)",
     "sigs": ['"_links"', '"health"', "self"], "html_ok": False, "sev": "HIGH"},
    {"path": "/admin/",              "product": "Admin interface", "default": "varies",
     "sigs": ["password", "username", "login"], "sev": "LOW"},
    {"path": "/pgadmin4/",           "product": "pgAdmin",        "default": "admin/admin",
     "sigs": ["pgAdmin"], "sev": "HIGH"},
    {"path": "/kibana/",             "product": "Kibana",         "default": "elastic/changeme",
     "sigs": ["kibana", "kbn-"], "sev": "HIGH"},
]


def _check_default_creds(base_url: str, asset: str, baseline: dict = None) -> list:
    """Fingerprint exposed admin/login panels known to ship with default
    credentials and flag the risk. NO login attempts are made."""
    findings = []
    base = base_url.rstrip("/")
    if baseline is None:
        baseline = _soft404_baseline(base)

    def _probe(entry):
        res = _fetch_path(base, entry["path"])
        if not res:
            return None
        status, ctype, text, _ = res
        realm_hit = False
        if status in (401, 403):
            # Basic/Digest-auth protected mgmt panel — confirm by realm if given.
            return None  # handled by generic basic-auth check below; avoid panel FP
        if status != 200 or not text:
            return None
        if _looks_like_soft404(res, baseline):
            return None
        if not entry.get("html_ok", True) and ("html" in ctype or "<html" in text[:400].lower()):
            return None
        if not any(s in text for s in entry["sigs"]):
            return None
        return _mk_finding(entry["sev"], "Default Credentials", asset,
            f"Exposed {entry['product']} interface",
            f"A publicly reachable {entry['product']} interface was detected. Products like "
            f"this ship with well-known default credentials ({entry['default']}); if unchanged, "
            "an attacker gains immediate access.",
            "Restrict the interface to trusted networks/VPN, and ensure default credentials "
            "have been changed to strong, unique values.",
            evidence=f"GET {entry['path']} -> 200 ({entry['product']})",
            confidence="Confirmed", owasp="A07:2021 Identification & Authentication Failures")

    with ThreadPoolExecutor(max_workers=6) as ex:
        for fnd in ex.map(_probe, _DEFAULT_CRED_PANELS):
            if fnd:
                findings.append(fnd)

    # Generic HTTP Basic/Digest auth on the site root (often default-cred devices).
    res = _fetch_path(base, "/")
    if res:
        status, _, _, _ = res
        if status == 401:
            try:
                r = _probe_session.get(base + "/", timeout=PROBE_TIMEOUT,
                                       allow_redirects=False, verify=False)
                wa = r.headers.get("www-authenticate", "")
                r.close()
            except Exception:
                wa = ""
            if wa:
                realm = re.search(r'realm="([^"]*)"', wa)
                findings.append(_mk_finding("MEDIUM", "Default Credentials", asset,
                    "HTTP authentication on root — verify default credentials",
                    f"The site root is protected by HTTP {wa.split()[0]} auth"
                    + (f' (realm: {realm.group(1)})' if realm else "")
                    + ". Appliances/devices behind Basic-Auth frequently retain default credentials.",
                    "Confirm credentials are not vendor defaults; place management behind VPN.",
                    evidence=wa[:100], confidence="Likely",
                    owasp="A07:2021 Identification & Authentication Failures"))
    return findings


def scan_host(host: str) -> dict:
    """Deep-scan a single live host: resolve, probe, run web checks + Shodan CVEs."""
    result = {
        "host": host, "ips": [], "alive": False, "status": None, "scheme": None,
        "ports": [], "cves": [], "tech": [], "findings": [],
    }
    ips = _resolve_host(host)
    result["ips"] = ips
    if not ips:
        return result

    probe = _probe_http(host)
    if not probe.get("alive"):
        # Not serving web — still record resolution + Shodan data
        sh = _fetch_shodan_internetdb(ips[0])
        result["ports"] = sh.get("ports", [])
        result["cves"] = sh.get("vulns", [])
        return result

    result["alive"] = True
    result["status"] = probe.get("status")
    result["scheme"] = probe.get("scheme")
    headers = probe.get("headers", {})
    body = probe.get("body", "")
    asset = host

    findings = []
    findings += _check_https_redirect(probe, asset)
    findings += _check_security_headers(headers, asset, probe.get("status", 200),
                                        headers.get("content-type", ""))
    findings += _check_cookies(headers, asset)
    findings += _check_dir_listing(body, probe.get("status"), asset)
    if probe.get("scheme") == "https":
        findings += _check_tls(host, asset)
    tech, tech_findings = _fingerprint_tech(headers, body, asset)
    findings += tech_findings
    result["tech"] = tech
    # Shared soft-404 baseline (one set of probes) reused by path + panel checks.
    base_url = probe.get("final_url") or f"{probe['scheme']}://{host}"
    baseline = _soft404_baseline(base_url.rstrip("/"))
    findings += _probe_paths(base_url, asset, baseline=baseline)
    findings += _check_default_creds(base_url, asset, baseline=baseline)
    findings += _check_web_vulns(probe, asset)

    # Shodan InternetDB CVEs/ports for the host's primary IP
    sh = _fetch_shodan_internetdb(ips[0])
    result["ports"] = sh.get("ports", [])
    cves = sh.get("vulns", [])
    result["cves"] = cves
    for cve in cves:
        # Shodan InternetDB associates CVEs by inferred product/version (CPE),
        # which is frequently inaccurate — flag as unverified MEDIUM, not HIGH,
        # so it reads as "potential, validate" rather than a confirmed critical.
        findings.append(_mk_finding("MEDIUM", "Vulnerability", asset,
            f"{cve} — potential exposure (version-inferred)",
            "Shodan InternetDB associates this CVE with a service on this host's IP "
            "based on inferred product/version. This is not validated and may be a false positive.",
            "Confirm the affected product/version, then patch or mitigate if the service is exposed.",
            evidence=f"{ips[0]} (Shodan InternetDB, version-inferred)", cve=cve, unverified=True))

    result["findings"] = findings
    return result


def _build_remediation(findings: list) -> list:
    """Group findings into a prioritised remediation roadmap."""
    groups = {}
    for f in findings:
        key = (f.get("category", ""), f.get("title", ""))
        g = groups.setdefault(key, {
            "title": f.get("title", ""),
            "category": f.get("category", ""),
            "severity": f.get("severity", "INFO"),
            "remediation": f.get("remediation", ""),
            "assets": set(),
        })
        if SEVERITY_ORDER.get(f.get("severity", "INFO"), 0) > SEVERITY_ORDER.get(g["severity"], 0):
            g["severity"] = f.get("severity", "INFO")
        if f.get("asset"):
            g["assets"].add(f["asset"])
    roadmap = []
    for g in groups.values():
        roadmap.append({
            "title": g["title"],
            "category": g["category"],
            "severity": g["severity"],
            "remediation": g["remediation"],
            "affected_count": len(g["assets"]),
            "affected_assets": sorted(g["assets"])[:10],
        })
    roadmap.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 0), r["affected_count"]), reverse=True)
    return roadmap


# ── IP resolution helper ───────────────────────────────────────────────────────

def _resolve_to_ips(query: str, qtype: str, dns_data: dict) -> list:
    """Return list of IPs to scan depending on query type."""
    if qtype == "ip":
        return [query]
    if qtype == "domain":
        ips = dns_data.get("A", []) + dns_data.get("AAAA", [])
        # fallback socket resolve
        if not ips:
            try:
                info = socket.getaddrinfo(query, None)
                ips = list({i[4][0] for i in info})[:4]
            except Exception:
                pass
        return ips[:8]
    return []


# ── ASN prefix enumeration ─────────────────────────────────────────────────────

def _fetch_asn_prefixes(asn: str) -> list:
    """Use bgp.he.net JSON endpoint for prefix list."""
    try:
        asn_num = re.sub(r'^[Aa][Ss]', '', asn)
        r = _session.get(
            f"https://bgp.he.net/AS{asn_num}",
            headers={"Accept": "text/html"},
            timeout=TIMEOUT,
        )
        # Parse prefixes from the page with simple regex
        prefixes = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', r.text)
        return list(dict.fromkeys(prefixes))[:50]
    except Exception:
        return []


# ── Risk scorer ────────────────────────────────────────────────────────────────

def _compute_risk(result: dict) -> dict:
    score = 0
    factors = []

    # Ports
    ports_services = result.get("ports_services", {})
    all_ports = set()
    for ip_data in ports_services.values():
        all_ports.update(ip_data.get("ports", []))
    risky_found = all_ports & RISKY_PORTS
    if risky_found:
        pts = min(30, len(risky_found) * 8)
        score += pts
        factors.append(f"{len(risky_found)} risky port(s) exposed: {', '.join(str(p) for p in sorted(risky_found))}")

    # Vulnerabilities
    vulns = result.get("vulnerabilities", [])
    if vulns:
        pts = min(30, len(vulns) * 5)
        score += pts
        factors.append(f"{len(vulns)} CVE(s) referenced in Shodan data")

    # Email security
    email_sec = result.get("email_security", {})
    email_score = email_sec.get("score", 100)
    if email_score < 75:
        pts = int((75 - email_score) / 75 * 20)
        score += pts
        factors.append(f"Email security grade: {email_sec.get('grade','F')} (score {email_score}/100)")

    # GreyNoise
    gn = result.get("greynoise", {})
    if gn.get("noise"):
        score += 15
        factors.append("IP flagged as internet-scanning noise by GreyNoise")
    if gn.get("classification") == "malicious":
        score += 20
        factors.append("GreyNoise classifies IP as malicious")

    # VirusTotal
    vt = result.get("virustotal", {})
    if vt.get("available"):
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        if mal > 0:
            pts = min(25, mal * 3)
            score += pts
            factors.append(f"VirusTotal: {mal} engines flagged as malicious")
        elif sus > 0:
            score += 8
            factors.append(f"VirusTotal: {sus} engines flagged as suspicious")

    # AbuseIPDB
    abuse = result.get("abuseipdb", {})
    if abuse.get("available"):
        abuse_score = abuse.get("abuse_score", 0)
        if abuse_score >= 75:
            score += 20
            factors.append(f"AbuseIPDB confidence score: {abuse_score}%")
        elif abuse_score >= 25:
            score += 10
            factors.append(f"AbuseIPDB confidence score: {abuse_score}%")

    # OTX
    otx = result.get("reputation", {})
    if otx.get("available"):
        pulse_count = otx.get("pulse_count", 0)
        if pulse_count >= 5:
            pts = min(15, pulse_count)
            score += pts
            factors.append(f"OTX: found in {pulse_count} threat intelligence pulse(s)")

    # URLScan malicious
    urlscan = result.get("urlscan", {})
    if urlscan.get("malicious_count", 0) > 0:
        score += 10
        factors.append(f"URLScan: {urlscan['malicious_count']} recent scan(s) flagged as malicious")

    # Web application findings (security headers, TLS, exposed paths, etc.)
    findings = result.get("findings", [])
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_counts[f.get("severity", "INFO")] = sev_counts.get(f.get("severity", "INFO"), 0) + 1
    web_pts = (sev_counts["CRITICAL"] * 15 + sev_counts["HIGH"] * 8
               + sev_counts["MEDIUM"] * 3 + sev_counts["LOW"] * 1)
    if web_pts:
        web_pts = min(40, web_pts)
        score += web_pts
        crit_hi = sev_counts["CRITICAL"] + sev_counts["HIGH"]
        if crit_hi:
            factors.append(f"{crit_hi} critical/high web finding(s) across attack surface")
        else:
            factors.append(f"{sum(sev_counts.values())} web security finding(s) detected")

    # Live host exposure
    hosts = result.get("hosts", [])
    live = [h for h in hosts if h.get("alive")]
    if len(live) > 5:
        score += min(10, len(live) // 5)
        factors.append(f"{len(live)} live web hosts expand the external attack surface")

    score = min(100, score)

    if score == 0:
        level = "CLEAN"
    elif score < 20:
        level = "LOW"
    elif score < 45:
        level = "MEDIUM"
    elif score < 70:
        level = "HIGH"
    else:
        level = "CRITICAL"

    if not factors:
        factors.append("No significant threat indicators detected")

    return {"score": score, "level": level, "factors": factors}


# ── Main entry point ────────────────────────────────────────────────────────────

def scan_target(query: str) -> dict:
    """
    Run a comprehensive attack surface scan against query (domain/IP/ASN).
    Returns a structured, JSON-serialisable dict.
    """
    query = query.strip()
    qtype = detect_type(query)
    ts = datetime.now(timezone.utc).isoformat()

    result = {
        "query": query,
        "type": qtype,
        "timestamp": ts,
        "dns": {},
        "infrastructure": {},
        "certificates": [],
        "subdomains": [],
        "lookalike_domains": [],
        "ports_services": {},
        "vulnerabilities": [],
        "email_security": {},
        "reputation": {},
        "virustotal": {},
        "abuseipdb": {},
        "greynoise": {},
        "urlscan": {},
        "whois": {},
        "hosts": [],
        "findings": [],
        "remediation": [],
        "risk_score": {},
        "sources_used": [],
    }

    if qtype == "unknown":
        result["error"] = f"Cannot determine query type for '{query}'. Provide a domain, IP, or ASN (e.g. AS12345)."
        return result

    sources_used = []

    # ── Build task map ─────────────────────────────────────────────────────────
    tasks = {}

    if qtype == "domain":
        tasks["dns"] = lambda: _fetch_dns(query)
        tasks["subenum"] = lambda: _enumerate_subdomains(query)
        tasks["email_security"] = lambda: _fetch_email_security(query)
        tasks["urlscan"] = lambda: _fetch_urlscan(query)
        tasks["rdap"] = lambda: _fetch_rdap(query, qtype)
        tasks["otx"] = lambda: _fetch_otx(query, qtype)
        tasks["virustotal"] = lambda: _fetch_virustotal(query, qtype)
        tasks["lookalikes"] = lambda: detect_lookalikes(query)

    elif qtype == "ip":
        tasks["shodan"] = lambda: _fetch_shodan_internetdb(query)
        tasks["ipinfo"] = lambda: _fetch_ipinfo(query)
        tasks["greynoise"] = lambda: _fetch_greynoise(query)
        tasks["rdap"] = lambda: _fetch_rdap(query, qtype)
        tasks["urlscan"] = lambda: _fetch_urlscan(query)
        tasks["abuseipdb"] = lambda: _fetch_abuseipdb(query)
        tasks["otx"] = lambda: _fetch_otx(query, qtype)
        tasks["virustotal"] = lambda: _fetch_virustotal(query, qtype)

    elif qtype == "asn":
        tasks["rdap"] = lambda: _fetch_rdap(query, qtype)
        tasks["ipinfo"] = lambda: _fetch_ipinfo(query)

    # ── Execute concurrently (tolerate slow sources → partial results) ──────────
    task_results = {name: {} for name in tasks}
    executor = ThreadPoolExecutor(max_workers=10)
    future_map = {executor.submit(fn): name for name, fn in tasks.items()}
    try:
        for future in as_completed(future_map, timeout=35):
            name = future_map[future]
            try:
                task_results[name] = future.result()
                sources_used.append(name)
            except Exception as e:
                logger.warning(f"Task '{name}' failed: {e}")
    except FuturesTimeout:
        done = sum(1 for f in future_map if f.done())
        logger.warning(f"Scan tasks timed out; proceeding with {done}/{len(future_map)} sources")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    # ── Post-process: DNS ──────────────────────────────────────────────────────
    dns_data = task_results.get("dns", {})
    result["dns"] = dns_data

    # ── Post-process: IPs to scan ──────────────────────────────────────────────
    ips_to_scan = _resolve_to_ips(query, qtype, dns_data)

    # ── Post-process: per-IP Shodan + GreyNoise + ipinfo ──────────────────────
    if qtype == "domain" and ips_to_scan:
        ip_tasks = {}
        for ip in ips_to_scan[:4]:
            ip_tasks[f"shodan_{ip}"] = (lambda _ip=ip: _fetch_shodan_internetdb(_ip))
            ip_tasks[f"greynoise_{ip}"] = (lambda _ip=ip: _fetch_greynoise(_ip))
            ip_tasks[f"ipinfo_{ip}"] = (lambda _ip=ip: _fetch_ipinfo(_ip))

        for name in ip_tasks:
            task_results.setdefault(name, {})
        executor2 = ThreadPoolExecutor(max_workers=12)
        future_map2 = {executor2.submit(fn): name for name, fn in ip_tasks.items()}
        try:
            for future in as_completed(future_map2, timeout=25):
                name = future_map2[future]
                try:
                    task_results[name] = future.result()
                except Exception as e:
                    logger.debug(f"IP sub-task '{name}' failed: {e}")
        except FuturesTimeout:
            done = sum(1 for f in future_map2 if f.done())
            logger.warning(f"IP sub-tasks timed out; proceeding with {done}/{len(future_map2)} results")
        finally:
            executor2.shutdown(wait=False, cancel_futures=True)

    # ── Aggregate ports / services / vulns ─────────────────────────────────────
    all_vulns = set()
    infra = {}

    if qtype == "ip":
        shodan_data = task_results.get("shodan", {})
        ipinfo_data = task_results.get("ipinfo", {})
        if shodan_data:
            ports = shodan_data.get("ports", [])
            cpes = shodan_data.get("cpes", [])
            vulns = shodan_data.get("vulns", [])
            tags = shodan_data.get("tags", [])
            hostnames = shodan_data.get("hostnames", [])
            result["ports_services"][query] = {
                "ports": ports,
                "cpes": cpes,
                "tags": tags,
                "hostnames": hostnames,
            }
            all_vulns.update(vulns)
        if ipinfo_data:
            infra[query] = {
                "city": ipinfo_data.get("city", ""),
                "region": ipinfo_data.get("region", ""),
                "country": ipinfo_data.get("country", ""),
                "org": ipinfo_data.get("org", ""),
                "hostname": ipinfo_data.get("hostname", ""),
                "timezone": ipinfo_data.get("timezone", ""),
            }
        result["greynoise"] = task_results.get("greynoise", {})
        result["abuseipdb"] = task_results.get("abuseipdb", {})

    elif qtype == "domain":
        for ip in ips_to_scan[:4]:
            shodan_data = task_results.get(f"shodan_{ip}", {})
            ipinfo_data = task_results.get(f"ipinfo_{ip}", {})
            gn_data = task_results.get(f"greynoise_{ip}", {})
            if shodan_data:
                ports = shodan_data.get("ports", [])
                cpes = shodan_data.get("cpes", [])
                vulns = shodan_data.get("vulns", [])
                tags = shodan_data.get("tags", [])
                hostnames = shodan_data.get("hostnames", [])
                result["ports_services"][ip] = {
                    "ports": ports,
                    "cpes": cpes,
                    "tags": tags,
                    "hostnames": hostnames,
                }
                all_vulns.update(vulns)
            if ipinfo_data:
                infra[ip] = {
                    "city": ipinfo_data.get("city", ""),
                    "region": ipinfo_data.get("region", ""),
                    "country": ipinfo_data.get("country", ""),
                    "org": ipinfo_data.get("org", ""),
                    "hostname": ipinfo_data.get("hostname", ""),
                    "timezone": ipinfo_data.get("timezone", ""),
                }
            # Use the first IP's greynoise data as representative
            if ip == ips_to_scan[0] and gn_data:
                result["greynoise"] = gn_data

    # ── Certificates + subdomains ──────────────────────────────────────────────
    subenum = task_results.get("subenum", {}) or {}
    sub_names = subenum.get("names", [])
    if sub_names:
        result["subdomains"] = sub_names[:200]
        # Certificate metadata (from crt.sh) for display
        result["certificates"] = (subenum.get("certs") or [])[:10]

    # ── Email security ─────────────────────────────────────────────────────────
    result["email_security"] = task_results.get("email_security", {})

    # ── Reputation (OTX) ──────────────────────────────────────────────────────
    result["reputation"] = task_results.get("otx", {})

    # ── VirusTotal ────────────────────────────────────────────────────────────
    result["virustotal"] = task_results.get("virustotal", {})

    # ── WHOIS/RDAP ────────────────────────────────────────────────────────────
    result["whois"] = task_results.get("rdap", {})

    # ── URLScan ───────────────────────────────────────────────────────────────
    result["urlscan"] = task_results.get("urlscan", {})

    # ── Infrastructure summary ────────────────────────────────────────────────
    result["infrastructure"] = infra

    # ── ipinfo for IP type ────────────────────────────────────────────────────
    if qtype == "ip":
        ipinfo_data = task_results.get("ipinfo", {})
        result["infrastructure"][query] = {
            "city": ipinfo_data.get("city", ""),
            "region": ipinfo_data.get("region", ""),
            "country": ipinfo_data.get("country", ""),
            "org": ipinfo_data.get("org", ""),
            "hostname": ipinfo_data.get("hostname", ""),
            "timezone": ipinfo_data.get("timezone", ""),
            "loc": ipinfo_data.get("loc", ""),
        }
    elif qtype == "asn":
        ipinfo_data = task_results.get("ipinfo", {})
        if ipinfo_data:
            result["infrastructure"]["asn"] = ipinfo_data

    # ── Active host discovery + web-application checks ─────────────────────────
    all_findings = []
    hosts_out = []

    if qtype == "domain":
        # Candidate hosts: apex + discovered subdomains
        candidates = [query] + [s for s in result["subdomains"] if s != query]
        candidates = list(dict.fromkeys(candidates))[:MAX_SUBDOMAINS_RESOLVE]

        # Fast concurrent DNS resolution to keep only names that exist
        resolved = []
        ex = ThreadPoolExecutor(max_workers=30)
        fut = {ex.submit(_resolve_host, h): h for h in candidates}
        try:
            for f in as_completed(fut, timeout=40):
                h = fut[f]
                try:
                    if f.result():
                        resolved.append(h)
                except Exception:
                    pass
        except FuturesTimeout:
            logger.debug("host resolution timed out; using partial results")
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

        # Prioritise apex + shorter names, cap deep scans
        resolved.sort(key=lambda h: (0 if h == query else 1, h.count("."), h))
        deep_targets = resolved[:MAX_HOSTS_DEEP_SCAN]

        ex = ThreadPoolExecutor(max_workers=12)
        fut = {ex.submit(scan_host, h): h for h in deep_targets}
        try:
            for f in as_completed(fut, timeout=120):
                h = fut[f]
                try:
                    hr = f.result()
                    hosts_out.append(hr)
                    all_findings.extend(hr.get("findings", []))
                    # Merge ports/CVEs into the global views
                    for ip in hr.get("ips", []):
                        if hr.get("ports"):
                            result["ports_services"].setdefault(ip, {
                                "ports": hr["ports"], "cpes": [], "tags": [],
                                "hostnames": [hr["host"]],
                            })
                    all_vulns.update(hr.get("cves", []))
                except Exception as e:
                    logger.debug(f"Deep host scan '{h}' failed: {e}")
        except FuturesTimeout:
            logger.warning("host probing timed out; using hosts scanned so far")
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

        result["resolved_count"] = len(resolved)

    elif qtype == "ip":
        try:
            hr = scan_host(query)
            hosts_out.append(hr)
            all_findings.extend(hr.get("findings", []))
            all_vulns.update(hr.get("cves", []))
        except Exception as e:
            logger.debug(f"IP host scan failed: {e}")

    # Email-security findings folded into the unified findings list (domain only)
    em = result.get("email_security", {})
    for issue in em.get("issues", []):
        all_findings.append(_mk_finding("MEDIUM", "Email Security", query,
            issue,
            "Weak email authentication enables spoofing / phishing using this domain.",
            "Publish/strengthen SPF, DMARC (p=reject) and configure MTA-STS."))

    # ── Rogue / look-alike domains (DNS-confirmed only) ────────────────────────
    lookalikes = task_results.get("lookalikes", []) or []
    result["lookalike_domains"] = lookalikes
    if lookalikes:
        homs = [l for l in lookalikes if l.get("homograph")]
        examples = ", ".join(l["domain"] + (f" ({l['punycode']})" if l.get("punycode") else "")
                             for l in lookalikes[:8])
        sev = "HIGH" if homs else "MEDIUM"
        all_findings.append(_mk_finding(sev, "Domain Impersonation", query,
            f"{len(lookalikes)} registered look-alike domain(s) detected"
            + (f" — {len(homs)} homograph/IDN" if homs else ""),
            "Registered domains closely resembling this domain were confirmed via DNS. "
            "These are commonly used for phishing, brand impersonation, and credential "
            "harvesting against your users.",
            "Monitor and, where warranted, file takedowns / UDRP; defensively register the "
            "highest-risk variants; deploy DMARC (p=reject) and user-awareness controls.",
            evidence=examples, confidence="Confirmed"))

    # Flag if the TARGET itself is an IDN/punycode (possible homograph of another brand)
    if qtype == "domain" and ("xn--" in query.lower() or any(ord(c) > 127 for c in query)):
        all_findings.append(_mk_finding("MEDIUM", "Domain Impersonation", query,
            "Target is an internationalized (IDN/punycode) domain",
            "This domain uses non-ASCII / punycode characters, which can be used to "
            "visually impersonate a different brand (homograph attack).",
            "Verify the domain's legitimacy and that users can distinguish it from look-alikes.",
            confidence="Confirmed"))

    # Sort hosts: live first, then by host name
    hosts_out.sort(key=lambda h: (0 if h.get("alive") else 1, h.get("host", "")))
    result["hosts"] = hosts_out

    # Dedupe findings (by severity+title+asset) and sort by severity
    seen_f = set()
    deduped = []
    for f in all_findings:
        key = (f.get("severity"), f.get("title"), f.get("asset"))
        if key in seen_f:
            continue
        seen_f.add(key)
        deduped.append(f)
    deduped.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 0), reverse=True)
    result["findings"] = deduped

    # Prioritised remediation roadmap
    result["remediation"] = _build_remediation(deduped)

    # ── Vulnerabilities list ──────────────────────────────────────────────────
    result["vulnerabilities"] = sorted(all_vulns)

    # ── Risk score ────────────────────────────────────────────────────────────
    result["risk_score"] = _compute_risk(result)

    # ── Sources used ──────────────────────────────────────────────────────────
    result["sources_used"] = sorted(set(sources_used))

    return result
