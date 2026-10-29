"""
Threat Intelligence Data Fetcher
Sources: CISA KEV, NVD, Feodo Tracker, URLhaus, MalwareBazaar,
         MITRE ATT&CK, Have I Been Pwned, Security RSS feeds
"""

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

import enrich

logger = logging.getLogger(__name__)


def research_id(link: str, title: str) -> str:
    """Content-derived, refresh-stable id for a research item.

    Prefers the canonical article link; falls back to the title. The same
    article therefore keeps the same id across refreshes/re-sorts, so the
    /api/research/report/<id> endpoint always resolves the article the user is
    actually viewing (positional r0/r1/… ids did not — they drifted whenever the
    live feeds re-sorted).
    """
    ident = (link or "").strip() or (title or "")
    return "r" + hashlib.sha1(ident.encode("utf-8", "replace")).hexdigest()[:12]


# Live security-research / exploit-analysis RSS sources (complement the bundled
# feed.rss). Any that are unreachable are skipped gracefully at fetch time.
RESEARCH_FEEDS = [
    # ── Zero Day Initiative ─────────────────────────────────────────────────
    ("ZDI: Published Advisories", "https://www.zerodayinitiative.com/rss/published/"),
    ("ZDI: Upcoming Advisories",  "https://www.zerodayinitiative.com/rss/upcoming/"),
    ("ZDI Blog",                  "https://www.zerodayinitiative.com/blog?format=rss"),
    # ── US-CERT / CISA ──────────────────────────────────────────────────────
    ("CISA Advisories",           "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("US-CERT Alerts",            "https://www.us-cert.gov/ncas/alerts.xml"),
    ("CERT/CC Vulnerability Notes", "https://www.kb.cert.org/vuls/atomfeed"),
    # ── Vendor PSIRT / Security Advisories ──────────────────────────────────
    ("Cisco Security Advisory",   "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("Palo Alto Networks",        "https://security.paloaltonetworks.com/rss.xml"),
    ("FortiGuard",                "https://www.fortiguard.com/rss/threatsignal.xml"),
    ("Oracle Security Alerts",    "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml"),
    ("Tenable Security",          "https://www.tenable.com/security/feed"),
    ("Siemens ProductCERT",       "https://cert-portal.siemens.com/productcert/rss/advisories.atom"),
    ("Splunk Security",           "https://advisory.splunk.com/feed.xml"),
    ("NetApp Product Security",   "https://security.netapp.com/advisory/index.xml"),
    ("Okta Trust",                "https://trust.okta.com/security-advisories.xml"),
    ("A10 Networks",              "https://support.a10networks.com/support/security-advisories/rss.xml"),
    ("Lenovo Product Security",   "https://support.lenovo.com/us/en/api/v4/search/psrss?language=en&country=us&brand=EBG,TPG,IPG,MOTO,PHONE,TABLET,SMART"),
    ("Silver Peak",               "https://www.silver-peak.com/security-advisories-rss.xml"),
    # ── Threat Intelligence / News ───────────────────────────────────────────
    ("The Hacker News",           "https://thehackernews.com/feeds/posts/default"),
    ("Wired Security",            "https://www.wired.com/feed/security/rss"),
    ("Threatpost",                "https://threatpost.com/feed/"),
    ("Security Affairs",          "https://securityaffairs.co/wordpress/feed"),
    ("Help Net Security",         "https://www.helpnetsecurity.com/feed/"),
    ("CyberSecurity Help",        "https://www.cybersecurity-help.cz/blog/rss/"),
    ("Mandiant Blog",             "https://www.mandiant.com/resources/blog/rss.xml"),
    ("Cyware Blog",               "https://www.cyware.com/rss"),
    ("McAfee Blogs",              "https://www.mcafee.com/blogs/feed/"),
    ("ZDNet Security",            "https://www.zdnet.com/news/rss.xml"),
    # ── Research / Exploit Analysis ──────────────────────────────────────────
    ("Project Zero",              "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("Rapid7",                    "https://www.rapid7.com/blog/rss/"),
    ("SANS ISC",                  "https://isc.sans.edu/rssfeed_full.xml"),
    ("Schneier on Security",      "https://www.schneier.com/feed/atom/"),
]

_CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.I)

_TAG_RE      = re.compile(r"<[^>]+>")
_SCRIPT_RE   = re.compile(r"<(script|style|iframe|object|embed)[^>]*>.*?</\1>", re.I | re.S)
_VOID_BAD_RE = re.compile(r"<(script|style|iframe|object|embed|link|meta)[^>]*/?>", re.I | re.S)
_ON_ATTR_RE  = re.compile(r"\son\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)
_JS_HREF_RE  = re.compile(r"(href|src)\s*=\s*([\"'])\s*javascript:[^\"']*\2", re.I)


def _looks_markdown(text: str) -> bool:
    """Heuristic: content is markdown (not HTML) if it has md markers and few tags."""
    if not text:
        return False
    has_md = bool(re.search(r"(^|\n)#{1,6}\s|\n```|\*\*|\n[-*]\s|\]\(http", text))
    tag_density = len(_TAG_RE.findall(text))
    return has_md and tag_density < 5


def _clean_html(html: str) -> str:
    """Strip dangerous tags/attributes from feed HTML (keep basic formatting)."""
    if not html:
        return ""
    out = _SCRIPT_RE.sub("", html)
    out = _VOID_BAD_RE.sub("", out)
    out = _ON_ATTR_RE.sub("", out)
    out = _JS_HREF_RE.sub(r'\1="#"', out)
    return out.strip()


def _text_preview(text: str, limit: int = 280) -> str:
    """Plain-text preview from markdown/HTML content."""
    if not text:
        return ""
    plain = _TAG_RE.sub(" ", text)
    plain = re.sub(r"[`*#>_]+", "", plain)
    plain = re.sub(r"\s+", " ", plain).strip()
    return plain[:limit] + ("…" if len(plain) > limit else "")


def _writable_base() -> Path:
    """Pick a writable directory for cache/history.

    Tries DATA_DIR env, then the app directory, then the OS temp dir. This keeps
    the app from crashing on read-only filesystems (e.g. serverless platforms).
    """
    candidates = []
    if os.environ.get("DATA_DIR"):
        candidates.append(Path(os.environ["DATA_DIR"]))
    candidates.append(Path(__file__).resolve().parent)
    candidates.append(Path(tempfile.gettempdir()) / "jatayu_data")
    for base in candidates:
        try:
            (base / "cache").mkdir(parents=True, exist_ok=True)
            (base / "history").mkdir(parents=True, exist_ok=True)
            return base
        except Exception:
            continue
    # Last resort: temp dir itself (always writable)
    return Path(tempfile.gettempdir())


_BASE_DIR = _writable_base()
CACHE_DIR = _BASE_DIR / "cache"
HISTORY_DIR = _BASE_DIR / "history"
MITRE_CACHE = CACHE_DIR / "mitre_groups.json"
MITRE_TECH_CACHE = CACHE_DIR / "mitre_techniques.json"
CAPEC_CACHE = CACHE_DIR / "capec_cwe_attack.json"
MITRE_TTL = 86400      # 24 hours — MITRE data changes slowly
CAPEC_TTL = 604800     # 7 days — CAPEC↔ATT&CK mappings change rarely

COUNTRY_FLAGS = {
    "Russia": "🇷🇺", "RU": "🇷🇺",
    "China": "🇨🇳", "CN": "🇨🇳",
    "North Korea": "🇰🇵", "KP": "🇰🇵",
    "South Korea": "🇰🇷", "KR": "🇰🇷",
    "Iran": "🇮🇷", "IR": "🇮🇷",
    "USA": "🇺🇸", "United States": "🇺🇸", "US": "🇺🇸",
    "Germany": "🇩🇪", "DE": "🇩🇪",
    "Netherlands": "🇳🇱", "NL": "🇳🇱",
    "Ukraine": "🇺🇦", "UA": "🇺🇦",
    "India": "🇮🇳", "IN": "🇮🇳",
    "Brazil": "🇧🇷", "BR": "🇧🇷",
    "France": "🇫🇷", "FR": "🇫🇷",
    "UK": "🇬🇧", "United Kingdom": "🇬🇧", "GB": "🇬🇧",
    "Vietnam": "🇻🇳", "VN": "🇻🇳",
    "Pakistan": "🇵🇰", "PK": "🇵🇰",
    "Turkey": "🇹🇷", "TR": "🇹🇷",
    "Japan": "🇯🇵", "JP": "🇯🇵",
    "Singapore": "🇸🇬", "SG": "🇸🇬",
    "Canada": "🇨🇦", "CA": "🇨🇦",
    "Australia": "🇦🇺", "AU": "🇦🇺",
    "Sweden": "🇸🇪", "SE": "🇸🇪",
    "Hong Kong": "🇭🇰", "HK": "🇭🇰",
    "Romania": "🇷🇴", "RO": "🇷🇴",
    "Bulgaria": "🇧🇬", "BG": "🇧🇬",
    "Unknown": "🌐",
}

# ISO 3166-1 alpha-2 → display name (used by _compute_geopolitical to resolve
# Feodo Tracker's 2-letter country codes to human-readable names for charts)
_ISO2_COUNTRY = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AO": "Angola",
    "AR": "Argentina", "AM": "Armenia", "AU": "Australia", "AT": "Austria",
    "AZ": "Azerbaijan", "BH": "Bahrain", "BD": "Bangladesh", "BY": "Belarus",
    "BE": "Belgium", "BO": "Bolivia", "BA": "Bosnia and Herzegovina",
    "BR": "Brazil", "BG": "Bulgaria", "CA": "Canada", "CL": "Chile",
    "CN": "China", "CO": "Colombia", "HR": "Croatia", "CZ": "Czech Republic",
    "DK": "Denmark", "EG": "Egypt", "EE": "Estonia", "ET": "Ethiopia",
    "FI": "Finland", "FR": "France", "GE": "Georgia", "DE": "Germany",
    "GH": "Ghana", "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary",
    "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
    "IE": "Ireland", "IL": "Israel", "IT": "Italy", "JP": "Japan",
    "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KP": "North Korea",
    "KR": "South Korea", "KW": "Kuwait", "KG": "Kyrgyzstan", "LV": "Latvia",
    "LB": "Lebanon", "LT": "Lithuania", "LU": "Luxembourg", "MY": "Malaysia",
    "MX": "Mexico", "MD": "Moldova", "MN": "Mongolia", "MA": "Morocco",
    "MM": "Myanmar", "NL": "Netherlands", "NZ": "New Zealand", "NG": "Nigeria",
    "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PE": "Peru",
    "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar",
    "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia", "RS": "Serbia",
    "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "ZA": "South Africa",
    "ES": "Spain", "LK": "Sri Lanka", "SE": "Sweden", "CH": "Switzerland",
    "SY": "Syria", "TW": "Taiwan", "TH": "Thailand", "TN": "Tunisia",
    "TR": "Turkey", "TM": "Turkmenistan", "UA": "Ukraine",
    "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States",
    "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam",
}


class DataFetcher:
    def __init__(self):
        # Directories are already ensured by _writable_base(); guard anyway.
        for d in (CACHE_DIR, HISTORY_DIR):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
        self.current_data: dict = {}
        self.last_updated: datetime | None = None
        self._lock = threading.Lock()
        self.otx_key = os.environ.get("OTX_API_KEY", "")
        self.abusech_key = os.environ.get("ABUSECH_AUTH_KEY", "")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ThreatIntelDashboard/2.0 (Security Research; contact@example.com)"
        })

    # ─────────────────────────────────────────────────────────────────────────
    # Public interface
    # ─────────────────────────────────────────────────────────────────────────

    def refresh_all(self):
        logger.info("Starting threat intelligence refresh…")
        results: dict = {}

        # Capture previous data now so we can fall back to it on timeout or error.
        with self._lock:
            _prev_ti   = (self.current_data.get("threat_intel") or {})
            _prev_iocs = (_prev_ti.get("iocs") or {})
            prev_zeroday = list(_prev_ti.get("zeroday")           or [])
            prev_feodo   = list(_prev_iocs.get("malicious_ips")   or [])
            prev_urlhaus = list(_prev_iocs.get("malicious_urls")  or [])
            prev_hashes  = list(_prev_iocs.get("malware_hashes")  or [])

        # Map task keys → previous good data so both timeout and exception paths
        # can retain the last successful values instead of blanking the category.
        _prev_fallback: dict = {
            "feodo_ips":      prev_feodo,
            "urlhaus":        prev_urlhaus,
            "malware_hashes": prev_hashes,
            "zeroday":        prev_zeroday,
        }

        def _fetch(key, fn):
            try:
                results[key] = fn()
            except Exception as exc:
                logger.error(f"[{key}] fetch failed: {exc}")
                # Retain last-good data rather than blanking the IOC category.
                fallback = _prev_fallback.get(key, [])
                results[key] = fallback if fallback else []

        tasks = [
            ("cisa_kev",       self._fetch_cisa_kev),
            ("nvd_critical",   self._fetch_nvd_critical),
            ("feodo_ips",      self._fetch_feodo_ips),
            ("urlhaus",        self._fetch_urlhaus),
            ("malware_hashes", self._fetch_malwarebazaar),
            ("threat_actors",  self._fetch_threat_actors),
            ("breaches",       self._fetch_hibp_breaches),
            ("dark_web",       self._fetch_dark_web_intel),
            ("research",       self._fetch_research_intel),
            ("zeroday",        self._fetch_zeroday),
        ]

        keyed_threads = [(k, threading.Thread(target=_fetch, args=(k, fn), daemon=True)) for k, fn in tasks]
        for _, t in keyed_threads:
            t.start()
        for k, t in keyed_threads:
            t.join(timeout=90)
            if t.is_alive() and k not in results:
                logger.warning("[%s] thread timed out after 90s; retaining previous data", k)
                fallback = _prev_fallback.get(k, [])
                if fallback:
                    results[k] = fallback

        geo = self._compute_geopolitical(results.get("feodo_ips", []))
        now = datetime.utcnow()

        kev = results.get("cisa_kev", [])
        nvd = results.get("nvd_critical", [])

        # ── EPSS / CVSS-4.0 enrichment (Shodan CVEDB) + CWE→CAPEC→ATT&CK mapping ──
        # Runs AFTER the threaded source fetches so a slow external call here can
        # never abort them. Each step is guarded; failures degrade to empty.
        enrichment = self._build_enrichment(kev, nvd)
        self._attach_kev_attack_map(kev, enrichment)

        src = {k: len(v) for k, v in results.items()}
        data = {
            "advisories": {
                "top_exploited_cves":      kev,
                "immediate_attention_cves": nvd,
            },
            "enrichment": enrichment,
            "threat_intel": {
                "iocs": {
                    "malicious_ips":    results.get("feodo_ips", []),
                    "malicious_urls":   results.get("urlhaus", []),
                    "malware_hashes":   results.get("malware_hashes", []),
                },
                "top_threat_actors": results.get("threat_actors", []),
                "geopolitical":      geo,
                "zeroday":           results.get("zeroday", []),
                "darkweb": {
                    "breaches":           results.get("breaches", []),
                    "forum_discussions":  results.get("dark_web", []),
                },
            },
            "research": results.get("research", []),
            "metadata": {
                "last_updated": now.isoformat() + "Z",
                "next_refresh": (now + timedelta(minutes=30)).isoformat() + "Z",
                "sources": src,
                "total_iocs": src.get("feodo_ips", 0) + src.get("urlhaus", 0) + src.get("malware_hashes", 0),
                "total_cves": src.get("cisa_kev", 0) + src.get("nvd_critical", 0),
            },
        }

        with self._lock:
            self.current_data = data
            self.last_updated = now

        self._save_history(data, now)
        logger.info(f"Refresh complete — sources: {src}")
        return data

    def get_current_data(self):
        with self._lock:
            return self.current_data.copy()

    def prime(self, data: dict):
        """Load a pre-built snapshot into memory (serverless cold-start)."""
        lu = (data or {}).get("metadata", {}).get("last_updated")
        with self._lock:
            self.current_data = data or {}
            try:
                self.last_updated = datetime.fromisoformat(str(lu).replace("Z", "")) if lu else datetime.utcnow()
            except Exception:
                self.last_updated = datetime.utcnow()

    def get_historical_data(self, date_str: str):
        path = HISTORY_DIR / f"{date_str}.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception as e:
                logger.error(f"History read error ({date_str}): {e}")
        return None

    def get_available_dates(self):
        return sorted([f.stem for f in HISTORY_DIR.glob("*.json")], reverse=True)[:7]

    # ─────────────────────────────────────────────────────────────────────────
    # Private — persistence
    # ─────────────────────────────────────────────────────────────────────────

    def _save_history(self, data: dict, dt: datetime):
        path = HISTORY_DIR / f"{dt.strftime('%Y-%m-%d')}.json"
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error(f"History write error: {e}")

        cutoff = datetime.utcnow() - timedelta(days=8)
        for f in HISTORY_DIR.glob("*.json"):
            try:
                if datetime.strptime(f.stem, "%Y-%m-%d") < cutoff:
                    f.unlink()
            except ValueError:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # Private — data sources
    # ─────────────────────────────────────────────────────────────────────────

    def _fetch_cisa_kev(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        resp = self.session.get(url, timeout=30)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        out = []
        for v in vulns[:200]:
            out.append({
                "cve_id":             v.get("cveID", ""),
                "vendor":             v.get("vendorProject", ""),
                "product":            v.get("product", ""),
                "vulnerability_name": v.get("vulnerabilityName", ""),
                "description":        (v.get("shortDescription") or "")[:350],
                "date_added":         v.get("dateAdded", ""),
                "due_date":           v.get("dueDate", ""),
                "required_action":    (v.get("requiredAction") or "")[:250],
                "severity":           "CRITICAL",
                "known_ransomware":   v.get("knownRansomwareCampaignUse", "Unknown"),
                # CISA KEV now carries CWE ids — the entry point for the
                # CWE→CAPEC→ATT&CK technique mapping (see _build_kev_attack_map).
                "cwes":               [c for c in (v.get("cwes") or []) if c],
            })
        return out

    def _fetch_nvd_critical(self):
        end_dt   = datetime.utcnow()
        start_dt = end_dt - timedelta(days=30)
        params = {
            "cvssV3Severity": "CRITICAL",
            "pubStartDate":   start_dt.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate":     end_dt.strftime("%Y-%m-%dT23:59:59.000"),
            "resultsPerPage": 20,
        }
        resp = self.session.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, timeout=30
        )
        resp.raise_for_status()

        out = []
        for item in resp.json().get("vulnerabilities", []):
            cve     = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss    = {}
            cvss_version = ""
            # Prefer CVSS 4.0 when NVD publishes it, then 3.1, then 3.0.
            if metrics.get("cvssMetricV40"):
                cvss = metrics["cvssMetricV40"][0].get("cvssData", {})
                cvss_version = "4.0"
            elif metrics.get("cvssMetricV31"):
                cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_version = "3.1"
            elif metrics.get("cvssMetricV30"):
                cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_version = "3.0"

            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            refs  = [r.get("url", "") for r in cve.get("references", [])[:3]]

            weaknesses = []
            for w in cve.get("weaknesses", []):
                for wd in w.get("description", []):
                    if wd.get("lang") == "en":
                        weaknesses.append(wd.get("value", ""))

            out.append({
                "cve_id":              cve.get("id", ""),
                "description":         desc[:500],
                "cvss_score":          cvss.get("baseScore", 0),
                "cvss_version":        cvss_version,
                "cvss_vector":         cvss.get("vectorString", ""),
                "attack_vector":       cvss.get("attackVector", ""),
                "attack_complexity":   cvss.get("attackComplexity", ""),
                "privileges_required": cvss.get("privilegesRequired", ""),
                "user_interaction":    cvss.get("userInteraction", ""),
                "severity":            cvss.get("baseSeverity", "CRITICAL"),
                "published":           cve.get("published", ""),
                "last_modified":       cve.get("lastModified", ""),
                "weaknesses":          weaknesses[:3],
                "references":          refs,
            })

        out.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        return out[:20]

    def _fetch_feodo_ips(self):
        resp = self.session.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=30
        )
        resp.raise_for_status()
        out = []
        for e in resp.json()[:100]:
            out.append({
                "ip":         e.get("ip_address", ""),
                "port":       e.get("port", ""),
                "status":     e.get("status", ""),
                "malware":    e.get("malware", ""),
                "country":    e.get("country", ""),
                "as_name":    e.get("as_name", ""),
                "first_seen": e.get("first_seen", ""),
                "last_online":e.get("last_online", ""),
                "type":       "Botnet C2",
            })
        return out

    def _fetch_urlhaus(self):
        # URLhaus API v1 — requires a free Auth-Key from auth.abuse.ch
        # Old bulk CSV endpoint (urlhaus.abuse.ch/downloads/csv_recent/) returned 410 Gone.
        if not self.abusech_key:
            logger.warning("ABUSECH_AUTH_KEY not set — skipping URLhaus feed (get a free key at https://auth.abuse.ch/)")
            return []
        resp = self.session.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/60/",
            headers={"Auth-Key": self.abusech_key},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            logger.warning(f"URLhaus API returned status: {data.get('query_status')}")
            return []
        out = []
        for e in (data.get("urls") or [])[:60]:
            raw_tags = e.get("tags") or []
            tags = raw_tags if isinstance(raw_tags, list) else [t.strip() for t in str(raw_tags).split(",") if t.strip()]
            out.append({
                "url":        e.get("url", ""),
                "url_status": e.get("url_status", ""),
                "date_added": e.get("date_added", ""),
                "threat":     e.get("threat", ""),
                "tags":       tags[:5],
                "reporter":   e.get("reporter", "URLhaus"),
                "type":       "Malicious URL",
            })
        return out

    def _fetch_malwarebazaar(self):
        # MalwareBazaar recent samples CSV — requires a free Auth-Key from auth.abuse.ch
        # Old endpoint (urlhaus.abuse.ch/downloads/payloads/) returned 410 Gone; moved to bazaar.abuse.ch.
        if not self.abusech_key:
            logger.warning("ABUSECH_AUTH_KEY not set — skipping MalwareBazaar feed (get a free key at https://auth.abuse.ch/)")
            return []
        import csv, io as _io
        resp = self.session.get(
            f"https://mb-api.abuse.ch/v2/files/exports/{self.abusech_key}/recent.csv",
            timeout=30,
        )
        resp.raise_for_status()
        lines = [l for l in resp.text.splitlines() if l and not l.startswith("#")]
        if not lines:
            return []
        reader = csv.DictReader(lines)
        out = []
        for e in reader:
            if len(out) >= 60:
                break
            sha = (e.get("sha256_hash") or e.get("sha256") or "").strip('"')
            if not sha or len(sha) != 64:
                continue
            sig = (e.get("signature") or e.get("characteristic") or "").strip('"')
            ft  = (e.get("file_type_mime") or e.get("file_type") or e.get("file_type_guess") or "").strip('"')
            tags_raw = (e.get("tags") or "").strip('"')
            extra_tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []
            try:
                fsize = int((e.get("file_size") or "0").strip('"') or 0)
            except (ValueError, AttributeError):
                fsize = 0
            out.append({
                "sha256":     sha,
                "md5":        (e.get("md5_hash") or e.get("md5") or "").strip('"'),
                "file_name":  (e.get("file_name") or "").strip('"'),
                "file_type":  ft,
                "file_size":  fsize,
                "signature":  sig,
                "tags":       ([sig] if sig else []) + extra_tags[:4],
                "first_seen": (e.get("first_seen") or "").strip('"'),
                "reporter":   (e.get("reporter") or "MalwareBazaar").strip('"'),
                "type":       "Malware Hash",
            })
        return out

    def _fetch_threat_actors(self):
        # Serve from local cache if fresh
        if MITRE_CACHE.exists() and (time.time() - MITRE_CACHE.stat().st_mtime) < MITRE_TTL:
            return json.loads(MITRE_CACHE.read_text(encoding="utf-8"))

        logger.info("Downloading MITRE ATT&CK enterprise bundle (this may take ~30s)…")
        resp = self.session.get(
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            timeout=120,
        )
        resp.raise_for_status()
        objects = resp.json().get("objects", [])

        groups = []
        for obj in objects:
            if obj.get("type") != "intrusion-set" or obj.get("revoked"):
                continue
            desc = obj.get("description") or ""
            ext  = obj.get("external_references") or []
            mitre_id = next(
                (r.get("external_id") for r in ext if r.get("source_name") == "mitre-attack"), ""
            )
            groups.append({
                "name":          obj.get("name", ""),
                "mitre_id":      mitre_id,
                "aliases":       (obj.get("aliases") or [])[:6],
                "description":   desc[:600],
                "created":       obj.get("created", ""),
                "modified":      obj.get("modified", ""),
                "country":       self._attr_country(desc, obj.get("name", "")),
                "sophistication":self._sophistication(obj),
            })

        groups.sort(key=lambda x: x.get("modified", ""), reverse=True)
        groups = groups[:25]

        try:
            MITRE_CACHE.write_text(json.dumps(groups, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"MITRE cache write failed: {e}")

        # Build the technique map from the same bundle (avoids a second download).
        try:
            tech = self._extract_attack_techniques(objects)
            MITRE_TECH_CACHE.write_text(json.dumps(tech), encoding="utf-8")
        except Exception as e:
            logger.warning(f"MITRE technique-map build failed: {e}")
        return groups

    @staticmethod
    def _extract_attack_techniques(objects: list) -> dict:
        """Map ATT&CK technique id (Txxxx[.yyy]) → {name, tactic, url} from STIX
        attack-pattern objects in the enterprise bundle."""
        tech = {}
        for obj in objects:
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            ext = obj.get("external_references") or []
            ref = next((r for r in ext if r.get("source_name") == "mitre-attack"), None)
            tid = (ref or {}).get("external_id", "")
            if not tid:
                continue
            tactics = [p.get("phase_name", "") for p in (obj.get("kill_chain_phases") or [])
                       if p.get("kill_chain_name") == "mitre-attack"]
            tactic = (tactics[0].replace("-", " ").title() if tactics else "")
            tech[tid] = {
                "name": obj.get("name", ""),
                "tactic": tactic,
                "url": (ref or {}).get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"),
            }
        return tech

    def _fetch_attack_techniques(self) -> dict:
        """ATT&CK technique id → {name, tactic, url}. Served from the cache that
        _fetch_threat_actors writes; downloads the bundle only on a cache miss."""
        if MITRE_TECH_CACHE.exists() and (time.time() - MITRE_TECH_CACHE.stat().st_mtime) < MITRE_TTL:
            try:
                return json.loads(MITRE_TECH_CACHE.read_text(encoding="utf-8"))
            except Exception:
                pass
        try:
            resp = self.session.get(
                "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                timeout=120,
            )
            resp.raise_for_status()
            tech = self._extract_attack_techniques(resp.json().get("objects", []))
            try:
                MITRE_TECH_CACHE.write_text(json.dumps(tech), encoding="utf-8")
            except Exception:
                pass
            return tech
        except Exception as e:
            logger.warning(f"ATT&CK technique fetch failed: {e}")
            return {}

    def _fetch_capec_map(self) -> dict:
        """Build {CWE numeric id → [ATT&CK technique ids]} from the CAPEC catalog.

        CAPEC attack patterns carry both Related_Weaknesses (CWE ids) and
        Taxonomy_Mappings to ATT&CK (technique Entry_IDs), letting us resolve the
        full CWE → CAPEC → ATT&CK chain. Only the derived map is cached (7d).
        """
        if CAPEC_CACHE.exists() and (time.time() - CAPEC_CACHE.stat().st_mtime) < CAPEC_TTL:
            try:
                return json.loads(CAPEC_CACHE.read_text(encoding="utf-8"))
            except Exception:
                pass
        logger.info("Downloading CAPEC catalog for CWE→ATT&CK mapping…")
        resp = self.session.get("https://capec.mitre.org/data/xml/capec_latest.xml", timeout=120)
        resp.raise_for_status()
        cwe_to_tech = self._parse_capec(resp.content)
        try:
            CAPEC_CACHE.write_text(json.dumps(cwe_to_tech), encoding="utf-8")
        except Exception as e:
            logger.warning(f"CAPEC cache write failed: {e}")
        return cwe_to_tech

    @staticmethod
    def _parse_capec(xml_bytes: bytes) -> dict:
        """Parse CAPEC XML → {cwe_id(str): sorted[technique_ids]}. Namespace-agnostic.

        CAPEC's ATT&CK taxonomy mappings are sparse at the leaf level: a specific
        pattern (e.g. CAPEC-88 OS Command Injection, referencing CWE-78) often has
        no direct ATT&CK mapping, while its parent (CAPEC-248 Command Injection)
        does. We therefore let each pattern inherit its ancestors' ATT&CK mappings
        via the CAPEC ``ChildOf`` hierarchy, which markedly improves CWE coverage
        without inventing mappings.
        """
        import xml.etree.ElementTree as ET

        def local(tag: str) -> str:
            return tag.rsplit("}", 1)[-1]  # strip {namespace}

        root = ET.fromstring(xml_bytes)
        # Pass 1 — collect each pattern's CWEs, direct techniques, and parents.
        direct, parents, cwes_of = {}, {}, {}
        for ap in root.iter():
            if local(ap.tag) != "Attack_Pattern":
                continue
            pid = ap.get("ID")
            if not pid:
                continue
            techs, cwes, pars = set(), [], set()
            for el in ap.iter():
                lt = local(el.tag)
                if lt == "Related_Weakness":
                    cid = el.get("CWE_ID")
                    if cid:
                        cwes.append(str(cid))
                elif lt == "Related_Attack_Pattern" and (el.get("Nature") or "") == "ChildOf":
                    if el.get("CAPEC_ID"):
                        pars.add(el.get("CAPEC_ID"))
                elif lt == "Taxonomy_Mapping" and (el.get("Taxonomy_Name") or "").upper() == "ATTACK":
                    for c in el:
                        if local(c.tag) == "Entry_ID" and (c.text or "").strip():
                            techs.add("T" + c.text.strip())
            direct[pid], parents[pid], cwes_of[pid] = techs, pars, cwes

        # Pass 2 — effective techniques = own + all ancestors' (memoized, cycle-safe).
        memo = {}

        def effective(pid, stack):
            if pid in memo:
                return memo[pid]
            if pid in stack or pid not in direct:
                return set()
            stack.add(pid)
            techs = set(direct.get(pid, set()))
            for par in parents.get(pid, ()):  # walk up
                techs |= effective(par, stack)
            stack.discard(pid)
            memo[pid] = techs
            return techs

        cwe_to_tech: dict = {}
        for pid, cwes in cwes_of.items():
            techs = effective(pid, set())
            if not techs:
                continue
            for cid in cwes:
                cwe_to_tech.setdefault(cid, set()).update(techs)
        return {k: sorted(v) for k, v in cwe_to_tech.items()}

    def _fetch_zeroday(self):
        """Zero-day intelligence: ZDI RSS feeds (primary) + zero-day.cz (supplement).

        ZDI RSS is the primary source — feedparser is always available, no scraping
        needed, and the feeds are authoritative.  zero-day.cz is scraped as a best-
        effort supplement that enriches records already found via ZDI.
        """
        import feedparser
        import html as _html
        import time as _t

        records: list = []
        seen_cves: set = set()

        _VT_RE = re.compile(
            r"\b(Use-After-Free|Type Confusion|Out-of-Bounds(?:\s+Read|\s+Write)?|"
            r"Stack[-\s]Overflow|Heap[-\s]Overflow|Integer Overflow|Command Injection|"
            r"SQL Injection|SSRF|XXE|RCE|Memory Corruption|Buffer Overflow|"
            r"Path Traversal|Information Disclosure|Privilege Escalation|"
            r"Arbitrary Code Execution|Remote Code Execution)\b",
            re.I,
        )

        _ZDI_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/124.0 Safari/537.36")

        # ── Primary: ZDI published + upcoming RSS ─────────────────────────────
        for label, feed_url in [
            ("ZDI Published", "https://www.zerodayinitiative.com/rss/published/"),
            ("ZDI Upcoming",  "https://www.zerodayinitiative.com/rss/upcoming/"),
        ]:
            try:
                # Use self.session so we get controlled timeout + retry behaviour.
                # feedparser.parse() does its own uncontrolled fetch; passing
                # the already-fetched text avoids hanging the refresh thread.
                resp = self.session.get(
                    feed_url,
                    headers={"User-Agent": _ZDI_UA,
                             "Accept": "application/rss+xml,application/xml,text/xml,*/*"},
                    timeout=20,
                )
                resp.raise_for_status()
                parsed = feedparser.parse(resp.text)
                for entry in (parsed.entries or [])[:50]:
                    title   = (entry.get("title") or "").strip()
                    link    = entry.get("link", "")
                    summary = entry.get("summary") or entry.get("description") or ""
                    clean   = re.sub(r"<[^>]+>", " ", _html.unescape(summary)).strip()[:500]

                    m   = _CVE_RE.search(title) or _CVE_RE.search(clean)
                    cve = m.group(0).upper() if m else ""
                    if cve and cve in seen_cves:
                        continue
                    if cve:
                        seen_cves.add(cve)

                    pub = ""
                    try:
                        ts = entry.get("published_parsed") or entry.get("updated_parsed")
                        if ts:
                            pub = _t.strftime("%Y-%m-%d", ts)
                    except Exception:
                        pass

                    # ZDI titles: "ZDI-24-xxx: Vendor Product VulnType" or
                    #             "CVE-2024-XXXX: Vendor Product VulnType"
                    software  = ""
                    vuln_type = ""
                    colon_split = re.split(r":\s*", title, 1)
                    if len(colon_split) == 2:
                        rest   = colon_split[1]
                        vt_m   = _VT_RE.search(rest)
                        if vt_m:
                            vuln_type = vt_m.group(0)
                            software  = rest[:vt_m.start()].strip().rstrip("-").strip()[:80]
                        else:
                            software = rest[:80]

                    records.append({
                        "cve": cve, "title": title, "vuln_type": vuln_type,
                        "description": clean, "software": software,
                        "links": [link] if link else [],
                        "date_discovered": pub, "date_updated": pub,
                        "actively_exploited": False, "malware": [],
                        "detail_url": link, "source": label,
                    })
            except Exception as exc:
                logger.warning("[zeroday] %s feed error: %s", label, exc)

        # ── Supplement: zero-day.cz (best-effort, enriches records found above) ─
        try:
            from bs4 import BeautifulSoup  # noqa: F401
            resp = self.session.get(
                "https://www.zero-day.cz/database/",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/124.0 Safari/537.36"},
                timeout=20,
            )
            resp.raise_for_status()
            for r in self._parse_zeroday(resp.text):
                cve = r.get("cve", "")
                if cve and cve in seen_cves:
                    for existing in records:
                        if existing.get("cve") == cve:
                            for k in ("vuln_type", "description", "software",
                                      "malware", "actively_exploited"):
                                if r.get(k):
                                    existing[k] = r[k]
                            break
                else:
                    if cve:
                        seen_cves.add(cve)
                    records.append(r)
        except ImportError:
            logger.warning("[zeroday] beautifulsoup4 missing — zero-day.cz skipped")
        except Exception as exc:
            logger.warning("[zeroday] zero-day.cz unavailable (%s); ZDI RSS used", exc)

        return records[:100]

    @staticmethod
    def _parse_zeroday(html: str) -> list:
        """Parse zero-day.cz database HTML into normalized records (testable, no I/O)."""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        _date_re = re.compile(r"\d{4}-\d{2}-\d{2}")
        # Sentinels that mark the start of the prose description inside block[0]
        _desc_sentinels = (
            " The vulnerability", " The Vulnerability",
            " A vulnerability", " A remote", " A local", " An attacker",
            " An authenticated", " This vulnerability",
        )
        records, seen = [], set()

        for h3 in soup.find_all("h3"):
            a = h3.find("a", href=True)
            if not a or "/database/" not in a["href"]:
                continue
            title = " ".join(a.get_text().split())
            detail_url = a["href"]
            if not detail_url.startswith("http"):
                detail_url = "https://www.zero-day.cz" + detail_url
            if detail_url in seen:
                continue
            seen.add(detail_url)

            m = _CVE_RE.search(title)
            cve = m.group(0).upper() if m else ""

            block, links, dates, software, malware = [], [], [], "", []
            capture_malware, seen_txt = False, set()
            for sib in h3.next_siblings:
                name = getattr(sib, "name", None)
                if name == "h3":
                    break
                if name is None:
                    continue
                for a2 in ([sib] if name == "a" else sib.find_all("a", href=True)):
                    href = a2.get("href", "")
                    if href.startswith("http") and "zero-day.cz" not in href and href not in links:
                        links.append(href)
                txt = " ".join(sib.get_text().split())
                if not txt or txt in seen_txt:
                    continue
                seen_txt.add(txt)
                # Extract all ISO-dates from the text node (handles "2026-05-21 2026-05-21")
                found_dates = _date_re.findall(txt)
                if found_dates:
                    dates.extend(found_dates)
                    continue
                if txt.startswith("Software:"):
                    software = txt.replace("Software:", "").strip(); continue
                if capture_malware:
                    malware = [x.strip() for x in txt.split(",") if x.strip()]
                    capture_malware = False; continue
                if "Known/fameous malware" in txt or "Known/famous malware" in txt:
                    capture_malware = True; continue
                if txt.startswith("Links:") or txt.startswith("Full report"):
                    continue
                block.append(txt)

            joined = " ".join(block)
            actively = bool(re.search(r"actively exploited|exploited in the wild", joined, re.I))

            # block[0] contains "VulnType prose description..." concatenated.
            # Split off the short type label from the prose description.
            vuln_type_raw = block[0] if block else ""
            vuln_type = ""
            desc = ""
            if vuln_type_raw:
                split_pos = -1
                for sentinel in _desc_sentinels:
                    idx = vuln_type_raw.find(sentinel)
                    if 5 <= idx <= 80:
                        split_pos = idx
                        break
                if split_pos > 0:
                    vuln_type = vuln_type_raw[:split_pos].strip()
                    desc = vuln_type_raw[split_pos:].strip()
                elif len(vuln_type_raw) <= 80:
                    vuln_type = vuln_type_raw
                else:
                    # No clean sentinel — break at word boundary near 60 chars
                    vuln_type = vuln_type_raw[:60].rsplit(" ", 1)[0]
                    desc = vuln_type_raw[len(vuln_type):].strip()
            # Supplement description from additional block items if needed
            if not desc and len(block) > 1:
                desc = max(block[1:], key=len)

            records.append({
                "cve": cve, "title": title, "vuln_type": vuln_type,
                "description": desc[:500], "software": software, "links": links[:6],
                "date_discovered": dates[0] if dates else "",
                "date_updated": dates[1] if len(dates) > 1 else (dates[0] if dates else ""),
                "actively_exploited": actively, "malware": malware,
                "detail_url": detail_url, "source": "zero-day.cz",
            })
            if len(records) >= 100:
                break
        return records

    # ── enrichment + MITRE mapping (post-fetch) ────────────────────────────────
    def _build_enrichment(self, kev: list, nvd: list) -> dict:
        """EPSS/CVSS/KEV enrichment (Shodan CVEDB) for KEV + NVD-critical CVEs and
        the most relevant ingested-finding CVEs. Bounded + disk-cached in enrich.py."""
        cves = set()
        for item in kev:
            if item.get("cve_id"):
                cves.add(item["cve_id"].upper())
        for item in nvd:
            if item.get("cve_id"):
                cves.add(item["cve_id"].upper())
        # Include ingested-finding CVEs (top ~1000 by severity) so risk.py can use EPSS.
        try:
            import connectors
            sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            findings = connectors.store.load_findings()
            findings.sort(key=lambda f: (sev_rank.get(f.get("severity"), 0), f.get("cvss") or 0), reverse=True)
            for f in findings[:1000]:
                for c in (f.get("cve_ids") or []):
                    cves.add(c.upper())
        except Exception as e:
            logger.debug(f"enrichment: finding-CVE collection skipped: {e}")
        try:
            return enrich.enrich_cves(cves)
        except Exception as e:
            logger.warning(f"CVEDB enrichment failed: {e}")
            return {}

    def _attach_kev_attack_map(self, kev: list, enrichment: dict) -> None:
        """Attach EPSS/CVSS enrichment to all KEV items, and the full
        CWE→CAPEC→ATT&CK technique mapping to the top 10 exploitable CVEs."""
        for item in kev:
            e = enrichment.get((item.get("cve_id") or "").upper())
            if e:
                item["epss"] = e.get("epss")
                item["epss_percentile"] = e.get("percentile")
                item["cvss_v4"] = e.get("cvss_v4")
                item["cvss_version"] = e.get("cvss_version")
        try:
            capec_map = self._fetch_capec_map()
            tech_map = self._fetch_attack_techniques()
        except Exception as e:
            logger.warning(f"MITRE chain unavailable: {e}")
            capec_map, tech_map = {}, {}
        if not capec_map:
            return
        for item in kev[:10]:
            tids, seen = [], set()
            for cwe in (item.get("cwes") or []):
                num = re.sub(r"\D", "", str(cwe))          # "CWE-79" → "79"
                for tid in capec_map.get(num, []):
                    if tid not in seen:
                        seen.add(tid)
                        tids.append(tid)
            techniques = []
            for tid in tids[:8]:
                meta = tech_map.get(tid) or tech_map.get(tid.split(".")[0]) or {}
                techniques.append({
                    "id": tid,
                    "name": meta.get("name", ""),
                    "tactic": meta.get("tactic", ""),
                    "url": meta.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"),
                })
            item["techniques"] = techniques

    def _fetch_hibp_breaches(self):
        resp = self.session.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "ThreatIntelDashboard/2.0"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        data.sort(key=lambda x: x.get("AddedDate", ""), reverse=True)
        out = []
        for b in data[:25]:
            out.append({
                "name":         b.get("Name", ""),
                "title":        b.get("Title", ""),
                "domain":       b.get("Domain", ""),
                "breach_date":  b.get("BreachDate", ""),
                "added_date":   b.get("AddedDate", ""),
                "pwn_count":    b.get("PwnCount", 0),
                "data_classes": (b.get("DataClasses") or [])[:6],
                "description":  (b.get("Description") or "")[:350],
                "is_verified":  b.get("IsVerified", False),
                "is_sensitive": b.get("IsSensitive", False),
            })
        return out

    def _fetch_dark_web_intel(self):
        try:
            import feedparser
        except ImportError:
            logger.warning("feedparser not installed — skipping RSS dark web intel")
            return []

        feeds = [
            ("BleepingComputer",  "https://www.bleepingcomputer.com/feed/"),
            ("The Hacker News",   "https://feeds.feedburner.com/TheHackersNews"),
            ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
            ("Dark Reading",      "https://www.darkreading.com/rss.xml"),
            ("SecurityWeek",      "https://feeds.feedburner.com/SecurityWeek"),
        ]
        keywords = [
            "dark web", "darkweb", "ransomware", "forum", "leak", "credential dump",
            "data dump", "underground", "tor ", "onion", "cybercriminal", "hacker forum",
            "stolen data", "extortion", "infostealer", "malware-as-a-service",
        ]
        # Curated dark-web sources — every article is already on-topic, skip keyword filter
        curated_feeds = [
            ("Daily Dark Web", "https://dailydarkweb.net/feed/"),
        ]

        articles = []
        for src, furl in feeds:
            try:
                feed = feedparser.parse(furl)
                for entry in (feed.entries or [])[:15]:
                    title   = entry.get("title", "")
                    summary = entry.get("summary") or ""
                    if not summary and entry.get("content"):
                        summary = entry["content"][0].get("value", "")
                    combined = (title + " " + summary).lower()
                    if any(kw in combined for kw in keywords):
                        articles.append({
                            "title":     title,
                            "summary":   summary[:400],
                            "source":    src,
                            "published": entry.get("published", ""),
                            "link":      entry.get("link", ""),
                            "category":  self._cat_dw(combined),
                        })
            except Exception as e:
                logger.warning(f"RSS feed error ({furl}): {e}")

        for src, furl in curated_feeds:
            try:
                feed = feedparser.parse(furl)
                for entry in (feed.entries or [])[:15]:
                    title   = entry.get("title", "")
                    summary = entry.get("summary") or ""
                    if not summary and entry.get("content"):
                        summary = entry["content"][0].get("value", "")
                    combined = (title + " " + summary).lower()
                    articles.append({
                        "title":     title,
                        "summary":   summary[:400],
                        "source":    src,
                        "published": entry.get("published", ""),
                        "link":      entry.get("link", ""),
                        "category":  self._cat_dw(combined),
                    })
            except Exception as e:
                logger.warning(f"RSS feed error ({furl}): {e}")

        # Conflictly (JavaScript SPA — Playwright render)
        try:
            articles.extend(self._fetch_conflictly())
        except Exception as e:
            logger.warning(f"Conflictly fetch failed: {e}")

        articles.sort(key=lambda x: x.get("published", ""), reverse=True)
        return articles[:40]

    def _fetch_conflictly(self) -> list:
        """Scrape conflictly.app (JavaScript SPA — requires Playwright).

        Returns items in the same format as _fetch_dark_web_intel so they
        can be merged directly into the dark-web articles list.
        """
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        except ImportError:
            logger.warning("playwright not installed — skipping Conflictly feed")
            return []

        fetched_at = datetime.now(timezone.utc).isoformat()
        html = ""
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                try:
                    ctx = browser.new_context(
                        user_agent=(
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/124.0 Safari/537.36"
                        )
                    )
                    page = ctx.new_page()
                    page.goto("https://www.conflictly.app/", timeout=30000)
                    try:
                        page.wait_for_selector(
                            "article, [class*='card'], [class*='post'], [class*='item'], h2 a, h3 a",
                            timeout=10000,
                        )
                    except PWTimeout:
                        pass  # proceed with whatever rendered
                    html = page.content()
                finally:
                    browser.close()
        except Exception as e:
            logger.warning(f"Conflictly Playwright fetch failed: {e}")
            return []

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        seen_links: set = set()
        records: list = []

        containers = (
            soup.find_all("article")
            or soup.find_all(attrs={"class": re.compile(r"card|post|item|story|event|news", re.I)})
            or soup.find_all(["h2", "h3"])
        )

        for el in containers[:40]:
            a = el.find("a", href=True)
            if not a:
                continue
            link = a.get("href", "")
            if not link.startswith("http"):
                link = "https://www.conflictly.app" + link
            if link in seen_links:
                continue
            seen_links.add(link)
            title = " ".join((a.get_text() or el.get_text()).split())[:200]
            if not title or len(title) < 10:
                continue
            p_el = el.find("p")
            summary = " ".join(p_el.get_text().split())[:400] if p_el else ""
            combined = (title + " " + summary).lower()
            records.append({
                "title":     title,
                "summary":   summary,
                "source":    "Conflictly",
                "published": fetched_at,
                "link":      link,
                "category":  self._cat_dw(combined),
            })

        if not records:
            logger.warning("Conflictly: no articles extracted — page structure may have changed")
        return records[:20]

    def _fetch_research_intel(self):
        """Security-research / exploit-analysis intelligence.

        Combines a bundled offline feed (feed.rss — Dayzerosec 0day write-ups,
        full long-form content) with live research RSS sources. Each item embeds
        a (capped) full body so the UI reader page can render it without an extra
        round-trip.
        """
        try:
            import feedparser
        except ImportError:
            logger.warning("feedparser not installed — skipping research intel")
            return []

        items = []
        seen_titles = set()

        def _add(entry, source, content_type_hint=None):
            title = (entry.get("title") or "").strip()
            if not title or title.lower() in seen_titles:
                return
            # Prefer full content:encoded, fall back to summary
            body = ""
            if entry.get("content"):
                body = entry["content"][0].get("value", "") or ""
            if not body:
                body = entry.get("summary") or entry.get("description") or ""
            ctype = content_type_hint or ("md" if _looks_markdown(body) else "html")
            clean_body = body if ctype == "md" else _clean_html(body)
            preview = _text_preview(clean_body, 280)
            sev, cat = self._research_meta(title + " " + preview)
            seen_titles.add(title.lower())
            # Stable, content-derived id so a given article keeps the same id
            # across refreshes/re-sorts. Positional ids (r0, r1, …) would point
            # the report endpoint at a *different* article after the scheduler
            # re-fetches the live feeds. Prefer the canonical link; fall back to
            # the title when a feed item has no link.
            rid = research_id(entry.get("link", ""), title)
            items.append({
                "id":          rid,
                "title":       title,
                "source":      source,
                "published":   entry.get("published", "") or entry.get("updated", ""),
                "_sortkey":    entry.get("published_parsed") or entry.get("updated_parsed"),
                "link":        entry.get("link", ""),
                "category":    cat,
                "severity":    sev,
                "preview":     preview,
                "content":     clean_body[:16000],
                "content_type": ctype,
            })

        # 1) Bundled offline research feed (full exploit write-ups)
        local = Path(__file__).resolve().parent / "feed.rss"
        if local.exists():
            try:
                feed = feedparser.parse(str(local))
                fsrc = (feed.feed.get("title") if getattr(feed, "feed", None) else "") or "0day Research"
                for entry in (feed.entries or [])[:24]:
                    _add(entry, fsrc, content_type_hint="md")
            except Exception as e:
                logger.warning(f"bundled research feed error: {e}")

        # 2) Live research sources
        for src, furl in RESEARCH_FEEDS:
            try:
                feed = feedparser.parse(furl)
                for entry in (feed.entries or [])[:6]:
                    _add(entry, src)
            except Exception as e:
                logger.warning(f"research feed error ({furl}): {e}")

        # De-duplicate across feeds (exact CVE + fuzzy title) — intel.md §4
        items = self._dedupe_research(items)
        # Newest first (fall back to string compare when no parsed date)
        items.sort(key=lambda x: (x.get("_sortkey") or ()), reverse=True)
        for it in items:
            it.pop("_sortkey", None)
        # IDs are content-derived (see _add) — stable across refreshes, so no
        # positional re-keying. Guard against the rare hash collision by
        # de-duplicating ids deterministically.
        seen_ids = set()
        for it in items:
            base = it["id"]
            rid = base
            n = 1
            while rid in seen_ids:
                rid = f"{base}-{n}"
                n += 1
            it["id"] = rid
            seen_ids.add(rid)
        return items[:48]

    def _dedupe_research(self, items: list) -> list:
        """Drop duplicates: same CVE id, or near-identical titles (Jaccard ≥ 0.62)."""
        kept, fingerprints = [], []
        for it in items:
            blob = f"{it.get('title','')} {it.get('preview','')}"
            m = _CVE_RE.search(blob)
            cve = m.group(0).lower() if m else None
            toks = {t for t in re.sub(r"[^a-z0-9 ]", " ", it.get("title", "").lower()).split() if len(t) > 2}
            dup = False
            for kcve, ktoks in fingerprints:
                if cve and kcve and cve == kcve:
                    dup = True
                    break
                if toks and ktoks:
                    inter = len(toks & ktoks)
                    union = len(toks | ktoks)
                    if union and inter / union >= 0.62:
                        dup = True
                        break
            if not dup:
                kept.append(it)
                fingerprints.append((cve, toks))
        return kept

    def _research_meta(self, text: str):
        """Return (severity, category) from heuristics on title+preview."""
        t = text.lower()
        if any(k in t for k in ("critical", "rce", "remote code", "zero-day", "0day",
                                "actively exploited", "wormable", "unauthenticated", "drain")):
            sev = "CRITICAL"
        elif any(k in t for k in ("exploit", "privilege escalation", "sql injection",
                                  "deserial", "auth bypass", "use-after-free", "overflow")):
            sev = "HIGH"
        elif any(k in t for k in ("xss", "csrf", "disclosure", "info leak", "ssrf", "medium")):
            sev = "MEDIUM"
        else:
            sev = "INFO"
        if any(k in t for k in ("bridge", "defi", "web3", "smart contract", "ethereum",
                                "blockchain", "token", "wallet", "solidity", "on-chain")):
            cat = "Web3 / DeFi"
        elif any(k in t for k in ("exploit", "poc", "proof of concept", "rce", "payload", "shellcode")):
            cat = "Exploit Research"
        elif any(k in t for k in ("ransomware", "malware", "stealer", "botnet", "backdoor", "trojan")):
            cat = "Malware"
        elif any(k in t for k in ("cve-", "vulnerability", "advisory", "patch", "0day", "zero-day")):
            cat = "Vulnerability"
        else:
            cat = "Security Research"
        return sev, cat

    # ─────────────────────────────────────────────────────────────────────────
    # Private — helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_geopolitical(self, feodo_ips: list):
        stats: dict = {}
        for e in feodo_ips:
            raw = (e.get("country") or "Unknown").strip()
            # Feodo Tracker returns ISO-2 codes; resolve to full display names.
            c = _ISO2_COUNTRY.get(raw, raw) if raw else "Unknown"
            m = e.get("malware") or "Unknown"
            if c not in stats:
                stats[c] = {"count": 0, "malware": set()}
            stats[c]["count"] += 1
            stats[c]["malware"].add(m)

        out = []
        for country, s in sorted(stats.items(), key=lambda x: x[1]["count"], reverse=True):
            if country == "Unknown":
                continue
            count = s["count"]
            out.append({
                "country":         country,
                "flag":            COUNTRY_FLAGS.get(country, "🌍"),
                "threat_count":    count,
                "malware_families":list(s["malware"])[:5],
                "primary_threat":  "Botnet C2 Infrastructure",
                "risk_level": (
                    "CRITICAL" if count > 20 else
                    "HIGH"     if count > 10 else
                    "MEDIUM"   if count > 3  else
                    "LOW"
                ),
            })
        return out[:20]

    def _attr_country(self, description: str, name: str = "") -> str:
        text = (description + " " + name).lower()
        mapping = [
            ("Russia",      ["russia", "russian", "gru", "fsb", "svr", "apt28", "apt29", "cozy bear", "fancy bear"]),
            ("China",       ["china", "chinese", "prc", "pla", "apt40", "apt41", "winnti", "goblin panda"]),
            ("North Korea", ["north korea", "dprk", "lazarus", "kimsuky", "bluenoroff"]),
            ("Iran",        ["iran", "iranian", "irgc", "apt33", "apt34", "charming kitten"]),
            ("Vietnam",     ["vietnam", "vietnamese", "ocean lotus", "apt32"]),
            ("Pakistan",    ["pakistan", "transparent tribe", "apt36"]),
            ("India",       ["india", "sidewinder", "apt-c-17"]),
        ]
        for country, kws in mapping:
            if any(k in text for k in kws):
                return country
        return "Unknown"

    def _sophistication(self, obj: dict) -> str:
        aliases = len(obj.get("aliases") or [])
        if aliases >= 5:
            return "Nation-State"
        elif aliases >= 3:
            return "Advanced"
        else:
            return "Moderate"

    def _cat_dw(self, text: str) -> str:
        if "ransomware" in text or "extortion" in text:
            return "Ransomware Activity"
        if "breach" in text or "leak" in text or "dump" in text:
            return "Data Breach / Leak"
        if "forum" in text or "underground" in text:
            return "Underground Forum"
        if "credential" in text or "password" in text or "infostealer" in text:
            return "Credential Exposure"
        if "tor" in text or "onion" in text:
            return "Tor Network Activity"
        return "Dark Web Activity"
