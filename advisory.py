"""
advisory.py — live vendor-advisory fetch + remediation extraction.

For a given CVE we pick the most authoritative vendor advisory URL from its
NVD/CVEDB reference list, fetch the page, and heuristically extract the
remediation / fixed-version text so the risk drawer can show guidance that
matches the vendor's own wording (rather than a generic template).

Strictly best-effort: brittle per-site scraping is wrapped so a failure returns
an empty excerpt (the rule-based guidance in risk.py still stands) plus a
guaranteed deep link to the vendor's security portal.

Results are cached to disk (cache/advisory/<cve>.json, ~7d TTL) and fetched
lazily (only when an analyst opens a CVE), so the 4h refresh stays fast.
"""

import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_TTL = 604_800  # 7 days
_TIMEOUT = (8, 14)

# Known vendor advisory domains, ranked — higher = preferred as the source page.
# (domain substring, vendor label, rank)
_VENDOR_DOMAINS = [
    ("msrc.microsoft.com", "Microsoft", 100),
    ("microsoft.com", "Microsoft", 80),
    ("sec.cloudapps.cisco.com", "Cisco", 100),
    ("tools.cisco.com", "Cisco", 95),
    ("cisco.com", "Cisco", 80),
    ("fortiguard.com", "Fortinet", 100),
    ("fortinet.com", "Fortinet", 90),
    ("support.broadcom.com", "VMware / Broadcom", 100),
    ("vmware.com", "VMware", 90),
    ("oracle.com", "Oracle", 95),
    ("helpx.adobe.com", "Adobe", 100),
    ("adobe.com", "Adobe", 85),
    ("ubuntu.com", "Ubuntu", 95),
    ("access.redhat.com", "Red Hat", 100),
    ("redhat.com", "Red Hat", 85),
    ("debian.org", "Debian", 90),
    ("suse.com", "SUSE", 90),
    ("support.citrix.com", "Citrix", 100),
    ("citrix.com", "Citrix", 90),
    ("forums.ivanti.com", "Ivanti", 100),
    ("ivanti.com", "Ivanti", 90),
    ("security.paloaltonetworks.com", "Palo Alto Networks", 100),
    ("paloaltonetworks.com", "Palo Alto Networks", 85),
    ("psirt.global.sonicwall.com", "SonicWall", 100),
    ("confluence.atlassian.com", "Atlassian", 95),
    ("atlassian.com", "Atlassian", 85),
    ("community.progress.com", "Progress", 100),
    ("progress.com", "Progress", 85),
    ("chromereleases.googleblog.com", "Google Chrome", 100),
    ("support.apple.com", "Apple", 100),
    ("apache.org", "Apache", 95),
    ("gitlab.com", "GitLab", 90),
    ("kb.juniper.net", "Juniper", 100),
    ("juniper.net", "Juniper", 85),
    ("f5.com", "F5", 90),
    ("github.com", "GitHub advisory", 60),
    ("nvd.nist.gov", "NVD", 20),
]

# Guaranteed deep-link fallback to a vendor's security portal (CVE-searchable
# where possible), keyed by lowercased vendor name substring.
_VENDOR_PORTALS = {
    "microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
    "cisco": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    "fortinet": "https://www.fortiguard.com/psirt?date=&severity=&product=",
    "vmware": "https://support.broadcom.com/group/ecx/security-advisory",
    "broadcom": "https://support.broadcom.com/group/ecx/security-advisory",
    "oracle": "https://www.oracle.com/security-alerts/",
    "adobe": "https://helpx.adobe.com/security/security-bulletin.html",
    "ubuntu": "https://ubuntu.com/security/{cve}",
    "canonical": "https://ubuntu.com/security/{cve}",
    "red hat": "https://access.redhat.com/security/cve/{cve}",
    "redhat": "https://access.redhat.com/security/cve/{cve}",
    "debian": "https://security-tracker.debian.org/tracker/{cve}",
    "citrix": "https://support.citrix.com/securitybulletins",
    "ivanti": "https://www.ivanti.com/blog/topics/security-advisory",
    "palo alto": "https://security.paloaltonetworks.com/{cve}",
    "sonicwall": "https://psirt.global.sonicwall.com/vuln-detail/{cve}",
    "atlassian": "https://www.atlassian.com/trust/security/advisories",
    "progress": "https://www.progress.com/security",
    "google": "https://chromereleases.googleblog.com/",
    "apple": "https://support.apple.com/en-us/HT201222",
    "apache": "https://www.apache.org/security/",
}

_REMEDIATION_HEADINGS = re.compile(
    r"(solution|remediation|fixed (?:in|version|release)|fix(?:ed)? (?:information|details)|"
    r"recommended? (?:action|update|version)|patch(?:es)?|upgrade|mitigation|workaround|"
    r"affected (?:and fixed|products?))",
    re.I,
)


def _writable_base() -> Path:
    candidates = []
    if os.environ.get("DATA_DIR"):
        candidates.append(Path(os.environ["DATA_DIR"]))
    candidates.append(Path(__file__).resolve().parent)
    candidates.append(Path(tempfile.gettempdir()) / "jatayu_data")
    for base in candidates:
        try:
            (base / "cache" / "advisory").mkdir(parents=True, exist_ok=True)
            return base
        except Exception:
            continue
    return Path(tempfile.gettempdir())


_CACHE_DIR = _writable_base() / "cache" / "advisory"

_session = requests.Session()
_session.headers.update({
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml",
})


def _vendor_for_url(url: str):
    host = (urlparse(url).hostname or "").lower()
    best = None
    for dom, label, rank in _VENDOR_DOMAINS:
        if dom in host and (best is None or rank > best[2]):
            best = (label, dom, rank)
    return best  # (label, dom, rank) or None


def pick_advisory_url(references) -> tuple:
    """Choose the best vendor advisory URL from a reference list.
    Returns (url, vendor_label) or (None, '')."""
    ranked = []
    for url in (references or []):
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        v = _vendor_for_url(url)
        rank = v[2] if v else 10
        ranked.append((rank, url, v[0] if v else ""))
    if not ranked:
        return None, ""
    ranked.sort(key=lambda x: x[0], reverse=True)
    return ranked[0][1], ranked[0][2]


def portal_link(vendor: str, cve: str) -> str:
    v = (vendor or "").lower()
    for key, tmpl in _VENDOR_PORTALS.items():
        if key in v:
            return tmpl.format(cve=cve)
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def _extract_remediation(html: str) -> str:
    """Pull a concise remediation excerpt from advisory HTML (best-effort)."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "header", "footer", "nav", "svg"]):
        tag.decompose()

    # 1) Look for a heading whose text matches remediation keywords; collect the
    #    following block text until the next heading.
    chunks = []
    for h in soup.find_all(["h1", "h2", "h3", "h4", "strong", "b", "dt"]):
        htxt = " ".join(h.get_text().split())
        if not htxt or not _REMEDIATION_HEADINGS.search(htxt):
            continue
        body = []
        for sib in h.next_siblings:
            name = getattr(sib, "name", None)
            if name in ("h1", "h2", "h3", "h4"):
                break
            if name is None:
                continue
            t = " ".join(sib.get_text(" ").split())
            if t:
                body.append(t)
            if sum(len(x) for x in body) > 700:
                break
        seg = (htxt + ": " + " ".join(body)).strip()
        if len(seg) > len(htxt) + 2:
            chunks.append(seg)
        if len(chunks) >= 3:
            break
    if chunks:
        return _clean(" \n".join(chunks))[:1200]

    # 2) Fallback: scan paragraphs/list-items for a remediation keyword sentence.
    for el in soup.find_all(["p", "li", "td"]):
        t = " ".join(el.get_text(" ").split())
        if len(t) > 40 and _REMEDIATION_HEADINGS.search(t):
            return _clean(t)[:1200]
    return ""


def _clean(t: str) -> str:
    return re.sub(r"\s+", " ", t or "").strip()


def fetch_advisory(cve: str, references=None) -> dict:
    """Return {cve, url, vendor, text, portal, fetched_at}. Disk-cached, best-effort."""
    cve = (cve or "").upper()
    if not _CVE_RE.match(cve):
        return {"cve": cve, "url": "", "vendor": "", "text": "", "portal": "", "fetched_at": ""}

    cache = _CACHE_DIR / f"{cve}.json"
    try:
        if cache.exists() and (time.time() - cache.stat().st_mtime) < _TTL:
            return json.loads(cache.read_text(encoding="utf-8"))
    except Exception:
        pass

    url, vendor = pick_advisory_url(references)
    rec = {"cve": cve, "url": url or "", "vendor": vendor or "",
           "text": "", "portal": portal_link(vendor, cve),
           "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if url:
        try:
            r = _session.get(url, timeout=_TIMEOUT)
            r.raise_for_status()
            ctype = r.headers.get("Content-Type", "")
            if "html" in ctype or "<html" in r.text[:500].lower():
                rec["text"] = _extract_remediation(r.text)
            if not rec["vendor"]:
                v = _vendor_for_url(url)
                rec["vendor"] = v[0] if v else (urlparse(url).hostname or "")
        except Exception as e:
            logger.info("advisory fetch failed for %s (%s): %s", cve, url, e)

    try:
        cache.write_text(json.dumps(rec), encoding="utf-8")
    except Exception:
        pass
    return rec
