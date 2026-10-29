"""
selftest.py — JATAYU functional self-test / QA harness.

Runs fully offline (no network, no API keys) and exercises the parts of the
app that previously shipped functional bugs, plus the core data path:

  • connectors: CSV / Nessus parsing, severity normalization, Tenable export
    record mapping (real asset identity + CVE list).
  • risk: prioritization correctly counts assets and unique CVEs from the
    normalized findings.
  • fetcher.research_id: stable, content-derived ids (the "newsletter/brief
    downloads something random" bug).
  • report: research brief / scan PDF / XLSX generation produces valid,
    non-empty documents.

Usage:
    python selftest.py            # run all checks, exit 0 on success
    python selftest.py -v         # verbose (print each check)

Exit code is non-zero if any check fails — suitable for CI / pre-deploy gates.
"""

import sys
import traceback

import connectors
import risk
import report
import enrich
import advisory
import scanner
import patchsphere
from fetcher import research_id, DataFetcher

_VERBOSE = "-v" in sys.argv or "--verbose" in sys.argv
_results = []  # (name, ok, detail)


def check(name):
    def deco(fn):
        try:
            fn()
            _results.append((name, True, ""))
            if _VERBOSE:
                print(f"  PASS  {name}")
        except AssertionError as e:
            _results.append((name, False, str(e) or "assertion failed"))
            print(f"  FAIL  {name}: {e}")
        except Exception as e:  # unexpected error
            _results.append((name, False, f"{type(e).__name__}: {e}"))
            print(f"  ERROR {name}: {e}")
            if _VERBOSE:
                traceback.print_exc()
        return fn
    return deco


# A representative Tenable.io vulnerability-export record (the shape the export
# API streams in each chunk).
_TENABLE_EXPORT_RECORD = {
    "asset": {"hostname": "web01.corp.local", "ipv4": "10.0.0.12", "uuid": "abc-123"},
    "plugin": {"id": 100001, "name": "OpenSSL RCE",
               "cve": ["CVE-2026-42271", "CVE-2026-48027"],
               "cvss3_base_score": 9.8, "description": "Remote code execution."},
    "port": {"port": 443, "protocol": "TCP"},
    "severity": "critical", "severity_id": 4,
    "first_found": "2026-06-10T12:00:00Z",
}

_SAMPLE_CSV = (
    b"IP,DNS,CVE,Severity,CVSS,Name,Port,First Seen\n"
    b"10.0.0.12,web01.corp.local,CVE-2026-42271,Critical,9.8,RCE in LiteLLM,443,2026-06-10\n"
    b"10.0.0.34,db01.corp.local,CVE-2026-50751,Critical,9.4,DB flaw,1433,2026-06-11\n"
    b"10.0.0.99,print01.corp.local,,Info,0,Informational only,9100,2026-06-12\n"
)

_SAMPLE_NESSUS = b"""<?xml version="1.0"?>
<NessusClientData_v2><Report name="t">
  <ReportHost name="10.0.0.55">
    <HostProperties><tag name="host-ip">10.0.0.55</tag>
      <tag name="host-fqdn">app02.corp.local</tag></HostProperties>
    <ReportItem severity="4" pluginName="BlueKeep RDP RCE" port="3389">
      <cve>CVE-2019-0708</cve><cvss3_base_score>9.8</cvss3_base_score>
      <description>RDP RCE.</description>
    </ReportItem>
    <ReportItem severity="0" pluginName="Open port info" port="80">
      <description>Just informational.</description>
    </ReportItem>
  </ReportHost>
</Report></NessusClientData_v2>"""


# ── connectors ───────────────────────────────────────────────────────────────
@check("severity: numeric + CVSS banding")
def _():
    assert connectors.normalize_severity("4") == "CRITICAL"
    assert connectors.normalize_severity("Critical") == "CRITICAL"
    assert connectors.normalize_severity(None, 9.8) == "CRITICAL"
    assert connectors.normalize_severity(None, 5.0) == "MEDIUM"
    assert connectors.normalize_severity("", None) == "INFO"


@check("csv parser: rows + info-without-cve dropped")
def _():
    findings = connectors.parse_csv(_SAMPLE_CSV)
    assert len(findings) == 2, f"expected 2 actionable findings, got {len(findings)}"
    f0 = findings[0]
    assert f0["ip"] == "10.0.0.12" and f0["hostname"] == "web01.corp.local"
    assert f0["cve_ids"] == ["CVE-2026-42271"]
    assert f0["severity"] == "CRITICAL"


@check("nessus parser: cve + info-skip")
def _():
    findings = connectors.parse_nessus(_SAMPLE_NESSUS)
    assert len(findings) == 1, f"expected 1 finding (info skipped), got {len(findings)}"
    assert findings[0]["cve_ids"] == ["CVE-2019-0708"]
    assert findings[0]["ip"] == "10.0.0.55"


@check("tenable export mapping: real asset + cves + severity")
def _():
    f = connectors.TenableClient._map_vuln(_TENABLE_EXPORT_RECORD)
    assert f["source"] == "tenable"
    assert f["ip"] == "10.0.0.12", f"asset ip lost: {f}"
    assert f["hostname"] == "web01.corp.local"
    assert f["asset"] == "web01.corp.local", "asset label must be the host, not a count string"
    assert f["cve_ids"] == ["CVE-2026-42271", "CVE-2026-48027"], f"cves lost: {f['cve_ids']}"
    assert f["severity"] == "CRITICAL"
    assert f["cvss"] == 9.8 and f["port"] == "443"


@check("ingest store: dedup counts distinct real assets")
def _():
    f1 = connectors.TenableClient._map_vuln(_TENABLE_EXPORT_RECORD)
    rec2 = {**_TENABLE_EXPORT_RECORD,
            "asset": {"hostname": "db01.corp.local", "ipv4": "10.0.0.34"}}
    f2 = connectors.TenableClient._map_vuln(rec2)
    # stats() reads from disk; emulate its asset-counting on an in-memory list.
    assets = {(x.get("ip") or x.get("asset") or "").lower() for x in (f1, f2)}
    assert len(assets) == 2, f"expected 2 distinct assets, got {assets}"


# ── risk ─────────────────────────────────────────────────────────────────────
@check("risk: tenable findings produce assets + unique cves (regression)")
def _():
    findings = [
        connectors.TenableClient._map_vuln(_TENABLE_EXPORT_RECORD),
        connectors.TenableClient._map_vuln(
            {**_TENABLE_EXPORT_RECORD,
             "asset": {"hostname": "db01.corp.local", "ipv4": "10.0.0.34"}}),
    ]
    out = risk.prioritize(findings, intel={})
    s = out["summary"]
    assert s["total_assets"] == 2, f"asset count collapsed: {s}"
    assert s["unique_cves"] == 2, f"cves not ingested: {s}"
    assert len(out["items"]) == 2


@check("risk: KEV correlation boosts score")
def _():
    findings = [connectors.TenableClient._map_vuln(_TENABLE_EXPORT_RECORD)]
    intel = {"advisories": {"top_exploited_cves": [
        {"cve_id": "CVE-2026-42271", "known_ransomware": "Known", "vendor": "X", "product": "Y"}]}}
    out = risk.prioritize(findings, intel)
    kev_item = next(i for i in out["items"] if i["cve_id"] == "CVE-2026-42271")
    assert kev_item["in_kev"] and kev_item["ransomware"]
    assert kev_item["priority"] in ("CRITICAL", "HIGH")


# ── fetcher: stable research ids (newsletter bug) ──────────────────────────────
@check("research_id: stable & link-derived (newsletter regression)")
def _():
    a = research_id("https://example.com/post-1", "Title A")
    b = research_id("https://example.com/post-1", "A DIFFERENT title after re-fetch")
    assert a == b, "id must depend on link, not title/position"
    c = research_id("https://example.com/post-2", "Title A")
    assert a != c, "different articles must get different ids"
    assert a.startswith("r") and len(a) == 13


# ── report generation ──────────────────────────────────────────────────────────
@check("report: research brief PDF is valid + non-trivial")
def _():
    item = {"id": "r1", "title": "Critical RCE in WidgetServer",
            "category": "Exploit", "source": "ZDI", "severity": "CRITICAL",
            "published": "2026-06-10", "link": "https://example.com/x",
            "preview": "A critical unauthenticated RCE affecting WidgetServer.",
            "content": "## Overview\nCVE-2026-42271 affects 10.0.0.12. SHA256 "
                       "a" * 64 + ".\nExploitation is trivial.",
            "content_type": "md"}
    pdf = report.build_research_pdf(item)
    assert pdf[:5] == b"%PDF-", "not a PDF"
    assert len(pdf) > 1500, f"PDF suspiciously small: {len(pdf)} bytes"
    assert report.research_report_filename(item).endswith(".pdf")


@check("report: scan PDF + XLSX generate")
def _():
    result = {
        "query": "example.com", "type": "domain", "timestamp": "2026-06-10T00:00:00Z",
        "risk_score": {"score": 72, "level": "HIGH", "factors": ["Open RDP"]},
        "findings": [{"severity": "HIGH", "category": "Web", "asset": "example.com",
                      "title": "Missing HSTS", "remediation": "Add HSTS header"}],
        "hosts": [{"host": "example.com", "alive": True, "ips": ["1.2.3.4"],
                   "ports": [443], "cves": [], "findings": [], "tech": ["nginx"]}],
        "vulnerabilities": ["CVE-2021-44228"], "remediation": [],
        "sources_used": ["dns", "tls"],
    }
    pdf = report.build_pdf(result)
    assert pdf[:5] == b"%PDF-"
    xlsx = report.build_xlsx(result)
    assert xlsx[:2] == b"PK", "XLSX is not a valid zip/openxml container"


# ── enrichment (Shodan CVEDB) ──────────────────────────────────────────────────
@check("enrich: CVEDB JSON → normalized record")
def _():
    raw = {"cve_id": "CVE-2021-44228", "cvss": 10.0, "cvss_v2": 9.3, "cvss_v3": 10.0,
           "cvss_v4": None, "epss": 0.97, "ranking_epss": 0.99, "kev": True,
           "ransomware_campaign": "Known", "euvd": {"id": "EUVD-2021-34768"}}
    rec = enrich._normalize("CVE-2021-44228", raw)
    assert rec["epss"] == 0.97 and rec["percentile"] == 0.99
    assert rec["cvss"] == 10.0 and rec["cvss_version"] == "3.x"
    assert rec["kev"] is True and rec["ransomware"] is True
    assert rec["euvd"] == "EUVD-2021-34768", "euvd must be slimmed to its id"


@check("enrich: cvss_v4 present → version 4.0; bad input ignored")
def _():
    rec = enrich._normalize("CVE-2024-0001", {"cvss_v4": 9.3, "cvss_v3": 8.8, "epss": "bad"})
    assert rec["cvss_v4"] == 9.3 and rec["cvss_version"] == "4.0"
    assert rec["epss"] is None, "non-numeric EPSS must normalize to None"
    assert enrich.enrich_cves(["not-a-cve", ""]) == {}, "invalid CVE ids filtered"


# ── MITRE CWE→CAPEC→ATT&CK chain ───────────────────────────────────────────────
_CAPEC_XML = b"""<?xml version="1.0"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
 <Attack_Patterns>
  <Attack_Pattern ID="66" Name="SQL Injection">
   <Related_Weaknesses><Related_Weakness CWE_ID="89"/></Related_Weaknesses>
   <Taxonomy_Mappings>
     <Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>1190</Entry_ID></Taxonomy_Mapping>
   </Taxonomy_Mappings>
  </Attack_Pattern>
 </Attack_Patterns>
</Attack_Pattern_Catalog>"""

_ATTACK_OBJS = [{"type": "attack-pattern", "name": "Exploit Public-Facing Application",
                 "external_references": [{"source_name": "mitre-attack", "external_id": "T1190",
                                          "url": "https://attack.mitre.org/techniques/T1190"}],
                 "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]}]


@check("mitre: CAPEC XML parses to CWE→technique map")
def _():
    m = DataFetcher._parse_capec(_CAPEC_XML)
    assert m.get("89") == ["T1190"], f"unexpected CAPEC map: {m}"


@check("mitre: ATT&CK technique extraction (id→name/tactic)")
def _():
    t = DataFetcher._extract_attack_techniques(_ATTACK_OBJS)
    assert t["T1190"]["name"] == "Exploit Public-Facing Application"
    assert t["T1190"]["tactic"] == "Initial Access"


# ── risk: EPSS / CVSS4 enrichment ──────────────────────────────────────────────
@check("risk: EPSS enrichment raises score + populates fields")
def _():
    finding = connectors.TenableClient._map_vuln(
        {"asset": {"hostname": "h1", "ipv4": "10.0.0.1"},
         "plugin": {"name": "X", "cve": ["CVE-2021-44228"]}, "severity_id": 4})
    intel = {"advisories": {"top_exploited_cves": []},
             "enrichment": {"CVE-2021-44228": {"epss": 0.95, "percentile": 0.99, "cvss": 10.0,
                            "cvss_v3": 10.0, "cvss_v4": None, "cvss_version": "3.x",
                            "kev": True, "ransomware": True, "euvd": "EUVD-2021-34768"}}}
    base = risk.prioritize([finding], {"advisories": {"top_exploited_cves": []}})
    enriched = risk.prioritize([finding], intel)
    it = next(i for i in enriched["items"] if i["cve_id"] == "CVE-2021-44228")
    assert it["epss"] == 0.95 and it["euvd"] == "EUVD-2021-34768"
    assert it["in_kev"] and it["cvss"] == 10.0
    b = next(i for i in base["items"] if i["cve_id"] == "CVE-2021-44228")
    assert it["priority_score"] > b["priority_score"], "EPSS+KEV must raise the score"
    assert enriched["summary"]["high_epss"] == 1


# ── zero-day parser ────────────────────────────────────────────────────────────
@check("zeroday: HTML parses to normalized records")
def _():
    html = ('<div><h3><a href="/database/123/">Critical RCE CVE-2026-12345</a></h3>'
            '<p>Remote Code Execution</p>'
            '<p>An unauthenticated attacker can execute code; actively exploited in the wild.</p>'
            '<p>Software: WidgetServer 1.0</p><p>2026-06-01</p>'
            '<h3><a href="/database/124/">Another CVE-2026-22222</a></h3><p>XSS</p></div>')
    recs = DataFetcher._parse_zeroday(html)
    assert len(recs) == 2, f"expected 2 records, got {len(recs)}"
    r0 = recs[0]
    assert r0["cve"] == "CVE-2026-12345" and r0["vuln_type"] == "Remote Code Execution"
    assert r0["actively_exploited"] is True
    assert r0["software"] == "WidgetServer 1.0" and r0["date_discovered"] == "2026-06-01"
    assert r0["detail_url"] == "https://www.zero-day.cz/database/123/"


# ── enrichment: propose_action + references ─────────────────────────────────────
@check("enrich: captures propose_action + references")
def _():
    rec = enrich._normalize("CVE-2021-44228", {
        "cvss": 10.0, "epss": 0.9, "propose_action": "Upgrade to Log4j 2.17.1.",
        "references": ["https://logging.apache.org/log4j/2.x/security.html", ""]})
    assert rec["propose_action"] == "Upgrade to Log4j 2.17.1."
    assert rec["references"] == ["https://logging.apache.org/log4j/2.x/security.html"]


# ── risk: structured remediation + grouping ─────────────────────────────────────
def _risk_with_intel():
    findings = [
        connectors.TenableClient._map_vuln(
            {"asset": {"hostname": "h1", "ipv4": "10.0.0.1"},
             "plugin": {"name": "Log4Shell", "cve": ["CVE-2021-44228"]}, "severity_id": 4}),
        connectors.TenableClient._map_vuln(
            {"asset": {"hostname": "h2", "ipv4": "10.0.0.2"},
             "plugin": {"name": "Other", "cve": ["CVE-2020-0001"]}, "severity_id": 3}),
    ]
    intel = {"advisories": {"top_exploited_cves": [
        {"cve_id": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j2",
         "known_ransomware": "Known", "due_date": "2021-12-24",
         "required_action": "Apply updates per vendor instructions."}],
        "immediate_attention_cves": [
        {"cve_id": "CVE-2021-44228", "references": ["https://logging.apache.org/log4j/2.x/security.html"]}]},
        "enrichment": {"CVE-2021-44228": {"epss": 0.99, "cvss": 10.0, "cvss_v3": 10.0,
                       "kev": True, "ransomware": True, "propose_action": "Upgrade to 2.17.1."}}}
    return risk.prioritize(findings, intel)


@check("risk: item carries structured remediation")
def _():
    out = _risk_with_intel()
    it = next(i for i in out["items"] if i["cve_id"] == "CVE-2021-44228")
    rem = it.get("remediation")
    assert rem and rem.get("sla") and rem.get("steps"), f"missing remediation: {rem}"
    assert any("CISA Known Exploited" in s for s in rem["steps"]), "KEV step missing"
    assert any("2.17.1" in s for s in rem["steps"]), "propose_action step missing"
    assert any(a["url"].startswith("https://nvd.nist.gov") for a in rem["advisories"])
    assert "2021-12-24" in rem["sla"], "should use CISA due date as SLA"


@check("risk: group_remediations by vendor_product and kev")
def _():
    out = _risk_with_intel()
    g_vp = risk.group_remediations(out["items"], "vendor_product")
    labels = [g["label"] for g in g_vp["groups"]]
    assert "Apache Log4j2" in labels, f"vendor+product group missing: {labels}"
    g_kev = risk.group_remediations(out["items"], "kev")
    assert g_kev["count"] == 1 and g_kev["groups"][0]["items"][0]["cve_id"] == "CVE-2021-44228"
    g_sel = risk.group_remediations(out["items"], "selection", "CVE-2020-0001")
    assert g_sel["count"] == 1


# ── report: new XLSX builders ────────────────────────────────────────────────────
@check("report: risk / findings / intel / remediation / custom XLSX")
def _():
    out = _risk_with_intel()
    findings = [{"source": "tenable", "asset": "h1", "ip": "10.0.0.1", "hostname": "h1",
                 "severity": "CRITICAL", "cvss": 10.0, "cve_ids": ["CVE-2021-44228"],
                 "port": "443", "plugin_name": "Log4Shell", "first_seen": "2026-01-01"}]
    stats = {"total": 1, "assets": 1, "unique_cves": 1, "by_severity": {"CRITICAL": 1},
             "by_source": {"tenable": 1}}
    data = {"advisories": {"top_exploited_cves": [], "immediate_attention_cves": []},
            "threat_intel": {"iocs": {"malicious_ips": []}, "top_threat_actors": [],
                             "darkweb": {"breaches": []}, "zeroday": []}}
    grouped = risk.group_remediations(out["items"], "kev")
    for name, b in [
        ("risk", report.build_risk_xlsx(out)),
        ("findings", report.build_findings_xlsx(findings, stats)),
        ("intel", report.build_intel_xlsx(data)),
        ("remediation", report.build_remediation_xlsx(grouped)),
        ("custom", report.build_custom_report_xlsx(
            ["risk", "findings", "threat-intel"], data=data, risk_result=out,
            findings=findings, stats=stats)),
    ]:
        assert b[:2] == b"PK", f"{name} not a valid XLSX"
        assert len(b) > 2000, f"{name} XLSX suspiciously small ({len(b)})"


# ── advisory: vendor URL pick + remediation extraction ──────────────────────────
@check("advisory: picks highest-ranked vendor URL")
def _():
    url, vendor = advisory.pick_advisory_url([
        "https://example.com/blog", "https://msrc.microsoft.com/update-guide/CVE-2024-1"])
    assert "msrc.microsoft.com" in url and vendor == "Microsoft", (url, vendor)
    assert advisory.portal_link("Microsoft", "CVE-2024-1").endswith("CVE-2024-1")


@check("advisory: extracts remediation text from advisory HTML")
def _():
    html = ("<html><body><h2>Overview</h2><p>blah blah.</p>"
            "<h2>Solution</h2><p>Upgrade to FortiOS 7.4.3 or later per the vendor advisory.</p>"
            "<h2>References</h2><p>links</p></body></html>")
    txt = advisory._extract_remediation(html)
    assert "Upgrade to FortiOS 7.4.3" in txt, f"extraction failed: {txt!r}"


# ── attack vector population (regression) ───────────────────────────────────────
@check("attack vector: parsed from scanner CVSS vector")
def _():
    f = connectors.TenableClient._map_vuln(
        {"asset": {"ipv4": "10.0.0.1"}, "severity_id": 3,
         "plugin": {"name": "X", "cve": ["CVE-2021-1"],
                    "cvss3_vector": {"raw": "CVSS:3.1/AV:L/AC:L/PR:N"}}})
    assert f["attack_vector"] == "LOCAL", f["attack_vector"]
    out = risk.prioritize([f], {"advisories": {"top_exploited_cves": [], "immediate_attention_cves": []}})
    assert out["items"][0]["attack_vector"] == "LOCAL"


@check("attack vector: enrichment fallback fills it (regression)")
def _():
    f = connectors.TenableClient._map_vuln(
        {"asset": {"ipv4": "10.0.0.2"}, "severity_id": 4,
         "plugin": {"name": "Y", "cve": ["CVE-2021-44228"]}})
    intel = {"advisories": {"top_exploited_cves": [], "immediate_attention_cves": []},
             "enrichment": {"CVE-2021-44228": {"kev": True, "attack_vector": "NETWORK", "cvss": 10.0}}}
    it = risk.prioritize([f], intel)["items"][0]
    assert it["attack_vector"] == "NETWORK", "enrichment attack_vector must fill when scan/NVD lack it"
    assert enrich.attack_vector_from_vector("CVSS:3.1/AV:P/AC:L") == "PHYSICAL"


# ── scanner: false-positive suppression + new detectors ─────────────────────────
@check("scanner: SPA soft-404 catch-all suppresses bogus path findings")
def _():
    spa = "<html><body>login password API_KEY DB_ SECRET</body></html>"
    orig = scanner._fetch_path
    scanner._fetch_path = lambda base, path: (200, "text/html", spa, len(spa))
    try:
        assert scanner._probe_paths("https://x", "x") == [], "SPA catch-all must yield 0 findings"
    finally:
        scanner._fetch_path = orig


@check("scanner: real exposed .env is a Confirmed CRITICAL finding")
def _():
    def fake(base, path):
        if path == "/.env":
            b = "APP_ENV=production\nDB_PASSWORD=s3cr3t\nAWS_SECRET=x\n"
            return (200, "text/plain", b, len(b))
        return (404, "text/html", "<html>nf</html>", 14)
    orig = scanner._fetch_path
    scanner._fetch_path = fake
    try:
        fs = scanner._probe_paths("https://y", "y")
        assert len(fs) == 1 and fs[0]["severity"] == "CRITICAL"
        assert fs[0]["confidence"] == "Confirmed"
    finally:
        scanner._fetch_path = orig


@check("scanner: homograph lookalike generation + punycode")
def _():
    cand = scanner._generate_lookalikes("google.com")
    assert any(t == "homograph" for t in cand.values()), "no homograph candidates"
    assert any(t == "tld-swap" for t in cand.values())
    ace = scanner._to_ace("gооgle.com")   # cyrillic-o google
    assert ace.startswith("xn--"), f"punycode encoding failed: {ace}"
    assert scanner._split_domain("foo.co.uk") == ("foo", "co.uk")


@check("scanner: SQLi error-signature detection (OWASP A03)")
def _():
    from urllib.parse import urlparse, parse_qs
    def fake_get(url, allow_redirects=False):
        val = "".join(v for vals in parse_qs(urlparse(url).query).values() for v in vals)
        if "'" in val or '"' in val:
            return (200, {"content-type": "text/html"},
                    "You have an error in your SQL syntax near MySQL server")
        return (200, {"content-type": "text/html"}, "normal")
    orig = scanner._get
    scanner._get = fake_get
    try:
        fs = scanner._check_web_vulns(
            {"final_url": "https://t/p?id=1", "body": '<a href="/p?id=1">x</a>'}, "t")
        sqli = [f for f in fs if f["category"] == "SQL Injection"]
        assert sqli and sqli[0]["owasp"].startswith("A03"), f"SQLi not detected: {fs}"
    finally:
        scanner._get = orig


@check("scanner: default-credential panel detection (detect-only)")
def _():
    def fake(base, path):
        if path == "/manager/html":
            b = "<html><title>Apache Tomcat</title> manager-gui</html>"
            return (200, "text/html", b, len(b))
        return (404, "text/html", "<html>nf</html>", 14)
    orig = scanner._fetch_path
    scanner._fetch_path = fake
    try:
        fs = scanner._check_default_creds("https://t", "t", baseline={"statuses": {404}, "hashes": set(), "html_catchall": False})
        tom = [f for f in fs if "Tomcat" in f["title"]]
        assert tom and tom[0]["category"] == "Default Credentials"
        assert tom[0]["owasp"].startswith("A07")
    finally:
        scanner._fetch_path = orig


# ── PatchSphere: dedup, top-5, blast radius, choke points ───────────────────────
def _patchsphere_fixture():
    """Findings where web01+app03 share a CVE, web01+db01 share a /24, and
    Log4Shell is reported by BOTH Tenable and Qualys (cross-scanner dup)."""
    findings = [
        {"source": "tenable", "asset": "web01", "ip": "10.0.0.12", "hostname": "web01",
         "cve_ids": ["CVE-2021-44228"], "severity": "CRITICAL", "cvss": 10.0,
         "attack_vector": "NETWORK", "plugin_name": "Log4Shell"},
        {"source": "qualys", "asset": "web01", "ip": "10.0.0.12", "hostname": "web01",
         "cve_ids": ["CVE-2021-44228"], "severity": "CRITICAL", "cvss": 9.8,
         "attack_vector": "NETWORK", "plugin_name": "QID 12345"},
        {"source": "tenable", "asset": "app03", "ip": "10.0.0.13", "hostname": "app03",
         "cve_ids": ["CVE-2021-44228"], "severity": "HIGH", "cvss": 9.0,
         "attack_vector": "NETWORK", "plugin_name": "Log4Shell"},
        {"source": "tenable", "asset": "db01", "ip": "10.0.0.50", "hostname": "db01",
         "cve_ids": ["CVE-2026-50751"], "severity": "CRITICAL", "cvss": 9.4,
         "attack_vector": "LOCAL", "plugin_name": "DB flaw"},
    ]
    intel = {"advisories": {"top_exploited_cves": [
        {"cve_id": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j2",
         "known_ransomware": "Known", "due_date": "2021-12-24"}],
        "immediate_attention_cves": []},
        "enrichment": {"CVE-2021-44228": {"kev": True, "epss": 0.99, "cvss": 10.0}}}
    return findings, intel


@check("patchsphere: de-duplicates findings and reconciles cross-scanner CVEs")
def _():
    findings, intel = _patchsphere_fixture()
    out = patchsphere.analyze(findings, intel)
    d = out["dedup"]
    assert d["raw_findings"] == 4, d
    assert d["unique_cves"] == 2, d
    # Log4Shell reported by tenable AND qualys → exactly one reconciled CVE
    assert d["reconciled_cross_scanner"] == 1, d
    assert set(d["scanners"]) == {"tenable", "qualys"}, d


@check("patchsphere: top fixes are ≤5 and match risk.prioritize order")
def _():
    findings, intel = _patchsphere_fixture()
    out = patchsphere.analyze(findings, intel)
    fixes = out["top_fixes"]
    assert len(fixes) <= 5 and fixes, "expected 1-5 fixes"
    ranked = risk.prioritize(findings, intel)["items"][:5]
    assert [f["cve_id"] for f in fixes] == [i["cve_id"] for i in ranked], "order must mirror risk engine"
    # Log4Shell (KEV, network, 2 assets) outranks the local DB flaw
    assert fixes[0]["cve_id"] == "CVE-2021-44228", fixes[0]["cve_id"]
    assert "blast_radius" in fixes[0], "each fix must carry a blast_radius"


@check("patchsphere: blast radius — reachable ⊇ direct, subnet pulls in db01")
def _():
    findings, intel = _patchsphere_fixture()
    out = patchsphere.analyze(findings, intel)
    br = next(f for f in out["top_fixes"] if f["cve_id"] == "CVE-2021-44228")["blast_radius"]
    assert br["direct_count"] == 2, br          # web01 + app03 carry the CVE
    # db01 shares the 10.0.0.0/24 subnet → reachable via lateral movement
    assert br["reachable_count"] >= 1, br
    assert "db01" in br["reachable_sample"], br
    assert 0 < br["blast_pct"] <= 100, br


@check("patchsphere: choke points ranked by reach, exploitable flagged")
def _():
    findings, intel = _patchsphere_fixture()
    out = patchsphere.analyze(findings, intel)
    chokes = out["choke_points"]
    assert chokes, "expected at least one choke point"
    assert all(c["reach"] > 0 for c in chokes), "choke must reach >0 assets"
    top = chokes[0]
    assert top["exploitable"] is True, "exposed+exploitable asset should rank first"
    # graph payload is well-formed for the SVG
    g = out["graph"]
    assert g["entry_vectors"] and g["choke_points"] and g["edges"], g.keys()


@check("patchsphere: blast_radius() returns detail for present / None for absent CVE")
def _():
    findings, intel = _patchsphere_fixture()
    d = patchsphere.blast_radius(findings, intel, "CVE-2021-44228")
    assert d and d["direct_count"] == 2 and d["cve_id"] == "CVE-2021-44228", d
    assert patchsphere.blast_radius(findings, intel, "CVE-0000-0000") is None


@check("patchsphere: empty findings yield empty, non-crashing payload")
def _():
    out = patchsphere.analyze([], {"advisories": {"top_exploited_cves": [], "immediate_attention_cves": []}})
    assert out["top_fixes"] == [] and out["choke_points"] == []
    assert out["summary"]["total_assets"] == 0


# ── summary ────────────────────────────────────────────────────────────────────
def main():
    total = len(_results)
    failed = [r for r in _results if not r[1]]
    print()
    print(f"JATAYU self-test: {total - len(failed)}/{total} checks passed.")
    if failed:
        print("FAILURES:")
        for name, _ok, detail in failed:
            print(f"  - {name}: {detail}")
        return 1
    print("All functional checks passed. [OK]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
