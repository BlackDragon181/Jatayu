"""
VM / ASM / SBOM Expert assessment engine (see ASM/SKILL.md).

Transforms the raw attack-surface scan (scanner.scan_target) into a structured,
Big-4-style assessment: phase coverage, ASM-formatted findings (VULN-IDs with
confidence, standards mapping, compensating controls, patch guidance, validation),
threat-intel/KEV correlation, an executive summary, and a remediation roadmap.

Scope: exposure identification, vulnerability validation, risk analysis and
defensive remediation only — no exploitation procedures.
"""

import re

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# Severity → remediation timeline (patch-framework.md)
TIMELINE = {
    "CRITICAL": "Immediate (24h)", "HIGH": "7 days",
    "MEDIUM": "30 days", "LOW": "90 days", "INFO": "Backlog / risk-accept",
}

# Keyword → standards mapping + compensating control. First match wins, so order
# from most specific to most general.
PATTERNS = [
    (("sql inject",),                         dict(cwe="CWE-89 (SQL Injection)", owasp="A03:2021 – Injection", mitre="T1190 – Exploit Public-Facing App", control="WAF virtual patch + parameterized queries", vtype="Injection")),
    (("command inject", "rce", "remote code", "code execution", "deserial"), dict(cwe="CWE-94 (Code Injection)", owasp="A03:2021 – Injection", mitre="T1190 – Exploit Public-Facing App", control="WAF virtual patch, network isolation", vtype="RCE / Code Injection")),
    (("xss", "cross-site script"),            dict(cwe="CWE-79 (Cross-site Scripting)", owasp="A03:2021 – Injection", mitre="T1059 – Command & Scripting", control="Content-Security-Policy + output encoding", vtype="XSS")),
    (("ssrf", "server-side request"),         dict(cwe="CWE-918 (SSRF)", owasp="A10:2021 – SSRF", mitre="T1190 – Exploit Public-Facing App", control="Egress filtering, metadata endpoint blocklist", vtype="SSRF")),
    (("xxe", "xml external"),                 dict(cwe="CWE-611 (XXE)", owasp="A05:2021 – Security Misconfiguration", mitre="T1190 – Exploit Public-Facing App", control="Disable external entity parsing", vtype="XXE")),
    (("subdomain takeover", "dangling"),      dict(cwe="CWE-350 (Reliance on Untrusted Inputs)", owasp="A05:2021 – Security Misconfiguration", mitre="T1584 – Compromise Infrastructure", control="Remove dangling DNS record / reclaim resource", vtype="Subdomain Takeover")),
    (("default credential", "default password", "weak credential"), dict(cwe="CWE-798 (Hard-coded Credentials)", owasp="A07:2021 – Identification & Auth Failures", mitre="T1078 – Valid Accounts", control="Credential rotation, account lockout", vtype="Default Credentials")),
    (("auth bypass", "authentication bypass", "unauthenticated admin", "open admin", "exposed admin", "login panel", "admin interface", "management interface"), dict(cwe="CWE-287 (Improper Authentication)", owasp="A07:2021 – Identification & Auth Failures", mitre="T1190 – Exploit Public-Facing App", control="IP allow-listing / VPN gate + MFA", vtype="Exposed Admin Interface")),
    (("directory listing", "index of", "autoindex"), dict(cwe="CWE-548 (Information Exposure Through Directory Listing)", owasp="A05:2021 – Security Misconfiguration", mitre="T1083 – File & Directory Discovery", control="Disable directory autoindex", vtype="Information Disclosure")),
    (("cors",),                               dict(cwe="CWE-942 (Permissive CORS)", owasp="A05:2021 – Security Misconfiguration", mitre="T1190 – Exploit Public-Facing App", control="Restrict Access-Control-Allow-Origin", vtype="Misconfiguration")),
    (("tls", "ssl", "cipher", "certificate", "cert ", "https"), dict(cwe="CWE-327 (Broken/Risky Crypto)", owasp="A02:2021 – Cryptographic Failures", mitre="T1557 – Adversary-in-the-Middle", control="Enforce TLS 1.2+ at load balancer, replace weak ciphers", vtype="Weak TLS")),
    (("spf", "dmarc", "dkim", "mta-sts", "email", "spoof"), dict(cwe="CWE-290 (Authentication Bypass by Spoofing)", owasp="A07:2021 – Identification & Auth Failures", mitre="T1566 – Phishing", control="Publish SPF -all, DMARC p=reject, MTA-STS", vtype="Email Authentication")),
    (("security header", "hsts", "csp", "x-frame", "clickjack", "content-security", "missing header"), dict(cwe="CWE-693 (Protection Mechanism Failure)", owasp="A05:2021 – Security Misconfiguration", mitre="T1190 – Exploit Public-Facing App", control="Add security headers (HSTS, CSP, X-Frame-Options) at edge", vtype="Missing Security Headers")),
    (("eol", "end of life", "end-of-life", "unsupported", "outdated", "obsolete"), dict(cwe="CWE-1104 (Unmaintained Third-Party Components)", owasp="A06:2021 – Vulnerable & Outdated Components", mitre="T1190 – Exploit Public-Facing App", control="Upgrade to a vendor-supported release", vtype="EOL Software")),
    (("version", "banner", "disclosure", "fingerprint", "info leak", "information"), dict(cwe="CWE-200 (Information Exposure)", owasp="A01:2021 – Broken Access Control", mitre="T1592 – Gather Victim Host Info", control="Suppress version banners / verbose errors", vtype="Information Disclosure")),
    (("open port", "exposed service", "service exposed", "port ", "rdp", "smb", "redis", "elasticsearch", "mongodb", "database exposed"), dict(cwe="CWE-1327 (Binding to Unrestricted IP)", owasp="A05:2021 – Security Misconfiguration", mitre="T1046 – Network Service Discovery", control="Firewall ACL — restrict service to trusted networks", vtype="Exposed Service")),
    (("malicious", "abuse", "blocklist", "blacklist", "reputation", "threat intel", "noise", "pulse"), dict(cwe="—", owasp="—", mitre="T1583 – Acquire Infrastructure", control="Investigate, isolate, and monitor the asset", vtype="Reputation")),
    (("vulnerab", "cve", "exploit"),          dict(cwe="CWE-1395 (Dependency on Vulnerable Component)", owasp="A06:2021 – Vulnerable & Outdated Components", mitre="T1190 – Exploit Public-Facing App", control="Patch / virtual-patch (WAF, RASP) until upgraded", vtype="Vulnerable Component")),
]

_DEFAULT_MAP = dict(cwe="—", owasp="—", mitre="—", control="Apply vendor security guidance", vtype="General")

# Confidence is "directly observed" for these classes; CVE-by-version is "Likely".
_OBSERVED_TYPES = {"Weak TLS", "Email Authentication", "Missing Security Headers",
                   "Information Disclosure", "Exposed Service", "Exposed Admin Interface",
                   "Misconfiguration", "Subdomain Takeover"}


def _classify(finding):
    # Match on category + title only. Descriptions cross-reference other issues
    # (e.g. a CSP finding mentions "cross-site scripting") and cause misclassification.
    text = f"{finding.get('category','')} {finding.get('title','')}".lower()
    for keys, mapping in PATTERNS:
        if any(k in text for k in keys):
            return mapping
    return _DEFAULT_MAP


def _confidence(finding, mapping, in_kev, unverified=False):
    # Version-inferred / unvalidated findings (e.g. Shodan InternetDB CVEs) are
    # the main false-positive source — never rate them "Confirmed".
    if unverified:
        return "Likely" if in_kev else "Potential"
    if in_kev:
        return "Confirmed"
    vtype = mapping["vtype"]
    if vtype == "Reputation":
        return "Potential"
    if finding.get("evidence") or vtype in _OBSERVED_TYPES:
        return "Confirmed"
    if finding.get("cve") or _CVE_RE.search(finding.get("title", "") + finding.get("description", "")):
        return "Likely"
    return "Potential"


def _risk_description(finding, mapping):
    sev = finding.get("severity", "INFO")
    av = "network" if mapping["vtype"] in ("RCE / Code Injection", "Exposed Service", "Exposed Admin Interface",
                                           "Injection", "SSRF", "XXE", "Weak TLS", "Email Authentication",
                                           "Missing Security Headers", "Vulnerable Component") else "network/local"
    outcomes = {
        "RCE / Code Injection": "remote code execution and full host compromise",
        "Injection": "database compromise and data exfiltration",
        "SSRF": "internal network pivoting and cloud-metadata theft",
        "XXE": "file disclosure and internal request forgery",
        "Exposed Admin Interface": "administrative takeover if credentials are guessed or bypassed",
        "Exposed Service": "direct exploitation of the exposed service and lateral movement",
        "Weak TLS": "interception or downgrade of encrypted traffic (adversary-in-the-middle)",
        "Email Authentication": "domain spoofing and phishing of customers and staff",
        "Missing Security Headers": "clickjacking, MIME-sniffing, or transport downgrade",
        "Information Disclosure": "reconnaissance that accelerates a targeted attack",
        "Vulnerable Component": "exploitation of a known CVE in the affected component",
        "EOL Software": "exploitation of unpatched vulnerabilities with no vendor fix",
        "Subdomain Takeover": "hijacking of the subdomain to host malicious content",
        "Reputation": "association with known-malicious infrastructure",
    }.get(mapping["vtype"], "compromise of the affected asset")
    return (f"Attack vector: {av}. A successful attacker could achieve {outcomes}. "
            f"Given the {sev.lower()} severity, the realistic business consequence ranges from "
            f"reconnaissance value to data breach, service disruption, or regulatory exposure.")


def _root_cause(mapping):
    return {
        "Weak TLS": "Insecure default / legacy protocol or cipher left enabled.",
        "Email Authentication": "Missing or permissive DNS authentication records.",
        "Missing Security Headers": "Security headers not configured at the web edge.",
        "Exposed Service": "Service bound to a public interface without network restriction.",
        "Exposed Admin Interface": "Administrative endpoint reachable from the internet.",
        "Vulnerable Component": "Missing patch / outdated software version.",
        "EOL Software": "Software past vendor end-of-life with no security updates.",
        "Information Disclosure": "Verbose banners / default error pages enabled.",
        "Subdomain Takeover": "Dangling DNS record pointing to an unclaimed resource.",
        "Default Credentials": "Insecure default credentials never rotated.",
    }.get(mapping["vtype"], "Misconfiguration or unpatched component (requires hands-on validation).")


def _validation(mapping):
    base = {
        "Weak TLS": ["Re-run an SSL/TLS scan (e.g. testssl.sh / SSL Labs) targeting the endpoint",
                     "Confirm only TLS 1.2+ and strong ciphers are negotiated"],
        "Email Authentication": ["Re-query SPF, DMARC and MTA-STS DNS records",
                                 "Confirm DMARC policy is p=reject and SPF ends in -all"],
        "Missing Security Headers": ["Re-fetch the response headers",
                                     "Confirm HSTS, CSP and X-Frame-Options are present"],
        "Exposed Service": ["Re-scan the port externally",
                            "Confirm the service is no longer reachable from untrusted networks"],
        "Vulnerable Component": ["Re-scan with the VM tool targeting the specific plugin/CVE",
                                 "Confirm the installed version matches the fixed version"],
    }.get(mapping["vtype"], ["Re-scan the asset with the same check",
                             "Confirm the response/behaviour has changed to a non-vulnerable state"])
    return base + ["Sign-off: finding closed when the re-scan no longer detects the issue"]


def _patch_block(finding):
    cve = finding.get("cve")
    ver = finding.get("version") or finding.get("installed_version")
    fixed = finding.get("fixed_version")
    nd = "Not determined — requires hands-on validation"
    return {
        "installed_version": ver or nd,
        "fixed_version": fixed or (nd if not cve else "Latest vendor-patched release"),
        "recommended_version": "Latest stable supported release",
        "upgrade_path": nd,
        "breaking_changes": "Review vendor changelog / migration guide",
        "compatibility": nd,
    }


def build_assessment(scan: dict, intel: dict | None = None) -> dict:
    intel = intel or {}
    adv = intel.get("advisories", {}) or {}
    kev = {}
    for c in adv.get("top_exploited_cves", []) or []:
        cid = (c.get("cve_id") or "").upper()
        if cid:
            kev[cid] = (c.get("known_ransomware") or "").lower() == "known"

    qtype = scan.get("type", "unknown")
    raw_findings = scan.get("findings", []) or []
    hosts = scan.get("hosts", []) or []

    # ── Group raw findings by type (one VULN per finding, assets aggregated) ─────
    groups = {}
    for f in raw_findings:
        key = (f.get("title", "") or "Untitled finding").strip().lower()
        g = groups.get(key)
        if g is None:
            g = {"rep": f, "sev": f.get("severity", "INFO"), "assets": set(),
                 "cves": set(), "unverified": True}
            groups[key] = g
        if f.get("asset"):
            g["assets"].add(f["asset"])
        if f.get("cve"):
            g["cves"].add(f["cve"].upper())
        # representative = highest-severity instance in the group
        if SEV_ORDER.get(f.get("severity", "INFO"), 0) > SEV_ORDER.get(g["sev"], 0):
            g["sev"], g["rep"] = f.get("severity", "INFO"), f
        if not f.get("unverified"):
            g["unverified"] = False

    ordered = sorted(groups.values(), key=lambda g: SEV_ORDER.get(g["sev"], 0), reverse=True)

    # ── ASM findings ───────────────────────────────────────────────────────────
    findings, kev_count, ransomware_count = [], 0, 0
    for i, g in enumerate(ordered, 1):
        f = g["rep"]
        cves = sorted(g["cves"])
        in_kev = any(c in kev for c in cves)
        is_ransom = any(kev.get(c) for c in cves)
        if in_kev:
            kev_count += 1
        if is_ransom:
            ransomware_count += 1
        mapping = _classify(f)
        sev = (g["sev"] or "INFO").upper()
        unverified = g["unverified"]
        timeline = "Immediate (24h)" if (in_kev or is_ransom) else TIMELINE.get(sev, "Backlog / risk-accept")
        assets = sorted(g["assets"]) or [scan.get("query", "")]
        findings.append({
            "id": f"VULN-{i:03d}",
            "title": f.get("title", "Untitled finding"),
            "severity": sev,
            "confidence": _confidence(f, mapping, in_kev, unverified),
            "category": f.get("category", ""),
            "standards": {
                "cve": (", ".join(cves[:4]) + ("…" if len(cves) > 4 else "")) if cves else "—",
                "cwe": mapping["cwe"],
                "owasp": mapping["owasp"],
                "mitre": mapping["mitre"],
                "kev": "Yes" if in_kev else "No",
                "ransomware": is_ransom,
            },
            "affected_assets": assets,
            "affected_count": len(assets),
            "unverified": unverified,
            "evidence": f.get("evidence") or "Observed during external assessment.",
            "risk_description": _risk_description(f, mapping),
            "root_cause": _root_cause(mapping),
            "immediate_mitigation": mapping["control"],
            "permanent_fix": f.get("remediation") or "Apply vendor security guidance and re-test.",
            "patch": _patch_block(f),
            "validation": _validation(mapping),
            "remediation_timeline": timeline,
        })

    # ── Counts / severity distribution ──────────────────────────────────────────
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    total = len(findings)
    sev_dist = [{"severity": s, "count": counts[s],
                 "pct": round(100 * counts[s] / total) if total else 0}
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]

    # ── Attack-surface metrics ──────────────────────────────────────────────────
    live_hosts = [h for h in hosts if h.get("alive")]
    techs = set()
    for h in hosts:
        for t in (h.get("tech") or []):
            techs.add(t)
    open_ports = 0
    for ps in (scan.get("ports_services") or {}).values():
        open_ports += len(ps.get("ports", []) or [])
    eol_count = sum(1 for f in findings if "EOL" in f["standards"]["cwe"] or "eol" in (f["category"] + f["title"]).lower())
    tls_weak = sum(1 for f in findings if "Cryptographic" in f["standards"]["owasp"])
    attack_surface = {
        "assets_discovered": len(set(scan.get("subdomains", []) or [])) + max(len(hosts), 1),
        "internet_exposed_services": open_ports or len(live_hosts),
        "live_hosts": len(live_hosts),
        "technologies": len(techs),
        "eol_technologies": eol_count,
        "weak_tls_endpoints": tls_weak,
        "expired_certs": sum(1 for c in (scan.get("certificates") or []) if c.get("expired")),
    }

    # ── Roadmap by timeline ─────────────────────────────────────────────────────
    roadmap = {"24h": [], "7d": [], "30d": [], "90d": []}
    bucket = {"Immediate (24h)": "24h", "7 days": "7d", "30 days": "30d", "90 days": "90d"}
    for f in findings:
        b = bucket.get(f["remediation_timeline"])
        if b:
            roadmap[b].append({"id": f["id"], "title": f["title"],
                               "asset": f["affected_assets"][0] if f["affected_assets"] else "",
                               "action": f["immediate_mitigation"]})

    # ── Executive summary ───────────────────────────────────────────────────────
    top = findings[: 5]
    if counts["CRITICAL"] or kev_count:
        risk_stmt = (f"The target exposes {counts['CRITICAL']} critical and {counts['HIGH']} high-severity "
                     f"weaknesses" + (f", including {kev_count} actively-exploited (CISA KEV) issue(s)" if kev_count else "")
                     + ". In the realistic worst case an attacker could chain these for unauthorized access, "
                     "data exposure, or service disruption. Immediate remediation of the items below is advised.")
    elif counts["HIGH"]:
        risk_stmt = (f"The target exposes {counts['HIGH']} high-severity weaknesses with no confirmed active "
                     "exploitation. These materially raise breach likelihood and should be remediated within 7 days.")
    elif total:
        risk_stmt = ("No critical or high-severity issues were confirmed. The remaining medium/low findings "
                     "represent hardening opportunities that reduce the attack surface.")
    else:
        risk_stmt = "No material weaknesses were identified in this external assessment pass."

    immediate_actions = []
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH") or f["standards"]["kev"] == "Yes":
            who = "Security/Infra team"
            immediate_actions.append(f"[{f['remediation_timeline']}] {f['title']} — {f['immediate_mitigation']} (owner: {who})")
        if len(immediate_actions) >= 4:
            break

    summary = {
        "counts": {"total": total, **{k.lower(): counts[k] for k in counts},
                   "kev": kev_count, "actively_exploited": kev_count, "ransomware": ransomware_count},
        "severity_distribution": sev_dist,
        "key_risk_statement": risk_stmt,
        "immediate_actions": immediate_actions or ["No immediate actions required — maintain monitoring."],
        "attack_surface": attack_surface,
        "top_risks": [{"id": f["id"], "title": f["title"], "severity": f["severity"],
                       "kev": f["standards"]["kev"]} for f in top],
    }

    # ── Phase coverage (assessment-phases.md) ───────────────────────────────────
    has_web = bool(live_hosts) or qtype == "domain"
    phases = [
        (1, "Attack Surface Discovery", qtype in ("domain", "ip")),
        (2, "Technology Fingerprinting", bool(techs) or has_web),
        (3, "Service Enumeration", open_ports > 0 or qtype == "ip"),
        (4, "Vulnerability Analysis", total > 0),
        (5, "Security Configuration Review", any(f["standards"]["owasp"].startswith("A05") for f in findings) or bool(scan.get("email_security"))),
        (6, "Software Composition Analysis", False),
        (7, "SBOM Analysis", False),
        (8, "Container & Kubernetes Security", False),
        (9, "Supply Chain Risk Assessment", False),
        (10, "Threat Intelligence Correlation", True),
    ]
    phase_cov = [{"id": pid, "name": name, "covered": cov} for pid, name, cov in phases]

    return {
        "scope": {
            "target": scan.get("query", ""),
            "type": qtype,
            "assessment_type": "External Attack Surface & Vulnerability Assessment",
            "authorization_note": "Authorized, non-intrusive external assessment. No exploitation performed.",
        },
        "phases": phase_cov,
        "summary": summary,
        "findings": findings,
        "roadmap": roadmap,
    }
