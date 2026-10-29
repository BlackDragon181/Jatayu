"""
Risk prioritization for JATAYU.

Correlates ingested vulnerability-scan findings (from connectors.py) with the
live threat-intelligence dataset (CISA KEV, ransomware association, NVD
critical CVEs / attack vector) to produce a ranked, actionable risk list.

The core idea: a vulnerability on your network matters far more when it is
*actively exploited in the wild*. This module surfaces exactly those.
"""

import logging
import re

logger = logging.getLogger(__name__)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

_SEV_BASE = {"CRITICAL": 36, "HIGH": 28, "MEDIUM": 16, "LOW": 6, "INFO": 0}

# MTTW: estimated days from CVE disclosure to active exploit in the wild.
# Informed by empirical data: KEV CVEs weaponize in hours; EPSS provides a
# probabilistic estimate; severity/CVSS give a coarse fallback.
_MTTW_BASE = {
    "CRITICAL": 12.0, "HIGH": 44.0, "MEDIUM": 90.0, "LOW": 210.0, "INFO": 365.0,
}

# MTTR: organizational SLA — how many days until the vuln should be patched.
_MTTR_SLA = {
    "CRITICAL": 15, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "INFO": 365,
}


def _mttw(severity, epss=None, in_kev=False, cvss=None):
    """Mean Time to Weaponize (days from disclosure to usable exploit).

    Priority: KEV (already exploited = 0) → EPSS-derived curve → severity/CVSS fallback.
    """
    if in_kev:
        return 0.0
    if epss is not None and float(epss) > 0:
        # EPSS=1.0 → 1 day, EPSS=0.1 → ~9 days, EPSS=0.01 → ~75 days
        return max(0.5, round(30.0 / (1.0 + float(epss) * 29.0), 1))
    base = _MTTW_BASE.get((severity or "INFO").upper(), 180.0)
    if cvss:
        # Higher CVSS → faster weaponization
        factor = max(0.4, 1.4 - float(cvss) * 0.08)
        base = round(base * factor, 1)
    return max(1.0, base)


def _mttr(severity, in_kev=False):
    """Mean Time to Remediate — organizational SLA target (days)."""
    if in_kev:
        return 3.0
    return float(_MTTR_SLA.get((severity or "INFO").upper(), 90))


def _awe(mttw_days, mttr_days):
    """Average Window Exposure = MTTR − MTTW.

    Positive → exploit available before the org patches (exposure gap, act now).
    Negative → org patches before weaponization (ahead of attackers).
    """
    return round(mttr_days - mttw_days, 1)


def _build_intel_index(intel: dict) -> dict:
    """Index live intel by CVE id for O(1) correlation."""
    intel = intel or {}
    adv = intel.get("advisories", {}) or {}
    kev = {}
    for c in adv.get("top_exploited_cves", []) or []:
        cid = (c.get("cve_id") or "").upper()
        if cid:
            kev[cid] = {
                "vendor": c.get("vendor", ""),
                "product": c.get("product", ""),
                "ransomware": (c.get("known_ransomware") or "").lower() == "known",
                "due_date": c.get("due_date", ""),
                "required_action": c.get("required_action", ""),
                "name": c.get("vulnerability_name") or c.get("description", ""),
            }
    crit = {}
    refs = {}
    for c in adv.get("immediate_attention_cves", []) or []:
        cid = (c.get("cve_id") or "").upper()
        if cid:
            crit[cid] = {
                "cvss": c.get("cvss_score"),
                "attack_vector": c.get("attack_vector", ""),
                "severity": c.get("severity", ""),
            }
            if c.get("references"):
                refs[cid] = [r for r in c["references"] if r][:5]
    # EPSS / CVSS (incl. v4) enrichment from Shodan CVEDB (see enrich.py / fetcher).
    enrich = {}
    for cid, e in (intel.get("enrichment") or {}).items():
        if cid:
            enrich[cid.upper()] = e
    return {"kev": kev, "crit": crit, "enrich": enrich, "refs": refs}


def _score(cvss, severity, in_kev, ransomware, network, asset_count, epss=None, awe_days=None):
    """Composite 0-100 priority score.

    Components: CVSS-derived base (≤35), CISA-KEV exploited (+28), ransomware
    association (+13), network attack vector (+7), asset exposure (≤10),
    EPSS exploit-probability (≤15), and AWE exposure window boost (≤8).
    AWE boost elevates CVEs where the exploit window opens before the org patches.
    """
    if cvss:
        base = min(35.0, float(cvss) * 3.5)
    else:
        base = _SEV_BASE.get(severity, 0) * 0.9
    kev_boost = 28 if in_kev else 0
    ransom_boost = 13 if ransomware else 0
    net_boost = 7 if network else 0
    exposure = min(10.0, min(asset_count, 8) * 1.25)
    epss_boost = round(15.0 * float(epss), 1) if epss else 0.0
    # AWE boost: up to +8 pts when exploit is available before patch window closes.
    # +1 pt per 15 days of exposure gap (e.g. AWE=30 → +2, AWE=120 → +8 cap).
    awe_boost = 0.0
    if awe_days is not None and awe_days > 0:
        awe_boost = min(8.0, round(awe_days / 15.0, 1))
    return round(min(100.0, base + kev_boost + ransom_boost + net_boost + exposure + epss_boost + awe_boost), 1)


def _label(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _action(in_kev, ransomware, cvss, severity, network):
    if in_kev:
        return "Patch immediately — actively exploited (CISA KEV)"
    if ransomware:
        return "Prioritize — linked to ransomware campaigns"
    if (cvss and float(cvss) >= 9.0) or severity == "CRITICAL":
        return "Remediate urgently — critical severity"
    if network and cvss and float(cvss) >= 7.0:
        return "Schedule remediation — network-exploitable"
    return "Review and remediate per SLA"


# Patch SLA by priority when CISA doesn't mandate a due date (calendar days).
_SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}


def build_remediation(ctx: dict) -> dict:
    """Assemble structured, deterministic remediation guidance for one CVE from
    authoritative sources only (CISA KEV required action, CVEDB propose_action,
    NVD/vendor advisory links). No invented patch versions — links let analysts
    verify the exact fixed release.

    ctx keys: cve_id, vendor, product, plugin_name, priority, in_kev, ransomware,
    network, cvss, due_date, required_action, propose_action, references[].
    """
    cve = ctx.get("cve_id", "")
    vendor = (ctx.get("vendor") or "").strip()
    product = (ctx.get("product") or "").strip()
    vp = " ".join(p for p in (vendor, product) if p).strip()
    priority = ctx.get("priority", "LOW")
    due_date = ctx.get("due_date") or ""
    sla = (f"CISA-mandated remediation by {due_date}" if due_date
           else f"Remediate within {_SLA_DAYS.get(priority, 90)} days ({priority} priority SLA)")

    # Ordered, deterministic steps.
    steps = []
    if ctx.get("in_kev"):
        steps.append(f"PRIORITIZE — {cve} is on the CISA Known Exploited Vulnerabilities "
                     "catalog (actively exploited in the wild). Treat as emergency change.")
    if ctx.get("ransomware"):
        steps.append("Linked to known ransomware campaigns — escalate and verify backups / "
                     "segmentation while patching.")
    if vp:
        steps.append(f"Identify all instances of {vp} on affected assets and apply the "
                     f"vendor's fixed release for {cve} (see advisory links).")
    else:
        steps.append(f"Identify the affected component for {cve} and apply the vendor's "
                     "patched version (see advisory links).")
    if ctx.get("required_action"):
        steps.append(f"CISA required action: {ctx['required_action']}")
    if ctx.get("propose_action"):
        steps.append(ctx["propose_action"])
    if ctx.get("network"):
        steps.append("Network-exploitable — if immediate patching isn't possible, restrict "
                     "exposure via firewall/WAF rules or network segmentation as a temporary "
                     "compensating control.")
    steps.append("Verify remediation with a re-scan and confirm the finding is cleared on all "
                 "affected assets.")

    # Advisory links (KEV/NVD references + CVE databases analysts can verify against).
    advisories = []
    for url in (ctx.get("references") or [])[:5]:
        advisories.append({"label": "Vendor / NVD advisory", "url": url})
    advisories.append({"label": "NVD entry", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"})
    advisories.append({"label": "CISA KEV catalog",
                       "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"})

    summary = (f"{cve}{' — ' + vp if vp else ''}: "
               f"{'actively exploited; patch immediately.' if ctx.get('in_kev') else 'apply the vendor patch and re-scan.'}")
    return {
        "cve_id": cve,
        "sla": sla,
        "due_date": due_date,
        "summary": summary,
        "steps": steps,
        "kev_action": ctx.get("required_action", ""),
        "propose_action": ctx.get("propose_action", ""),
        "advisories": advisories,
    }


def group_remediations(items: list, mode: str, value: str = None) -> dict:
    """Resolve a set of risk items into grouped remediation guidance for bulk export.

    mode:
      "vendor_product" — group items by "vendor|product" (value optional filter)
      "kev"            — only actively-exploited (CISA KEV) items
      "selection"      — items whose cve_id is in the comma-separated `value`
    Returns {"groups": [{"key", "label", "items":[remediation,...]}], "count": n}.
    """
    items = items or []
    if mode == "kev":
        subset = [it for it in items if it.get("in_kev")]
        return {"groups": [{"key": "kev", "label": "Actively Exploited (CISA KEV)",
                            "items": [it.get("remediation") for it in subset if it.get("remediation")]}],
                "count": len(subset)}
    if mode == "selection":
        wanted = {c.strip().upper() for c in (value or "").split(",") if c.strip()}
        subset = [it for it in items if it.get("cve_id", "").upper() in wanted]
        return {"groups": [{"key": "selection", "label": "Selected CVEs",
                            "items": [it.get("remediation") for it in subset if it.get("remediation")]}],
                "count": len(subset)}
    # vendor_product (default)
    buckets = {}
    for it in items:
        vp = " ".join(p for p in (it.get("vendor", ""), it.get("product", "")) if p).strip() or "Unattributed"
        if value and value.lower() not in vp.lower():
            continue
        buckets.setdefault(vp, []).append(it)
    groups = [{"key": vp, "label": vp,
               "items": [it.get("remediation") for it in grp if it.get("remediation")]}
              for vp, grp in sorted(buckets.items(), key=lambda kv: -len(kv[1]))]
    return {"groups": groups, "count": sum(len(g["items"]) for g in groups)}


def prioritize(findings: list, intel: dict, top_n: int = 500) -> dict:
    """Group findings by CVE, correlate with intel, and rank by priority score.

    Returns {"items": [...], "summary": {...}}.
    """
    findings = findings or []
    idx = _build_intel_index(intel)
    kev, crit, enrich, refs = idx["kev"], idx["crit"], idx["enrich"], idx["refs"]

    # Group findings by CVE id; track affected assets and best CVSS/severity.
    groups = {}
    assets_all = set()
    skipped_no_cve = 0
    for f in findings:
        asset = (f.get("ip") or f.get("asset") or "unknown")
        assets_all.add(asset.lower())
        cves = f.get("cve_ids") or []
        if not cves:
            skipped_no_cve += 1
            continue
        for cve in cves:
            cve = cve.upper()
            g = groups.setdefault(cve, {
                "cve_id": cve, "assets": set(), "cvss": None,
                "severity": "INFO", "plugin_name": "", "sources": set(),
                "attack_vector": "",
            })
            g["assets"].add(asset)
            g["sources"].add(f.get("source", ""))
            if not g["plugin_name"] and f.get("plugin_name"):
                g["plugin_name"] = f["plugin_name"]
            # Attack vector straight from the scanner (Tenable/Nessus/CSV), if present.
            if not g["attack_vector"] and f.get("attack_vector"):
                g["attack_vector"] = f["attack_vector"]
            fc = f.get("cvss")
            if fc and (g["cvss"] is None or fc > g["cvss"]):
                g["cvss"] = fc
            if _SEV_BASE.get(f.get("severity"), 0) > _SEV_BASE.get(g["severity"], 0):
                g["severity"] = f.get("severity", "INFO")

    items = []
    exploited_count = ransomware_count = critical_count = 0
    for cve, g in groups.items():
        k = kev.get(cve)
        c = crit.get(cve)
        e = enrich.get(cve) or {}
        in_kev = k is not None or bool(e.get("kev"))
        ransomware = bool((k and k["ransomware"]) or e.get("ransomware"))
        # Attack-vector precedence: NVD-critical (authoritative) → scanner finding
        # → CVEDB/CIRCL enrichment (universal fallback).
        attack_vector = ((c or {}).get("attack_vector", "")
                         or g.get("attack_vector", "")
                         or e.get("attack_vector", ""))
        network = attack_vector.upper() == "NETWORK"
        # CVSS precedence: scan finding → CVEDB v4 → CVEDB v3 → NVD-critical intel.
        cvss = g["cvss"] or e.get("cvss_v4") or e.get("cvss_v3") or e.get("cvss") or (c or {}).get("cvss")
        cvss_version = ("4.0" if (not g["cvss"] and e.get("cvss_v4")) else
                        e.get("cvss_version") or ("3.x" if cvss else "—"))
        epss = e.get("epss")
        severity = g["severity"]
        asset_count = len(g["assets"])
        mttw = _mttw(severity, epss, in_kev, cvss)
        mttr = _mttr(severity, in_kev)
        awe = _awe(mttw, mttr)
        score = _score(cvss, severity, in_kev, ransomware, network, asset_count, epss, awe)
        label = _label(score)
        if in_kev:
            exploited_count += 1
        if ransomware:
            ransomware_count += 1
        if label == "CRITICAL":
            critical_count += 1
        items.append({
            "cve_id": cve,
            "affected_assets": asset_count,
            "assets": sorted(g["assets"])[:25],
            "cvss": cvss,
            "cvss_version": cvss_version,
            "epss": epss,
            "epss_percentile": e.get("percentile"),
            "euvd": e.get("euvd", ""),
            "severity": severity,
            "in_kev": in_kev,
            "ransomware": ransomware,
            "attack_vector": attack_vector,
            "exploited": in_kev,
            "priority_score": score,
            "priority": label,
            "mttw_days": mttw,
            "mttr_days": mttr,
            "awe_days": awe,
            "action": _action(in_kev, ransomware, cvss, severity, network),
            "plugin_name": g["plugin_name"],
            "vendor": (k or {}).get("vendor", ""),
            "product": (k or {}).get("product", ""),
            "sources": sorted(s for s in g["sources"] if s),
        })
        items[-1]["remediation"] = build_remediation({
            "cve_id": cve,
            "vendor": items[-1]["vendor"],
            "product": items[-1]["product"],
            "plugin_name": g["plugin_name"],
            "priority": label,
            "in_kev": in_kev,
            "ransomware": ransomware,
            "network": network,
            "cvss": cvss,
            "due_date": (k or {}).get("due_date", ""),
            "required_action": (k or {}).get("required_action", ""),
            "propose_action": e.get("propose_action", ""),
            "references": refs.get(cve) or e.get("references") or [],
        })

    if skipped_no_cve:
        logger.warning("risk.prioritize: skipped %d findings with no CVE IDs", skipped_no_cve)

    items.sort(key=lambda x: (x["priority_score"], x["affected_assets"]), reverse=True)
    total_unique_cves = len(groups)
    items = items[:top_n]

    # EPSS ≥ 0.5 → upstream community considers exploitation likely in 30 days.
    high_epss = sum(1 for it in items if (it.get("epss") or 0) >= 0.5)
    awe_list = [it["awe_days"] for it in items]
    positive_awe_count = sum(1 for a in awe_list if a > 0)
    avg_awe = round(sum(awe_list) / len(awe_list), 1) if awe_list else 0.0
    max_awe = round(max(awe_list), 1) if awe_list else 0.0
    summary = {
        "total_findings": len(findings),
        "total_assets": len(assets_all),
        "unique_cves": total_unique_cves,
        "displayed_cves": len(items),
        "exploited_cves": exploited_count,
        "ransomware_cves": ransomware_count,
        "critical_priorities": critical_count,
        "high_epss": high_epss,
        "positive_awe_count": positive_awe_count,
        "avg_awe_days": avg_awe,
        "max_awe_days": max_awe,
    }
    return {"items": items, "summary": summary}
