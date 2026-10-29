"""
PatchSphere — patch-decision surface for JATAYU.

Turns the flat vulnerability-finding store (Tenable/Qualys/Nessus/CSV, via
connectors.py) into an organization-level remediation view:

  1. De-duplicates findings across scanners into unique, actionable "fixes"
     (the same CVE reported by Tenable *and* Qualys on overlapping assets is
     reconciled into one).
  2. Recommends the top-5 fixes to remediate immediately, ranked by the existing
     risk-prioritization engine (risk.prioritize — no scoring is duplicated here).
  3. Assesses the "blast radius" of patching a vulnerability and identifies
     "choke points": assets whose compromise lets an attacker reach the most.

IMPORTANT — the attack graph is *inferred* from scan data, not a CMDB:
two assets are treated as reachable from one another if they **share an
exploitable CVE** (same exploit ⇒ lateral movement) or sit in the **same /24
subnet** (flat-network assumption). Reach is a depth-limited BFS over that graph.
The UI labels this clearly; it is a heuristic decision aid, not ground truth.
"""

import risk

# ── Bounds (the store can hold tens of thousands of findings) ────────────────
GRAPH_ASSET_CAP = 200      # assets (by worst score) included in the choke graph
GROUP_FANOUT_CAP = 40      # max neighbours contributed by one CVE/subnet group
BFS_DEPTH = 3              # lateral-movement hops modelled
REACH_VISIT_CAP = 400      # safety cap on a single reach computation
TOP_CHOKE = 6              # choke points drawn in the flow diagram
TOP_ENTRY = 6              # entry vectors drawn in the flow diagram
EXPLOITABLE_MIN_SCORE = 50.0  # priority score at/above which a CVE is "exploitable now"


def _asset_key(f: dict) -> str:
    return ((f.get("ip") or f.get("asset") or f.get("hostname") or "unknown")).strip().lower()


def _subnet(ip: str) -> str:
    """/24 prefix of a dotted-quad IPv4, else ''."""
    ip = (ip or "").strip()
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3]) + ".0/24"
    return ""


def _rollup(findings: list) -> dict:
    """Per-asset aggregate built from the raw (uncapped) findings."""
    assets = {}
    for f in findings or []:
        key = _asset_key(f)
        a = assets.get(key)
        if a is None:
            a = assets[key] = {
                "asset": f.get("hostname") or f.get("asset") or f.get("ip") or key,
                "ip": f.get("ip", ""),
                "hostname": f.get("hostname", ""),
                "subnet": _subnet(f.get("ip", "")),
                "cves": set(),
                "severity": "INFO",
                "exposed": False,
                "scanners": set(),
            }
        for c in (f.get("cve_ids") or []):
            a["cves"].add(c.upper())
        if not a["subnet"]:
            a["subnet"] = _subnet(f.get("ip", ""))
        if (f.get("attack_vector") or "").upper() == "NETWORK":
            a["exposed"] = True
        if f.get("source"):
            a["scanners"].add(f["source"])
        if risk._SEV_BASE.get(f.get("severity"), 0) > risk._SEV_BASE.get(a["severity"], 0):
            a["severity"] = f.get("severity", "INFO")
    return assets


class _Graph:
    """Inferred reachability graph over a chosen set of asset keys."""

    def __init__(self, rollup: dict, cve_meta: dict, asset_keys: list):
        self.rollup = rollup
        self.cve_meta = cve_meta
        keyset = set(asset_keys)
        self.cve_groups = {}      # cve -> [asset_key, ...] (within keyset)
        self.subnet_groups = {}   # subnet -> [asset_key, ...]
        self.asset_cves = {}      # asset_key -> [cve, ...]
        self.asset_subnet = {}    # asset_key -> subnet
        self.truncated = False
        for k in asset_keys:
            a = rollup[k]
            cves = sorted(a["cves"])
            self.asset_cves[k] = cves
            self.asset_subnet[k] = a["subnet"]
            for c in cves:
                self.cve_groups.setdefault(c, []).append(k)
            if a["subnet"]:
                self.subnet_groups.setdefault(a["subnet"], []).append(k)
        # note truncation for honest UI messaging
        for g in list(self.cve_groups.values()) + list(self.subnet_groups.values()):
            if len(g) > GROUP_FANOUT_CAP:
                self.truncated = True
                break

    def neighbors(self, a: str) -> set:
        res = set()
        for c in self.asset_cves.get(a, []):
            res.update(self.cve_groups.get(c, [])[:GROUP_FANOUT_CAP])
        sn = self.asset_subnet.get(a)
        if sn:
            res.update(self.subnet_groups.get(sn, [])[:GROUP_FANOUT_CAP])
        res.discard(a)
        return res

    def reach_set(self, starts) -> set:
        """Assets reachable within BFS_DEPTH hops (includes the start set)."""
        visited = set(starts)
        frontier = set(starts)
        depth = 0
        while frontier and depth < BFS_DEPTH and len(visited) < REACH_VISIT_CAP:
            nxt = set()
            for a in frontier:
                for b in self.neighbors(a):
                    if b not in visited:
                        nxt.add(b)
            visited |= nxt
            frontier = nxt
            depth += 1
        return visited

    def reach(self, a: str) -> int:
        return len(self.reach_set([a]) - {a})


def _exploitable_cve(cve: str, cve_meta: dict) -> bool:
    m = cve_meta.get(cve.upper())
    if not m:
        return False
    return bool(m.get("in_kev")) or (m.get("priority_score") or 0) >= EXPLOITABLE_MIN_SCORE


def _asset_exploitable(rollup: dict, key: str, cve_meta: dict) -> bool:
    a = rollup.get(key)
    if not a or not a["exposed"]:
        return False
    return any(_exploitable_cve(c, cve_meta) for c in a["cves"])


def _dedup_story(findings: list) -> dict:
    cve_sources = {}
    for f in findings or []:
        srcs = cve_sources
        for c in (f.get("cve_ids") or []):
            srcs.setdefault(c.upper(), set()).add(f.get("source", ""))
    reconciled = sum(1 for s in cve_sources.values() if len({x for x in s if x}) > 1)
    scanners = sorted({(f.get("source") or "") for f in (findings or []) if f.get("source")})
    return {
        "raw_findings": len(findings or []),
        "unique_cves": len(cve_sources),
        "reconciled_cross_scanner": reconciled,
        "scanners": scanners,
    }


def _blast_for(cve: str, rollup: dict, graph: "_Graph", cve_meta: dict, total_assets: int) -> dict:
    cve = cve.upper()
    direct = sorted(k for k, a in rollup.items() if cve in a["cves"])
    reachable = graph.reach_set(direct)
    reachable_only = sorted(reachable - set(direct))
    choke_involved = sorted(
        rollup[k]["asset"] for k in direct
        if rollup[k]["exposed"] and graph.reach(k) > 0
    )
    score = (cve_meta.get(cve) or {}).get("priority_score", 0)
    return {
        "cve_id": cve,
        "direct": [rollup[k]["asset"] for k in direct],
        "direct_count": len(direct),
        "reachable_count": len(reachable_only),
        "reachable_sample": [rollup[k]["asset"] for k in reachable_only[:25]],
        "blast_pct": round(100.0 * len(reachable) / total_assets, 1) if total_assets else 0.0,
        "risk_removed": score,
        "choke_involved": choke_involved[:10],
    }


def _context(findings: list, intel: dict):
    """Shared setup: rollup, risk items, cve_meta, and the graph asset universe."""
    rollup = _rollup(findings)
    risk_result = risk.prioritize(findings, intel, top_n=10 ** 9)
    items = risk_result.get("items", [])
    cve_meta = {it["cve_id"].upper(): it for it in items}
    # Worst score per asset → choose the graph universe (top assets by exposure).
    def worst(key):
        return max((cve_meta.get(c, {}).get("priority_score", 0) for c in rollup[key]["cves"]), default=0)
    ranked_assets = sorted(rollup.keys(), key=lambda k: (worst(k), len(rollup[k]["cves"])), reverse=True)
    return rollup, items, cve_meta, ranked_assets, risk_result.get("summary", {})


def analyze(findings: list, intel: dict) -> dict:
    """Full PatchSphere payload (see module docstring)."""
    findings = findings or []
    rollup, items, cve_meta, ranked_assets, risk_summary = _context(findings, intel)
    total_assets = len(rollup)

    graph_assets = ranked_assets[:GRAPH_ASSET_CAP]
    graph = _Graph(rollup, cve_meta, graph_assets)

    # ── Choke points: assets ranked by reach, exploitable entries first ──────
    choke_rows = []
    for k in graph_assets:
        a = rollup[k]
        rch = graph.reach(k)
        if rch <= 0:
            continue
        exploitable = _asset_exploitable(rollup, k, cve_meta)
        top_cves = sorted(
            a["cves"], key=lambda c: cve_meta.get(c, {}).get("priority_score", 0), reverse=True
        )[:5]
        # Max AWE across this asset's CVEs — positive means exploit window open
        awe_values = [
            cve_meta.get(c, {}).get("awe_days")
            for c in a["cves"]
            if cve_meta.get(c, {}).get("awe_days") is not None
        ]
        max_awe = round(max(awe_values), 1) if awe_values else None
        choke_rows.append({
            "asset": a["asset"],
            "ip": a["ip"],
            "reach": rch,
            "exploitable": exploitable,
            "severity": a["severity"],
            "cve_count": len(a["cves"]),
            "top_cves": top_cves,
            "scanners": sorted(s for s in a["scanners"] if s),
            "max_awe": max_awe,
            "_key": k,
        })
    choke_rows.sort(
        key=lambda c: (c["exploitable"], c.get("max_awe") or -999, c["reach"], c["cve_count"]),
        reverse=True,
    )

    # ── Top-5 fixes augmented with blast radius ──────────────────────────────
    top_fixes = []
    for it in items[:5]:
        fix = dict(it)
        fix["blast_radius"] = _blast_for(it["cve_id"], rollup, graph, cve_meta, total_assets)
        top_fixes.append(fix)

    # ── Flow-diagram payload (entry vectors → choke points → downstream) ─────
    top_choke = choke_rows[:TOP_CHOKE]
    entry_vectors = []
    seen = set()
    for it in items:
        awe = it.get("awe_days")
        is_network = it.get("attack_vector", "").upper() == "NETWORK"
        qualifies = (
            it.get("in_kev")
            or it["priority_score"] >= EXPLOITABLE_MIN_SCORE
            or (awe is not None and awe > 0 and it["priority_score"] >= 20)
        )
        if is_network and qualifies:
            if it["cve_id"] not in seen:
                entry_vectors.append({
                    "cve_id": it["cve_id"], "priority": it["priority"],
                    "priority_score": it["priority_score"], "in_kev": it.get("in_kev", False),
                    "awe_days": awe,
                })
                seen.add(it["cve_id"])
        if len(entry_vectors) >= TOP_ENTRY:
            break

    edges = []
    downstream = {}
    for c in top_choke:
        k = c["_key"]
        # entry CVE → choke asset (when the choke carries that exploitable CVE)
        for ev in entry_vectors:
            if ev["cve_id"].upper() in rollup[k]["cves"]:
                edges.append({"from": ev["cve_id"], "to": c["asset"], "kind": "entry"})
        # choke → its downstream blast assets (sample)
        reach_assets = sorted(graph.reach_set([k]) - {k})
        sample = [rollup[x]["asset"] for x in reach_assets[:6]]
        downstream[c["asset"]] = sample
        for d in sample:
            edges.append({"from": c["asset"], "to": d, "kind": "blast"})

    # strip internal key before returning
    for c in choke_rows:
        c.pop("_key", None)

    # ── Posture summary ──────────────────────────────────────────────────────
    dedup = _dedup_story(findings)
    exposed_assets = sum(1 for a in rollup.values() if a["exposed"])
    entry_points = sum(1 for k in rollup if _asset_exploitable(rollup, k, cve_meta))
    exploitable_chokes = sum(1 for c in choke_rows if c["exploitable"])
    total_score = sum(it["priority_score"] for it in items) or 0.0
    top5_score = sum(it["priority_score"] for it in items[:5])
    risk_reduction = round(100.0 * top5_score / total_score, 1) if total_score else 0.0
    worst_reach = choke_rows[0]["reach"] if choke_rows else 0

    summary = {
        "total_assets": total_assets,
        "exposed_assets": exposed_assets,
        "entry_points": entry_points,
        "exploitable_choke_points": exploitable_chokes,
        "unique_fixes": dedup["unique_cves"],
        "raw_findings": dedup["raw_findings"],
        "reconciled_cross_scanner": dedup["reconciled_cross_scanner"],
        "risk_reduction_top5_pct": risk_reduction,
        "worst_reach": worst_reach,
        "critical_priorities": risk_summary.get("critical_priorities", 0),
        "graph_truncated": graph.truncated or len(ranked_assets) > GRAPH_ASSET_CAP,
        "graph_asset_cap": GRAPH_ASSET_CAP,
        "positive_awe_count": risk_summary.get("positive_awe_count", 0),
        "avg_awe_days": risk_summary.get("avg_awe_days", 0.0),
        "max_awe_days": risk_summary.get("max_awe_days", 0.0),
    }

    return {
        "summary": summary,
        "dedup": dedup,
        "top_fixes": top_fixes,
        "choke_points": choke_rows[:20],
        "graph": {
            "entry_vectors": entry_vectors,
            "choke_points": top_choke,
            "downstream": downstream,
            "edges": edges,
        },
    }


def blast_radius(findings: list, intel: dict, cve: str) -> dict:
    """Uncapped per-CVE blast-radius detail for the drawer. None if CVE absent."""
    findings = findings or []
    cve = (cve or "").upper()
    rollup, items, cve_meta, ranked_assets, _ = _context(findings, intel)
    if cve not in cve_meta and not any(cve in a["cves"] for a in rollup.values()):
        return None
    total_assets = len(rollup)
    # build the graph over all assets carrying any reachable relationship to the
    # CVE's direct assets (single on-demand call → use the full universe, capped fanout)
    graph = _Graph(rollup, cve_meta, list(rollup.keys()))
    detail = _blast_for(cve, rollup, graph, cve_meta, total_assets)
    meta = cve_meta.get(cve) or {}
    detail.update({
        "priority": meta.get("priority", ""),
        "priority_score": meta.get("priority_score", 0),
        "severity": meta.get("severity", ""),
        "in_kev": meta.get("in_kev", False),
        "ransomware": meta.get("ransomware", False),
        "attack_vector": meta.get("attack_vector", ""),
        "plugin_name": meta.get("plugin_name", ""),
    })
    return detail
