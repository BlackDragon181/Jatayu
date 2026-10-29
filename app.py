"""
Threat Intelligence Dashboard — Flask backend
Run: python app.py
Optional env: OTX_API_KEY=<your-key>  ABUSECH_AUTH_KEY=<your-key>
"""

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; rely on environment variables being set externally

import csv
import hashlib as _hashlib
import io
import json
import logging
import os
import re
import threading
import time as _time
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, jsonify, make_response, render_template, request

from fetcher import DataFetcher
from scanner import scan_target as _scan_target
import report
import connectors
import risk
import asm
import advisory
import patchsphere

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app     = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload cap
fetcher = DataFetcher()

# ── Simple in-memory rate limiter for the expensive scan endpoint ────────────
_scan_rate: dict = {}          # ip -> [timestamps]
_SCAN_RATE_WINDOW = 60         # seconds
_SCAN_RATE_MAX    = 5          # requests per window per IP
_scan_rate_lock   = threading.Lock()

def _scan_rate_ok(ip: str) -> bool:
    now = _time.time()
    with _scan_rate_lock:
        hits = [t for t in _scan_rate.get(ip, []) if now - t < _SCAN_RATE_WINDOW]
        if len(hits) >= _SCAN_RATE_MAX:
            return False
        hits.append(now)
        _scan_rate[ip] = hits
    return True


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    return resp

# Serverless platforms (Vercel/Lambda) run stateless functions with no
# persistent background process and tight execution-time limits.
IS_SERVERLESS = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
SNAPSHOT_FILE = Path(__file__).resolve().parent / "data_snapshot.json"


def _prime_from_snapshot() -> bool:
    """Load the bundled build-time data snapshot into the fetcher (serverless)."""
    try:
        if SNAPSHOT_FILE.exists():
            data = json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))
            fetcher.prime(data)
            logger.info("Primed data from data_snapshot.json")
            return True
    except Exception as e:
        logger.warning(f"Snapshot prime failed: {e}")
    return False


def _ensure_data():
    """Make sure data is available before serving (used on serverless)."""
    data = fetcher.get_current_data()
    if data:
        # On serverless the execution context is frozen after the HTTP response —
        # background threads are killed before they can run. Stale data can only
        # be refreshed by rebuilding data_snapshot.json and redeploying.
        last_updated = fetcher.last_updated
        if last_updated and (datetime.utcnow() - last_updated).total_seconds() > 86400:
            logger.warning(
                "Snapshot data is stale (>24 h). Rebuild data_snapshot.json "
                "and redeploy to refresh threat intel."
            )
        return
    if _prime_from_snapshot():
        return
    # Last resort — a live refresh (may be slow / exceed serverless limits).
    try:
        fetcher.refresh_all()
    except Exception as e:
        logger.warning(f"On-demand refresh failed: {e}")


def _safe_refresh():
    try:
        fetcher.refresh_all()
    except Exception as e:
        logger.warning(f"Background refresh failed: {e}")


if IS_SERVERLESS:
    # No scheduler on serverless — serve the bundled snapshot instead.
    _prime_from_snapshot()
else:
    # Prime instantly from the bundled snapshot so the very first request gets
    # a 200 (no "data loading" 503 polling) while the scheduler refreshes in
    # the background and replaces current_data.
    _prime_from_snapshot()
    # ── Scheduler: refresh every 30 minutes, run immediately on startup ──────────
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        fetcher.refresh_all,
        trigger="interval",
        minutes=30,
        id="data_refresh",
        next_run_time=datetime.now(),
    )
    scheduler.start()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    if IS_SERVERLESS:
        _ensure_data()
    lu = fetcher.last_updated
    from datetime import timedelta
    return jsonify({
        "last_updated":     lu.isoformat() + "Z" if lu else None,
        "next_refresh":     (lu + timedelta(minutes=30)).isoformat() + "Z" if lu else None,
        "data_loaded":      bool(fetcher.current_data),
        "available_dates":  fetcher.get_available_dates(),
    })


@app.route("/api/data")
def api_data():
    if IS_SERVERLESS:
        _ensure_data()
    data = fetcher.get_current_data()
    if not data:
        return jsonify({"error": "Data is loading — please wait a moment and refresh."}), 503
    resp = jsonify(data)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/api/force-refresh", methods=["POST"])
def api_force_refresh():
    """Kick off an immediate background refresh (non-serverless only)."""
    if IS_SERVERLESS:
        return jsonify({"error": "Manual refresh not available in serverless mode"}), 400
    threading.Thread(target=_safe_refresh, daemon=True).start()
    return jsonify({"status": "refresh_started"})


@app.route("/api/data/<date_str>")
def api_historical(date_str: str):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_str or ""):
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400
    data = fetcher.get_historical_data(date_str)
    if data is None:
        return jsonify({"error": f"No archived data for {date_str}"}), 404
    return jsonify(data)


# In-memory cache of recent scans so report exports don't re-run a full scan.
# Single-user local app: a small bounded dict keyed by normalized query is sufficient.
_SCAN_CACHE: dict = {}
_SCAN_CACHE_MAX = 16


def _cache_put(query: str, result: dict):
    key = query.strip().lower()
    _SCAN_CACHE[key] = {"result": result, "ts": datetime.utcnow()}
    # Evict oldest entries beyond the cap
    if len(_SCAN_CACHE) > _SCAN_CACHE_MAX:
        oldest = sorted(_SCAN_CACHE.items(), key=lambda kv: kv[1]["ts"])
        for k, _ in oldest[: len(_SCAN_CACHE) - _SCAN_CACHE_MAX]:
            _SCAN_CACHE.pop(k, None)


def _cache_get(query: str):
    entry = _SCAN_CACHE.get(query.strip().lower())
    return entry["result"] if entry else None


# ── Scan history (disk-persisted; survives restarts) ────────────────────────────

def _scan_hist_dir() -> Path:
    base = Path(os.environ.get("DATA_DIR") or Path(__file__).resolve().parent)
    d = base / "cache" / "scans"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        d = Path(__file__).resolve().parent / "cache" / "scans"
        d.mkdir(parents=True, exist_ok=True)
    return d


_SCAN_HIST_MAX = 25


def _scan_hist_id(query: str) -> str:
    return _hashlib.sha1(query.strip().lower().encode("utf-8", "replace")).hexdigest()[:12]


def _scan_hist_save(query: str, result: dict):
    """Persist a scan result keyed by domain so re-scanning the same target
    overwrites (refreshes) its entry. Prunes to the most recent _SCAN_HIST_MAX."""
    try:
        d = _scan_hist_dir()
        sid = _scan_hist_id(query)
        rs = result.get("risk_score", {}) or {}
        record = {
            "id": sid, "query": query, "type": result.get("type", ""),
            "timestamp": result.get("timestamp", "") or datetime.utcnow().isoformat() + "Z",
            "risk_level": rs.get("level", ""), "risk_score": rs.get("score", 0),
            "hosts": len(result.get("hosts", []) or []),
            "findings": len(result.get("findings", []) or []),
            "lookalikes": len(result.get("lookalike_domains", []) or []),
            "result": result,
        }
        (d / f"{sid}.json").write_text(json.dumps(record), encoding="utf-8")
        # Prune oldest beyond the cap.
        files = sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in files[_SCAN_HIST_MAX:]:
            try:
                p.unlink()
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"scan history save failed: {e}")


def _scan_hist_list() -> list:
    out = []
    try:
        for p in _scan_hist_dir().glob("*.json"):
            try:
                r = json.loads(p.read_text(encoding="utf-8"))
                out.append({k: r.get(k) for k in
                            ("id", "query", "type", "timestamp", "risk_level",
                             "risk_score", "hosts", "findings", "lookalikes")})
            except Exception:
                continue
    except Exception:
        pass
    out.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return out


def _scan_hist_get(sid: str):
    try:
        p = _scan_hist_dir() / f"{(sid or '').strip()}.json"
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8")).get("result")
    except Exception:
        pass
    return None


def _enrich_asm(result: dict) -> dict:
    """Attach the VM/ASM expert assessment (see asm.py / ASM/SKILL.md)."""
    try:
        result["asm"] = asm.build_assessment(result, fetcher.get_current_data())
    except Exception as e:
        logger.warning(f"ASM assessment failed: {e}")
    return result


@app.route("/api/scan")
def api_scan():
    ip = (request.headers.get("X-Forwarded-For", "") or request.remote_addr or "").split(",")[0].strip()
    if not _scan_rate_ok(ip):
        return jsonify({"error": "Too many requests — please wait before scanning again"}), 429
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Provide ?q=domain.com or ?q=1.2.3.4 or ?q=AS12345"}), 400
    try:
        result = _scan_target(q)
        _enrich_asm(result)
        _cache_put(q, result)
        _scan_hist_save(q, result)
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Scan error for '{q}'")
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/history")
def api_scan_history():
    return jsonify({"scans": _scan_hist_list()})


@app.route("/api/scan/history/<sid>")
def api_scan_history_get(sid: str):
    if not re.fullmatch(r"[0-9a-f]{12}", sid or ""):
        return jsonify({"error": "Invalid scan id"}), 400
    result = _scan_hist_get(sid)
    if result is None:
        return jsonify({"error": "Scan not found"}), 404
    # Re-prime the in-memory cache so report exports work for a reloaded scan.
    q = result.get("query")
    if q:
        _cache_put(q, result)
    return jsonify(result)


@app.route("/api/scan/history/<sid>", methods=["DELETE"])
def api_scan_history_delete(sid: str):
    if not re.fullmatch(r"[0-9a-f]{12}", sid or ""):
        return jsonify({"error": "Invalid scan id"}), 400
    try:
        p = _scan_hist_dir() / f"{sid}.json"
        if not p.exists():
            return jsonify({"error": "Scan not found"}), 404
        p.unlink()
        return jsonify({"ok": True})
    except Exception as e:
        logger.warning(f"scan history delete failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/history", methods=["DELETE"])
def api_scan_history_clear():
    """Delete all scan history entries."""
    try:
        d = _scan_hist_dir()
        count = 0
        for p in d.glob("*.json"):
            try:
                p.unlink()
                count += 1
            except Exception:
                pass
        return jsonify({"ok": True, "deleted": count})
    except Exception as e:
        logger.warning(f"scan history clear failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/export/<fmt>")
def api_scan_export(fmt: str):
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Provide ?q=<domain|ip|asn>"}), 400
    fmt = (fmt or "").lower()
    if fmt not in ("pdf", "xlsx"):
        return jsonify({"error": "Supported formats: pdf, xlsx"}), 400

    # Use in-memory cache, then disk history, then run a fresh scan.
    result = _cache_get(q)
    if result is None:
        result = _scan_hist_get(_scan_hist_id(q))
        if result:
            _cache_put(q, result)
    if result is None:
        try:
            result = _scan_target(q)
            _enrich_asm(result)
            _cache_put(q, result)
            _scan_hist_save(q, result)
        except Exception as e:
            logger.exception(f"Scan error during export for '{q}'")
            return jsonify({"error": str(e)}), 500

    try:
        if fmt == "pdf":
            data = report.build_pdf(result)
            ctype = "application/pdf"
        else:
            data = report.build_xlsx(result)
            ctype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        fname = report.report_filename(result, fmt)
        resp = make_response(data)
        resp.headers["Content-Type"] = ctype
        resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
        return resp
    except Exception as e:
        logger.exception(f"Report generation failed for '{q}' ({fmt})")
        return jsonify({"error": str(e)}), 500


@app.route("/api/research/report/<rid>")
def api_research_report(rid: str):
    """Generate a Big-4 style threat-intel PDF brief for one research item."""
    data = fetcher.get_current_data() or {}
    items = data.get("research", []) or []
    item = next((x for x in items if x.get("id") == rid), None)
    if not item:
        return jsonify({"error": "Research item not found"}), 404
    try:
        pdf = report.build_research_pdf(item)
        resp = make_response(pdf)
        resp.headers["Content-Type"] = "application/pdf"
        resp.headers["Content-Disposition"] = (
            f'attachment; filename="{report.research_report_filename(item)}"'
        )
        return resp
    except Exception as e:
        logger.exception(f"Research report failed for '{rid}'")
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/<fmt>")
def api_export(fmt: str):
    date_str = request.args.get("date")
    data     = fetcher.get_historical_data(date_str) if date_str else fetcher.get_current_data()
    if not data:
        return jsonify({"error": "No data available for export"}), 404

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # ── JSON ──────────────────────────────────────────────────────────────────
    if fmt == "json":
        resp = make_response(json.dumps(data, indent=2, ensure_ascii=False))
        resp.headers["Content-Type"]        = "application/json; charset=utf-8"
        resp.headers["Content-Disposition"] = f"attachment; filename=threat_intel_{ts}.json"
        return resp

    # ── CSV ───────────────────────────────────────────────────────────────────
    if fmt == "csv":
        buf = io.StringIO()
        w   = csv.writer(buf)
        adv = data.get("advisories", {})
        ti  = data.get("threat_intel", {})
        ioc = ti.get("iocs", {})
        dw  = ti.get("darkweb", {})

        def section(title, headers, rows):
            w.writerow([])
            w.writerow([f"=== {title} ==="])
            w.writerow(headers)
            for r in rows:
                w.writerow(r)

        section("Top Exploited CVEs (CISA KEV)",
            ["CVE ID", "Vendor", "Product", "Date Added", "Due Date", "Known Ransomware", "Description"],
            [[c.get("cve_id",""), c.get("vendor",""), c.get("product",""), c.get("date_added",""),
              c.get("due_date",""), c.get("known_ransomware",""), (c.get("description") or "")[:120]]
             for c in adv.get("top_exploited_cves", [])])

        section("CVEs Requiring Immediate Attention (NVD)",
            ["CVE ID", "CVSS Score", "Attack Vector", "Severity", "Published", "Description"],
            [[c.get("cve_id",""), c.get("cvss_score",""), c.get("attack_vector",""),
              c.get("severity",""), c.get("published",""), (c.get("description") or "")[:120]]
             for c in adv.get("immediate_attention_cves", [])])

        section("IOCs — Malicious IPs (Botnet C2)",
            ["IP Address", "Port", "Malware Family", "Country", "Status", "First Seen"],
            [[i.get("ip",""), i.get("port",""), i.get("malware",""),
              i.get("country",""), i.get("status",""), i.get("first_seen","")]
             for i in ioc.get("malicious_ips", [])])

        section("IOCs — Malicious URLs",
            ["URL", "Status", "Threat", "Tags", "Date Added", "Reporter"],
            [[u.get("url",""), u.get("url_status",""), u.get("threat",""),
              "|".join(u.get("tags") or []), u.get("date_added",""), u.get("reporter","")]
             for u in ioc.get("malicious_urls", [])])

        section("IOCs — Malware Hashes (MalwareBazaar)",
            ["SHA256", "MD5", "File Name", "File Type", "Signature", "First Seen"],
            [[h.get("sha256",""), h.get("md5",""), h.get("file_name",""),
              h.get("file_type",""), h.get("signature",""), h.get("first_seen","")]
             for h in ioc.get("malware_hashes", [])])

        section("Top Threat Actors (MITRE ATT&CK)",
            ["Name", "MITRE ID", "Aliases", "Country Attribution", "Sophistication", "Last Modified"],
            [[a.get("name",""), a.get("mitre_id",""), "|".join(a.get("aliases") or []),
              a.get("country",""), a.get("sophistication",""), a.get("modified","")]
             for a in ti.get("top_threat_actors", [])])

        section("Geopolitical Threat Intelligence",
            ["Country", "Threat Count", "Risk Level", "Primary Threat", "Malware Families"],
            [[g.get("country",""), g.get("threat_count",""), g.get("risk_level",""),
              g.get("primary_threat",""), "|".join(g.get("malware_families") or [])]
             for g in ti.get("geopolitical", [])])

        section("Dark Web — Data Breaches (HIBP)",
            ["Title", "Domain", "Breach Date", "Records Exposed", "Data Types", "Verified"],
            [[b["title"], b["domain"], b["breach_date"],
              f'{b["pwn_count"]:,}', "|".join(b.get("data_classes") or []), b["is_verified"]]
             for b in dw.get("breaches", [])])

        section("Dark Web — Forum & News Intelligence",
            ["Title", "Category", "Source", "Published", "Link"],
            [[d["title"], d["category"], d["source"], d["published"], d["link"]]
             for d in dw.get("forum_discussions", [])])

        resp = make_response(buf.getvalue())
        resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = f"attachment; filename=threat_intel_{ts}.csv"
        return resp

    # ── XLSX ──────────────────────────────────────────────────────────────────
    if fmt == "xlsx":
        try:
            xlsx = report.build_intel_xlsx(data)
        except Exception as e:
            logger.exception("Threat-intel XLSX export failed")
            return jsonify({"error": str(e)}), 500
        resp = make_response(xlsx)
        resp.headers["Content-Type"]        = _XLSX_CT
        resp.headers["Content-Disposition"] = f"attachment; filename=threat_intel_{ts}.xlsx"
        return resp

    return jsonify({"error": "Supported formats: json, csv, xlsx"}), 400


# ── Connectors: vulnerability-scanner ingestion ─────────────────────────────────

_VALID_VENDORS = ("tenable", "qualys")


@app.route("/api/connectors/import", methods=["POST"])
def api_connectors_import():
    """Ingest an uploaded scan export (.nessus / Qualys XML / CSV)."""
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file uploaded. Provide a .nessus, .xml, or .csv scan export."}), 400
    try:
        content = f.read()
        source, findings = connectors.parse_file(f.filename, content)
        if not findings:
            return jsonify({"error": "No vulnerability findings could be parsed from this file. "
                                     "Supported: Nessus (.nessus), Qualys (XML/CSV), or generic CSV."}), 422
        summary = connectors.store.add_findings(findings)
        summary.update({"source": source, "filename": f.filename, "parsed": len(findings)})
        return jsonify(summary)
    except Exception as e:
        logger.exception(f"Import failed for '{f.filename}'")
        return jsonify({"error": f"Failed to parse file: {e}"}), 500


@app.route("/api/connectors/config", methods=["GET", "POST"])
def api_connectors_config():
    if request.method == "GET":
        return jsonify({
            "connectors": connectors.store.public_config(),
            "stats": connectors.store.stats(),
        })
    body = request.get_json(silent=True) or {}
    vendor = (body.get("vendor") or "").lower()
    if vendor not in _VALID_VENDORS:
        return jsonify({"error": f"Unknown vendor. Supported: {', '.join(_VALID_VENDORS)}"}), 400
    cfg = {k: v for k, v in body.items() if k != "vendor"}
    connectors.store.set_vendor_config(vendor, cfg)
    return jsonify({"ok": True, "vendor": vendor, "connectors": connectors.store.public_config()})


@app.route("/api/connectors/<vendor>/test", methods=["POST"])
def api_connectors_test(vendor: str):
    vendor = (vendor or "").lower()
    if vendor not in _VALID_VENDORS:
        return jsonify({"error": f"Unknown vendor. Supported: {', '.join(_VALID_VENDORS)}"}), 400
    # Use posted creds only when the body is non-empty; fall back to stored config.
    body = request.get_json(silent=True) or {}
    cfg = body if body else connectors.store.get_vendor_config(vendor)
    try:
        client = connectors.make_client(vendor, cfg)
        info = client.test()
        return jsonify({"ok": True, "vendor": vendor, **info})
    except connectors.ConnectorError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        logger.exception(f"Connector test failed for {vendor}")
        return jsonify({"ok": False, "error": f"Connection failed: {e}"}), 502


@app.route("/api/connectors/<vendor>/sync", methods=["POST"])
def api_connectors_sync(vendor: str):
    vendor = (vendor or "").lower()
    if vendor not in _VALID_VENDORS:
        return jsonify({"error": f"Unknown vendor. Supported: {', '.join(_VALID_VENDORS)}"}), 400
    cfg = connectors.store.get_vendor_config(vendor)
    if not cfg:
        return jsonify({"error": f"No saved credentials for {vendor}. Save a connector config first."}), 400
    try:
        client = connectors.make_client(vendor, cfg)
        findings = client.sync()
        summary = connectors.store.add_findings(findings)
        summary.update({"vendor": vendor, "pulled": len(findings)})
        return jsonify(summary)
    except connectors.ConnectorError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        logger.exception(f"Connector sync failed for {vendor}")
        return jsonify({"ok": False, "error": f"Sync failed: {e}"}), 502


@app.route("/api/findings")
def api_findings():
    return jsonify({"findings": connectors.store.load_findings(), "stats": connectors.store.stats()})


@app.route("/api/findings/clear", methods=["POST"])
def api_findings_clear():
    connectors.store.clear()
    return jsonify({"ok": True, "stats": connectors.store.stats()})


_XLSX_CT = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _risk_result():
    """Run risk prioritization against the current findings + intel."""
    if IS_SERVERLESS:
        _ensure_data()
    findings = connectors.store.load_findings()
    intel = fetcher.get_current_data() or {}
    return risk.prioritize(findings, intel), findings


def _filter_risk_items(items, args):
    """Apply the same filters the risk table exposes (q, priority, flag, vendor, epss_min)."""
    q = (args.get("q") or "").strip().lower()
    priority = (args.get("priority") or "").strip().upper()
    flag = (args.get("flag") or "").strip().lower()
    vendor = (args.get("vendor") or "").strip().lower()
    try:
        epss_min = float(args.get("epss_min")) if args.get("epss_min") else None
    except ValueError:
        epss_min = None
    out = []
    for it in items:
        if q:
            blob = f"{it.get('cve_id','')} {it.get('plugin_name','')} {it.get('vendor','')} {it.get('product','')} {' '.join(it.get('assets',[]))}".lower()
            if q not in blob:
                continue
        if priority and it.get("priority", "").upper() != priority:
            continue
        if flag == "exploited" and not it.get("in_kev"):
            continue
        if flag == "ransomware" and not it.get("ransomware"):
            continue
        if vendor and vendor not in f"{it.get('vendor','')} {it.get('product','')}".lower():
            continue
        if epss_min is not None and (it.get("epss") or 0) < epss_min:
            continue
        out.append(it)
    return out


@app.route("/api/risk/prioritized")
def api_risk_prioritized():
    result, _ = _risk_result()
    return jsonify(result)


@app.route("/api/patchsphere/analyze")
def api_patchsphere_analyze():
    """De-duplicated top fixes + inferred blast-radius / choke-point analysis."""
    if IS_SERVERLESS:
        _ensure_data()
    findings = connectors.store.load_findings()
    intel = fetcher.get_current_data() or {}
    return jsonify(patchsphere.analyze(findings, intel))


@app.route("/api/patchsphere/blast-radius/<cve>")
def api_patchsphere_blast_radius(cve):
    """Uncapped blast-radius detail for one CVE (drawer)."""
    if IS_SERVERLESS:
        _ensure_data()
    findings = connectors.store.load_findings()
    intel = fetcher.get_current_data() or {}
    detail = patchsphere.blast_radius(findings, intel, cve)
    if detail is None:
        return jsonify({"error": f"{cve} not found in current findings"}), 404
    return jsonify(detail)


@app.route("/api/risk/export/xlsx")
def api_risk_export():
    result, _ = _risk_result()
    items = _filter_risk_items(result.get("items", []), request.args)
    filtered = {"items": items, "summary": {**result.get("summary", {}), "filtered_items": len(items)}}
    try:
        xlsx = report.build_risk_xlsx(filtered)
    except Exception as e:
        logger.exception("Risk XLSX export failed")
        return jsonify({"error": str(e)}), 500
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    resp = make_response(xlsx)
    resp.headers["Content-Type"] = _XLSX_CT
    resp.headers["Content-Disposition"] = f"attachment; filename=risk_prioritization_{ts}.xlsx"
    return resp


@app.route("/api/findings/export/xlsx")
def api_findings_export():
    findings = connectors.store.load_findings()
    try:
        xlsx = report.build_findings_xlsx(findings, connectors.store.stats())
    except Exception as e:
        logger.exception("Findings XLSX export failed")
        return jsonify({"error": str(e)}), 500
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    resp = make_response(xlsx)
    resp.headers["Content-Type"] = _XLSX_CT
    resp.headers["Content-Disposition"] = f"attachment; filename=vuln_findings_{ts}.xlsx"
    return resp


def _resolve_remediation(args):
    """Resolve the remediation set for ?cve= / ?group= / filter params."""
    result, _ = _risk_result()
    items = result.get("items", [])
    cve = (args.get("cve") or "").strip().upper()
    group = (args.get("group") or "").strip().lower()
    if cve:
        return risk.group_remediations(items, "selection", cve), f"remediation_{cve}"
    if group == "kev":
        return risk.group_remediations(items, "kev"), "remediation_kev"
    if group.startswith("vendor:") or group.startswith("product:"):
        return risk.group_remediations(items, "vendor_product", group.split(":", 1)[1]), "remediation_vendor"
    if args.get("cves"):  # comma-separated selection
        return risk.group_remediations(items, "selection", args.get("cves")), "remediation_selection"
    # Default: group everything currently filtered, by vendor+product.
    items = _filter_risk_items(items, args)
    return risk.group_remediations(items, "vendor_product"), "remediation_all"


def _cve_references(cve: str) -> list:
    """Gather advisory reference URLs for a CVE from current intel (NVD + CVEDB)."""
    cve = (cve or "").upper()
    intel = fetcher.get_current_data() or {}
    refs = []
    for c in (intel.get("advisories", {}) or {}).get("immediate_attention_cves", []) or []:
        if (c.get("cve_id") or "").upper() == cve:
            refs += c.get("references", []) or []
    e = (intel.get("enrichment") or {}).get(cve) or {}
    refs += e.get("references", []) or []
    # de-dup, keep order
    seen, out = set(), []
    for u in refs:
        if u and u not in seen:
            seen.add(u); out.append(u)
    return out


@app.route("/api/remediation/advisory")
def api_remediation_advisory():
    """Lazy, cached live-fetch of the vendor advisory + extracted remediation text."""
    cve = (request.args.get("cve") or "").strip().upper()
    if not cve:
        return jsonify({"error": "Provide ?cve=CVE-YYYY-NNNN"}), 400
    try:
        return jsonify(advisory.fetch_advisory(cve, _cve_references(cve)))
    except Exception as e:
        logger.exception(f"Advisory fetch failed for {cve}")
        return jsonify({"error": str(e), "cve": cve, "text": "", "url": "", "portal": ""}), 200


_CVE_PARAM_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


@app.route("/api/remediation/ai")
def api_remediation_ai():
    """On-demand, key-gated AI (Claude) vendor-tailored remediation. Never auto-invoked."""
    cve = (request.args.get("cve") or "").strip().upper()
    if not cve:
        return jsonify({"error": "Provide ?cve=CVE-YYYY-NNNN"}), 400
    if not _CVE_PARAM_RE.match(cve):
        return jsonify({"error": "Invalid CVE identifier"}), 400
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify({"error": "AI guidance unavailable — set ANTHROPIC_API_KEY on the server to enable the Ask-AI feature."}), 400
    # Context: the matching risk item (vendor/product/cvss/epss/kev action) + live advisory.
    result, _ = _risk_result()
    item = next((it for it in result.get("items", []) if it.get("cve_id", "").upper() == cve), None)
    adv = advisory.fetch_advisory(cve, _cve_references(cve))
    try:
        text = _ai_remediation(cve, item, adv)
        return jsonify({"cve": cve, "guidance": text, "advisory_url": adv.get("url", ""),
                        "model": "claude-opus-4-5"})
    except Exception as e:
        logger.exception(f"AI remediation failed for {cve}")
        return jsonify({"error": f"AI request failed: {e}"}), 502


def _ai_remediation(cve, item, adv):
    """Call Claude grounded on the CVE metadata + fetched advisory excerpt (cached)."""
    cache = Path(advisory._CACHE_DIR).parent / "ai_remediation"
    try:
        cache.mkdir(parents=True, exist_ok=True)
        cf = cache / f"{cve}.json"
        if cf.exists():
            return json.loads(cf.read_text(encoding="utf-8")).get("guidance", "")
    except Exception:
        cf = None
    import anthropic
    item = item or {}
    rem = item.get("remediation") or {}
    ctx = (f"CVE: {cve}\n"
           f"Vendor/Product: {item.get('vendor','')} {item.get('product','')}\n"
           f"CVSS: {item.get('cvss','')} ({item.get('cvss_version','')})  EPSS: {item.get('epss','')}\n"
           f"Actively exploited (CISA KEV): {item.get('in_kev', False)}  Ransomware-linked: {item.get('ransomware', False)}\n"
           f"CISA required action: {rem.get('kev_action','')}\n"
           f"Vendor advisory ({adv.get('url','')}):\n{adv.get('text','') or '(no advisory text extracted)'}\n")
    prompt = (
        "You are a vulnerability-remediation analyst. Using ONLY the context below, write concise, "
        "vendor-specific patch/remediation guidance for this CVE: the exact fixed version(s) or "
        "update to apply, the vendor's official update mechanism, and any interim mitigation. "
        "Do not invent version numbers — if the advisory text doesn't state a fixed version, say so "
        "and point to the vendor advisory. Use short numbered steps.\n\n" + ctx)
    client = anthropic.Anthropic()
    msg = client.messages.create(
        model="claude-opus-4-5", max_tokens=700,
        messages=[{"role": "user", "content": prompt}])
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
    if cf:
        try:
            cf.write_text(json.dumps({"cve": cve, "guidance": text}), encoding="utf-8")
        except Exception:
            pass
    return text


@app.route("/api/remediation")
def api_remediation():
    grouped, _ = _resolve_remediation(request.args)
    return jsonify(grouped)


@app.route("/api/remediation/export/xlsx")
def api_remediation_export():
    grouped, base = _resolve_remediation(request.args)
    # Bounded live-advisory enrichment (cached) so the export carries vendor-specific text.
    budget = 25
    for g in grouped.get("groups", []):
        for rem in g.get("items", []) or []:
            if budget <= 0:
                break
            try:
                adv = advisory.fetch_advisory(rem.get("cve_id", ""), _cve_references(rem.get("cve_id", "")))
                rem["advisory_text"] = adv.get("text", "")
                rem["advisory_url"] = adv.get("url", "") or adv.get("portal", "")
            except Exception:
                pass
            budget -= 1
    try:
        xlsx = report.build_remediation_xlsx(grouped)
    except Exception as e:
        logger.exception("Remediation XLSX export failed")
        return jsonify({"error": str(e)}), 500
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    resp = make_response(xlsx)
    resp.headers["Content-Type"] = _XLSX_CT
    safe_base = re.sub(r"[^\w-]", "_", base or "remediation")
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_base}_{ts}.xlsx"'
    return resp


@app.route("/api/report/custom", methods=["POST"])
def api_report_custom():
    body = request.get_json(silent=True) or {}
    sections = body.get("sections") or []
    filters = body.get("filters") or {}
    result, findings = _risk_result()
    items = _filter_risk_items(result.get("items", []), filters)
    risk_filtered = {"items": items, "summary": result.get("summary", {})}
    intel = fetcher.get_current_data() or {}
    try:
        xlsx = report.build_custom_report_xlsx(
            sections, data=intel, risk_result=risk_filtered,
            findings=findings, stats=connectors.store.stats())
    except Exception as e:
        logger.exception("Custom report build failed")
        return jsonify({"error": str(e)}), 500
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    resp = make_response(xlsx)
    resp.headers["Content-Type"] = _XLSX_CT
    resp.headers["Content-Disposition"] = f"attachment; filename=jatayu_report_{ts}.xlsx"
    return resp


# ── Generic per-section export (every section's Export → XLSX / PDF) ────────────
_PCT = lambda v: (f"{round(v*100,1)}%" if isinstance(v, (int, float)) else "")


def _rows(items, cols):
    """items: list[dict]; cols: list[(header, key_or_fn)] → (headers, rows)."""
    headers = [c[0] for c in cols]
    out = []
    for it in (items or []):
        row = []
        for _, key in cols:
            v = key(it) if callable(key) else it.get(key, "")
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            row.append(v)
        out.append(row)
    return headers, out


def _section_tables(section: str):
    """Return (title, [tables]) for a section from the current intel/findings/risk."""
    data = fetcher.get_current_data() or {}
    adv = data.get("advisories", {}) or {}
    ti = data.get("threat_intel", {}) or {}
    iocs = ti.get("iocs", {}) or {}
    dw = ti.get("darkweb", {}) or {}

    def table(title, items, cols):
        h, r = _rows(items, cols)
        return {"title": title, "columns": h, "rows": r}

    s = (section or "").lower()
    if s == "exploited":
        return "Top Exploited CVEs (CISA KEV)", [table("Exploited CVEs",
            adv.get("top_exploited_cves", []),
            [("CVE", "cve_id"), ("Vendor", "vendor"), ("Product", "product"),
             ("Date Added", "date_added"), ("Due Date", "due_date"),
             ("Ransomware", "known_ransomware"), ("EPSS", lambda c: _PCT(c.get("epss"))),
             ("Description", lambda c: (c.get("description", "") or "")[:160])])]
    if s == "critical":
        return "Critical CVEs (NVD)", [table("Critical CVEs",
            adv.get("immediate_attention_cves", []),
            [("CVE", "cve_id"), ("CVSS", "cvss_score"), ("Ver", "cvss_version"),
             ("Attack Vector", "attack_vector"), ("Severity", "severity"),
             ("Published", "published"), ("Description", lambda c: (c.get("description", "") or "")[:160])])]
    if s == "iocs":
        return "Indicators of Compromise", [
            table("Malicious IPs", iocs.get("malicious_ips", []),
                  [("IP", "ip"), ("Port", "port"), ("Malware", "malware"),
                   ("Country", "country"), ("Status", "status"), ("First Seen", "first_seen")]),
            table("Malicious URLs", iocs.get("malicious_urls", []),
                  [("URL", "url"), ("Status", "url_status"), ("Threat", "threat"),
                   ("Date Added", "date_added"), ("Reporter", "reporter")]),
            table("Malware Hashes", iocs.get("malware_hashes", []),
                  [("SHA256", "sha256"), ("File Type", "file_type"),
                   ("Signature", "signature"), ("First Seen", "first_seen")])]
    if s == "actors":
        return "Top Threat Actors", [table("Threat Actors", ti.get("top_threat_actors", []),
            [("Name", "name"), ("MITRE ID", "mitre_id"), ("Aliases", "aliases"),
             ("Country", "country"), ("Sophistication", "sophistication")])]
    if s == "geo":
        return "Geopolitical Threat Intelligence", [table("Geopolitical", ti.get("geopolitical", []),
            [("Country", "country"), ("Threat Count", "threat_count"), ("Risk Level", "risk_level"),
             ("Primary Threat", "primary_threat"), ("Malware Families", "malware_families")])]
    if s == "darkweb":
        return "Dark Web Intelligence", [
            table("Breaches", dw.get("breaches", []),
                  [("Title", "title"), ("Domain", "domain"), ("Breach Date", "breach_date"),
                   ("Records", "pwn_count"), ("Verified", "is_verified")]),
            table("Forum & News", dw.get("forum_discussions", []),
                  [("Title", "title"), ("Category", "category"), ("Source", "source"),
                   ("Published", "published")])]
    if s == "research":
        return "Security Research Intel", [table("Research", data.get("research", []),
            [("Title", "title"), ("Category", "category"), ("Severity", "severity"),
             ("Source", "source"), ("Published", "published")])]
    if s == "analytics":
        kev = adv.get("top_exploited_cves", [])[:10]
        return "Threat Analytics", [
            table("Top 10 Exploitable CVEs + MITRE", kev,
                  [("CVE", "cve_id"), ("CWEs", "cwes"), ("EPSS", lambda c: _PCT(c.get("epss"))),
                   ("CVSS v4", "cvss_v4"),
                   ("Techniques", lambda c: ", ".join(t.get("id", "") for t in (c.get("techniques") or [])))]),
            table("Zero-Day Watch", ti.get("zeroday", []),
                  [("CVE", "cve"), ("Type", "vuln_type"), ("Software", "software"),
                   ("Actively Exploited", lambda z: "Yes" if z.get("actively_exploited") else "No"),
                   ("Discovered", "date_discovered")])]
    if s == "risk":
        items = risk.prioritize(connectors.store.load_findings(), data).get("items", [])
        return "Risk Prioritization", [table("Prioritized Risk", items,
            [("Priority", "priority"), ("Score", "priority_score"), ("CVE", "cve_id"),
             ("Severity", "severity"), ("CVSS", "cvss"), ("EPSS", lambda i: _PCT(i.get("epss"))),
             ("Attack Vector", "attack_vector"), ("Exploited", lambda i: "Yes" if i.get("in_kev") else "No"),
             ("Assets", "affected_assets"), ("Vendor", "vendor"), ("Action", "action")])]
    if s == "patchsphere":
        ps = patchsphere.analyze(connectors.store.load_findings(), data)
        fixes = ps.get("top_fixes", [])
        return "PatchSphere — Patch Decision Surface", [
            table("Top 5 Immediate Fixes", fixes,
                  [("CVE", "cve_id"), ("Priority", "priority"), ("Score", "priority_score"),
                   ("Affected Assets", "affected_assets"),
                   ("Reachable (blast)", lambda f: (f.get("blast_radius") or {}).get("reachable_count", 0)),
                   ("Blast %", lambda f: f"{(f.get('blast_radius') or {}).get('blast_pct', 0)}%"),
                   ("CVSS", "cvss"), ("EPSS", lambda f: _PCT(f.get("epss"))),
                   ("Exploited", lambda f: "Yes" if f.get("in_kev") else "No"),
                   ("Vendor", "vendor"), ("Action", "action")]),
            table("Choke Points (cut these first)", ps.get("choke_points", []),
                  [("Asset", "asset"), ("IP", "ip"), ("Can Reach", "reach"),
                   ("Exploitable Now", lambda c: "Yes" if c.get("exploitable") else "No"),
                   ("Severity", "severity"), ("Vulnerabilities", "cve_count"),
                   ("Top CVEs", "top_cves"), ("Scanners", "scanners")]),
            table("Blast Radius per Fix", fixes,
                  [("CVE", "cve_id"),
                   ("Directly Affected", lambda f: (f.get("blast_radius") or {}).get("direct_count", 0)),
                   ("Laterally Reachable", lambda f: (f.get("blast_radius") or {}).get("reachable_count", 0)),
                   ("Blast %", lambda f: f"{(f.get('blast_radius') or {}).get('blast_pct', 0)}%"),
                   ("Risk Removed", lambda f: (f.get("blast_radius") or {}).get("risk_removed", 0)),
                   ("Choke Points Involved", lambda f: (f.get("blast_radius") or {}).get("choke_involved", []))])]
    if s == "connectors":
        return "Vulnerability Findings", [table("Findings", connectors.store.load_findings(),
            [("Source", "source"), ("Asset", "asset"), ("IP", "ip"), ("Severity", "severity"),
             ("CVSS", "cvss"), ("CVEs", "cve_ids"), ("Attack Vector", "attack_vector"),
             ("Plugin", "plugin_name")])]
    # overview / default → high-level summary
    meta = data.get("metadata", {}) or {}
    src = meta.get("sources", {}) or {}
    summ = [{"metric": k, "value": v} for k, v in {
        "Exploited CVEs (KEV)": len(adv.get("top_exploited_cves", []) or []),
        "Critical CVEs (NVD)": len(adv.get("immediate_attention_cves", []) or []),
        "Malicious IPs": len(iocs.get("malicious_ips", []) or []),
        "Malicious URLs": len(iocs.get("malicious_urls", []) or []),
        "Malware Hashes": len(iocs.get("malware_hashes", []) or []),
        "Threat Actors": len(ti.get("top_threat_actors", []) or []),
        "Breaches": len(dw.get("breaches", []) or []),
        "Zero-Day Records": len(ti.get("zeroday", []) or []),
        "Last Updated": meta.get("last_updated", ""),
    }.items()]
    return "Threat Command Center — Overview", [table("Summary", summ,
        [("Metric", "metric"), ("Value", "value")])]


@app.route("/api/section/export/<section>/<fmt>")
def api_section_export(section: str, fmt: str):
    if IS_SERVERLESS:
        _ensure_data()
    fmt = (fmt or "").lower()
    if fmt not in ("xlsx", "pdf"):
        return jsonify({"error": "Supported formats: xlsx, pdf"}), 400
    try:
        title, tables = _section_tables(section)
        if fmt == "xlsx":
            blob = report.build_section_xlsx(title, tables)
            ct, ext = _XLSX_CT, "xlsx"
        else:
            blob = report.build_section_pdf(title, tables)
            ct, ext = "application/pdf", "pdf"
    except Exception as e:
        logger.exception(f"Section export failed for {section}/{fmt}")
        return jsonify({"error": str(e)}), 500
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    resp = make_response(blob)
    resp.headers["Content-Type"] = ct
    safe_section = re.sub(r"[^\w-]", "_", section or "section")[:40]
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_section}_{ts}.{ext}"'
    return resp


# ── Trends: time-series aggregated from the rolling history ─────────────────────

@app.route("/api/trends")
def api_trends():
    """Aggregate per-day counts across archived snapshots for trend charts."""
    series = []
    for date_str in sorted(fetcher.get_available_dates()):
        data = fetcher.get_historical_data(date_str)
        if not data:
            continue
        adv = data.get("advisories", {}) or {}
        ti = data.get("threat_intel", {}) or {}
        iocs = ti.get("iocs", {}) or {}
        dw = ti.get("darkweb", {}) or {}
        series.append({
            "date": date_str,
            "exploited_cves": len(adv.get("top_exploited_cves", []) or []),
            "critical_cves": len(adv.get("immediate_attention_cves", []) or []),
            "iocs": (len(iocs.get("malicious_ips", []) or [])
                     + len(iocs.get("malicious_urls", []) or [])
                     + len(iocs.get("malware_hashes", []) or [])),
            "breaches": len(dw.get("breaches", []) or []),
            "research": len(data.get("research", []) or []),
        })
    return jsonify({"series": series})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting Threat Intel Dashboard on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
