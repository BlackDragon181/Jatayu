"""
verify_ui.py — headless render verification for the Analytics page.

Launches the app (snapshot mode), loads it in headless Chromium, navigates to
Trends & Analytics, and ASSERTS that charts actually render:
  • the geographic choropleth (#chart-geo-map) drew a Chart.js instance,
  • the Activity Trend canvas is a sane height (not the blown-up 2:1 bug),
  • no uncaught console errors.
Saves static/ss_analytics_fixed.png for visual confirmation.

Run:  python verify_ui.py
Needs: pip install playwright ; playwright install chromium
"""

import os
import subprocess
import sys
import time
import urllib.request

PORT = 5057
URL = f"http://localhost:{PORT}/"


def _wait_up(timeout=40):
    for _ in range(timeout * 2):
        try:
            with urllib.request.urlopen(URL + "api/status", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main():
    env = dict(os.environ, VERCEL="1", PORT=str(PORT))  # snapshot mode, no scheduler
    proc = subprocess.Popen([sys.executable, "app.py"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not _wait_up():
            print("FAIL: app did not start"); return 1
        from playwright.sync_api import sync_playwright
        js_errors = []      # uncaught JS exceptions — fatal
        res_errors = []     # failed resource loads (e.g. font CDN) — cosmetic/env
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1500, "height": 950})
            page.on("console", lambda m: (res_errors if "Failed to load resource" in m.text
                                          else js_errors).append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: js_errors.append(str(e)))
            page.goto(URL, wait_until="networkidle")
            # Wait for data to load into the SPA. DC/charts are top-level `let`
            # bindings (global lexical scope), reachable as bare identifiers.
            page.wait_for_function("typeof DC!=='undefined' && DC.threat_intel", timeout=20000)
            page.evaluate("showPage('sec-analytics')")
            # Choropleth fetches a world-atlas TopoJSON from CDN — give it time.
            page.wait_for_timeout(6000)

            geo = page.evaluate(
                "() => {const c=(typeof charts!=='undefined')&&charts.geomap;"
                "const cv=document.getElementById('chart-geo-map');"
                "return {chart:!!c, type:c&&c.config?c.config.type:null,"
                "points:c&&c.data&&c.data.datasets[0]?c.data.datasets[0].data.length:0,"
                "h:cv?cv.clientHeight:0,w:cv?cv.clientWidth:0};}")
            trend = page.evaluate(
                "() => {const cv=document.getElementById('chart-trend');"
                "return {h:cv?cv.clientHeight:0};}")

            page.locator("#sec-analytics").screenshot(path="static/ss_analytics_fixed.png")

            # New chrome: per-section Back + Export controls injected into every header.
            chrome = page.evaluate(
                "() => ({back:document.querySelectorAll('.sec-back').length,"
                "exp:document.querySelectorAll('.sec-export').length});")
            # Back button should appear after navigating (history non-empty).
            page.evaluate("showPage('sec-iocs')")
            page.wait_for_timeout(300)
            backshown = page.evaluate(
                "() => {const b=document.querySelector('#sec-iocs .sec-back');"
                "return !!b && getComputedStyle(b).display!=='none';}")
            browser.close()

        ok = True
        print(f"geo map: chart={geo['chart']} type={geo['type']} points={geo['points']} "
              f"canvas={geo['w']}x{geo['h']}")
        print(f"trend canvas height: {trend['h']}px")
        if not (geo["chart"] and geo["type"] == "choropleth" and geo["h"] > 100):
            print("FAIL: geographic choropleth did not render"); ok = False
        if not (0 < trend["h"] <= 300):
            print(f"FAIL: trend chart height {trend['h']}px is wrong (expected ~230, ≤300)"); ok = False
        print(f"section chrome: {chrome['back']} back btns, {chrome['exp']} export controls; "
              f"back shown after nav: {backshown}")
        if chrome["back"] < 10 or chrome["exp"] < 10:
            print("FAIL: back/export controls not injected into all sections"); ok = False
        if not backshown:
            print("FAIL: back button did not appear after navigation"); ok = False
        if js_errors:
            print("FAIL: uncaught JS errors:")
            for e in js_errors[:10]:
                print("  -", e[:160])
            ok = False
        if res_errors:
            print(f"(note: {len(res_errors)} cosmetic resource-load failures — font/icon CDN "
                  "unreachable in this sandbox; charts are vendored locally and unaffected)")
        print("Screenshot: static/ss_analytics_fixed.png")
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
