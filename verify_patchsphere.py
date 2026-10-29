"""verify_patchsphere.py — headless render check for the PatchSphere section.

Launches the app (snapshot mode), navigates to PatchSphere, and asserts the
section actually renders: top-5 fix cards present, the choke-point SVG flow
drew at least one choke node, and no uncaught JS errors. Saves a screenshot.
"""
import os, subprocess, sys, time, urllib.request

PORT = 5059
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
    env = dict(os.environ, VERCEL="1", PORT=str(PORT))
    proc = subprocess.Popen([sys.executable, "app.py"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not _wait_up():
            print("FAIL: app did not start"); return 1
        from playwright.sync_api import sync_playwright
        js_errors, res_errors = [], []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1500, "height": 1000})
            page.on("console", lambda m: (res_errors if "Failed to load resource" in m.text
                                          else js_errors).append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: js_errors.append(str(e)))
            page.goto(URL, wait_until="networkidle")
            page.wait_for_function("typeof DC!=='undefined' && DC.threat_intel", timeout=20000)
            page.evaluate("showPage('sec-patchsphere')")
            # loadPatchSphere fetches /api/patchsphere/analyze then renders
            page.wait_for_timeout(2500)

            info = page.evaluate(
                "() => ({"
                "empty: getComputedStyle(document.getElementById('patchsphere-empty')).display,"
                "content: getComputedStyle(document.getElementById('patchsphere-content')).display,"
                "fixes: document.querySelectorAll('#ps-fixes .ps-fix').length,"
                "svg: document.querySelectorAll('#patch-flow svg').length,"
                "chokeNodes: document.querySelectorAll('#patch-flow svg .choke-node').length,"
                "chokeRows: document.querySelectorAll('#body-choke tr').length,"
                "badge: (document.getElementById('nb-patchsphere')||{}).textContent,"
                "back: document.querySelectorAll('#sec-patchsphere .sec-back').length,"
                "exp: document.querySelectorAll('#sec-patchsphere .sec-export').length})")

            # cosmetic: drop the 10s boot overlay so the capture is clean
            page.evaluate("document.getElementById('loading') && document.getElementById('loading').remove()")
            page.wait_for_timeout(150)
            page.locator("#sec-patchsphere").screenshot(path="static/ss_patchsphere.png")
            browser.close()

        ok = True
        print(f"empty={info['empty']} content={info['content']} fixes={info['fixes']} "
              f"svg={info['svg']} chokeNodes={info['chokeNodes']} chokeRows={info['chokeRows']} "
              f"badge={info['badge']} back={info['back']} export={info['exp']}")
        if info["content"] == "none":
            print("FAIL: PatchSphere content not shown (no findings? expected populated in sandbox)"); ok = False
        if info["fixes"] < 1:
            print("FAIL: no top-5 fix cards rendered"); ok = False
        if info["svg"] < 1 or info["chokeNodes"] < 1:
            print("FAIL: choke-point SVG flow did not draw any nodes"); ok = False
        if info["back"] < 1 or info["exp"] < 1:
            print("FAIL: Back/Export controls missing on PatchSphere header"); ok = False
        if js_errors:
            print("FAIL: uncaught JS errors:")
            for e in js_errors[:10]:
                print("  -", e[:160])
            ok = False
        if res_errors:
            print(f"(note: {len(res_errors)} cosmetic resource-load failures — font/icon CDN "
                  "unreachable in this sandbox)")
        print("Screenshot: static/ss_patchsphere.png")
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
