import time
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1600, "height": 900})
    page.goto("http://localhost:5000/")
    # Wait 30s for loading to complete
    time.sleep(30)
    page.screenshot(path="static/ss_final_dashboard.png")
    print("Dashboard after loading complete")
    
    # Check header
    page.screenshot(path="static/ss_header_zoom.png", clip={"x":0,"y":0,"width":500,"height":70})
    print("Header zoom screenshot")
    
    # Check if loading screen is gone
    loading_visible = page.evaluate("document.getElementById('loading')?.style.display !== 'none'")
    print(f"Loading visible: {loading_visible}")
    
    browser.close()
