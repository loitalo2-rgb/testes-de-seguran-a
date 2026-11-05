import pytest
from playwright.sync_api import sync_playwright

# Fixture que fornece uma página do navegador
@pytest.fixture
def page():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        yield page
        browser.close()

def test_web_automation_form(page):
    page.goto("https://example.com")
    title = page.title()

    assert "Example Domain" in title, f"Título incorreto: {title}"