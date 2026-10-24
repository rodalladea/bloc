"""Focused browser proof for the dashboard shell, without database fixtures."""
from pathlib import Path
import re
import os
import shutil
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]


def verify():
    sidebar = (ROOT / 'templates/sidebar.html').read_text()
    sidebar = re.sub(r'{%.*?%}', '', sidebar)
    sidebar = re.sub(r'{{.*?}}', 'synthetic@example.test', sidebar)
    html = '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">'
    html += '<style>' + (ROOT / 'assets/ui.css').read_text() + (ROOT / 'assets/admin.css').read_text() + '</style>'
    html += '</head><body class="ui application">' + sidebar + '<main class="workspace">Dashboard</main></body></html>'
    with sync_playwright() as p:
        executable = os.environ.get('BLOC_BROWSER_EXECUTABLE') or shutil.which('chromium')
        browser = p.chromium.launch(executable_path=executable, headless=True)
        for scripting in (True, False):
            context = browser.new_context(viewport={'width': 375, 'height': 812}, java_script_enabled=scripting)
            page = context.new_page()
            page.set_content(html)
            if scripting:
                page.add_script_tag(path=ROOT / 'assets/admin.js')
                toggle = page.get_by_role('button', name='Navigation menu')
                nav = page.get_by_role('navigation', name='Administration')
                expect(toggle).to_be_visible()
                expect(toggle).to_have_attribute('aria-expanded', 'false')
                expect(nav).to_be_hidden()
                toggle.focus()
                page.keyboard.press('Enter')
                expect(toggle).to_have_attribute('aria-expanded', 'true')
                expect(nav).to_be_visible()
                expect(page.get_by_label('Workspace menu', exact=True)).to_be_visible()
                page.keyboard.press('Escape')
                expect(nav).to_be_hidden()
                expect(toggle).to_be_focused()
                toggle.click()
                page.locator('.workspace').click()
                expect(nav).to_be_hidden()
                page.set_viewport_size({'width': 1280, 'height': 900})
                expect(nav).to_be_visible()
                expect(toggle).to_be_hidden()
                page.set_viewport_size({'width': 375, 'height': 812})
                expect(nav).to_be_hidden()
            else:
                expect(page.get_by_role('navigation', name='Administration')).to_be_visible()
            assert page.locator('body').evaluate('e => e.scrollWidth <= innerWidth')
            context.close()
        browser.close()
    print('Mobile menu: keyboard, dismissal, resize, desktop and no-JavaScript checks passed')


if __name__ == '__main__':
    verify()
