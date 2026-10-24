"""Focused browser proof for the dashboard shell, without database fixtures."""
from pathlib import Path
import re
import os
import shutil
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]


def verify():
    sidebar = (ROOT / 'templates/sidebar.html').read_text()
    sidebar = re.sub(r'{% if active == "overview" %}(.*?){% endif %}', lambda match: match.group(1), sidebar)
    sidebar = re.sub(r'{% if active == .*?%}.*?{% endif %}', '', sidebar)
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
                page.add_script_tag(path=ROOT / 'assets/navigation.js')
                toggle = page.get_by_role('button', name='Navigation menu')
                nav = page.get_by_role('navigation', name='Administration')
                expect(toggle).to_be_visible()
                expect(toggle).to_have_attribute('aria-expanded', 'false')
                expect(nav).to_be_hidden()
                expect(page.get_by_label('Workspace menu', exact=True)).to_be_visible()
                toggle.focus()
                page.keyboard.press('Enter')
                expect(toggle).to_have_attribute('aria-expanded', 'true')
                expect(nav).to_be_visible()
                expect(page.get_by_role('dialog', name='Navigation')).to_be_visible()
                page.wait_for_timeout(320)
                assert page.locator('.workspace').bounding_box()['x'] == 307
                assert page.locator('.sidebar-header').bounding_box()['x'] == 307
                expect(page.get_by_role('link', name='Overview', exact=True)).to_be_focused()
                expect(page.locator('.mobile-menu-close')).to_have_count(0)
                assert page.locator('.sidebar').evaluate("e => getComputedStyle(e, '::before').borderBottomLeftRadius") == '28px'
                assert page.locator('.workspace').evaluate('e => e.inert')
                page.keyboard.press('Shift+Tab')
                expect(page.get_by_role('link', name='Help', exact=True)).to_be_focused()
                page.keyboard.press('Tab')
                expect(page.get_by_role('link', name='Overview', exact=True)).to_be_focused()
                page.keyboard.press('Escape')
                expect(nav).to_be_hidden()
                expect(toggle).to_be_focused()
                toggle.click()
                page.locator('.mobile-menu-backdrop').click(position={'x': 34, 'y': 400})
                expect(nav).to_be_hidden()
                toggle.click()
                page.get_by_role('link', name='Overview', exact=True).evaluate("e => e.addEventListener('click', event => event.preventDefault())")
                page.get_by_role('link', name='Overview', exact=True).click()
                expect(toggle).to_have_attribute('aria-expanded', 'false')
                page.set_viewport_size({'width': 1280, 'height': 900})
                expect(nav).to_be_visible()
                expect(toggle).to_be_hidden()
                page.set_viewport_size({'width': 375, 'height': 812})
                expect(nav).to_be_hidden()
                for width in (320, 390, 639):
                    page.set_viewport_size({'width': width, 'height': 812})
                    page.emulate_media(reduced_motion='reduce', color_scheme='dark')
                    toggle.click()
                    expect(nav).to_be_visible()
                    assert abs(page.locator('.workspace').bounding_box()['x'] - (width - 68)) < 1
                    expect(page.locator('.sidebar-content')).to_have_css('transition-duration', '0s')
                    page.keyboard.press('Escape')
                    expect(nav).to_be_hidden()
            else:
                expect(page.get_by_role('navigation', name='Administration')).to_be_visible()
            assert page.locator('body').evaluate('e => e.scrollWidth <= innerWidth')
            context.close()
        browser.close()
    print('Mobile menu: keyboard, dismissal, resize, desktop and no-JavaScript checks passed')


if __name__ == '__main__':
    verify()
