"""Appearance and plain-HTML consumer proofs shared by the real browser suite."""
from pathlib import Path
import os
from playwright.sync_api import expect


def control_density(page):
    touch = page.evaluate("matchMedia('(pointer: coarse), (max-width: 639px)').matches")
    for control in page.locator('.ui').locator('input:not([type="hidden"]),button,.ui-button,select').all():
        if control.is_visible():
            minimum = 44 if touch else 30
            assert control.bounding_box()['height'] >= minimum


def keyboard_focus(control):
    expect(control).to_be_focused()
    assert control.evaluate("e=>e.matches(':focus-visible')")
    if control.evaluate("e=>e.matches('input,select,textarea')"):
        expect(control).to_have_css('outline-style', 'none')
        expect(control).not_to_have_css('box-shadow', 'none')
    else:
        expect(control).to_have_css('outline-width', '2px')
        expect(control).to_have_css('outline-style', 'solid')


def choose_appearance(page, theme):
    native = page.get_by_role('combobox', name='Appearance', exact=True)
    if native.count():
        native.select_option(theme)
    else:
        page.locator('.appearance-menu > summary').click()
        page.locator('[data-ui-theme-choice="' + theme + '"]').click()


def capture_menu(page, name):
    evidence = os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE')
    if evidence:
        target = Path(evidence)
        target.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(target / f'{name}-{page.viewport_size["width"]}.png'), full_page=True, animations='disabled')


def workspace_menus(page):
    expect(page.locator('header')).to_have_count(0)
    trigger = page.get_by_label('Workspace menu', exact=True)
    trigger.click()
    expect(page.get_by_role('link', name='Switch tenant', exact=True)).to_be_visible()
    expect(page.get_by_role('button', name='Log out', exact=True)).to_be_visible()
    capture_menu(page, 'workspace-menu')
    page.keyboard.press('Escape')
    expect(trigger).to_be_focused()
    expect(page.locator('.workspace-menu')).not_to_have_attribute('open', '')
    page.locator('.appearance-menu > summary').click()
    page.locator('[data-ui-theme-choice="dark"]').click()
    expect(page.locator('html')).to_have_attribute('data-ui-theme', 'dark')
    page.locator('.appearance-menu > summary').click()
    expect(page.locator('[data-ui-theme-choice="dark"]')).to_have_attribute('aria-pressed', 'true')
    capture_menu(page, 'appearance-menu')
    page.locator('.workspace').click(position={'x': 2, 'y': 2})
    expect(page.locator('.appearance-menu')).not_to_have_attribute('open', '')
    choose_appearance(page, 'system')


def appearance(page, browser, origin):
    page.emulate_media(color_scheme='dark')
    expect(page.locator('html')).to_have_css('background-color', 'rgb(24, 24, 27)')
    choice = page.get_by_role('combobox', name='Appearance', exact=True)
    choice.select_option('light')
    expect(page.locator('html')).to_have_css('background-color', 'rgb(255, 255, 255)')
    page.reload()
    expect(choice).to_have_value('light')
    page.goto(origin + '/admin/login')
    expect(choice).to_have_value('light')
    choice.select_option('system')
    expect(page.locator('html')).to_have_css('background-color', 'rgb(24, 24, 27)')
    page.emulate_media(color_scheme='light')
    expect(page.locator('html')).to_have_css('background-color', 'rgb(255, 255, 255)')
    choice.select_option('dark')
    expect(page.locator('html')).to_have_css('background-color', 'rgb(24, 24, 27)')
    other = page.context.new_page()
    other.goto(origin + '/admin/login')
    expect(other.get_by_role('combobox', name='Appearance')).to_have_value('dark')
    choice.select_option('light')
    expect(other.get_by_role('combobox', name='Appearance')).to_have_value('light')
    other.close()
    choice.select_option('system')
    page.goto(origin + '/admin/setup')

    denied = browser.new_context(color_scheme='light')
    denied.add_init_script("Object.defineProperty(window, 'localStorage', {get() {throw new DOMException('Unavailable', 'SecurityError')}})")
    storage_page = denied.new_page()
    errors = []
    storage_page.on('pageerror', lambda error: errors.append(str(error)))
    storage_page.goto(origin + '/admin/login')
    storage_page.get_by_role('combobox', name='Appearance').select_option('dark')
    expect(storage_page.locator('html')).to_have_css('background-color', 'rgb(24, 24, 27)')
    expect(storage_page.get_by_role('button', name='Sign in', exact=True)).to_be_enabled()
    assert errors == []
    denied.close()

    plain = browser.new_context(java_script_enabled=False, color_scheme='dark')
    plain_page = plain.new_page()
    plain_page.goto(origin + '/admin/login')
    expect(plain_page.locator('html')).to_have_css('background-color', 'rgb(24, 24, 27)')
    expect(plain_page.get_by_role('combobox', name='Appearance')).not_to_be_visible()
    expect(plain_page.get_by_role('button', name='Sign in', exact=True)).to_be_enabled()
    plain.close()

    consumer = browser.new_context(color_scheme='light')
    sample = consumer.new_page()
    requests = []
    sample.on('request', lambda request: requests.append(request.url))
    sample.route('**/ui-consumer', lambda route: route.fulfill(
        status=200, content_type='text/html',
        body=(Path(__file__).parents[1] / 'fixtures/ui-consumer.html').read_text()))
    sample.goto(origin + '/ui-consumer')
    host_before = sample.locator('#outside').evaluate('e=>({background:getComputedStyle(e).backgroundColor,radius:getComputedStyle(e).borderRadius})')
    sample.get_by_role('combobox', name='Appearance').select_option('dark')
    expect(sample.locator('#kit')).to_have_css('background-color', 'rgb(24, 24, 27)')
    expect(sample.locator('#kit button')).to_have_css('border-radius', '12px')
    expect(sample.locator('#kit button')).to_have_css('height', '30px')
    field = sample.get_by_role('textbox', name='Name')
    expect(field).to_have_css('height', '32px')
    expect(field).to_have_css('border-radius', '12px')
    for theme, border in [('dark', 'rgb(113, 113, 122)'), ('light', 'rgb(139, 155, 162)')]:
        sample.get_by_role('combobox', name='Appearance').select_option(theme)
        field.focus()
        expect(field).to_have_css('border-color', border)
        expect(field).to_have_css('outline-style', 'none')
        expect(field).not_to_have_css('box-shadow', 'none')
    host_after = sample.locator('#outside').evaluate('e=>({background:getComputedStyle(e).backgroundColor,radius:getComputedStyle(e).borderRadius})')
    assert host_before == host_after
    assert all(url in [origin + '/ui-consumer', origin + '/assets/ui.css', origin + '/assets/ui.js'] for url in requests)
    consumer.close()

    touch = browser.new_context(has_touch=True, viewport={'width': 1280, 'height': 900})
    touch_page = touch.new_page()
    touch_page.route('**/ui-consumer', lambda route: route.fulfill(
        status=200, content_type='text/html',
        body=(Path(__file__).parents[1] / 'fixtures/ui-consumer.html').read_text()))
    touch_page.goto(origin + '/ui-consumer')
    assert touch_page.evaluate("matchMedia('(pointer: coarse)').matches")
    control_density(touch_page)
    touch.close()
