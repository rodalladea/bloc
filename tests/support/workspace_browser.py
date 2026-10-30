"""Realm workspace navigation through the live authenticated application."""
from pathlib import Path
import os
from playwright.sync_api import expect


def verify(page, browser, origin, create_realm, create_user, sql):
    first = create_realm(page, 'Acme')
    page.goto(origin + '/admin')
    page.wait_for_url(first + '/users')
    second = create_realm(page, 'Acme')
    user = create_user(page, second)
    context = page.context
    # Keep the administrator session but remove the optional navigation hint.
    context.clear_cookies(name='__Host-bloc-workspace')
    page.goto(origin + '/admin')
    page.wait_for_url(origin + '/admin/realms')
    for label, suffix in [('Users', '/users'), ('Settings', ''), ('Authentication', '/authentication')]:
        row = page.locator(f'tr[data-record="{first.rsplit("/", 1)[1]}"]')
        row.get_by_role('link', name=label, exact=True).click()
        page.wait_for_url(first + suffix)
        expect(page.locator('.workspace-name strong')).to_have_text('Acme')
        expected = {'Users':'Users', 'Settings':'General', 'Authentication':'Authentication'}[label]
        expect(page.locator('.sidebar-nav [aria-current=page]')).to_have_text(expected)
        page.goto(origin + '/admin/realms')
    for width in [375, 768, 1440]:
        page.set_viewport_size({'width': width, 'height': 1000})
        for theme in ['light', 'dark']:
            page.emulate_media(color_scheme=theme, reduced_motion='reduce')
            page.goto(first + '/users')
            page.get_by_label('Workspace menu', exact=True).click()
            menu = page.locator('.workspace-menu-panel')
            expect(menu.locator('.workspace-realms a')).to_have_count(2)
            expect(menu).to_contain_text(first.rsplit('/', 1)[1])
            expect(menu).to_contain_text(second.rsplit('/', 1)[1])
            target = os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE')
            if target:
                Path(target).mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(Path(target) / f'workspace-menu-{width}-{theme}.png'), full_page=True)
            menu.locator(f'a[href="{second.removeprefix(origin)}/users"]').click()
            page.wait_for_url(second + '/users')
            page.goto(origin + '/admin')
            page.wait_for_url(second + '/users')
            if width < 640:
                page.get_by_role('button', name='Navigation menu', exact=True).click()
            page.locator('.sidebar-nav').get_by_role('link', name='Authentication', exact=True).click()
            page.wait_for_url(second + '/authentication')
            expect(page.locator('.sidebar-nav [aria-current=page]')).to_have_text('Authentication')
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            if target:
                page.screenshot(path=str(Path(target) / f'workspace-authentication-{width}-{theme}.png'), full_page=True)
            page.goto(user)
            expect(page.locator('.sidebar-nav [aria-current=page]')).to_have_text('Users')
            page.get_by_role('link', name='Manage user access', exact=True).click()
            page.wait_for_url(user + '/access-links')
            expect(page.locator('.workspace-name strong')).to_have_text('Acme')
            expect(page.locator('.sidebar-nav [aria-current=page]')).to_have_text('Users')
    page.get_by_label('Workspace menu', exact=True).click()
    page.locator('.workspace-menu-panel').get_by_role('link', name='Installation', exact=True).click()
    page.wait_for_url(origin + '/admin?installation=1')
    expect(page.get_by_role('heading', name='Installation details', exact=True)).to_be_visible()
    page.goto(origin + '/admin')
    page.wait_for_url(second + '/users')
    page.go_back()
    page.wait_for_url(origin + '/admin?installation=1')
    page.go_forward()
    page.wait_for_url(second + '/users')
    # Ordinary navigation also works without scripting, at mobile width.
    native = browser.new_context(storage_state=context.storage_state(), java_script_enabled=False,
                                 viewport={'width':375,'height':900})
    plain = native.new_page()
    plain.goto(origin + '/admin')
    plain.wait_for_url(second + '/users')
    plain.get_by_label('Workspace menu', exact=True).click()
    plain.locator('.workspace-menu-panel').locator(f'a[href="{first.removeprefix(origin)}/users"]').click()
    plain.wait_for_url(first + '/users')
    plain.locator('.sidebar-nav').get_by_role('link', name='General', exact=True).click()
    plain.wait_for_url(first)
    native.close()
    sql("INSERT INTO bloc.realm(id,name,created_at,updated_at) SELECT gen_random_uuid(),'Extra realm',clock_timestamp(),clock_timestamp() FROM generate_series(1,51)")
    page.goto(origin + '/admin/realms')
    page.get_by_label('Workspace menu', exact=True).click()
    expect(page.locator('.workspace-realms a')).to_have_count(50)
    expect(page.locator('.workspace-menu-panel').get_by_role('link',name='Browse all realms')).to_be_visible()
    page.keyboard.press('Escape')
    expect(page.get_by_label('Workspace menu', exact=True)).to_be_focused()
    page.get_by_role('link', name='Next page →', exact=True).click()
    expect(page.locator('tbody tr')).to_have_count(3)
