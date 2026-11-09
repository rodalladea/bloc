"""Real HTTPS account-factor forms, responsive layout, and keyboard regression."""
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, expect

ORIGIN = os.environ['BLOC_TEST_ORIGIN']
REALM = '11111111-1111-4111-8111-111111111111'
USER = '22222222-2222-4222-8222-222222222222'
FACTOR = '99999999-1111-4111-8111-111111111111'
BASE = f'{ORIGIN}/realms/{REALM}'
PASSWORD = 'a synthetic password'

def sql(statement):
    database = urlparse(Path(os.environ['BLOC_DATABASE_URL_FILE']).read_text().strip()).path[1:]
    return subprocess.run(['docker', 'exec', os.environ['BLOC_SETUP_CONTAINER'], 'psql', '-U', 'probe', '-d', database, '-v', 'ON_ERROR_STOP=1', '-At', '-c', statement], check=True, capture_output=True, text=True).stdout.strip()

def login(page):
    page.goto(BASE + '/login')
    page.get_by_label('Email address', exact=True).fill('Alice@example.test')
    page.get_by_label('Password', exact=True).fill(PASSWORD)
    page.get_by_role('button', name='Sign in', exact=True).click()
    page.wait_for_url(BASE + '/account**')

def layout(page, width, theme):
    page.set_viewport_size({'width': width, 'height': 960})
    page.emulate_media(color_scheme=theme)
    page.reload()
    expect(page.get_by_role('heading', name='Account security', exact=True)).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (width, theme)
    assert page.locator('aside[aria-label="Account navigation"]').count() == 1
    assert page.locator('table').count() <= 1

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, channel='chromium', args=['--no-proxy-server', '--host-resolver-rules=MAP bloc.example.test 127.0.0.1', '--ignore-certificate-errors-spki-list=' + os.environ['BLOC_TEST_SPKI']])
    context = browser.new_context(viewport={'width': 1440, 'height': 960})
    page = context.new_page()
    responses = []
    page.on('response', lambda response: responses.append(response) if '/account/security' in response.url else None)
    login(page)
    page.goto(BASE + '/account/security')
    expect(page.get_by_text('No second factor enrolled.', exact=False)).to_be_visible()
    expect(page.get_by_role('link', name='Set up authenticator app', exact=True)).to_be_visible()
    expect(page.get_by_role('link', name='Add passkey or security key', exact=True)).to_be_visible()
    for width in [1440, 390]:
        for theme in ['light', 'dark']:
            layout(page, width, theme)
    page.set_viewport_size({'width': 1440, 'height': 960})
    page.get_by_role('link', name='Set up authenticator app', exact=True).focus()
    page.keyboard.press('Enter')
    expect(page.get_by_role('heading', name='Confirm this security change', exact=True)).to_be_visible()
    page.get_by_label('Current password', exact=True).fill(PASSWORD)
    page.get_by_role('button', name='Verify and continue', exact=True).click()
    page.wait_for_url(BASE + '/account/security/continue')
    expect(page.get_by_role('button', name='Set up authenticator app', exact=True)).to_be_visible()
    assert sql('SELECT count(*) FROM bloc.realm_user_factor') == '0'
    # The established forms also work when enhancement scripts are absent.
    plain = browser.new_context(java_script_enabled=False, viewport={'width': 390, 'height': 960})
    plain.add_cookies(context.cookies())
    nojs = plain.new_page()
    nojs.goto(BASE + '/account/security/continue')
    nojs.get_by_role('button', name='Set up authenticator app', exact=True).click()
    nojs.wait_for_url(BASE + '/account/security/totp/setup')
    expect(nojs.locator('#setup-key')).to_be_visible()
    assert sql('SELECT count(*) FROM bloc.realm_user_factor') == '0'
    nojs.get_by_role('button', name='Cancel', exact=True).click()
    nojs.wait_for_url(BASE + '/login?mfa-canceled=1')
    expect(nojs.get_by_text('You have left the verification flow. Existing factors have not changed.', exact=True)).to_be_visible()
    sql("UPDATE bloc.realm_authentication_settings SET mfa_mode='disabled',version=version+1; DELETE FROM bloc.realm_admission_bucket")
    sql(f"INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label) VALUES('{FACTOR}','{REALM}','{USER}','webauthn','Personal laptop')")
    nojs.goto(BASE + '/account/security')
    expect(nojs.get_by_text('Existing factors are retained but do not protect sign-in.', exact=False)).to_be_visible()
    assert nojs.get_by_role('link', name='Add passkey or security key', exact=True).count() == 0
    nojs.get_by_role('link', name='Rename', exact=True).click()
    nojs.get_by_label('Factor name', exact=True).fill('Renamed laptop')
    nojs.get_by_role('button', name='Save name', exact=True).click()
    nojs.wait_for_url(BASE + '/account/security')
    expect(nojs.get_by_role('cell').filter(has_text='Renamed laptop')).to_be_visible()
    before = sql('SELECT factor_epoch FROM bloc.realm_user_mfa_state')
    nojs.get_by_role('link', name='Preferred verification method', exact=True).click()
    expect(nojs.get_by_role('heading', name='Preferred verification method', exact=True)).to_be_visible()
    nojs.get_by_label('Preferred factor', exact=True).select_option(FACTOR)
    nojs.get_by_role('button', name='Save preference', exact=True).click()
    nojs.wait_for_url(BASE + '/account/security')
    assert sql('SELECT factor_epoch FROM bloc.realm_user_mfa_state') == before
    nojs.get_by_role('link', name='Remove', exact=True).click()
    nojs.get_by_label('Current password', exact=True).fill(PASSWORD)
    nojs.get_by_role('button', name='Verify and continue', exact=True).click()
    nojs.wait_for_url(BASE + '/account/security/continue')
    nojs.get_by_label('I understand the change in protection.', exact=True).check()
    nojs.get_by_role('button', name='Remove factor', exact=True).click()
    nojs.wait_for_url(BASE + '/account/security')
    assert sql('SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL') == '0'
    assert sql('SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL') == '1'
    page.goto(BASE + '/account/security')
    # The removed-factor operation rotated authority: the other browser is signed out.
    page.wait_for_url(BASE + '/login**')
    for response in responses:
        headers = response.all_headers()
        assert headers.get('cache-control') == 'no-store'
        assert headers.get('referrer-policy') == 'no-referrer'
    logs = ''.join(path.read_text() for path in Path(os.environ['BLOC_REALM_SERVICE_LOGS']).glob('service-*.*'))
    assert PASSWORD not in logs and 'Alice@example.test' not in logs
    print(json.dumps({'proof': 'realm_mfa_account_browser', 'engine': browser.version, 'viewport_theme_combinations': 4, 'keyboard_activation': True, 'no_javascript_forms': ['totp_candidate', 'cancel', 'rename', 'preferred', 'password_reauthentication', 'factor_removal'], 'normal_account_data_without_full_authority': False}))
    browser.close()
