"""C74/C75 production-browser acceptance, synthetic identities and real guarded authority.

The screen inventory is the approved design's 34 states, not a rendering fixture.
No state is credited until its visible production DOM and arrangement are checked.
"""
import base64
import hashlib
import json
import select
import socket
import socketserver
import ssl
import threading
import time
import traceback
import uuid
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from playwright.sync_api import sync_playwright, expect

ORIGIN = os.environ['BLOC_TEST_ORIGIN']
REALM = '11111111-1111-4111-8111-111111111111'
USER = '22222222-2222-4222-8222-222222222222'
SEED_USER = USER
EMAIL = 'Alice@example.test'
PRINCIPALS = []
BASE = f'{ORIGIN}/realms/{REALM}'
ADMIN = f'{ORIGIN}/admin/realms/{REALM}'
PASSWORD = 'a synthetic password'
INVENTORY = set('policy impact policy-invalid stale challenge invalid methods passkey unsupported required totp enroll-passkey codes codes-lost recovery-code replacement no-recovery assisted link expired limited unavailable account empty disabled reauth remove required-remove label preference password-recovery loading no-js cancel'.split())
PRIMARY_ACTION = {
    'policy': 'Review changes', 'impact': 'Apply policy',
    'policy-invalid': 'Return to settings', 'stale': 'Reload',
    'challenge': 'Verify', 'invalid': 'Verify', 'methods': 'Cancel',
    'passkey': 'Use passkey', 'unsupported': 'Choose another method',
    'required': 'Sign out', 'totp': 'Confirm authenticator',
    'enroll-passkey': 'Create passkey', 'codes': 'Finish setup',
    'codes-lost': 'Replace code set', 'recovery-code': 'Continue to replacement',
    'replacement': 'Cancel recovery', 'no-recovery': 'Return to sign in',
    'assisted': 'Issue recovery link', 'link': 'Done',
    'expired': 'Return to sign in', 'limited': 'Return to sign in',
    'unavailable': 'Try again', 'account': 'Done', 'empty': 'Done',
    'disabled': 'Done', 'reauth': 'Verify and continue', 'remove': 'Remove factor',
    'required-remove': 'Replace factor', 'label': 'Save name',
    'preference': 'Save preference', 'password-recovery': 'Continue',
    'loading': 'Checking…', 'no-js': 'Use another method', 'cancel': 'Sign in',
}
# Ordered body regions from the approved screen inventory.
ORDERED_STATE_REGIONS = {
    'codes-lost': (
        '#feedback.ui-notice',
        'form[action$="/recovery-codes/replace"] button[type=submit]',
    ),
    'empty': (
        '.ui-notice[role=status]',
        '.actions a[href$="operation=totp_enroll"]',
        '.actions a[href$="operation=webauthn_enroll"]',
        '.settings-actions a[href$="/account/profile"]',
    ),
    'invalid': (
        '#feedback.ui-notice[role=alert]',
        'form[action$="/mfa/verify"] .ui-field label[for=authentication-code]',
        'form[action$="/mfa/verify"] #authentication-code',
        'form[action$="/mfa/verify"] button[type=submit]',
    ),
    'policy-invalid': (
        '#feedback.ui-notice[role=alert]',
        ':scope > p > a[href$="/authentication"]',
    ),
    'stale': (
        '#feedback.ui-notice[role=alert]',
        '#feedback a[href$="/authentication"]',
    ),
    'required': (
        '#feedback.ui-notice[role=status]',
        'form[action$="/totp/start"] button[type=submit]',
        'a[href$="/webauthn/setup"]',
        'form.settings-actions[action$="/mfa/cancel"] button[type=submit]',
    ),
    'no-js': (
        '.heading [data-webauthn-intro]',
        '[data-webauthn-fallback]',
    ),
    'unsupported': (
        '[data-webauthn-status][role=status]',
        '[data-webauthn-fallback]',
    ),
    'required-remove': (
        '.ui-notice[role=status]',
        ':scope > a[href$="/account/security"]',
    ),
    'cancel': (
        '#feedback.ui-notice',
        'form.access-form--plain .ui-field label[for=email]',
        'form.access-form--plain input#email[type=email]',
        'form.access-form--plain .ui-field label[for=password]',
        'form.access-form--plain input#password[type=password]',
        'form.access-form--plain .actions button[type=submit]',
    ),
    'expired': (
        '#feedback.ui-notice',
        ':scope > a[href$="/login"]',
    ),
    'limited': (
        '#feedback.ui-notice[role=alert]',
        ':scope > a[href$="/login"]',
    ),
    'no-recovery': (
        '#feedback.ui-notice[role=status]',
        'form.settings-actions[action$="/mfa/cancel"] button[type=submit]',
    ),
    'disabled': (
        '.ui-notice[role=status]',
        '.ui-table-scroll tbody a[href*="operation=factor_remove:"]',
        '.settings-actions a[href$="/account/profile"]',
    ),
    'loading': (
        '[data-webauthn-status].ui-sr-only[role=status]:not([hidden])',
        'form[data-webauthn-form][aria-busy=true] button[aria-busy=true]:disabled',
    ),
    'unavailable': (
        '#feedback.ui-notice[role=alert]',
        ':scope > a[href$="/mfa"]',
    ),
}
SEEN = {}
RESPONSE_VIOLATIONS = []
RESPONSE_CHECKS = []
POLICY_SUBMISSIONS = []
ADMISSION_WAITS = []
SECRETS = [PASSWORD, 'Alice@example.test']
MODE = sys.argv[1] if len(sys.argv) > 1 else 'transport'
EVIDENCE = Path(os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE', tempfile.mkdtemp(prefix='bloc-mfa-browser-'))) / ('mfa-' + MODE)
EVIDENCE.mkdir(parents=True, exist_ok=True)


class PinnedFixtureRelay:
    """CONNECT mapping only for the canonical disposable TLS fixture."""
    def __init__(self):
        self.certificate_hash = None
        self.verify()
        fixture = self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                line = self.rfile.readline(4097)
                if len(line) > 4096 or line != b'CONNECT bloc.example.test:4443 HTTP/1.1\r\n':
                    self.wfile.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                    return
                size = 0
                while True:
                    header = self.rfile.readline(4097)
                    size += len(header)
                    if size > 16384 or not header:
                        return
                    if header == b'\r\n':
                        break
                fixture.verify()
                upstream = socket.create_connection(('127.0.0.1', 4443), timeout=15)
                self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                self.wfile.flush()
                try:
                    while True:
                        ready, _, _ = select.select([self.connection, upstream], [], [], 30)
                        if not ready:
                            return
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.connection else self.connection).sendall(data)
                finally:
                    upstream.close()
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        self.server = Server(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def verify(self):
        # TLS acceptance here is bounded by the caller-supplied SPKI, then the exact
        # certificate fingerprint captured from that verified synthetic fixture.
        with socket.create_connection(('127.0.0.1', 4443), timeout=10) as connection:
            with ssl._create_unverified_context().wrap_socket(connection, server_hostname='bloc.example.test') as tls:
                certificate = tls.getpeercert(binary_form=True)
        public = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'], input=certificate, capture_output=True, check=True).stdout
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, check=True).stdout
        pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
        assert pin == os.environ['BLOC_TEST_SPKI'], 'fixture TLS SPKI changed'
        fingerprint = hashlib.sha256(certificate).hexdigest()
        if self.certificate_hash is None:
            self.certificate_hash = fingerprint
        assert fingerprint == self.certificate_hash, 'fixture certificate changed'

    def close(self):
        self.server.shutdown()
        self.server.server_close()


RELAY = None
ENGINE_RESULTS = []


def browser_context(browser, **options):
    if RELAY is not None:
        RELAY.verify()
    if browser.browser_type.name != 'chromium':
        options['ignore_https_errors'] = True
    context = browser.new_context(**options)
    def same_origin(route):
        if route.request.url.startswith(ORIGIN + '/'):
            route.continue_()
        else:
            route.abort('blockedbyclient')
    context.route('**/*', same_origin)
    def response_policy(response):
        if response.url.startswith(ORIGIN + '/') and '/assets/' not in response.url:
            headers = response.all_headers()
            path = urlparse(response.url).path
            # Existing installation login/workspace/directory pages retain the global
            # same-origin policy. Every realm and newly introduced administrator MFA
            # surface requires the stricter no-referrer policy.
            existing_admin = path in {'/admin', '/admin/login'} or path == '/admin/realms/' + REALM + '/users'
            expected_referrer = 'same-origin' if existing_admin else 'no-referrer'
            record = {'url': ORIGIN + path, 'method': response.request.method, 'status': response.status, 'cache-control': headers.get('cache-control'), 'referrer-policy': headers.get('referrer-policy'), 'expected-referrer-policy': expected_referrer}
            RESPONSE_CHECKS.append(record)
            if headers.get('cache-control') != 'no-store' or headers.get('referrer-policy') != expected_referrer:
                RESPONSE_VIOLATIONS.append(record)
    context.on('response', response_policy)
    return context


def sql(statement):
    database = urlparse(Path(os.environ['BLOC_DATABASE_URL_FILE']).read_text().strip()).path[1:]
    result = subprocess.run(['docker', 'exec', os.environ['BLOC_SETUP_CONTAINER'], 'psql', '-U', 'probe', '-d', database, '-v', 'ON_ERROR_STOP=1', '-At', '-c', statement], check=True, capture_output=True, text=True)
    return result.stdout.strip()



def new_principal(branch):
    global USER, EMAIL
    USER = str(uuid.uuid4())
    EMAIL = 'Alice+' + USER + '@example.test'
    SECRETS.extend([EMAIL, EMAIL.lower()])
    sql(f"INSERT INTO bloc.realm_user(id,realm_id,email,display_name,created_at,updated_at) VALUES('{USER}','{REALM}','{EMAIL}','Alice',clock_timestamp(),clock_timestamp()); INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at) SELECT '{REALM}','{USER}',password_hash,1,clock_timestamp() FROM bloc.realm_user_credential WHERE user_id='{SEED_USER}'")
    PRINCIPALS.append({'branch': branch, 'synthetic_user_id': USER, 'starting_state': 'seeded directory+password; no factor/session; all enrollment through production UI'})


def prepare_totp(browser):
    # A fresh actor still shares the source's 10-per-minute form budget. Leave
    # room for start, setup, and QR without modifying any admission history.
    delay = int(sql("""
        SELECT greatest(0, coalesce(max(ceil(extract(epoch FROM
            e.admitted + interval '60 seconds' - clock_timestamp()))), 0))::integer
        FROM bloc.realm_admission_bucket AS b
        CROSS JOIN LATERAL (
            SELECT admitted FROM unnest(b.admitted_at) AS events(admitted)
            ORDER BY admitted DESC LIMIT 1 OFFSET 7
        ) AS e WHERE b.scope = 'form_source'
    """))
    if delay:
        wait_for_admission_window({'source': 'independent TOTP setup headroom', 'seconds': delay})
    context = browser_context(browser)
    page = context.new_page()
    login(page)
    page.wait_for_url(BASE + '/mfa')
    secret = enroll_totp(page)
    handoff(page)
    context.close()
    return secret


def totp(secret):
    # Use the pinned maintained Rust dependency; no handwritten verifier in the proof.
    while True:
        now = int(sql('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint'))
        floor = int(sql(f"SELECT coalesce(max(t.last_accepted_step),-1) FROM bloc.realm_totp_factor t JOIN bloc.realm_user_factor f ON f.id=t.factor_id WHERE f.revoked_at IS NULL AND f.user_id='{USER}'"))
        step = max(now // 30, floor + 1)
        if step <= now // 30 + 1:
            break
        time.sleep(min(1, max(0.05, (step - 1) * 30 - now)))
    timestamp = str(step * 30)
    with tempfile.TemporaryDirectory(prefix='bloc-mfa-reference-') as directory:
        output = Path(directory) / 'code'
        env = os.environ | {'BLOC_MFA_REFERENCE_SECRET': secret.replace(' ', ''), 'BLOC_MFA_REFERENCE_TIME': timestamp, 'BLOC_MFA_REFERENCE_OUTPUT': str(output)}
        result = subprocess.run([os.environ['BLOC_MFA_TEST_EXECUTABLE'], '--ignored', '--exact', 'realm_mfa_browser_reference_code'], env=env, capture_output=True)
        assert result.returncode == 0, 'maintained reference generator failed'
        value = output.read_text()
        SECRETS.append(value)
        return value


def sessions():
    return int(sql(f"SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL AND user_id='{USER}'"))


def factors():
    return int(sql(f"SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL AND user_id='{USER}'"))


def click(page, role, name):
    page.get_by_role(role, name=name, exact=True).click()


def wait_for_admission_window(record):
    delay = record['seconds']
    assert 0 < delay <= 600, 'admission wait must be bounded'
    ADMISSION_WAITS.append(record)
    (EVIDENCE / 'admission-waits.json').write_text(json.dumps(ADMISSION_WAITS, indent=2))
    deadline = time.monotonic() + delay
    while time.monotonic() < deadline:
        time.sleep(max(0.001, min(1, deadline-time.monotonic())))


def wait_admission(response, notice=None):
    delay = int(response.header_value('Retry-After'))
    if notice is not None:
        expect(notice).to_be_visible()
        expect(notice).to_contain_text(f'Try again in {delay} second')
    wait_for_admission_window({'url': ORIGIN + urlparse(response.url).path, 'status': response.status, 'seconds': delay})


def login(page, admin=False):
    path = ORIGIN + '/admin/login' if admin else BASE + '/login'
    for _ in range(5):
        response = page.goto(path)
        if response.status == 429:
            wait_admission(response)
            continue
        assert response.status == 200
        page.locator('[name=email]').fill('Owner@example.test' if admin else EMAIL)
        page.locator('[name=password]').fill(PASSWORD)
        with page.expect_response(lambda value: value.url == path and value.request.method == 'POST') as submitted:
            click(page, 'button', 'Sign in')
        if submitted.value.status == 429:
            wait_admission(submitted.value)
            continue
        assert submitted.value.status in (200, 303)
        expect(page).not_to_have_url(re.compile(r'/login(?:[?#].*)?$'))
        return
    raise AssertionError('login remained throttled after five declared retry windows')


def check_order(page, selectors):
    assert page.evaluate('''selectors => {
      const main=document.querySelector('main#content');
      const nodes=selectors.map(s=>main.querySelector(s));
      return nodes.every(Boolean) && nodes.every((n,i)=>i===0 || !!(nodes[i-1].compareDocumentPosition(n)&Node.DOCUMENT_POSITION_FOLLOWING));
    }''', selectors), 'approved content arrangement: ' + ', '.join(selectors)


def screen(page, state, heading, selectors=(), text=(), layout='public'):
    # Register secrets before any assertion can emit a browser accessibility snapshot.
    for selector in ('#recovery-codes', '#setup-key', '#access-code', '#access-link', 'input[name=code]'):
        for element in page.locator(selector).all():
            value = element.input_value() if element.evaluate("(node)=>node.matches('input,textarea')") else element.inner_text()
            if value:
                SECRETS.append(value)
                SECRETS.extend(value.splitlines())
                if selector == '#setup-key':
                    SECRETS.append(value.replace(' ', ''))
    assert state in INVENTORY
    if state == 'policy':
        policy_group = page.locator('section.form-group').filter(has=page.get_by_role('heading', name='Two-factor authentication', exact=True))
        expect(policy_group).to_have_count(1)
        assert policy_group.locator('#mfa-mode').count() == 1
        assert policy_group.locator('fieldset').count() == 2
    expect(page.get_by_role('heading', name=heading, exact=True)).to_be_visible()
    action = page.get_by_role('button', name=PRIMARY_ACTION[state], exact=True).or_(page.get_by_role('link', name=PRIMARY_ACTION[state], exact=True))
    expect(action.first).to_be_visible()
    for fragment in text:
        expect(page.get_by_text(fragment, exact=False).first).to_be_visible()
    selectors = tuple(selectors) or ORDERED_STATE_REGIONS[state]
    context_selector = '.account-context' if layout == 'workspace' else '.public-realm'
    check_order(page, [context_selector, '.heading h1', *selectors])
    for selector in selectors:
        expect(page.locator('main#content').locator(selector).first).to_be_visible()
    if state == 'no-js':
        expect(page.locator('main#content').get_by_text('Passkeys require JavaScript.', exact=False)).to_have_count(1)
        expect(page.locator('[data-webauthn-intro]')).to_have_text('Passkeys require JavaScript. Use an allowed enrolled authenticator app or an enabled recovery path. The policy is unchanged.')
        expect(page.locator('[data-webauthn-form]')).to_be_hidden()
    elif state == 'unsupported':
        expect(page.locator('[data-webauthn-form]')).to_be_hidden()
    assert 'DEMO' not in page.locator('body').inner_text()
    assert 'QR preview' not in page.locator('body').inner_text()
    assert page.locator('[data-screen-selector], #screen-selector').count() == 0
    if layout == 'workspace':
        assert page.locator('aside.sidebar, aside[aria-label="Account navigation"]').count() == 1
        assert page.locator('details.shell-menu.workspace-menu[data-ui-dropdown]').count() == 1
        assert page.locator('body > aside.sidebar nav.sidebar-nav').count() == 1
        assert page.locator('body > aside.sidebar ~ .workspace > main#content').count() == 1
    else:
        assert page.locator('.access-layout > .access-introduction + main#content').count() == 1
        if state not in {'limited', 'unavailable'}:
            expect(page.locator('.public-realm')).to_have_text('Acme')
    combinations = []
    # Do not reload secret pages: their one-time response is part of the contract.
    for width in (1440, 390):
        for theme in ('light', 'dark'):
            page.set_viewport_size({'width': width, 'height': 960})
            page.emulate_media(color_scheme=theme)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (state, width, theme)
            expect(page.get_by_role('heading', name=heading, exact=True)).to_be_visible()
            if layout == 'public':
                introduction = page.locator('.access-introduction')
                assert introduction.is_visible() == (width >= 900)
            if state == 'totp':
                assert page.evaluate('''width=>{
                  const qr=document.querySelector('.ui-setup-secret img').getBoundingClientRect();
                  const manual=document.querySelector('#setup-key').parentElement.getBoundingClientRect();
                  return width<640 ? manual.top>=qr.bottom : manual.left>=qr.right;
                }''', width), 'manual setup key must stack below QR on narrow screens'
            if state == 'codes':
                assert page.evaluate('''()=>{
                  const input=document.querySelector('.ui-recovery-handoff [name=saved]');
                  const label=input.closest('label');
                  const walker=document.createTreeWalker(label,NodeFilter.SHOW_TEXT);
                  let node; while(node=walker.nextNode()) {
                    if(!node.textContent.includes('I saved my recovery codes.')) continue;
                    const range=document.createRange();range.selectNodeContents(node);
                    const text=range.getBoundingClientRect(),box=input.getBoundingClientRect();
                    return text.left>=box.right && text.left-box.right<=16 && Math.abs((text.top+text.bottom-box.top-box.bottom)/2)<=8;
                  }
                  return false;
                }'''), 'saved-code acknowledgment checkbox and text must remain adjacent'
            if state == 'policy':
                assert page.evaluate('''width=>{
                  const label=document.querySelector('label[for="mfa-mode"]').getBoundingClientRect();
                  const field=document.querySelector('#mfa-mode').getBoundingClientRect();
                  return width<1000 ? field.top>=label.bottom : field.left>=label.right;
                }''', width), 'settings row must stack on narrow screens'
            combinations.append([width, theme])
            if state in {'policy', 'challenge', 'codes', 'account', 'totp'} and (width, theme) in {(1440, 'light'), (390, 'dark')}:
                sample_masks = page.locator('#setup-key, .ui-setup-secret img, #recovery-codes, #access-code, #access-link, input[type=password], input[name=code]')
                page.screenshot(path=str(EVIDENCE / f'{page.context.browser.browser_type.name}-{state}-{width}-{theme}.png'), full_page=True, mask=[sample_masks])
    page.set_viewport_size({'width': 1440, 'height': 960})
    # Screenshots mask secrets after DOM assertions; no usable fixture credential in evidence.
    masks = page.locator('#setup-key, .ui-setup-secret img, #recovery-codes, #access-code, #access-link, input[type=password], input[name=code]')
    page.screenshot(path=str(EVIDENCE / f'{page.context.browser.browser_type.name}-{state}-{len(SEEN)}.png'), full_page=True, mask=[masks])
    visit = {'engine': page.context.browser.browser_type.name, 'engine_version': page.context.browser.version, 'combinations': combinations}
    if state in SEEN:
        SEEN[state]['visits'].append(visit)
    else:
        SEEN[state] = {'heading': heading, 'arrangement': list(selectors), 'visits': [visit]}


def verify_totp(page, secret):
    page.locator('[name=code]').fill(totp(secret))
    click(page, 'button', 'Verify')
    page.wait_for_url(BASE + '/account/**')


def handoff(page, lost=False, javascript=True, resume_secret=None):
    page.wait_for_url(BASE + '/account/security/recovery-codes')
    codes = page.locator('#recovery-codes').input_value().splitlines()
    assert len(codes) == len(set(codes)) == 10
    assert all(re.fullmatch('[A-Z2-7]{26}', code) for code in codes)
    SECRETS.extend(codes)
    stored = page.evaluate('JSON.stringify(localStorage)+JSON.stringify(sessionStorage)')
    assert not any(code in stored for code in codes)
    assert sessions() == 0
    assert page.locator('form.ui-recovery-handoff').get_attribute('hx-boost') == 'false'
    assert page.evaluate('JSON.parse(document.querySelector(\'meta[name="htmx-config"]\').content).historyCacheSize') == 0
    screen(page, 'codes', 'Save your recovery codes', ['#recovery-codes', '[data-ui-copy-codes]', '[data-ui-download-codes]', '[name=saved]', 'a[href$="recovery-codes/replace"]', 'button[type=submit]'])
    if javascript:
        # Clipboard is an external browser capability; stub its boundary and verify exact payload.
        page.evaluate("()=>{window.__copied=null; navigator.clipboard.writeText=async value=>{window.__copied=value};}")
        click(page, 'button', 'Copy codes')
        expect(page.locator('.ui-recovery-handoff [role=status]')).to_contain_text('copied', ignore_case=True)
        assert page.evaluate('window.__copied') == '\n'.join(codes)
        with page.expect_download() as download:
            click(page, 'button', 'Download codes')
        expect(page.locator('.ui-recovery-handoff [role=status]')).to_have_text('Recovery code download started. Check that you saved the file.')
        downloaded = Path(download.value.path()).read_text()
        assert downloaded == '\n'.join(codes) + '\n'
    # A hostile client bypassing native required validation still receives no authority.
    rejected = page.evaluate("""async()=>{
      const form=document.querySelector('.ui-recovery-handoff');
      const body=new URLSearchParams({csrf:form.elements.csrf.value});
      const response=await fetch(form.action,{method:'POST',body,redirect:'manual'});
      return response.status;
    }""")
    assert rejected == 422 and sessions() == 0
    enhanced = page.evaluate("""async()=>{
      const response=await fetch(location.href,{headers:{'HX-Request':'true'},redirect:'manual'});
      return {status:response.status,redirect:response.headers.get('HX-Redirect'),body:await response.text()};
    }""")
    assert enhanced['redirect'] and not any(code in enhanced['body'] for code in codes)
    # Native form validation refuses unchecked acknowledgment.
    click(page, 'button', 'Finish setup')
    assert page.url.endswith('/recovery-codes') and sessions() == 0
    if lost:
        generation = sql(f"SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL AND user_id='{USER}'")
        page.reload()
        screen(page, 'codes-lost', 'Replace unsaved codes', text=['Every code in the previous set will stop working.'])
        assert page.locator('#recovery-codes').count() == 0
        click(page, 'button', 'Replace code set')
        page.wait_for_url(BASE + '/account/security/recovery-codes')
        replacement = page.locator('#recovery-codes').input_value().splitlines()
        assert len(replacement) == 10 and not set(codes) & set(replacement)
        assert sql(f"SELECT count(*) FROM bloc.realm_mfa_recovery_generation WHERE id='{generation}' AND invalidated_at IS NULL") == '0'
        codes = replacement
        SECRETS.extend(codes)
    if resume_secret:
        generation = sql(f"SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL AND user_id='{USER}'")
        sql(f"UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE consumed_at IS NULL AND user_id='{USER}'")
        page.goto(BASE + '/mfa')
        login(page)
        page.goto(BASE + '/mfa')
        verify_totp(page, resume_secret)
        page.wait_for_url(BASE + '/account/security/recovery-codes')
        resumed = page.locator('#recovery-codes').input_value().splitlines()
        assert len(resumed) == 10 and not set(codes) & set(resumed)
        assert sql(f"SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL AND user_id='{USER}'") != generation
        codes = resumed
        SECRETS.extend(codes)
        assert sessions() == 0
    page.locator('[name=saved]').check()
    click(page, 'button', 'Finish setup')
    page.wait_for_url(BASE + '/account/profile')
    assert sessions() == 1
    page.go_back()
    assert page.locator('#recovery-codes').count() == 0, 'history must not restore the one-time code handoff'
    page.goto(BASE + '/account/profile')
    return codes


def enroll_totp(page):
    existing_factors = factors()
    replacement = page.get_by_role('heading', name='Replace your factors', exact=True).count() == 1
    page.get_by_role('button', name='Set up a replacement authenticator' if replacement else 'Set up an authenticator app', exact=True).click()
    page.wait_for_url(BASE + '/account/security/totp/setup')
    secret = page.locator('#setup-key').inner_text().replace(' ', '')
    SECRETS.append(secret)
    assert re.fullmatch('[A-Z2-7]+', secret)
    assert page.locator('.ui-setup-secret img').evaluate('(image)=>image.complete && image.naturalWidth>0')
    assert page.locator('form[action$="totp/confirm"]').get_attribute('hx-boost') == 'false'
    assert factors() == existing_factors, 'pending candidate must preserve existing protection without becoming active'
    screen(page, 'totp', 'Set up an authenticator app', ['.ui-setup-secret img', '#setup-key', '#mfa-totp-confirm label[for="confirmation-code"]', '#confirmation-code[aria-describedby="totp-confirmation-help"]', '#mfa-totp-confirm .ui-field > #totp-confirmation-help.ui-help', '#mfa-totp-confirm button[type=submit]'], ['Your factor becomes active only after confirmation.'])
    page.locator('[name=code]').fill(totp(secret))
    click(page, 'button', 'Confirm authenticator')
    return secret


def reauthenticate(page, operation, secret):
    page.goto(BASE + '/account/security/reauthenticate?operation=' + operation)
    screen(page, 'reauth', 'Confirm this security change', ['[name=current_password]', 'button[type=submit]'], ['for up to five minutes.'], 'workspace')
    page.locator('[name=current_password]').fill(PASSWORD)
    with page.expect_response(lambda response: response.url == BASE + '/account/security/reauthenticate' and response.request.method == 'POST') as password_proof:
        click(page, 'button', 'Verify and continue')
    assert password_proof.value.status in (200, 303)
    page.wait_for_url(re.compile(re.escape(BASE) + r'/(?:mfa|account/security/continue)$'))
    if page.url.endswith('/mfa'):
        verify_totp(page, secret)
    page.wait_for_url(BASE + '/account/security/continue')


def drop_handoff_response(page, confirm):
    """Drop the actual production GET response after its one-time server read."""
    cdp = page.context.new_cdp_session(page)
    cdp.send('Fetch.enable', {'patterns': [{'urlPattern': BASE + '/account/security/recovery-codes', 'requestStage': 'Response'}]})
    dropped = []
    def intercept(event):
        assert event['responseStatusCode'] == 200
        dropped.append(True)
        cdp.send('Fetch.failRequest', {'requestId': event['requestId'], 'errorReason': 'ConnectionClosed'})
    cdp.on('Fetch.requestPaused', intercept)
    with page.expect_event('requestfailed'):
        confirm()
    cdp.send('Fetch.disable')
    cdp.detach()
    assert dropped == [True] and sessions() == 0
    previous = sql(f"SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL AND user_id='{USER}'")
    page.goto(BASE + '/account/security/recovery-codes')
    screen(page, 'codes-lost', 'Replace unsaved codes', text=['Every code in the previous set will stop working.'])
    assert page.locator('#recovery-codes').count() == 0
    click(page, 'button', 'Replace code set')
    page.wait_for_url(BASE + '/account/security/recovery-codes')
    assert sql(f"SELECT id::text FROM bloc.realm_mfa_recovery_generation WHERE invalidated_at IS NULL AND user_id='{USER}'") != previous
    assert sql(f"SELECT count(*) FROM bloc.realm_mfa_recovery_generation WHERE id='{previous}' AND invalidated_at IS NULL") == '0'


def account_journey(browser):
    context = browser_context(browser, java_script_enabled=False, viewport={'width': 390, 'height': 960})
    page = context.new_page()
    login(page)
    page.goto(BASE + '/account/security')
    screen(page, 'empty', 'Account security', text=['No second factor enrolled.'], layout='workspace')
    click(page, 'link', 'Set up authenticator app')
    page.locator('[name=current_password]').fill(PASSWORD)
    click(page, 'button', 'Verify and continue')
    click(page, 'button', 'Set up authenticator app')
    page.wait_for_url(BASE + '/account/security/totp/setup')
    secret = page.locator('#setup-key').inner_text().replace(' ', '')
    SECRETS.append(secret)
    screen(page, 'totp', 'Set up an authenticator app', ['.ui-setup-secret img', '#setup-key', '#mfa-totp-confirm label[for="confirmation-code"]', '#confirmation-code[aria-describedby="totp-confirmation-help"]', '#mfa-totp-confirm .ui-field > #totp-confirmation-help.ui-help', '#mfa-totp-confirm button[type=submit]'])
    assert factors() == 0, 'unconfirmed candidate must not authenticate'
    page.locator('[name=code]').fill(totp(secret))
    drop_handoff_response(page, lambda: click(page, 'button', 'Confirm authenticator'))
    codes = handoff(page, lost=True, javascript=False)
    page.goto(BASE + '/account/security')
    screen(page, 'account', 'Account security', ['.ui-badge', '.ui-table-scroll', '.actions', 'section.form-group'], ['10 unused codes remaining'], 'workspace')
    factor = sql(f"SELECT id::text FROM bloc.realm_user_factor WHERE revoked_at IS NULL AND user_id='{USER}'")
    display_epoch = sql(f"SELECT factor_epoch::text FROM bloc.realm_user_mfa_state WHERE user_id='{USER}'")
    click(page, 'link', 'Rename')
    screen(page, 'label', 'Rename factor', ['[name=label]', 'button[type=submit]'], ['display name only'], 'workspace')
    page.locator('[name=label]').fill('Travel authenticator')
    click(page, 'button', 'Save name')
    page.wait_for_url(BASE + '/account/security')
    expect(page.get_by_role('cell').filter(has_text='Travel authenticator')).to_be_visible()
    assert sql(f"SELECT factor_epoch::text FROM bloc.realm_user_mfa_state WHERE user_id='{USER}'") == display_epoch
    click(page, 'link', 'Preferred verification method')
    page.locator('[name=factor]').select_option(factor)
    screen(page, 'preference', 'Preferred verification method', ['[name=factor]', 'form[action$="preferred"] button'], ['It never overrides realm policy.'], 'workspace')
    click(page, 'button', 'Save preference')
    assert sql(f"SELECT preferred_factor_id::text FROM bloc.realm_user_mfa_state WHERE user_id='{USER}'") == factor
    assert sql(f"SELECT factor_epoch::text FROM bloc.realm_user_mfa_state WHERE user_id='{USER}'") == display_epoch
    assert sessions() == 1
    login(page)
    page.goto(BASE + '/mfa')
    screen(page, 'challenge', 'Verify it’s you', ['.heading .intro', 'form[action$="/mfa/verify"] label[for=authentication-code]', '#authentication-code', 'form[action$="/mfa/verify"] .ui-field .ui-help', 'form[action$="/mfa/verify"] button[type=submit]'], ['Each code can be used once.'])
    expect(page.locator('.heading .intro')).to_have_text('Enter the six-digit code from your authenticator app.')
    page.locator('[name=code]').fill('000000' if totp(secret) != '000000' else '111111')
    with page.expect_response(BASE + '/mfa/verify') as invalid_response:
        click(page, 'button', 'Verify')
    assert invalid_response.value.status == 422
    screen(page, 'invalid', 'Check your code', text=['We couldn’t verify that proof.'])
    # Saved code is replacement-only authority, including without JavaScript.
    page.goto(BASE + '/mfa/recovery-code')
    screen(page, 'recovery-code', 'Recover your factors', ['label[for="saved-recovery-code"]', '#saved-recovery-code[placeholder="Enter a saved recovery code"]', '#saved-code-help.ui-help', 'button[type=submit]'], ['does not sign you into your account'])
    page.locator('[name=code]').fill(codes[0])
    click(page, 'button', 'Continue to replacement')
    page.wait_for_url(BASE + '/mfa')
    screen(page, 'replacement', 'Replace your factors', ['#feedback.ui-notice[role=status]', 'form[action$=\"totp/start\"]', 'a[href$=\"webauthn/setup\"]', 'form[action$=\"mfa/cancel\"]'], ['Your existing factors remain until a replacement is confirmed.', 'Set up a replacement authenticator', 'Create a replacement passkey'])
    assert sessions() == 0 and factors() == 1
    with page.expect_response(BASE + '/account/profile') as denied:
        page.goto(BASE + '/account/profile')
    assert denied.value.status == 303
    page.wait_for_url(BASE + '/login**')
    page.goto(BASE + '/mfa')
    replacement_secret = enroll_totp(page)
    handoff(page, javascript=False)
    assert factors() == 1
    # Replacement code cannot be reused after its consumption.
    login(page)
    page.goto(BASE + '/mfa/recovery-code')
    page.locator('[name=code]').fill(codes[0])
    click(page, 'button', 'Continue to replacement')
    assert not page.get_by_role('heading', name='Replace your factors', exact=True).count()
    login(page)
    page.goto(BASE + '/mfa')
    verify_totp(page, replacement_secret)
    reauthenticate(page, 'factor_remove:' + sql(f"SELECT id::text FROM bloc.realm_user_factor WHERE revoked_at IS NULL AND user_id='{USER}'"), replacement_secret)
    screen(page, 'remove', 'Remove your last factor?', ['[name=confirmed]', 'button[type=submit]'], ['password-only protection'], 'workspace')
    page.locator('[name=confirmed]').check()
    click(page, 'button', 'Remove factor')
    page.wait_for_url(BASE + '/account/security')
    assert factors() == 0
    page.locator('.workspace-menu > summary').click()
    click(page, 'button', 'Sign out')
    page.wait_for_url(BASE + '/login**')
    assert sessions() == 0
    context.close()



def shell_keyboard(page):
    summary = page.locator('.workspace-menu > summary')
    summary.focus()
    page.keyboard.press('Enter')
    expect(page.locator('.workspace-menu')).to_have_attribute('open', '')
    assert summary.evaluate("element=>getComputedStyle(element).outlineStyle !== 'none'")
    page.keyboard.press('Escape')
    assert page.locator('.workspace-menu').get_attribute('open') is None
    page.set_viewport_size({'width': 390, 'height': 960})
    toggle = page.get_by_role('button', name='Navigation menu', exact=True)
    toggle.click()
    expect(toggle).to_have_attribute('aria-expanded', 'true')
    page.keyboard.press('Tab')
    assert page.evaluate("document.activeElement.closest('.sidebar') !== null")
    page.keyboard.press('Escape')
    expect(toggle).to_have_attribute('aria-expanded', 'false')
    page.set_viewport_size({'width': 1440, 'height': 960})


def policy_journey(browser):
    context = browser_context(browser, )
    page = context.new_page()
    login(page, admin=True)
    page.goto(ADMIN + '/authentication')
    screen(page, 'policy', 'Authentication', ['#mfa-mode', 'input[name=mfa_totp_allowed]', 'input[name=mfa_webauthn_allowed]', 'input[name=mfa_recovery_codes_enabled]', 'input[name=mfa_admin_recovery_enabled]'], ['Two-factor authentication', 'Choose how people in Acme prove their identity after entering a password.'], 'workspace')
    shell_keyboard(page)
    assert page.locator('a[aria-current=page]').filter(has_text='Authentication').count() == 1
    page.locator('[name=mfa_mode]').select_option('required')
    click(page, 'button', 'Review changes')
    screen(page, 'impact', 'Review policy change', ['#confirmation dl', '[name=administrator_password]', '[name=confirmed]', '#confirmation button[type=submit]'], ['Review policy change', 'Existing noncompliant sessions must sign in again.'], 'workspace')
    # Impact numbers are guarded database-derived counts for this disposable fixture.
    counts = page.locator('#confirmation dd').all_text_contents()
    assert counts and all(re.fullmatch('[0-9]+', value) for value in counts)
    expected_enrollment = sql(f"SELECT count(*) FROM bloc.realm_user u JOIN bloc.realm_user_credential c ON c.realm_id=u.realm_id AND c.user_id=u.id WHERE u.realm_id='{REALM}' AND u.status='active' AND NOT EXISTS(SELECT FROM bloc.realm_user_factor f WHERE f.realm_id=u.realm_id AND f.user_id=u.id AND f.revoked_at IS NULL)")
    expected_stranded = sql(f"SELECT count(*) FROM bloc.realm_user u JOIN bloc.realm_user_credential c ON c.realm_id=u.realm_id AND c.user_id=u.id WHERE u.realm_id='{REALM}' AND u.status='active' AND EXISTS(SELECT FROM bloc.realm_user_factor f WHERE f.realm_id=u.realm_id AND f.user_id=u.id AND f.revoked_at IS NULL) AND NOT EXISTS(SELECT FROM bloc.realm_user_factor f WHERE f.realm_id=u.realm_id AND f.user_id=u.id AND f.revoked_at IS NULL AND f.kind IN('totp','webauthn'))")
    assert counts == [expected_enrollment, expected_stranded], 'policy impact must come from actual eligible account state'
    assert 'Example impact counts' not in page.locator('body').inner_text()
    page.locator('[name=administrator_password]').fill(PASSWORD)
    page.locator('[name=confirmed]').check()
    with page.expect_response(lambda response: response.url == ADMIN + '/authentication' and response.request.method == 'POST') as applied:
        click(page, 'button', 'Apply policy')
    submitted = parse_qs(applied.value.request.post_data)
    POLICY_SUBMISSIONS.append({'status': applied.value.status, 'fields': {key: value for key, value in submitted.items() if key not in {'csrf', 'administrator_password'}}, 'password_present': bool(submitted.get('administrator_password')), 'cache-control': applied.value.header_value('cache-control'), 'referrer-policy': applied.value.header_value('referrer-policy')})
    assert applied.value.status in (200, 303)
    page.wait_for_url(ADMIN + '/authentication')
    expect(page.get_by_role('heading', name='Authentication', exact=True)).to_be_visible()
    assert sql('SELECT mfa_mode FROM bloc.realm_authentication_settings') == 'required'
    page.reload()
    page.locator('[name=mfa_totp_allowed]').uncheck()
    page.locator('[name=mfa_webauthn_allowed]').uncheck()
    click(page, 'button', 'Review changes')
    screen(page, 'policy-invalid', 'Choose an allowed method', text=['Allow at least one method', 'Your policy has not changed.'], layout='workspace')
    expect(page.locator('main#content button[type=submit]')).to_have_count(0)
    click(page, 'link', 'Return to settings')
    expect(page.get_by_role('heading', name='Authentication', exact=True)).to_be_visible()
    sql('UPDATE bloc.realm_authentication_settings SET version=version+1')
    click(page, 'button', 'Review changes')
    screen(page, 'stale', 'This page is out of date', text=['Reload before continuing.'], layout='workspace')
    context.close()


def required_and_webauthn_states(browser):
    context = browser_context(browser, )
    page = context.new_page()
    login(page)
    page.wait_for_url(BASE + '/mfa')
    screen(page, 'required', 'Set up two-factor authentication', text=['Acme requires a second factor.'])
    page.get_by_role('link', name='Add a passkey or security key', exact=True).focus()
    assert page.locator('a[href$="webauthn/setup"]').evaluate('(element)=>element===document.activeElement')
    page.keyboard.press('Enter')
    screen(page, 'enroll-passkey', 'Add a passkey or security key', ['[name=label]', '[data-webauthn-submit]'], ['Private keys stay with your authenticator.'])
    original_parent = sql(f"SELECT expires_at::text||'|'||failed_attempts::text FROM bloc.realm_mfa_flow WHERE user_id='{USER}' AND consumed_at IS NULL AND parent_id IS NULL ORDER BY created_at DESC LIMIT 1")
    page.evaluate("()=>{navigator.credentials.create=async()=>{throw new DOMException('Canceled','NotAllowedError')};}")
    page.locator('[name=label]').fill('Canceled fixture key')
    click(page, 'button', 'Create passkey')
    expect(page.locator('[data-webauthn-status]')).to_contain_text('Canceled the prompt?')
    assert sql(f"SELECT expires_at::text||'|'||failed_attempts::text FROM bloc.realm_mfa_flow WHERE user_id='{USER}' AND consumed_at IS NULL AND parent_id IS NULL ORDER BY created_at DESC LIMIT 1") == original_parent
    assert factors() == sessions() == 0
    plain = browser_context(browser, java_script_enabled=False)
    plain.add_cookies(context.cookies())
    nojs = plain.new_page()
    nojs.goto(BASE + '/account/security/webauthn/setup')
    screen(nojs, 'no-js', 'Use an authenticator app', text=['Passkeys require JavaScript.', 'The policy is unchanged.'])
    assert nojs.locator('[data-webauthn-submit]').is_hidden()
    unsupported = browser_context(browser, )
    unsupported.add_cookies(context.cookies())
    unsupported.add_init_script('window.PublicKeyCredential=undefined')
    unsupported_page = unsupported.new_page()
    unsupported_page.goto(BASE + '/account/security/webauthn/setup')
    screen(unsupported_page, 'unsupported', 'Passkey unavailable', text=['can’t complete the request'])
    assert factors() == sessions() == 0
    unsupported.close()
    plain.close()
    page.goto(BASE + '/mfa')
    secret = enroll_totp(page)
    codes = handoff(page, lost=True, resume_secret=secret)
    assert factors() == sessions() == 1
    # Required-last removal remains a blocked replacement path after fresh proof.
    factor = sql(f"SELECT id::text FROM bloc.realm_user_factor WHERE revoked_at IS NULL AND user_id='{USER}'")
    reauthenticate(page, 'factor_remove:' + factor, secret)
    page.locator('[name=confirmed]').check()
    with page.expect_response(BASE + '/account/security/factors/' + factor + '/remove') as refused:
        click(page, 'button', 'Remove factor')
    assert refused.value.status == 409
    screen(page, 'required-remove', 'Keep an active factor', text=['You cannot remove your last factor.', 'Confirm a replacement first.'], layout='workspace')
    assert factors() == 1
    context.close()
    return secret, codes


def challenge_states(browser, secret):
    context = browser_context(browser, )
    page = context.new_page()
    login(page)
    deadline = sql(f"SELECT expires_at::text||'|'||failed_attempts::text FROM bloc.realm_mfa_flow WHERE consumed_at IS NULL AND user_id='{USER}' AND parent_id IS NULL ORDER BY created_at DESC LIMIT 1")
    page.goto(BASE + '/mfa/methods')
    assert sql(f"SELECT expires_at::text||'|'||failed_attempts::text FROM bloc.realm_mfa_flow WHERE consumed_at IS NULL AND user_id='{USER}' AND parent_id IS NULL ORDER BY created_at DESC LIMIT 1") == deadline
    screen(page, 'methods', 'Choose a verification method', ['a[href$=\"/mfa\"]', 'a[href$=\"mfa/recovery-code\"]', 'form[action$=\"mfa/cancel\"]'], ['Use an allowed factor enrolled on this account.', 'Authenticator app', 'Use a recovery code'])
    assert page.get_by_role('link', name='Passkey or security key', exact=True).count() == 0
    # Enrollment page must not offer unowned WebAuthn as an authenticating method.
    page.goto(BASE + '/mfa')
    click(page, 'button', 'Cancel')
    screen(page, 'cancel', 'Sign in', text=['You have left the verification flow.', 'Existing factors have not changed.'])
    expect(page.get_by_label('Email', exact=True)).to_have_attribute('placeholder', 'you@example.com')
    expect(page.get_by_label('Password', exact=True)).to_have_attribute('placeholder', 'Enter your password')
    login(page)
    sql(f"UPDATE bloc.realm_mfa_flow SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE consumed_at IS NULL AND user_id='{USER}'")
    page.goto(BASE + '/mfa')
    screen(page, 'expired', 'Sign in again', text=['This verification flow expired or changed.', 'No new access was granted.'])
    login(page)
    for attempt in range(5):
        page.locator('[name=code]').fill('000000' if totp(secret) != '000000' else '111111')
        with page.expect_response(BASE + '/mfa/verify') as rejected:
            click(page, 'button', 'Verify')
        assert rejected.value.status == (429 if attempt == 4 else 422)
    assert int(rejected.value.header_value('Retry-After')) > 0
    screen(page, 'limited', 'Try again later', text=['Too many unsuccessful attempts.', 'This flow has ended.'])
    assert re.search(r'\b[0-9]+\s*(?:seconds?|minutes?)', page.locator('main').inner_text()), 'visible retry period'
    assert sessions() == 1
    sql("UPDATE bloc.realm_authentication_settings SET mfa_mode='required',mfa_allowed_methods=ARRAY['webauthn'],mfa_recovery_codes_enabled=false,mfa_admin_recovery_enabled=false,version=version+1")
    login(page)
    page.goto(BASE + '/mfa')
    screen(page, 'no-recovery', 'Contact your administrator', text=['No allowed factor or enabled recovery path is available.', 'An administrator must change the policy'])
    assert page.locator('form[action$="totp/start"], a[href$="webauthn/setup"]').count() == 0
    sql("UPDATE bloc.realm_authentication_settings SET mfa_mode='disabled',version=version+1")
    login(page)
    page.goto(BASE + '/account/security')
    screen(page, 'disabled', 'Protection suspended', text=['Existing factors are retained but do not protect sign-in.', 'enrollment and code generation are unavailable.'], layout='workspace')
    assert page.get_by_role('link', name='Generate new codes', exact=True).count() == 0
    sql("UPDATE bloc.realm_authentication_settings SET mfa_mode='required',mfa_allowed_methods=ARRAY['totp','webauthn'],mfa_recovery_codes_enabled=true,mfa_admin_recovery_enabled=true,version=version+1")
    context.close()


def assisted_journey(browser):
    owner = browser_context(browser, )
    admin = owner.new_page()
    login(admin, admin=True)
    path = ADMIN + '/users/' + USER + '/mfa-recovery'
    admin.goto(path)
    screen(admin, 'assisted', 'Issue factor recovery', ['#feedback.ui-notice[role=status]', '.ui-field label[for="admin-password"]', '#admin-password[name=current_password]', 'label.check-row:has(input[name=identity_confirmed])', 'button[type=submit]'], ['Confirm the person’s identity before continuing.', 'Issuing a new link replaces the previous link'], 'workspace')
    password = admin.get_by_label('Administrator password', exact=True)
    expect(password).to_have_attribute('placeholder', 'Enter your current password')
    password.fill(PASSWORD)
    admin.get_by_role('checkbox', name='I have confirmed this person’s identity.', exact=True).check()
    click(admin, 'button', 'Issue recovery link')
    screen(admin, 'link', 'Recovery link created', ['.heading .intro', '#feedback.ui-notice[role=status]', 'label[for="access-link"]', '#access-link[readonly]', 'label[for="access-code"]', '#access-code[readonly]', '.meta-label > time[datetime]', '.settings-actions a.ui-button'], ['Share the link and the separate code through your approved recovery process.', 'This output is shown once.', 'Expires'], 'workspace')
    expiry = sql(f"SELECT to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM bloc.realm_mfa_recovery_link WHERE user_id='{USER}'")
    expect(admin.locator('label[for="access-code"]')).to_have_text('Separate code')
    expect(admin.locator('.meta-label > time')).to_have_text(expiry)
    expect(admin.locator('.meta-label > time')).to_have_attribute('datetime', expiry)
    old = admin.locator('#access-code').input_value()
    SECRETS.append(old)
    admin.goto(path)
    admin.locator('[name=current_password]').fill(PASSWORD)
    admin.locator('[name=identity_confirmed]').check()
    click(admin, 'button', 'Issue recovery link')
    code = admin.locator('#access-code').input_value()
    link = admin.locator('#access-link').input_value()
    SECRETS.extend([code, link])
    assert code != old and '#code=' in link
    # Reissuing the link invalidates its predecessor before either link is consumed.
    predecessor = browser_context(browser, java_script_enabled=False)
    previous_page = predecessor.new_page()
    previous_page.goto(BASE + '/recover-mfa')
    previous_page.locator('[name=code]').fill(old)
    click(previous_page, 'button', 'Continue')
    assert previous_page.get_by_role('heading', name='Confirm factor recovery', exact=True).count() == 0
    assert sql(f"SELECT consumed_at IS NOT NULL FROM bloc.realm_mfa_recovery_link WHERE user_id='{USER}'") == 'f'
    predecessor.close()
    context = browser_context(browser, )
    page = context.new_page()
    observed = []
    page.on('request', lambda request: observed.append(request.url))
    page.goto(link)
    assert '#' not in page.url
    assert page.locator('[name=code]').input_value() == code
    assert not any(code in url for url in observed)
    assert not sql(f"SELECT consumed_at IS NOT NULL FROM bloc.realm_mfa_recovery_link WHERE user_id='{USER}'") == 't'
    assert page.locator('[name=current_password]').count() == 0
    assert sql(f"SELECT count(*) FROM bloc.realm_mfa_recovery_form WHERE user_id='{USER}'") == '0'
    forged = page.evaluate('''async code=>{
      const response=await fetch(location.pathname+'/exchange',{method:'POST',body:new URLSearchParams({code}),redirect:'manual'});
      return response.status;
    }''', code)
    assert forged == 403
    assert sql(f"SELECT count(*) FROM bloc.realm_mfa_recovery_form WHERE user_id='{USER}'") == '0'
    context.close()

    # The recipient can enter the separate code and complete recovery with native forms.
    context = browser_context(browser, java_script_enabled=False)
    page = context.new_page()
    page.goto(BASE + '/recover-mfa')
    page.locator('[name=code]').fill(code)
    with page.expect_request(BASE + '/recover-mfa/exchange') as exchange:
        click(page, 'button', 'Continue')
    assert exchange.value.method == 'POST'
    assert 'csrf=' in exchange.value.post_data and 'code=' in exchange.value.post_data
    screen(page, 'password-recovery', 'Confirm factor recovery', ['label[for="current-password"]', '#current-password[placeholder="Enter your current password"]', '#password-recovery-help.ui-help', 'button[type=submit]'])
    expect(page.locator('#password-recovery-help')).to_have_text('This recovery link does not reset your password. Confirm your password to enter restricted factor replacement.')
    assert sessions() >= 1
    page.locator('[name=current_password]').fill(PASSWORD)
    click(page, 'button', 'Continue')
    page.wait_for_url(BASE + '/mfa')
    screen(page, 'replacement', 'Replace your factors', ['#feedback.ui-notice[role=status]', 'form[action$=\"totp/start\"]', 'a[href$=\"webauthn/setup\"]', 'form[action$=\"mfa/cancel\"]'], ['Your existing factors remain until a replacement is confirmed.', 'Set up a replacement authenticator', 'Create a replacement passkey'])
    assert sessions() == 0 and factors() == 1
    secret = enroll_totp(page)
    handoff(page, javascript=False)
    assert factors() == sessions() == 1
    # The consumed link cannot exchange again.
    plain = browser_context(browser, java_script_enabled=False)
    p = plain.new_page()
    p.goto(BASE + '/recover-mfa')
    p.locator('[name=code]').fill(code)
    click(p, 'button', 'Continue')
    assert p.get_by_role('heading', name='Confirm factor recovery', exact=True).count() == 0
    plain.close()
    context.close()
    owner.close()
    return secret



def finish_webauthn(page, route, action, first_submit=None):
    options_url = BASE + route + '/options'
    finish_url = BASE + route + '/finish'

    def terminal(response):
        return response.request.method == 'POST' and (
            response.url == finish_url or (response.url == options_url and response.status != 200)
        )

    for attempt in range(5):
        with page.expect_response(terminal) as completed:
            if attempt == 0 and first_submit is not None:
                first_submit()
            else:
                click(page, 'button', action)
        response = completed.value
        if response.url == options_url and response.status == 429:
            expect(page.get_by_role('button', name=action, exact=True)).to_be_enabled()
            wait_admission(response, page.locator('[data-webauthn-status]'))
            continue
        assert response.url == finish_url and response.status == 303, (response.url, response.status)
        page.wait_for_url(BASE + '/account/profile')
        return
    raise AssertionError('passkey options remained throttled after five declared retry windows')


def webauthn_journey(browser, secret):
    before = factors()
    context = browser_context(browser, )
    context.credentials.install()
    page = context.new_page()
    login(page)
    page.goto(BASE + '/mfa')
    verify_totp(page, secret)
    page.goto(BASE + '/account/security')
    click(page, 'link', 'Add passkey or security key')
    page.locator('[name=current_password]').fill(PASSWORD)
    click(page, 'button', 'Verify and continue')
    verify_totp(page, secret)
    page.wait_for_url(BASE + '/account/security/continue')
    click(page, 'link', 'Add a passkey or security key')
    page.locator('[name=label]').fill('Browser fixture passkey')
    finish_webauthn(page, '/account/security/webauthn/register', 'Create passkey')
    assert factors() == before + 1
    login(page)
    page.goto(BASE + '/mfa/webauthn')
    screen(page, 'passkey', 'Use your passkey',
           ['[data-webauthn-intro]', '[data-webauthn-status]', '[data-webauthn-submit]'],
           ['Your browser will ask you to verify using your passkey or security key.',
            'Canceled the prompt? Try again or choose another method.'])
    # A real request remains in flight while the shared busy affordance is inspected.
    pending = []
    def hold(route):
        if route.request.url != BASE + '/mfa/webauthn/options':
            route.abort('blockedbyclient')
            return
        pending.append(route)
    page.route('**/mfa/webauthn/options', hold)
    click(page, 'button', 'Use passkey')
    expect(page.locator('[data-webauthn-form]')).to_have_attribute('aria-busy', 'true')
    expect(page.locator('[data-webauthn-submit]')).to_be_disabled()
    expect(page.locator('[data-webauthn-submit]')).to_have_attribute('aria-busy', 'true')
    expect(page.locator('[data-webauthn-submit]')).to_have_text('Checking…')
    assert page.locator('[data-webauthn-submit]').evaluate("element=>getComputedStyle(element,'::before').content !== 'none'")
    expect(page.locator('[data-webauthn-status]')).to_contain_text('A repeated submission does not extend this flow.')
    expect(page.locator('[data-webauthn-status]')).to_have_attribute('aria-live', 'polite')
    assert page.locator('[data-webauthn-status]').evaluate('(element)=>{const box=element.getBoundingClientRect();return box.width<=1 && box.height<=1}')
    screen(page, 'loading', 'Verifying your proof')
    assert len(pending) == 1

    def release_options():
        pending[0].continue_()
        page.unroute('**/mfa/webauthn/options', hold)

    finish_webauthn(page, '/mfa/webauthn', 'Use passkey', release_options)
    assert sql(f"SELECT mfa_method FROM bloc.realm_user_session WHERE revoked_at IS NULL AND user_id='{USER}' ORDER BY created_at DESC LIMIT 1") == 'webauthn'
    # Repeated enhanced navigation preserves a single shell and one active content root.
    page.goto(BASE + '/account/security')
    for _ in range(3):
        page.get_by_role('link', name='Rename', exact=True).first.click()
        page.wait_for_url(BASE + '/account/security/factors/**/label')
        click(page, 'link', 'Cancel')
        page.wait_for_url(BASE + '/account/security')
        assert page.locator('main#content').count() == 1
        assert page.locator('aside[aria-label="Account navigation"]').count() == 1
    page.go_back()
    assert page.locator('main#content').count() == 1
    ENGINE_RESULTS.append({'engine': browser.browser_type.name, 'version': browser.version, 'authenticator': 'Playwright injected', 'production_registration_authentication': True, 'native_platform_dialog': False, 'certificate_validation': 'Chromium SPKI' if browser.browser_type.name == 'chromium' else 'scoped fixture acceptance; CONNECT relay independently checks SPKI + certificate hash'})
    context.close()


def unavailable_state(browser, secret):
    context = browser_context(browser, )
    page = context.new_page()
    login(page)
    page.goto(BASE + '/mfa')
    sql("CREATE FUNCTION bloc.browser_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$; CREATE TRIGGER browser_audit_failure BEFORE INSERT ON bloc.security_audit_event FOR EACH ROW WHEN (NEW.action='realm_mfa_sign_in') EXECUTE FUNCTION bloc.browser_audit_failure()")
    try:
        before = sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'")
        page.locator('[name=code]').fill(totp(secret))
        with page.expect_response(BASE + '/mfa/verify') as unavailable:
            click(page, 'button', 'Verify')
        assert unavailable.value.status == 503
        assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'") == before
        screen(page, 'unavailable', 'Temporarily unavailable', text=['No authentication success was recorded.'])
    finally:
        sql('DROP TRIGGER browser_audit_failure ON bloc.security_audit_event; DROP FUNCTION bloc.browser_audit_failure()')
    click(page, 'link', 'Try again')
    expect(page.get_by_role('heading', name='Verify it’s you', exact=True)).to_be_visible()
    verify_totp(page, secret)
    context.close()


def run():
    global RELAY
    RELAY = PinnedFixtureRelay()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, channel='chromium', args=['--no-proxy-server', '--host-resolver-rules=MAP bloc.example.test 127.0.0.1', '--ignore-certificate-errors-spki-list=' + os.environ['BLOC_TEST_SPKI']])
        try:
            account_journey(browser)
            new_principal('required-policy-and-terminal-states')
            policy_journey(browser)
            secret, codes = required_and_webauthn_states(browser)
            challenge_states(browser, secret)
            new_principal('assisted-recovery-and-audit-outage')
            prepare_totp(browser)
            secret = assisted_journey(browser)
            unavailable_state(browser, secret)
            new_principal('chromium-serialization')
            secret = prepare_totp(browser)
            webauthn_journey(browser, secret)
            cross_engines = (pw.firefox, pw.webkit) if MODE == 'journey' else ()
            for engine in cross_engines:
                cross = engine.launch(headless=True, proxy={'server': 'http://127.0.0.1:' + str(RELAY.server.server_address[1])})
                try:
                    new_principal(engine.name + '-serialization')
                    secret = prepare_totp(cross)
                    webauthn_journey(cross, secret)
                finally:
                    cross.close()
        finally:
            report = {'proof': 'realm_mfa_' + ('screen_contract' if sys.argv[1] == 'screen' else 'browser_contract'), 'engine': browser.version, 'engines': ENGINE_RESULTS, 'independent_principals': PRINCIPALS, 'response_header_checks': RESPONSE_CHECKS, 'response_header_violations': RESPONSE_VIOLATIONS, 'policy_submissions': POLICY_SUBMISSIONS, 'observed_admission_waits': ADMISSION_WAITS, 'continuous_journey': {'synthetic_user_id': SEED_USER, 'steps': ['optional account enrollment without JavaScript', 'actual network-lost recovery-code response and generation replacement', 'rename and preference native forms', 'password login and rejected proof', 'saved-code replacement-only recovery without JavaScript', 'rejected consumed recovery code', 'fresh factor reauthentication and optional-last removal', 'native signout']}, 'fixture_certificate_sha256': RELAY.certificate_hash, 'screens': SEEN, 'missing_states': sorted(INVENTORY - set(SEEN)), 'native_platform_coverage': False, 'fixture_controls': ['database-authority TTL/version/policy changes for terminal states', 'admission and consumed TOTP history retained; next real accepted TOTP window awaited'], 'notes': 'Real PostgreSQL authority and production HTTPS; no claim for unexecuted states/engines.'}
            (EVIDENCE / ('mfa-' + sys.argv[1] + '-report.json')).write_text(json.dumps(report, indent=2))
            print(json.dumps({key: value for key, value in report.items() if key not in {'screens', 'response_header_checks'}} | {'screen_count': len(SEEN), 'screen_states': sorted(SEEN), 'response_header_check_count': len(RESPONSE_CHECKS)}))
            browser.close()
            RELAY.close()
    logs = ''.join(path.read_text() for path in Path(os.environ['BLOC_REALM_SERVICE_LOGS']).glob('service-*.*'))
    assert all(secret not in logs for secret in SECRETS), 'secret in production service log'
    assert not RESPONSE_VIOLATIONS, 'required response headers: ' + json.dumps(RESPONSE_VIOLATIONS)
    assert set(SEEN) == INVENTORY, 'unproved approved screen states: ' + ', '.join(sorted(INVENTORY - set(SEEN)))
    expected_engines = {'chromium', 'firefox', 'webkit'} if MODE == 'journey' else {'chromium'}
    assert {result['engine'] for result in ENGINE_RESULTS} == expected_engines


if __name__ == '__main__':
    try:
        run()
    except BaseException:
        message = traceback.format_exc()
        for secret in sorted(set(SECRETS), key=len, reverse=True):
            message = message.replace(secret, '[REDACTED SYNTHETIC SECRET]')
        message = re.sub(r'\b[A-Z2-7]{26,64}\b', '[REDACTED SYNTHETIC SECRET]', message)
        message = re.sub(r'\b[0-9]{6}\b', '[REDACTED OTP]', message)
        message = re.sub(r'(#code=)[^\s<>\"\'&]+', r'\1[REDACTED SYNTHETIC SECRET]', message)
        print(message, file=sys.stderr)
        raise SystemExit(1)
