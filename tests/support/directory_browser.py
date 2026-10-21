"""Production HTTPS directory acceptance with synthetic data and pinned ingress."""
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, expect

MODE = sys.argv[1]
ORIGIN = os.environ['BLOC_TEST_ORIGIN']
UUID = re.compile(r'/[0-9a-f-]{36}$')


def sql(statement):
    database = urlparse(Path(os.environ['BLOC_DATABASE_URL_FILE']).read_text().strip()).path[1:]
    subprocess.run(['docker', 'exec', os.environ['BLOC_SETUP_CONTAINER'], 'psql', '-U', 'probe',
                    '-d', database, '-v', 'ON_ERROR_STOP=1', '-c', statement],
                   check=True, capture_output=True, text=True)


def capture(page, state):
    target = os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE')
    if target:
        target = Path(target)
        target.mkdir(parents=True, exist_ok=True)
        for width in [1280, 390]:
            page.set_viewport_size({'width': width, 'height': 1000})
            page.evaluate('scrollTo(0, 0)')
            page.evaluate('()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))')
            page.screenshot(path=str(target / f'{MODE}-{state}-{width}.png'), full_page=True)
        page.set_viewport_size({'width': 1280, 'height': 1000})


def submit(page, label):
    page.get_by_role('button', name=label, exact=True).click()


def setup(page):
    result = subprocess.run([os.environ['BLOC_TEST_BINARY'], 'admin', 'setup-code'],
                            check=True, capture_output=True, text=True)
    code = result.stdout.splitlines()[0][5:]
    page.goto(ORIGIN + '/admin/setup')
    for name, value in {'code': code, 'email': 'Owner@example.test',
                        'password': 'a synthetic password',
                        'password_confirmation': 'a synthetic password'}.items():
        page.locator(f'[name="{name}"]').fill(value)
    submit(page, 'Create administrator')
    page.wait_for_url(ORIGIN + '/admin/login')
    page.locator('[name=email]').fill('Owner@example.test')
    page.locator('[name=password]').fill('a synthetic password')
    submit(page, 'Sign in')
    page.wait_for_url(ORIGIN + '/admin')


def tenant(page, name='Acme'):
    page.goto(ORIGIN + '/admin/tenants/new')
    page.locator('[name=name]').fill(name)
    submit(page, 'Create tenant')
    page.wait_for_url(UUID)
    return page.url


def user(page, parent, email='Alice@example.com'):
    page.goto(parent + '/users/new')
    page.locator('[name=email]').fill(email)
    page.locator('[name=display_name]').fill('Alice')
    submit(page, 'Create user')
    page.wait_for_url(UUID)
    return page.url


def arrangement(page):
    expect(page.locator('header')).to_have_count(1)
    expect(page.locator('footer')).to_have_count(1)
    for width in [1280, 390]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        if page.locator('.grid').count():
            assert page.locator('.grid').evaluate('e=>getComputedStyle(e).display') == ('block' if width == 390 else 'grid')
            first = page.locator('.grid>div').bounding_box()
            aside = page.locator('.grid>aside').bounding_box()
            assert first and aside
            if width == 390:
                assert aside['y'] >= first['y'] + first['height']
            else:
                assert aside['x'] > first['x'] + first['width']
        if page.locator('.table-wrap').count():
            expect(page.locator('.table-wrap')).to_have_attribute('tabindex', '0')
            expect(page.locator('.table-wrap')).to_have_css('overflow-x', 'auto')
    page.set_viewport_size({'width': 1280, 'height': 1000})


def keyboard(page):
    page.reload()
    controls = page.locator('a[href],input:not([type="hidden"]),button,[tabindex="0"]').all()
    for control in controls:
        if control.is_visible() and control.is_enabled():
            page.keyboard.press('Tab')
            expect(control).to_be_focused()
            assert control.evaluate("e=>e.matches(':focus-visible') && getComputedStyle(e).outlineWidth==='2px' && getComputedStyle(e).outlineStyle==='solid'")


def loading(page):
    current = page.url
    waiting = []

    def hold(route):
        if route.request.headers.get('hx-request') == 'true' and route.request.method == 'GET':
            waiting.append(route)
        else:
            route.continue_()

    page.route('**/admin/tenants', hold)
    page.locator('.breadcrumbs a[href="/admin/tenants"]').click()
    expect(page.locator('main')).to_have_attribute('aria-busy', 'true')
    expect(page.locator('#directory-loading')).to_be_visible()
    capture(page, 'loading')
    assert len(waiting) == 1
    waiting.pop().continue_()
    expect(page.get_by_role('heading', name='Tenants', exact=True)).to_be_visible()
    page.unroute('**/admin/tenants', hold)
    page.goto(current)


def unavailable(page):
    current = page.url
    secret_values = [v for v in page.locator('input:not([type=hidden])').evaluate_all('es=>es.map(e=>e.value)') if v]
    secret_values += [v for v in page.locator('.mono').all_text_contents() if v.strip()]
    sql("UPDATE public._sqlx_migrations SET success=false WHERE version=3")
    try:
        response = page.goto(current)
        assert response.status == 503
        expect(page.locator('main')).to_contain_text('bloc cannot access the information needed for this request. Try again shortly.')
        for value in ['Acme', 'Alice@example.com', 'No tenants yet', 'No users yet'] + secret_values:
            expect(page.locator('main')).not_to_contain_text(value)
        expect(page.get_by_role('link', name='Try again', exact=True)).to_have_attribute('href', urlparse(current).path)
        capture(page, 'unavailable')
    finally:
        sql("UPDATE public._sqlx_migrations SET success=true WHERE version=3")
    page.get_by_role('link', name='Try again', exact=True).click()
    expect(page.locator('h1')).not_to_have_text('Directory access')


def expired(page):
    sql("UPDATE bloc.administrator_session SET revoked_at=clock_timestamp()")
    page.reload()
    page.wait_for_url(ORIGIN + '/admin/login?expired=1')
    expect(page.locator('main')).not_to_contain_text('Acme')
    expect(page.locator('main')).not_to_contain_text('Alice@example.com')


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(
        headless=True, executable_path=os.environ.get('BLOC_BROWSER_EXECUTABLE', playwright.chromium.executable_path),
        args=['--no-proxy-server', '--ignore-certificate-errors-spki-list=' + os.environ['BLOC_TEST_SPKI'],
              '--host-resolver-rules=MAP bloc.example.test 127.0.0.1'])
    context = browser.new_context(viewport={'width': 1280, 'height': 1000})
    page = context.new_page()
    page.set_default_timeout(10000)
    setup(page)
    if MODE == 't1':
        page.goto(ORIGIN + '/admin/tenants')
        expect(page.get_by_role('heading', name='No tenants yet')).to_be_visible()
        capture(page, 'empty')
        first = tenant(page)
        second = tenant(page)
        assert first != second
        page.goto(ORIGIN + '/admin/tenants')
        expect(page.locator('th')).to_have_text(['Name / tenant ID', 'Status', 'Created (UTC)'])
        expect(page.locator('tbody tr')).to_have_count(2)
        for target in [first, second]:
            expect(page.locator('main')).to_contain_text(target.rsplit('/', 1)[1])
    elif MODE == 't2':
        page.goto(ORIGIN + '/admin/tenants/new')
        expect(page.get_by_role('heading', name='Tenant profile')).to_be_visible()
        expect(page.locator('.form')).to_have_css('max-width', '680px')
        expect(page.locator('main')).to_contain_text('Created tenants start active. Duplicate names create independent directories.')
        capture(page, 'default')
        submit(page, 'Create tenant')
        expect(page.locator('#feedback')).to_be_focused()
        expect(page.locator('[name=name]')).to_have_attribute('aria-invalid', 'true')
    elif MODE == 't3':
        target = tenant(page, '<script>name</script>')
        expect(page.locator('h1')).to_have_text('<script>name</script>')
        expect(page.locator('main script')).to_have_count(0)
        page.locator('[name=name]').fill('Acme')
        submit(page, 'Save changes')
        expect(page.locator('h1')).to_have_text('Acme')
        expect(page.locator('[name=version]')).to_have_value('2')
        expect(page.locator('.grid>div h2')).to_have_text(['Profile', 'Tenant status'])
        expect(page.locator('.grid>aside h2')).to_have_text(['Record', 'Directory'])
        capture(page, 'default')
        page.get_by_role('link', name='Suspend tenant', exact=True).click()
        expect(page.locator('#confirmation')).to_be_focused()
        expect(page.locator('#confirmation [name=version]')).to_have_value('2')
        expect(page.locator('#confirmation')).to_contain_text('Individual user statuses will remain unchanged.')
        capture(page, 'confirmation')
        page.locator('#confirmation').get_by_role('link', name='Cancel').click()
        expect(page.locator('#status-action')).to_be_focused()
    elif MODE == 'u1':
        parent = tenant(page, 'A' * 128)
        page.goto(parent + '/users')
        expect(page.get_by_role('heading', name='No users yet')).to_be_visible()
        expect(page.locator('.context')).to_contain_text('Tenant: ' + 'A' * 128)
        capture(page, 'empty')
        user(page, parent)
        page.goto(parent + '/users')
        expect(page.locator('th')).to_have_text(['Email / user ID', 'Display name', 'User status', 'Created (UTC)'])
    elif MODE == 'u2':
        parent = tenant(page, 'A' * 128)
        page.goto(parent + '/users/new')
        expect(page.locator('.context')).to_be_visible()
        expect(page.get_by_role('heading', name='User profile')).to_be_visible()
        expect(page.locator('main')).to_contain_text('No verification email is sent and no credentials are created.')
        capture(page, 'default')
        page.locator('[name=email]').fill('bad')
        submit(page, 'Create user')
        expect(page.locator('#feedback')).to_be_focused()
        expect(page.locator('[name=email]')).to_have_value('bad')
    elif MODE == 'u3':
        parent = tenant(page)
        target = user(page, parent)
        capture(page, 'default')
        page.goto(parent)
        page.locator('[name=name]').fill('A' * 128)
        submit(page, 'Save changes')
        expect(page.locator('h1')).to_have_text('A' * 128)
        page.goto(target)
        page.locator('[name=display_name]').fill('B' * 128)
        submit(page, 'Save changes')
        expect(page.locator('[name=version]')).to_have_value('2')
        expect(page.locator('.grid>div h2')).to_have_text(['Profile', 'User status'])
        expect(page.locator('.grid>aside h2')).to_have_text(['Record'])
        for text in ['Combined directory status', 'Unverified', 'This user cannot sign in.']:
            expect(page.locator('main')).to_contain_text(text)
    else:
        parent = tenant(page)
        target = user(page, parent)
        for _ in range(2):
            page.get_by_role('link', name='Suspend user', exact=True).click()
            expect(page.locator('#confirmation')).to_be_focused()
            page.locator('#confirmation').get_by_role('link', name='Cancel').click()
            expect(page.locator('#status-action')).to_be_focused()
        page.locator('[name=email]').fill('bad')
        submit(page, 'Save changes')
        expect(page.locator('#feedback')).to_be_focused()
        page.locator('[name=email]').fill('Alice@example.com')
        submit(page, 'Save changes')
        expect(page.locator('#feedback')).to_have_count(0)
        page.route('**/users/*', lambda route: route.abort() if route.request.method == 'POST' else route.continue_())
        page.locator('[name=display_name]').fill('Lost')
        submit(page, 'Save changes')
        expect(page.locator('#feedback')).to_contain_text('Do not automatically resubmit.')
        page.unroute('**/users/*')
        page.reload()
        expect(page.locator('[name=display_name]')).to_have_value('Alice')
        page.goto(parent + '/users/new')
        page.locator('[name=email]').fill('Lost@example.com')
        posts = []

        def lose_after_commit(route):
            if route.request.method == 'POST':
                posts.append(route.request.url)
                # Forward through the same trusted loopback boundary, discard the committed response.
                connection = http.client.HTTPConnection('127.0.0.1', 31001, timeout=10)
                headers = dict(route.request.all_headers())
                headers['Host'] = urlparse(ORIGIN).netloc
                headers['X-Forwarded-Proto'] = 'https'
                headers['X-Forwarded-For'] = '127.0.0.1'
                connection.request('POST', urlparse(route.request.url).path,
                                   body=route.request.post_data, headers=headers)
                response = connection.getresponse()
                response.read()
                assert response.status in (200, 303)
                connection.close()
                route.abort()
            else:
                route.continue_()

        page.route('**/users', lose_after_commit)
        submit(page, 'Create user')
        expect(page.locator('#feedback')).to_contain_text('Do not automatically resubmit.')
        expect(page.get_by_role('link', name='Review directory', exact=True)).to_have_attribute('href', urlparse(parent).path + '/users')
        page.unroute('**/users', lose_after_commit)
        page.get_by_role('link', name='Review directory', exact=True).click()
        expect(page.locator('main')).to_contain_text('Lost@example.com')
        assert len(posts) == 1
        page.go_back()
        page.go_forward()
        assert len(posts) == 1
        page.goto(target)
        other = context.new_page()
        other.goto(target)
        other.locator('[name=display_name]').fill('Current')
        submit(other, 'Save changes')
        expect(other.locator('[name=version]')).to_have_value('2')
        page.locator('[name=display_name]').fill('Stale')
        submit(page, 'Save changes')
        expect(page.locator('#feedback')).to_contain_text('This record changed after you opened the form. Nothing was saved.')
        expect(page.get_by_role('link', name='Reload current record', exact=True)).to_be_visible()
        page.get_by_role('link', name='Reload current record', exact=True).click()
        expect(page.locator('[name=display_name]')).to_have_value('Current')
        page.get_by_role('link', name='Suspend user', exact=True).click()
        expect(page.locator('#confirmation [name=version]')).to_have_value('2')
        other.reload()
        other.locator('[name=display_name]').fill('Third')
        submit(other, 'Save changes')
        expect(other.locator('[name=version]')).to_have_value('3')
        page.locator('#confirmation').get_by_role('button', name='Suspend user', exact=True).click()
        expect(page.locator('#feedback')).to_contain_text('This record changed after you opened the form.')
        page.get_by_role('link', name='Reload current record', exact=True).click()
        expect(page.locator('#status-action')).to_have_text('Suspend user')
        other.close()
        nojs = browser.new_context(java_script_enabled=False)
        nojs.add_cookies(context.cookies())
        plain = nojs.new_page()
        plain.goto(parent + '/users/new')
        plain.locator('[name=email]').fill('Nojs@example.com')
        submit(plain, 'Create user')
        plain.wait_for_url(UUID)
        expect(plain.locator('main')).to_contain_text('Unverified')
        plain.locator('[name=display_name]').fill('Nojs edited')
        submit(plain, 'Save changes')
        expect(plain.locator('[name=version]')).to_have_value('2')
        plain.get_by_role('link', name='Suspend user', exact=True).click()
        expect(plain.locator('#confirmation')).to_contain_text('Only this user’s directory status will change.')
        submit(plain, 'Suspend user')
        expect(plain.get_by_role('link', name='Reactivate user', exact=True)).to_be_visible()
        plain.get_by_role('link', name='Reactivate user', exact=True).click()
        submit(plain, 'Reactivate user')
        expect(plain.locator('[name=version]')).to_have_value('4')
        plain.goto(parent)
        plain.locator('[name=name]').fill('Nojs tenant')
        submit(plain, 'Save changes')
        expect(plain.locator('[name=version]')).to_have_value('2')
        plain.get_by_role('link', name='Suspend tenant', exact=True).click()
        submit(plain, 'Suspend tenant')
        expect(plain.get_by_role('link', name='Reactivate tenant', exact=True)).to_be_visible()
        plain.get_by_role('link', name='Reactivate tenant', exact=True).click()
        plain.locator('#confirmation').get_by_role('link', name='Cancel').click()
        expect(plain.locator('[name=version]')).to_have_value('3')
        plain.goto(ORIGIN + '/admin/tenants/new')
        plain.locator('[name=name]').fill('Nojs independent')
        submit(plain, 'Create tenant')
        plain.wait_for_url(UUID)
        expect(plain.locator('h1')).to_have_text('Nojs independent')
        nojs.close()
        page.get_by_role('link', name='Administration', exact=True).click()
        expect(page.locator('link[rel=stylesheet][href="/assets/admin.css"]')).to_have_count(1)
        expect(page.locator('main')).to_have_class('home')
        page.get_by_role('link', name='Tenants', exact=True).click()
        expect(page.locator('link[rel=stylesheet][href="/assets/directory.css"]')).to_have_count(1)
        page.goto(target)
    if MODE in ('t1', 'u1'):
        current = page.url
        response = page.goto(current + '?cursor=invalid')
        assert response.status == 422
        expect(page.locator('#feedback')).to_contain_text('This page link is invalid. Return to the first page.')
        expect(page.locator('tbody tr')).to_have_count(0)
        if MODE == 'u1':
            expect(page.locator('.context')).to_contain_text('Tenant: ' + 'A' * 128)
        capture(page, 'invalid-cursor')
        page.get_by_role('link', name='First page', exact=True).click()
        expect(page.locator('tbody tr')).not_to_have_count(0)
    keyboard(page)
    arrangement(page)
    capture(page, 'result')
    if MODE != 'interactions':
        loading(page)
        unavailable(page)
        expired(page)
    print(json.dumps({'mode': MODE, 'widths': [1280, 390], 'production_https': True}))
    context.close()
    browser.close()
