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
from ui_browser import control_density, keyboard_focus, choose_appearance, workspace_menus

MODE = sys.argv[1]
ORIGIN = os.environ['BLOC_TEST_ORIGIN']
UUID = re.compile(r'/[0-9a-f-]{36}$')


def sql(statement):
    database = urlparse(Path(os.environ['BLOC_DATABASE_URL_FILE']).read_text().strip()).path[1:]
    result = subprocess.run(['docker', 'exec', os.environ['BLOC_SETUP_CONTAINER'], 'psql', '-U', 'probe',
                    '-d', database, '-v', 'ON_ERROR_STOP=1', '-At', '-c', statement],
                   check=True, capture_output=True, text=True)
    return result.stdout.strip()


def capture(page, state):
    target = os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE')
    if target:
        target = Path(target)
        target.mkdir(parents=True, exist_ok=True)
        for width in [1280, 390]:
            page.set_viewport_size({'width': width, 'height': 1000})
            control_density(page)
            page.evaluate('scrollTo(0, 0)')
            page.evaluate('()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))')
            page.screenshot(path=str(target / f'{MODE}-{state}-{width}.png'), full_page=True, animations='disabled')
            choose_appearance(page, 'dark')
            page.screenshot(path=str(target / f'{MODE}-{state}-dark-{width}.png'), full_page=True, animations='disabled')
            choose_appearance(page, 'system')
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


def realm(page, name='Acme'):
    page.goto(ORIGIN + '/admin/realms/new')
    page.locator('[name=name]').fill(name)
    submit(page, 'Create realm')
    page.wait_for_url(UUID)
    return page.url


def user(page, parent, email='Alice@example.com'):
    page.goto(parent + '/users/new')
    page.locator('[name=email]').fill(email)
    page.locator('[name=display_name]').fill('Alice')
    submit(page, 'Create user')
    page.wait_for_url(UUID)
    return page.url



def record(page, table, identity, parent=None):
    data = json.loads(sql(f"SELECT json_build_object('id',id::text,'version',version,'created',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),'updated',to_char(updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')) FROM bloc.{table} WHERE id='{identity}'"))
    labels = ['Realm ID' if parent is None else 'User ID']
    values = [identity]
    if parent:
        labels += ['Realm ID · immutable']
        values += [parent.rsplit('/', 1)[1]]
    labels += ['Version', 'Created', 'Updated']
    values += [str(data['version']), data['created'], data['updated']]
    if parent:
        labels += ['Email verification']
        values += ['Unverified']
    expect(page.locator('aside dt')).to_have_text(labels)
    expect(page.locator('aside dd')).to_have_text(values)
    for value in [data['created'], data['updated']]:
        assert re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z', value)


def realm_context(page, parent, name, status='Active'):
    expect(page.locator('.context strong')).to_have_text('Realm: ' + name)
    expect(page.locator('.context .mono')).to_have_text(parent.rsplit('/', 1)[1])
    expect(page.locator('.context .badge')).to_have_text(status)
    assert page.locator('.context').bounding_box()['y'] < page.locator('.heading').bounding_box()['y']


def profile_form(page, user):
    expect(page.locator('.form')).to_have_css('max-width', '680px')
    expect(page.locator('.form>div')).to_have_count(1)
    expect(page.locator('.form aside')).to_have_count(0)
    expect(page.locator('.form select')).to_have_count(0)
    fields = ['email', 'display_name'] if user else ['name']
    expect(page.locator('.form input:not([type=hidden])')).to_have_count(len(fields))
    assert page.locator('.form input:not([type=hidden])').evaluate_all('es=>es.map(e=>e.name)') == fields
    actions = page.locator('.form .actions')
    expect(actions.locator('button,a')).to_have_text(['Create user' if user else 'Create realm', 'Cancel'])
    assert actions.locator('button').bounding_box()['x'] < actions.locator('a').bounding_box()['x']
    if user:
        context = page.locator('.context').bounding_box()
        profile = page.locator('.form').bounding_box()
        assert context['y'] + context['height'] <= profile['y']
        expect(page.locator('#email-help')).to_have_text('Unverified. Domain case is normalized; local-part case is preserved.')
        expect(page.locator('label[for=display-name]')).to_have_text('Display name (optional)')
        expect(page.locator('#display-help')).to_have_text('Up to 128 characters and 512 UTF-8 bytes. Control characters are not allowed.')
    else:
        expect(page.locator('#name-help')).to_have_text('1–128 characters, up to 512 UTF-8 bytes. Names do not need to be unique.')


def continuation(page, table, parent=None):
    if parent:
        realm_id = parent.rsplit('/', 1)[1]
        sql(f"INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) SELECT gen_random_uuid(),'{realm_id}','Continuation'||n||'@example.com','2026-01-01'::timestamptz+n*interval '1 second','2026-01-01'::timestamptz+n*interval '1 second' FROM generate_series(1,50)n")
        where = f"WHERE realm_id='{realm_id}'"
        destination = parent + '/users'
    else:
        sql("INSERT INTO bloc.realm(id,name,created_at,updated_at) SELECT gen_random_uuid(),'Continuation','2026-01-01'::timestamptz+n*interval '1 second','2026-01-01'::timestamptz+n*interval '1 second' FROM generate_series(1,49)n")
        where = ''
        destination = ORIGIN + '/admin/realms'
    expected = json.loads(sql(f"SELECT json_agg(id::text ORDER BY created_at,id) FROM bloc.{table} {where}"))
    page.goto(destination)
    first = page.locator('tbody tr').evaluate_all('es=>es.map(e=>e.dataset.record)')
    assert first == expected[:50]
    page.get_by_role('link', name='Next page →', exact=True).click()
    expect(page.locator('tbody tr')).to_have_count(1)
    last = page.locator('tbody tr').evaluate_all('es=>es.map(e=>e.dataset.record)')
    assert last == expected[50:]
    assert len(set(first + last)) == 51
    expect(page.locator('a[rel=next]')).to_have_count(0)
    if parent:
        realm_context(page, parent, 'A' * 128)
    page.goto(destination)


def cancelled_forms(page, parent, target):
    snapshot = sql("SELECT json_build_object('realms',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM bloc.realm t),'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM bloc.realm_user u),'events',(SELECT count(*) FROM bloc.security_audit_event))")
    for path, field, value, destination in [
        (ORIGIN + '/admin/realms/new', 'name', 'Abandoned realm', ORIGIN + '/admin/realms'),
        (parent, 'name', 'Abandoned rename', parent),
        (parent + '/users/new', 'email', 'Abandoned@example.com', parent + '/users'),
        (target, 'display_name', 'Abandoned profile', target),
    ]:
        page.goto(path)
        page.locator(f'[name={field}]').fill(value)
        page.locator('form .actions').get_by_role('link', name='Cancel', exact=True).click()
        page.wait_for_url(destination)
        assert sql("SELECT json_build_object('realms',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM bloc.realm t),'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM bloc.realm_user u),'events',(SELECT count(*) FROM bloc.security_audit_event))") == snapshot
        page.goto(path)
        page.locator(f'[name={field}]').fill(value)
        page.locator('.breadcrumbs a[href="/admin/realms"]').click()
        page.wait_for_url(ORIGIN + '/admin/realms')
        assert sql("SELECT json_build_object('realms',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM bloc.realm t),'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM bloc.realm_user u),'events',(SELECT count(*) FROM bloc.security_audit_event))") == snapshot
    for path, label in [(parent, 'Suspend realm'), (target, 'Suspend user')]:
        page.goto(path)
        page.get_by_role('link', name=label, exact=True).click()
        page.locator('#confirmation').get_by_role('link', name='Cancel', exact=True).click()
        expect(page.locator('#status-action')).to_be_focused()
        assert sql("SELECT json_build_object('realms',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM bloc.realm t),'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM bloc.realm_user u),'events',(SELECT count(*) FROM bloc.security_audit_event))") == snapshot
    page.goto(target)


def saving(page):
    waiting = []
    def hold(route):
        if route.request.method == 'POST':
            waiting.append(route)
        else:
            route.continue_()
    page.route('**/users/*', hold)
    submit(page, 'Save changes')
    expect(page.locator('main')).to_have_attribute('aria-busy', 'true')
    expect(page.locator('#content form button')).to_be_disabled()
    expect(page.locator('#content form button')).to_have_text('Saving…')
    feedback = page.locator('form .working[role=status]')
    expect(feedback).to_be_visible()
    expect(feedback).to_have_text('Saving… Wait for a result before submitting again.')
    assert page.locator('form .working').evaluate("e=>e.getAttribute('role')==='status'")
    assert len(waiting) == 1
    waiting.pop().continue_()
    page.wait_for_load_state('networkidle')
    expect(page.locator('#content form button')).to_be_enabled()
    expect(page.locator('main')).not_to_have_attribute('aria-busy', 'true')
    page.unroute('**/users/*', hold)


def arrangement(page):
    workspace_menus(page)
    expect(page.get_by_role('navigation', name='Administration', exact=True)).to_have_count(1)
    expect(page.locator('.sidebar [aria-current=page]')).to_have_text('Realms')
    for width in [1280, 390]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        if page.locator('.grid').count():
            expect(page.locator('.grid')).to_have_css('display', 'grid')
            first = page.locator('.grid>div').bounding_box()
            aside = page.locator('.grid>aside').bounding_box()
            assert first and aside
            assert aside['y'] >= first['y'] + first['height']
        if page.locator('.table-wrap').count():
            expect(page.locator('.table-wrap')).to_have_attribute('tabindex', '0')
            expect(page.locator('.table-wrap')).to_have_css('overflow-x', 'auto')
    page.set_viewport_size({'width': 1280, 'height': 1000})


def keyboard(page):
    page.reload()
    controls = page.locator('a[href],summary,input:not([type="hidden"]),button,select,[tabindex="0"]').all()
    for control in controls:
        if control.is_visible() and control.is_enabled():
            page.keyboard.press('Tab')
            keyboard_focus(control)


def loading(page):
    current = page.url
    waiting = []

    def hold(route):
        if route.request.headers.get('hx-request') == 'true' and route.request.method == 'GET':
            waiting.append(route)
        else:
            route.continue_()

    page.route('**/admin/realms', hold)
    page.locator('.breadcrumbs a[href="/admin/realms"]').click()
    expect(page.locator('main')).to_have_attribute('aria-busy', 'true')
    expect(page.locator('#directory-loading')).to_be_visible()
    capture(page, 'loading')
    assert len(waiting) == 1
    waiting.pop().continue_()
    expect(page.get_by_role('heading', name='Realms', exact=True)).to_be_visible()
    expect(page.locator('h1')).to_be_focused()
    page.unroute('**/admin/realms', hold)
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
        for value in ['Acme', 'Alice@example.com', 'No realms yet', 'No users yet'] + secret_values:
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
        page.goto(ORIGIN + '/admin/realms')
        expect(page.get_by_role('heading', name='No realms yet')).to_be_visible()
        capture(page, 'empty')
        first = realm(page)
        second = realm(page)
        assert first != second
        page.goto(ORIGIN + '/admin/realms')
        expect(page.locator('th')).to_have_text(['Name / realm ID', 'Status', 'Created (UTC)'])
        expect(page.locator('tbody tr')).to_have_count(2)
        expect(page.locator('.heading h1')).to_have_text('Realms')
        expect(page.locator('.heading .button')).to_have_text('Create realm')
        assert page.locator('.heading h1').bounding_box()['x'] < page.locator('.heading .button').bounding_box()['x']
        expect(page.locator('tbody .badge')).to_have_text(['Active', 'Active'])
        for value in page.locator('tbody tr td:last-child').all_text_contents():
            assert re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z', value.strip())
        for target in [first, second]:
            expect(page.locator('main')).to_contain_text(target.rsplit('/', 1)[1])
        continuation(page, 'realm')
    elif MODE == 't2':
        page.goto(ORIGIN + '/admin/realms/new')
        expect(page.get_by_role('heading', name='Realm profile')).to_be_visible()
        expect(page.locator('.form')).to_have_css('max-width', '680px')
        profile_form(page, False)
        expect(page.locator('main')).to_contain_text('Created realms start active. Duplicate names create independent directories.')
        capture(page, 'default')
        submit(page, 'Create realm')
        expect(page.locator('#feedback')).to_have_count(0)
        expect(page.locator('[name=name]')).to_be_focused()
        expect(page.locator('[name=name]')).to_have_attribute('aria-invalid', 'true')
        page.locator('form .actions').get_by_role('link', name='Cancel', exact=True).click()
        page.wait_for_url(ORIGIN + '/admin/realms')
        expect(page.get_by_role('heading', name='No realms yet')).to_be_visible()
        page.get_by_role('link', name='Create realm', exact=True).click()
        expect(page.locator('[name=name]')).to_have_value('')
    elif MODE == 't3':
        target = realm(page, '<script>name</script>')
        expect(page.locator('h1')).to_have_text('<script>name</script>')
        expect(page.locator('main script')).to_have_count(0)
        page.locator('[name=name]').fill('Acme')
        submit(page, 'Save changes')
        expect(page.locator('h1')).to_have_text('Acme')
        expect(page.locator('[name=version]')).to_have_value('2')
        expect(page.locator('.grid>div h2')).to_have_text(['Profile', 'Realm status'])
        expect(page.locator('.grid>aside h2')).to_have_text(['Record'])
        expect(page.locator('.heading').get_by_role('link', name='View users', exact=True)).to_have_attribute('href', urlparse(target).path + '/users')
        record(page, 'realm', target.rsplit('/', 1)[1])
        capture(page, 'default')
        page.get_by_role('link', name='Suspend realm', exact=True).click()
        expect(page.locator('#confirmation')).to_be_focused()
        expect(page.locator('#confirmation [name=version]')).to_have_value('2')
        expect(page.locator('#confirmation')).to_contain_text('Individual user statuses will remain unchanged.')
        capture(page, 'confirmation')
        page.locator('#confirmation').get_by_role('link', name='Cancel').click()
        expect(page.locator('#status-action')).to_be_focused()
    elif MODE == 'u1':
        parent = realm(page, 'A' * 128)
        page.goto(parent + '/users')
        expect(page.get_by_role('heading', name='No users yet')).to_be_visible()
        expect(page.locator('.context')).to_contain_text('Realm: ' + 'A' * 128)
        realm_context(page, parent, 'A' * 128)
        capture(page, 'empty')
        user(page, parent)
        page.goto(parent + '/users')
        expect(page.locator('th')).to_have_text(['Email / user ID', 'Display name', 'User status', 'Created (UTC)'])
        realm_context(page, parent, 'A' * 128)
        expect(page.locator('.intro')).to_have_text('Independent users belonging to this realm. Directory records do not authenticate anyone.')
        continuation(page, 'realm_user', parent)
    elif MODE == 'u2':
        parent = realm(page, 'A' * 128)
        page.goto(parent + '/users/new')
        expect(page.locator('.context')).to_be_visible()
        expect(page.get_by_role('heading', name='User profile')).to_be_visible()
        realm_context(page, parent, 'A' * 128)
        profile_form(page, True)
        expect(page.locator('main')).to_contain_text('No verification email is sent and no credentials are created.')
        capture(page, 'default')
        page.locator('[name=email]').fill('bad')
        submit(page, 'Create user')
        expect(page.locator('#feedback')).to_be_focused()
        expect(page.locator('[name=email]')).to_have_value('bad')
        page.locator('form .actions').get_by_role('link', name='Cancel', exact=True).click()
        page.wait_for_url(parent + '/users')
        expect(page.get_by_role('heading', name='No users yet')).to_be_visible()
        page.get_by_role('link', name='Create user', exact=True).click()
        expect(page.locator('[name=email]')).to_have_value('')
    elif MODE == 'u3':
        parent = realm(page)
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
        realm_context(page, parent, 'A' * 128)
        record(page, 'realm_user', target.rsplit('/', 1)[1], parent)
        expect(page.locator('.grid>div>section').nth(1).locator('.badge')).to_have_text('Active')
        expect(page.locator('.grid>div>section').nth(1).locator('dd')).to_have_text(['Active', 'Active'])
        for status_path, action, realm_state, user_state, combined in [
            (parent, 'Suspend realm', 'Suspended', 'Active', 'Realm suspended'),
            (target, 'Suspend user', 'Suspended', 'Suspended', 'Realm suspended and user suspended'),
            (parent, 'Reactivate realm', 'Active', 'Suspended', 'User suspended'),
        ]:
            page.goto(status_path)
            page.get_by_role('link', name=action, exact=True).click()
            page.locator('#confirmation').get_by_role('button', name=action, exact=True).click()
            opposite = ('Reactivate' if action.startswith('Suspend') else 'Suspend') + ' ' + action.split()[-1]
            expect(page.locator('#status-action')).to_have_text(opposite)
            page.wait_for_url(status_path)
            page.goto(target)
            realm_context(page, parent, 'A' * 128, realm_state)
            expect(page.locator('.grid>div>section').nth(1).locator('.badge')).to_have_text(user_state)
            expect(page.locator('.grid>div>section').nth(1).locator('dd')).to_have_text([realm_state, combined])
            record(page, 'realm_user', target.rsplit('/', 1)[1], parent)
        for text in ['Combined directory status', 'Unverified', 'This user cannot sign in.']:
            expect(page.locator('main')).to_contain_text(text)
    else:
        parent = realm(page)
        target = user(page, parent)
        cancelled_forms(page, parent, target)
        saving(page)
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
        plain.locator('[name=name]').fill('Nojs realm')
        submit(plain, 'Save changes')
        expect(plain.locator('[name=version]')).to_have_value('2')
        plain.get_by_role('link', name='Suspend realm', exact=True).click()
        submit(plain, 'Suspend realm')
        expect(plain.get_by_role('link', name='Reactivate realm', exact=True)).to_be_visible()
        plain.get_by_role('link', name='Reactivate realm', exact=True).click()
        plain.locator('#confirmation').get_by_role('link', name='Cancel').click()
        expect(plain.locator('[name=version]')).to_have_value('3')
        plain.goto(ORIGIN + '/admin/realms/new')
        plain.locator('[name=name]').fill('Nojs independent')
        submit(plain, 'Create realm')
        plain.wait_for_url(UUID)
        expect(plain.locator('h1')).to_have_text('Nojs independent')
        nojs.close()
        page.get_by_role('link', name='Administration', exact=True).click()
        expect(page.locator('link[rel=stylesheet][href="/assets/admin.css"]')).to_have_count(1)
        expect(page.locator('main')).to_have_class('dashboard')
        page.get_by_role('link', name='Realms', exact=True).click()
        expect(page.locator('link[rel=stylesheet][href="/assets/directory.css"]')).to_have_count(1)
        page.goto(target)
    if MODE in ('t1', 'u1'):
        current = page.url
        response = page.goto(current + '?cursor=invalid')
        assert response.status == 422
        expect(page.locator('#feedback')).to_contain_text('This page link is invalid. Return to the first page.')
        expect(page.locator('tbody tr')).to_have_count(0)
        if MODE == 'u1':
            expect(page.locator('.context')).to_contain_text('Realm: ' + 'A' * 128)
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
