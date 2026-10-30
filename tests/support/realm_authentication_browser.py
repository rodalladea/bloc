"""Real two-replica TLS realm-account acceptance; all data is synthetic."""
import json
import http.client
import ssl
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse, urlencode
from playwright.sync_api import sync_playwright, expect

ORIGIN=os.environ['BLOC_TEST_ORIGIN']
REALM='11111111-1111-4111-8111-111111111111'
OTHER='33333333-3333-4333-8333-333333333333'
USER='22222222-2222-4222-8222-222222222222'
PASSWORD='a synthetic realm password'
BASE=f'{ORIGIN}/realms/{REALM}'
ADMIN=f'{ORIGIN}/admin/realms/{REALM}'
seen=set()
requests=[]
codes=[]
errors=[]
HEADINGS={
    **dict.fromkeys(['login','login-error','expired'],'Sign in to Acme'),
    **dict.fromkeys(['registration','registration-error','policy-error'],'Create your account'),
    'success':'Your account is ready','unavailable':'This realm is unavailable','registration-disabled':'Registration is unavailable',
    'forgot':'Need a new password?','link-entry':'Continue with your access code','activation':'Set your password','reset':'Choose a new password',
    'reset-success':'Your password was reset','link-invalid':'This link can’t be used',
    **dict.fromkeys(['profile','profile-saved','profile-conflict'],'Profile'),
    **dict.fromkeys(['password','password-saved'],'Password'),
    **dict.fromkeys(['sessions','revoke','revoke-current','revoke-one','sessions-ended'],'Sessions'),
    **dict.fromkeys(['settings','settings-saved','settings-invalid','settings-conflict'],'Authentication'),
    'settings-confirm':'Review session changes','issue':'User access','issue-activation':'User access',
    'link-output':'Password-reset link','activation-output':'Activation link','throttled':'Try again shortly','service-unavailable':'Temporarily unavailable',
}

def sql(statement):
    database=urlparse(Path(os.environ['BLOC_DATABASE_URL_FILE']).read_text().strip()).path[1:]
    out=subprocess.run(['docker','exec',os.environ['BLOC_SETUP_CONTAINER'],'psql','-U','probe','-d',database,'-v','ON_ERROR_STOP=1','-At','-c',statement],check=True,capture_output=True,text=True)
    return out.stdout.strip()

def reset_limits():
    sql('DELETE FROM bloc.realm_admission_bucket; DELETE FROM bloc.administrator_admission_bucket;')

def response_policy(response):
    path=urlparse(response.url).path
    if path.startswith('/realms/') or (path.startswith('/admin/realms/') and ('/access-links' in path or '/authentication' in path)):
        headers=response.all_headers()
        assert headers.get('cache-control')=='no-store',(path,'cache')
        assert "default-src 'none'" in headers.get('content-security-policy',''),(path,'csp')
        assert headers.get('referrer-policy')=='no-referrer',(path,'referrer')

def diagnostics_redacted(contexts):
    logs=''.join(p.read_text() for p in Path(os.environ['BLOC_REALM_SERVICE_LOGS']).glob('service-*.*'))
    secrets=set(codes+[PASSWORD,'a synthetic password','a native transport password','pending@example.test','browser@example.test','Owner@example.test','nojs@example.test'])
    for ctx in contexts:
        secrets.update(c['value'] for c in ctx.cookies() if c['value'])
        for p in ctx.pages:
            secrets.update(p.locator('input[name=csrf]').evaluate_all('es=>es.map(e=>e.value)'))
    secrets.update(sql("SELECT password_hash FROM bloc.realm_user_credential").splitlines())
    secrets.update(sql("SELECT password_hash FROM bloc.installation_administrator").splitlines())
    secrets.update(sql("SELECT device_label FROM bloc.realm_user_session").splitlines())
    secrets.update(sql("SELECT email FROM bloc.realm_user UNION SELECT email FROM bloc.installation_administrator").splitlines())
    secrets.update(url for url,_,_ in requests)
    audit=sql("SELECT coalesce(string_agg(row_to_json(e)::text,''),'') FROM bloc.security_audit_event e")
    for secret in secrets:
        if secret:
            assert secret not in logs,'service diagnostic exposed synthetic secret'
            assert secret not in audit,'audit exposed synthetic secret'
    return {'stdout_stderr_checked':True,'audit_checked':True,'secret_classes':['password','email','form_token','session_token','access_code','phc','device_label','full_url']}

def runtime_request(page,path,headers=None,form=None,body=None):
    connection=http.client.HTTPSConnection('127.0.0.1',4443,context=ssl._create_unverified_context())
    values={'host':urlparse(ORIGIN).netloc,'cookie':'; '.join(c['name']+'='+c['value'] for c in page.context.cookies()),'origin':ORIGIN}
    values.update({k.lower():v for k,v in (headers or {}).items()})
    if form is not None:body=urlencode(form);values['content-type']='application/x-www-form-urlencoded'
    connection.request('POST' if body is not None else 'GET',path,body,values)
    response=connection.getresponse();result=(response.status,{k.lower():v for k,v in response.getheaders()},response.read().decode());connection.close();return result

def account_http_contract(page):
    for path in ['/account/profile','/account/password','/account/sessions']:
        full=runtime_request(page,f'/realms/{REALM}'+path)
        fragment=runtime_request(page,f'/realms/{REALM}'+path,headers={'HX-Request':'true'})
        for status,headers,html in [full,fragment]:
            assert status==200
            assert headers['cache-control']=='no-store'
            assert "default-src 'none'" in headers['content-security-policy']
            assert headers['referrer-policy']=='no-referrer'
        assert '<!doctype html>' in full[2] and '<!doctype html>' not in fragment[2]
        assert 'id="content"' in fragment[2]
    csrf=page.locator('[name=csrf]').first.input_value()
    version=page.locator('[name=version]').input_value()
    for headers,data in [({'Origin':'https://foreign.example'},{'csrf':csrf,'version':version,'display_name':'Forbidden'}),({'Origin':ORIGIN},{'csrf':'invalid','version':version,'display_name':'Forbidden'})]:
        result=runtime_request(page,f'/realms/{REALM}/account/profile',headers=headers,form=data)
        assert result[0]==403
    assert sql("SELECT count(*) FROM bloc.realm_user WHERE display_name='Forbidden'")=='0'

def busy_lost_response(page):
    page.goto(BASE+'/account/profile')
    pending=[]
    page.route(BASE+'/account/profile',lambda route:pending.append(route) if route.request.method=='POST' else route.continue_())
    attack='<img src=x onerror=alert(1)>'
    fields(page,{'display_name':attack})
    page.locator('form').filter(has=page.locator('[name=display_name]')).evaluate('f=>f.requestSubmit()')
    expect(page.locator('main')).to_have_attribute('aria-busy','true')
    button=page.get_by_role('button',name='Saving…',exact=True)
    expect(button).to_be_disabled()
    expect(page.locator('.working')).to_be_visible()
    assert len(pending)==1
    request=pending[0].request
    response=runtime_request(page,urlparse(request.url).path,headers=request.all_headers(),body=request.post_data);assert response[0]==200
    pending[0].abort('failed')
    expect(page.locator('#feedback')).to_contain_text('response was lost')
    expect(page.get_by_role('button',name='Save changes',exact=True)).to_be_enabled()
    assert page.locator('main').get_attribute('aria-busy') is None
    expect(page.locator('#feedback')).to_be_focused()
    assert sql("SELECT display_name FROM bloc.realm_user WHERE email='browser@example.test'")==attack
    page.unroute(BASE+'/account/profile')
    page.get_by_role('link',name='Reload',exact=True).click()
    expect(page.locator('[name=display_name]')).to_have_value(attack)
    assert page.locator('main img').count()==0
    assert '&lt;img' in page.content()
    fragment=runtime_request(page,f'/realms/{REALM}/account/profile',headers={'HX-Request':'true'})
    assert fragment[0]==200 and '<img src=x' not in fragment[2]
    parsed=page.evaluate("""html => {
        const document = new DOMParser().parseFromString(html, 'text/html');
        return {value: document.querySelector('[name=display_name]').value,
                images: document.querySelectorAll('img').length};
    }""", fragment[2])
    assert parsed=={'value':attack,'images':0}

def loading_navigation(page):
    pending=[]
    page.route(BASE+'/account/password',lambda route:pending.append(route))
    page.get_by_role('link',name='Password',exact=True).click()
    expect(page.locator('#realm-loading')).to_be_visible()
    expect(page.locator('main')).to_have_attribute('aria-busy','true')
    assert len(pending)==1
    pending[0].continue_()
    page.wait_for_url(BASE+'/account/password')
    expect(page.locator('#realm-loading')).to_be_hidden()
    assert page.locator('main').get_attribute('aria-busy') is None
    expect(page.get_by_role('link',name='Password',exact=True)).to_have_attribute('aria-current','page')
    assert page.get_by_role('link',name='Profile',exact=True).get_attribute('aria-current') is None
    page.unroute(BASE+'/account/password')

def history_authority(page,browser):
    page.goto(BASE+'/account/profile');page.goto(BASE+'/account/password')
    revoker_context=browser.new_context();revoker=revoker_context.new_page();login(revoker,password='another synthetic password')
    revoker.goto(BASE+'/account/sessions/revoke-others');submit(revoker,'End other sessions');revoker.wait_for_url(BASE+'/account/sessions?ended=1')
    page.go_back();page.wait_for_url(BASE+'/login?expired=1')
    assert page.locator('[name=display_name]').count()==0
    assert page.locator('main').get_attribute('data-state')=='expired'
    revoker_context.close()

def measured_table(page,admin):
    admin.goto(ADMIN+'/users')
    measure="""() => {const wrap=document.querySelector('.ui-table-scroll'),table=wrap.querySelector('table'),th=table.querySelector('th'),td=table.querySelector('td');const pick=(e,keys)=>Object.fromEntries(keys.map(k=>[k,getComputedStyle(e)[k]]));return {wrapper:pick(wrap,['borderTopWidth','borderTopStyle','borderRadius','overflowX']),heading:pick(th,['backgroundColor','paddingTop','paddingRight','paddingBottom','paddingLeft','fontSize','borderBottomWidth']),cell:pick(td,['paddingTop','paddingRight','paddingBottom','paddingLeft','fontSize']),contained:wrap.getBoundingClientRect().right<=innerWidth,overflow:wrap.scrollWidth>wrap.clientWidth,documentFits:document.documentElement.scrollWidth<=innerWidth};}"""
    for width in [1440,390]:
        for theme in ['light','dark']:
            for p in [page,admin]:p.set_viewport_size({'width':width,'height':1000});p.evaluate('(theme)=>document.documentElement.dataset.uiTheme=theme',theme)
            actual=page.evaluate(measure);standard=admin.evaluate(measure)
            for key in ['wrapper','heading','cell']:assert actual[key]==standard[key],(key,width,actual[key],standard[key])
            assert actual['contained'] and actual['documentFits']
            assert actual['wrapper']['borderTopWidth']=='1px' and actual['wrapper']['borderTopStyle']=='solid'
            assert float(actual['wrapper']['borderRadius'].removesuffix('px'))>0
            if width==390:assert actual['overflow'],'table must scroll inside its wrapper at mobile width'
    for p in [page,admin]:p.set_viewport_size({'width':1440,'height':1000})

def capture(page,state):
    expect(page.locator('main')).to_have_attribute('data-state',state)
    expect(page.locator('main h1')).to_be_visible()
    expect(page.locator('main h1')).to_have_text(HEADINGS[state])
    seen.add(state)
    target=os.environ.get('BLOC_REALM_BROWSER_EVIDENCE') or os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE')
    for width in [1440,390]:
        page.set_viewport_size({'width':width,'height':1000})
        for theme in ['light','dark']:
            page.evaluate('(theme)=>document.documentElement.dataset.uiTheme=theme',theme)
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),state
            assert page.locator('main [id]').evaluate_all('es=>new Set(es.map(e=>e.id)).size===es.length'),state
            assert page.locator('main input:not([type=hidden]):not([type=checkbox])').evaluate_all('es=>es.every(e=>e.labels.length>0)'),state
            if target:
                directory=Path(target);directory.mkdir(parents=True,exist_ok=True)
                page.screenshot(path=str(directory/f'realm-{state}-{width}-{theme}.png'),full_page=True,animations='disabled')
    page.set_viewport_size({'width':1440,'height':1000})

def submit(page,label):
    page.get_by_role('button',name=label,exact=True).click()

def fields(page,values):
    for key,value in values.items():page.locator(f'input[name="{key}"]').fill(value)

def register(page,email,password=PASSWORD):
    fields(page,{'email':email,'display_name':'Browser person','password':password,'password_confirmation':password})
    submit(page,'Create account')

def login(page,email='browser@example.test',password=PASSWORD):
    reset_limits();page.goto(BASE+'/login');fields(page,{'email':email,'password':password});submit(page,'Sign in');page.wait_for_url(BASE+'/account/profile')

def issue(admin,purpose):
    reset_limits();admin.goto(ADMIN+f'/users/{USER}/access-links');capture(admin,'issue-activation' if purpose=='activation' else 'issue')
    admin.locator('[name=identity_confirmed]').check();submit(admin,'Create activation link' if purpose=='activation' else 'Create reset link')
    capture(admin,'activation-output' if purpose=='activation' else 'link-output')
    code=admin.locator('#access-code').input_value();codes.append(code)
    link=admin.locator('#access-link').input_value();assert link==BASE+('/activate' if purpose=='activation' else '/reset-password')+'#code='+code
    return code,link

def bound_password(page,password=PASSWORD):
    fields(page,{'password':password,'password_confirmation':password});submit(page,'Save password')

def administrator_native_logout(browser, admin):
    for path in [ADMIN+'/authentication', ADMIN+f'/users/{USER}/access-links']:
        native=browser.new_context(java_script_enabled=False)
        native.add_cookies(admin.context.cookies())
        native.on('response',response_policy)
        plain=native.new_page()
        response=plain.goto(path)
        assert response.status==200
        assert response.all_headers()['referrer-policy']=='no-referrer'
        plain.get_by_label('Workspace menu',exact=True).click()
        with plain.expect_response(lambda r:urlparse(r.url).path=='/admin/logout') as logout:
            plain.get_by_role('button',name='Log out',exact=True).click()
        assert logout.value.status==303
        headers=logout.value.request.all_headers()
        assert headers['origin']=='null'
        assert headers['sec-fetch-site']=='same-origin'
        plain.wait_for_url(ORIGIN+'/admin/login')
        assert not any(c['name']=='__Host-bloc-admin' for c in native.cookies())
        native.close()
        reset_limits()
        admin.goto(ORIGIN+'/admin/login')
        fields(admin,{'email':'Owner@example.test','password':'a synthetic password'})
        submit(admin,'Sign in')
        admin.wait_for_url(ORIGIN+'/admin/realms')

with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=pw.chromium.executable_path,headless=True,args=['--no-proxy-server','--host-resolver-rules=MAP bloc.example.test 127.0.0.1','--ignore-certificate-errors-spki-list='+os.environ['BLOC_TEST_SPKI']])
    context=browser.new_context(viewport={'width':1440,'height':1000},reduced_motion='reduce')
    context.on('request',lambda r:requests.append((r.url,r.method,r.post_data or '')))
    context.on('response',response_policy)
    page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
    admin_context=browser.new_context(viewport={'width':1440,'height':1000},reduced_motion='reduce');admin_context.on('response',response_policy);admin=admin_context.new_page();admin.on('pageerror',lambda e:errors.append(str(e)))
    code=subprocess.run([os.environ['BLOC_TEST_BINARY'],'admin','setup-code'],check=True,capture_output=True,text=True).stdout.splitlines()[0][5:]
    admin.goto(ORIGIN+'/admin/setup');fields(admin,{'code':code,'email':'Owner@example.test','password':'a synthetic password','password_confirmation':'a synthetic password'});submit(admin,'Create administrator');admin.wait_for_url(ORIGIN+'/admin/login');fields(admin,{'email':'Owner@example.test','password':'a synthetic password'});submit(admin,'Sign in');admin.wait_for_url(ORIGIN+'/admin/realms')
    sql(f"INSERT INTO bloc.realm(id,name,created_at,updated_at) VALUES('{REALM}','Acme',clock_timestamp(),clock_timestamp()),('{OTHER}','Other',clock_timestamp(),clock_timestamp()); INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES('{USER}','{REALM}','pending@example.test',clock_timestamp(),clock_timestamp());")
    administrator_native_logout(browser,admin)
    if len(sys.argv)>1 and sys.argv[1].startswith('transport'):
        code,link=issue(admin,'activation');reset_limits();page.goto(link)
        expect(page.locator('[name=code]')).to_have_attribute('type','password')
        expect(page.locator('[name=code]')).to_have_value(code)
        assert page.url==BASE+'/activate'
        assert code not in page.evaluate('JSON.stringify(localStorage)+JSON.stringify(sessionStorage)')
        submit(page,'Continue');page.wait_for_url(BASE+'/activate')
        bound_password(page,'short');expect(page.locator('[name=password]')).to_have_value('')
        assert code not in page.content()
        bound_password(page);page.wait_for_url(BASE+'/login?activated=1')
        code,link=issue(admin,'reset');reset_limits()
        native=browser.new_context(java_script_enabled=False)
        native.on('response',response_policy)
        native.on('request',lambda r:requests.append((r.url,r.method,r.post_data or '')))
        plain=native.new_page();plain.goto(BASE+'/reset-password');plain.locator('[name=code]').fill(code);submit(plain,'Continue');plain.wait_for_url(BASE+'/reset-password');bound_password(plain,'a native transport password');plain.wait_for_url(BASE+'/login?reset=1')
        login(page,email='pending@example.test',password='a native transport password')
        account_http_contract(page)
        for secret in codes:
            assert all(secret not in url for url,_,_ in requests)
            assert all('/exchange' in url and method=='POST' for url,method,body in requests if secret in body)
            assert all(cookie['value']!=secret for browser_context in [context,native] for cookie in browser_context.cookies())
            assert secret not in sql("SELECT coalesce(string_agg(row_to_json(e)::text,''),'') FROM bloc.security_audit_event e")
            assert secret not in page.evaluate('JSON.stringify(localStorage)+JSON.stringify(sessionStorage)')
        assert not errors,errors
        assert all(urlparse(url).netloc==urlparse(ORIGIN).netloc for url,_,_ in requests)
        redaction=diagnostics_redacted([context,admin_context,native])
        record={'diagnostics':redaction,'response_policies':True,'real_tls':True,'fragment_removed':True,'deliberate_exchange':True,'native_post':True,'code_redaction':True,'replicas':2}
        target=os.environ.get('BLOC_REALM_BROWSER_EVIDENCE') or os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE')
        if target:Path(target,'realm-'+sys.argv[1]+'.json').write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps(record));browser.close();sys.exit(0)
    admin.goto(ADMIN);admin.get_by_role('link',name='Authentication settings',exact=True).click();capture(admin,'settings');expect(admin.locator('script[src="/assets/realm.js"]')).to_have_count(1);expect(admin.locator('link[href="/assets/realm.css"]')).to_have_count(1)
    admin.locator('[name=password_min_length]').fill('15');submit(admin,'Save settings');capture(admin,'settings-invalid');expect(admin.locator('[name=password_min_length]')).to_have_attribute('aria-invalid','true')
    admin.goto(ADMIN+'/authentication');sql(f"UPDATE bloc.realm_authentication_settings SET version=version+1 WHERE realm_id='{REALM}'");submit(admin,'Save settings');capture(admin,'settings-conflict')
    admin.goto(ADMIN+'/authentication');admin.locator('[name=session_idle_seconds]').fill('20');submit(admin,'Save settings');capture(admin,'settings-confirm');submit(admin,'Apply settings');admin.wait_for_url(ADMIN+'/authentication?saved=1');capture(admin,'settings-saved')
    page.goto(BASE+'/register');capture(page,'registration-disabled')
    page.goto(f'{ORIGIN}/realms/99999999-9999-4999-8999-999999999999/login');capture(page,'unavailable')
    sql(f"UPDATE bloc.realm_authentication_settings SET registration_enabled=true,version=version+1 WHERE realm_id='{REALM}'")
    reset_limits();page.goto(BASE+'/register');capture(page,'registration');register(page,'pending@example.test');capture(page,'registration-error');assert 'already exists' not in page.locator('main').inner_text()
    register(page,'browser@example.test','short');capture(page,'policy-error');assert page.locator('[name=password]').input_value()==''
    register(page,'browser@example.test');page.wait_for_url(BASE+'/login?registered=1');capture(page,'success')
    page.goto(BASE+'/login');capture(page,'login');fields(page,{'email':'browser@example.test','password':'an incorrect password'});submit(page,'Sign in');capture(page,'login-error')
    page.goto(BASE+'/login?expired=1');capture(page,'expired');page.goto(BASE+'/login?help=1');capture(page,'forgot')
    code,link=issue(admin,'activation');reset_limits();page.goto(link);expect(page.locator('[name=code]')).to_have_value(code);assert page.url==BASE+'/activate';capture(page,'link-entry');assert code not in page.evaluate('JSON.stringify(localStorage)+JSON.stringify(sessionStorage)');submit(page,'Continue');page.wait_for_url(BASE+'/activate');capture(page,'activation');bound_password(page);page.wait_for_url(BASE+'/login?activated=1')
    code,link=issue(admin,'reset');reset_limits();page.goto(link);submit(page,'Continue');page.wait_for_url(BASE+'/reset-password');capture(page,'reset');bound_password(page,'a replacement synthetic password');page.wait_for_url(BASE+'/login?reset=1');capture(page,'reset-success')
    reset_limits();page.goto(link);submit(page,'Continue');capture(page,'link-invalid')
    login(page);capture(page,'profile');account_http_contract(page);fields(page,{'display_name':'Updated browser person'});submit(page,'Save changes');page.wait_for_url(BASE+'/account/profile?saved=1');capture(page,'profile-saved')
    page.goto(BASE+'/account/profile');sql(f"UPDATE bloc.realm_user SET version=version+1 WHERE realm_id='{REALM}' AND email='browser@example.test'");fields(page,{'display_name':'Stale name'});submit(page,'Save changes');capture(page,'profile-conflict')
    page.goto(BASE+'/account/password');capture(page,'password');fields(page,{'current_password':PASSWORD,'password':'another synthetic password','password_confirmation':'another synthetic password'});submit(page,'Change password');page.wait_for_url(BASE+'/account/password?saved=1');capture(page,'password-saved')
    second_context=browser.new_context();second=second_context.new_page();login(second,password='another synthetic password')
    page.goto(BASE+'/account/sessions');capture(page,'sessions');measured_table(page,admin);assert page.locator('thead th').all_text_contents()==['Device','Status','Created (UTC)','Last active','Actions']
    page.get_by_role('link',name='End all other sessions',exact=True).click();capture(page,'revoke');page.get_by_role('link',name='Cancel',exact=True).click()
    current=page.locator('tbody tr').filter(has_text='Current session');current.get_by_role('link',name='End session').click();capture(page,'revoke-current');page.get_by_role('link',name='Cancel',exact=True).click()
    page.locator('tbody tr').filter(has_not_text='Current session').get_by_role('link',name='End session').click();capture(page,'revoke-one');submit(page,'End session');page.wait_for_url(BASE+'/account/sessions?ended=1');capture(page,'sessions-ended')
    # Repeated enhanced navigation and history keep the same replacement target.
    for _ in range(2):
        page.goto(BASE+'/account/profile');page.locator('[name=display_name]').fill('History name');submit(page,'Save changes');page.wait_for_url(BASE+'/account/profile?saved=1');expect(page.locator('#content')).to_have_count(1)
    page.goto(BASE+'/account/password');page.go_back();expect(page.locator('h1')).to_have_text('Profile');page.reload();expect(page.locator('h1')).to_have_text('Profile')
    busy_lost_response(page)
    loading_navigation(page)
    # Real keyboard drawer behavior at mobile dimensions.
    page.set_viewport_size({'width':390,'height':844});toggle=page.get_by_role('button',name='Navigation menu');toggle.click();expect(toggle).to_have_attribute('aria-expanded','true');assert page.locator('.workspace').evaluate('e=>e.inert');page.keyboard.press('Escape');expect(toggle).to_have_attribute('aria-expanded','false');expect(toggle).to_be_focused()
    history_authority(page,browser)
    reset_limits();sql("INSERT INTO bloc.realm_admission_bucket(scope,subject_digest,admitted_at,expires_at) VALUES('public_work',decode(repeat('00',32),'hex'),array_fill(clock_timestamp(),ARRAY[20]),clock_timestamp()+interval '2 minutes')")
    page.goto(BASE+'/login');fields(page,{'email':'browser@example.test','password':'another synthetic password'});submit(page,'Sign in');capture(page,'throttled')
    sql('UPDATE bloc.installation SET recovery_required=true');page.goto(BASE+'/login');capture(page,'service-unavailable');sql('UPDATE bloc.installation SET recovery_required=false');reset_limits()
    # Native forms without JavaScript retain registration/login/profile/password/session behavior.
    nojs=browser.new_context(java_script_enabled=False);plain=nojs.new_page()
    plain.on('request',lambda r:print('native-request',r.method,urlparse(r.url).path,{k:v for k,v in r.all_headers().items() if k in ['origin','sec-fetch-site','content-type']},'cookie-present',bool(r.header_value('cookie')),flush=True) if r.method=='POST' else None)
    plain.goto(BASE+'/register');register(plain,'nojs@example.test');print('native-registration',plain.url,plain.locator('main').get_attribute('data-state'),plain.locator('main').inner_text(),flush=True);plain.wait_for_url(BASE+'/login?registered=1');fields(plain,{'email':'nojs@example.test','password':PASSWORD});submit(plain,'Sign in');plain.wait_for_url(BASE+'/account/profile');fields(plain,{'display_name':'Native form'});submit(plain,'Save changes');plain.wait_for_url(BASE+'/account/profile?saved=1');plain.goto(BASE+'/account/sessions');expect(plain.locator('table')).to_be_visible()
    plain.goto(BASE+'/account/password');fields(plain,{'current_password':PASSWORD,'password':'a native replacement password','password_confirmation':'a native replacement password'});submit(plain,'Change password');plain.wait_for_url(BASE+'/account/password?saved=1')
    plain.goto(BASE+'/account/sessions');plain.get_by_role('link',name='End all other sessions',exact=True).click();submit(plain,'End other sessions');plain.wait_for_url(BASE+'/account/sessions?ended=1')
    native_other=browser.new_context(java_script_enabled=False);native_second=native_other.new_page();login(native_second,email='nojs@example.test',password='a native replacement password')
    plain.goto(BASE+'/account/sessions');plain.locator('tbody tr').filter(has_not_text='Current session').get_by_role('link',name='End session').click();submit(plain,'End session');plain.wait_for_url(BASE+'/account/sessions?ended=1')
    native_second.goto(BASE+'/account/profile');native_second.wait_for_url(BASE+'/login?expired=1');native_other.close()
    plain.locator('tbody tr').filter(has_text='Current session').get_by_role('link',name='End session').click();submit(plain,'End session');plain.wait_for_url(BASE+'/login')
    login(plain,email='nojs@example.test',password='a native replacement password')
    plain.get_by_label('Account menu',exact=True).click();submit(plain,'Sign out');plain.wait_for_url(BASE+'/login')
    # No-JavaScript access-code transport is a native POST, with no secret query.
    native_admin=nojs.new_page();nojs.add_cookies(admin_context.cookies());native_admin.goto(ADMIN+'/authentication');native_admin.locator('[name=activation_ttl_seconds]').fill('2');submit(native_admin,'Save settings');native_admin.wait_for_url(ADMIN+'/authentication?saved=1')
    code,link=issue(native_admin,'reset');reset_limits();plain.goto(BASE+'/reset-password');plain.locator('[name=code]').fill(code);submit(plain,'Continue');plain.wait_for_url(BASE+'/reset-password');bound_password(plain,'a nojavascript reset password');plain.wait_for_url(BASE+'/login?reset=1')
    native_user='44444444-4444-4444-8444-444444444444'
    sql(f"INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at) VALUES('{native_user}','{REALM}','native-activation@example.test',clock_timestamp(),clock_timestamp())")
    reset_limits();native_admin.goto(ADMIN+f'/users/{native_user}/access-links');native_admin.locator('[name=identity_confirmed]').check();submit(native_admin,'Create activation link')
    native_code=native_admin.locator('#access-code').input_value();codes.append(native_code)
    plain.goto(BASE+'/activate');plain.locator('[name=code]').fill(native_code);submit(plain,'Continue');plain.wait_for_url(BASE+'/activate');bound_password(plain,'a native activation password');plain.wait_for_url(BASE+'/login?activated=1')
    for secret in codes:
        assert all(secret not in url for url,_,_ in requests)
        assert all('/exchange' in url and method=='POST' for url,method,body in requests if secret in body)
        assert all(c['value']!=secret for c in context.cookies())
    expected={'login','login-error','registration','registration-error','policy-error','success','unavailable','registration-disabled','forgot','link-entry','activation','reset','reset-success','link-invalid','expired','profile','profile-saved','profile-conflict','password','password-saved','sessions','revoke','revoke-current','revoke-one','sessions-ended','settings','settings-confirm','settings-saved','issue','link-output','issue-activation','throttled','service-unavailable','settings-invalid','settings-conflict','activation-output'}
    assert seen==expected,(expected-seen,seen-expected)
    assert not errors,errors
    assert all(urlparse(url).netloc==urlparse(ORIGIN).netloc for url,_,_ in requests)
    redaction=diagnostics_redacted([context,admin_context,nojs,second_context])
    result={'diagnostics':redaction,'measured_standard_table':True,'busy_lost_response':True,'loading_navigation':True,'history_authority':True,'full_fragment_policy':True,'response_policies':True,'states':sorted(seen),'screen_checks':len(seen)*4,'real_tls':True,'replicas':2,'native_forms':True,'fragment_transport':True,'keyboard_drawer':True,'errors':errors}
    target=os.environ.get('BLOC_REALM_BROWSER_EVIDENCE') or os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE')
    if target:Path(target,'realm-browser.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result));browser.close()
