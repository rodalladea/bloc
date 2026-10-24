"""Real Chromium checks against two production processes and pinned local HTTPS.

Requires Playwright, a synthetic TLS proxy, BLOC_TEST_ORIGIN and BLOC_TEST_SPKI.
Never treat this synthetic ingress as production certificate acceptance.
"""
import json, os, subprocess, sys
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from ui_browser import appearance, control_density, keyboard_focus, choose_appearance, workspace_menus

mode=sys.argv[1]
origin=os.environ['BLOC_TEST_ORIGIN']
def code(purpose):
    result=subprocess.run([os.environ['BLOC_TEST_BINARY'],'admin',purpose+'-code'],capture_output=True,text=True,check=True)
    rows=result.stdout.splitlines()
    assert len(rows)==2 and rows[0].startswith('code=') and rows[1].startswith('expires_at=')
    return rows[0][5:]

def fill(page, fields):
    for name,value in fields.items():page.locator('[name="'+name+'"]').fill(value)

def submit(page,label):
    page.get_by_role('button',name=label,exact=True).click()

def login(page,password='a synthetic password'):
    page.goto(origin+'/admin/login')
    fill(page,{'email':'Owner@example.test','password':password})
    submit(page,'Sign in')
    page.wait_for_url(origin+'/admin')

def empty_secrets(page):
    for control in page.locator('input[type="password"],input[name="code"]').all():
        expect(control).to_have_value('')

def validation_result(page, enhanced):
    expect(page.locator('[role="alert"]')).to_have_count(1)
    empty_secrets(page)
    if enhanced: expect(page.locator('#feedback')).to_be_focused()

def keyboard_order(page):
    page.reload()
    controls=[c for c in page.locator('a[href],summary,input:not([type="hidden"]),button,select').all() if c.is_visible() and c.is_enabled()]
    for control in controls:
        page.keyboard.press('Tab')
        keyboard_focus(control)

with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,executable_path=os.environ.get("BLOC_BROWSER_EXECUTABLE",p.chromium.executable_path),args=['--no-proxy-server','--host-resolver-rules=MAP bloc.example.test 127.0.0.1','--ignore-certificate-errors-spki-list='+os.environ['BLOC_TEST_SPKI']])
    context=browser.new_context(java_script_enabled=mode!='no_javascript',viewport={'width':1280,'height':1000})
    page=context.new_page()
    page.set_default_timeout(10000)
    responses=[]
    requests=[]
    page.on('request',lambda request: requests.append({'method':request.method,'origin':request.headers.get('origin'),'referer':request.headers.get('referer'),'cookie_present':'cookie' in request.all_headers()}))
    page.on('response',lambda response: responses.append((response.request.method,response.url.split('?')[0],response.status)))
    setup=code('setup')
    page.goto(origin+'/admin/setup')
    expect(page.get_by_role('heading',name='Set up bloc',exact=True)).to_be_visible()
    assert page.locator('input[name="code"]').input_value()==''
    if mode in ['validation','no_javascript']:
        fill(page,{'code':setup,'email':'Owner@EXAMPLE.test','password':'short','password_confirmation':'different'})
        submit(page,'Create administrator')
        validation_result(page,mode=='validation')
        if mode=='validation':
            fill(page,{'code':'A'*43,'email':'Owner@EXAMPLE.test','password':'a synthetic password','password_confirmation':'a synthetic password'})
            submit(page,'Create administrator')
            validation_result(page,True)
    if mode=='preview':
        appearance(page, browser, origin)
        for width in [375,639,640,1280]:
            page.set_viewport_size({'width':width,'height':1000})
            assert page.locator('form .field input').evaluate_all('(els)=>els.map(e=>e.name)')==['code','email','password','password_confirmation']
            assert page.locator('header').bounding_box()['height']==64
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            control_density(page)
            if width==1280:
                assert page.locator('main').evaluate('e=>e.clientWidth-parseFloat(getComputedStyle(e).paddingLeft)-parseFloat(getComputedStyle(e).paddingRight)')==432
            keyboard_order(page)
        page.set_viewport_size({'width':1280,'height':1000})
    fill(page,{'code':setup,'email':'Owner@EXAMPLE.test','password':'a synthetic password','password_confirmation':'a synthetic password'})
    submit(page,'Create administrator')
    try:page.wait_for_url(origin+'/admin/login')
    except Exception as error:
        raise RuntimeError({'url':page.url,'headings':page.locator('h1').all_text_contents(),'feedback':page.locator('#feedback').all_text_contents(),'cookie_names':[cookie['name'] for cookie in context.cookies()],'responses':responses,'requests':requests}) from error
    if mode in ['no_javascript','validation']:
        fill(page,{'email':'Owner@example.test','password':'wrong password'})
        submit(page,'Sign in')
        validation_result(page,mode=='validation')
    login(page)
    expect(page.locator('.account-email')).to_have_text('Owner@example.test')
    expect(page.get_by_text('Installation administrator',exact=True)).to_be_visible()
    if mode=='validation':
        config=json.loads(page.locator('meta[name="htmx-config"]').get_attribute('content'))
        for key,value in {'allowEval':False,'allowScriptTags':False,'selfRequestsOnly':True,'historyCacheSize':0,'includeIndicatorStyles':False,'historyRestoreAsHxRequest':False}.items(): assert config[key]==value
        page.goto(origin+'/admin/password')
        fill(page,{'current_password':'a synthetic password','password':'short','password_confirmation':'different'})
        submit(page,'Change password')
        expect(page.locator('#feedback')).to_be_focused()
        expect(page.locator('#password')).to_have_attribute('aria-invalid','true')
        assert page.locator('#feedback a').get_attribute('href')=='#password'
        for name in ['current_password','password','password_confirmation']:assert page.locator('[name="'+name+'"]').input_value()==''
        validation_result(page,True)
        fill(page,{'current_password':'wrong password','password':'the replacement password','password_confirmation':'the replacement password'})
        submit(page,'Change password')
        validation_result(page,True)
        recovery=code('recovery')
        page.goto(origin+'/admin/recovery')
        fill(page,{'code':recovery,'password':'short','password_confirmation':'different'})
        submit(page,'Reset password')
        validation_result(page,True)
        fill(page,{'code':'A'*43,'password':'the replacement password','password_confirmation':'the replacement password'})
        submit(page,'Reset password')
        validation_result(page,True)
    elif mode=='loading_network':
        page.goto(origin+'/admin/password')
        fill(page,{'current_password':'a synthetic password','password':'the replacement password','password_confirmation':'the replacement password'})
        pending=[]
        page.route('**/admin/password',lambda route: pending.append(route))
        submit(page,'Change password')
        expect(page.get_by_role('button',name='Working…',exact=True)).to_be_disabled()
        expect(page.locator('#content form')).to_have_attribute('aria-busy','true')
        assert len(pending)==1
        expect(page.get_by_role('link',name='Back to administration',exact=True)).to_be_enabled()
        assert not page.get_by_role('link',name='Back to administration',exact=True).get_attribute('aria-disabled')
        pending[0].abort('failed')
        expect(page.locator('#feedback')).to_contain_text('The request could not be confirmed.')
        expect(page.get_by_role('button',name='Change password',exact=True)).to_be_enabled()
        for name in ['current_password','password','password_confirmation']:assert page.locator('[name="'+name+'"]').input_value()==''
        page.wait_for_timeout(1200)
        assert len(pending)==1
    elif mode=='session_expiry':
        page.goto(origin+'/admin/password')
        other=context.new_page();other.goto(origin+'/admin/realms');other.get_by_label('Workspace menu',exact=True).click();submit(other,'Log out');other.wait_for_url(origin+'/admin/login')
        fill(page,{'current_password':'a synthetic password','password':'the replacement password','password_confirmation':'the replacement password'})
        submit(page,'Change password')
        page.wait_for_url(origin+'/admin/login?expired=1')
        expect(page.locator('#feedback')).to_contain_text('Your session ended. Sign in again.')
        assert page.locator('#password').input_value()==''
    elif mode=='preview':
        for width in [375,639,640,1280]:
            page.set_viewport_size({'width':width,'height':1000})
            for path,title,names in [('/admin','Overview',[]),('/admin/password','Change password',['current_password','password','password_confirmation']),('/admin/login','Sign in to bloc',['email','password']),('/admin/recovery','Recover administrator access',['code','password','password_confirmation']),('/admin/setup','Setup is complete',[])]:
                page.goto(origin+path)
                expect(page.get_by_role('heading',name=title,exact=True)).to_be_visible()
                assert page.locator('header').count() == (0 if path in ('/admin','/admin/password') else 1)
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                actual=page.locator('form .field input').evaluate_all('(els)=>els.map(e=>e.name)')
                assert actual==names, (path, width, actual, page.locator('main').inner_text())
                control_density(page)
                if path in ('/admin','/admin/password'):
                    workspace_menus(page)
                    nav=page.get_by_role('navigation',name='Administration',exact=True)
                    expect(nav.locator('[aria-current=page]')).to_have_text('Overview' if path=='/admin' else 'Account security')
                    expect(nav.get_by_role('link',name='Realms',exact=True)).to_be_visible()
                    expect(page.locator('.app-rail')).to_have_count(0)
                    expect(page.get_by_role('navigation',name='Administration',exact=True)).to_have_count(1)
                    shell=page.locator('.sidebar').bounding_box()
                    content=page.locator('main').bounding_box()
                    assert shell['y']+shell['height']<=content['y'] if width<640 else shell['x']+shell['width']<=content['x']
                else:
                    expect(page.locator('.sidebar')).to_have_count(0)
                    assert page.locator('main').evaluate('e=>e.clientWidth-parseFloat(getComputedStyle(e).paddingLeft)-parseFloat(getComputedStyle(e).paddingRight)')<=480
                if path=='/admin':
                    expect(page.get_by_role('link',name='Create realm',exact=True)).to_be_visible()
                    expect(page.get_by_role('link',name='Browse realms',exact=True)).to_be_visible()
                    expect(page.get_by_role('button',name='Sign out',exact=True)).to_be_visible()
                    panels=page.locator('.overview-grid>div,.overview-grid>.installation-panel').all()
                    a,b=[panel.bounding_box() for panel in panels]
                    assert (b['y']>=a['y']+a['height']) if width<=1100 else b['x']>=a['x']+a['width']
                evidence=os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE')
                if evidence and width in (375,1280):
                    target=Path(evidence)
                    target.mkdir(parents=True,exist_ok=True)
                    page.screenshot(path=str(target / f"admin-{path.rsplit('/',1)[-1]}-{width}.png"),full_page=True,animations='disabled')
                    choose_appearance(page, 'dark')
                    page.screenshot(path=str(target / f"admin-{path.rsplit('/',1)[-1]}-dark-{width}.png"),full_page=True,animations='disabled')
                    if path == '/admin/password':
                        page.locator('[name="current_password"]').focus()
                        page.screenshot(path=str(target / f"admin-password-focus-dark-{width}.png"),full_page=True,animations='disabled')
                    choose_appearance(page, 'system')
                    if path == '/admin/password':
                        page.locator('[name="current_password"]').focus()
                        page.screenshot(path=str(target / f"admin-password-focus-{width}.png"),full_page=True,animations='disabled')
                keyboard_order(page)
                if names:
                    page.locator('[name="'+names[0]+'"]').focus()
                    expect(page.locator('[name="'+names[0]+'"]').first).to_be_focused()
    else:
        page.goto(origin+'/admin/password')
        fill(page,{'current_password':'a synthetic password','password':'short','password_confirmation':'different'})
        submit(page,'Change password')
        validation_result(page,False)
        page.goto(origin+'/admin/password')
        fill(page,{'current_password':'a synthetic password','password':'the replacement password','password_confirmation':'the replacement password'})
        submit(page,'Change password');page.wait_for_url(origin+'/admin/login')
        login(page,'the replacement password')
        page.get_by_label('Workspace menu',exact=True).click()
        submit(page,'Log out');page.wait_for_url(origin+'/admin/login')
        recovery=code('recovery')
        page.goto(origin+'/admin/recovery')
        fill(page,{'code':recovery,'password':'short','password_confirmation':'different'})
        submit(page,'Reset password')
        validation_result(page,False)
        fill(page,{'code':recovery,'password':'a recovered password','password_confirmation':'a recovered password'})
        submit(page,'Reset password');page.wait_for_url(origin+'/admin/login')
        login(page,'a recovered password')
    print(json.dumps({'mode':mode,'result':'passed','browser':browser.version,'widths':[375,639,640,1280] if mode=='preview' else [1280],'javascript':mode!='no_javascript'}))
    browser.close()
