"""Production HTTPS/two-replica WebAuthn proofs, using synthetic browser credentials."""
import base64, concurrent.futures, http.client, json, os, ssl, subprocess, sys
from pathlib import Path
from urllib.parse import urlencode, urlparse
from playwright.sync_api import sync_playwright, expect

ORIGIN=os.environ['BLOC_TEST_ORIGIN']
REALM='11111111-1111-4111-8111-111111111111'
OTHER='33333333-3333-4333-8333-333333333333'
BASE=f'{ORIGIN}/realms/{REALM}'
MODE=sys.argv[1]
def sql(statement):
    database=urlparse(Path(os.environ['BLOC_DATABASE_URL_FILE']).read_text().strip()).path[1:]
    return subprocess.run(['docker','exec',os.environ['BLOC_SETUP_CONTAINER'],'psql','-U','probe','-d',database,'-v','ON_ERROR_STOP=1','-At','-c',statement],check=True,capture_output=True,text=True).stdout.strip()
def request(context,path,fields=None,extra=None):
    connection=http.client.HTTPSConnection('127.0.0.1',4443,context=ssl._create_unverified_context())
    headers={'Host':urlparse(ORIGIN).netloc,'Origin':ORIGIN,'Cookie':'; '.join(c['name']+'='+c['value'] for c in context.cookies())}
    if extra:headers.update(extra)
    body=None
    if fields is not None:body=urlencode(fields);headers['Content-Type']='application/x-www-form-urlencoded'
    connection.request('POST' if fields is not None else 'GET',path,body,headers)
    response=connection.getresponse();result=(response.status,dict(response.getheaders()),response.read().decode());connection.close();return result

def login(page,realm=REALM):
    page.goto(f'{ORIGIN}/realms/{realm}/login')
    page.locator('[name=email]').fill('Alice@example.test');page.locator('[name=password]').fill('a synthetic password')
    page.get_by_role('button',name='Sign in',exact=True).click();page.wait_for_url(f'{ORIGIN}/realms/{realm}/mfa')
    return page.locator('[name=csrf]').first.input_value()

def start(page,csrf,registration=False,realm=REALM):
    path=f'/realms/{realm}/'+('account/security/webauthn/register/options' if registration else 'mfa/webauthn/options')
    status,headers,body=request(page.context,path,dict(csrf=csrf,**({'label':'Personal laptop'} if registration else {})))
    assert status==200,(status,body)
    value=json.loads(body);assert set(value)=={'publicKey','ceremony_id'}
    assert headers.get('cache-control')=='no-store'
    assert 'server_state' not in body and 'library_version' not in body
    return value

def finish(context,csrf,options,credential,registration=False,realm=REALM):
    path=f'/realms/{realm}/'+('account/security/webauthn/register/finish' if registration else 'mfa/webauthn/finish')
    return request(context,path,dict(csrf=csrf,ceremony_id=options['ceremony_id'],credential=json.dumps(credential)))

JS=r'''async({options,registration})=>{
const dec=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const enc=b=>b?btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'):null;
const p=options.publicKey;p.challenge=dec(p.challenge);if(p.user)p.user.id=dec(p.user.id);
for(const c of(p.allowCredentials||[]))c.id=dec(c.id);for(const c of(p.excludeCredentials||[]))c.id=dec(c.id);
if(registration)p.authenticatorSelection.residentKey='required';
const c=await navigator.credentials[registration?'create':'get']({publicKey:p}),r=c.response;
return {id:c.id,rawId:enc(c.rawId),type:c.type,response:registration?{attestationObject:enc(r.attestationObject),clientDataJSON:enc(r.clientDataJSON),transports:r.getTransports?r.getTransports():[]}:{authenticatorData:enc(r.authenticatorData),clientDataJSON:enc(r.clientDataJSON),signature:enc(r.signature),userHandle:enc(r.userHandle)},extensions:c.getClientExtensionResults()};}'''
def signed(page,options,registration=False):return page.evaluate(JS,dict(options=options,registration=registration))
RESIGN=r"""async({credential,key})=>{
 const dec=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
 const enc=b=>btoa(String.fromCharCode(...b)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
 const privateKey=await crypto.subtle.importKey('pkcs8',dec(key),{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
 const auth=dec(credential.response.authenticatorData),hash=new Uint8Array(await crypto.subtle.digest('SHA-256',dec(credential.response.clientDataJSON)));
 const message=new Uint8Array(auth.length+hash.length);message.set(auth);message.set(hash,auth.length);
 const raw=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,message));
 const integer=part=>{let first=0;while(first<part.length-1&&part[first]===0)first++;let value=[...part.slice(first)];if(value[0]&128)value.unshift(0);return [2,value.length,...value];};
 const r=integer(raw.slice(0,32)),ss=integer(raw.slice(32));credential.response.signature=enc([48,r.length+ss.length,...r,...ss]);return credential;
}"""
def resign(page,cdp,aid,credential):
    key=cdp.send('WebAuthn.getCredentials',{'authenticatorId':aid})['credentials'][0]['privateKey']
    return page.evaluate(RESIGN,dict(credential=credential,key=key))

def active_count():return int(sql('SELECT count(*) FROM bloc.realm_user_factor WHERE revoked_at IS NULL'))
def session_count():return int(sql('SELECT count(*) FROM bloc.realm_user_session WHERE revoked_at IS NULL'))
def parent():return sql("SELECT id::text||'|'||expires_at::text||'|'||failed_attempts::text FROM bloc.realm_mfa_flow WHERE parent_id IS NULL AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1")
def enroll_direct(page,csrf):
    options=start(page,csrf,True);credential=signed(page,options,True)
    status,headers,_=finish(page.context,csrf,options,credential,True)
    assert (status, headers.get('location')) == (303, f'/realms/{REALM}/account'), (status, headers.get('location'))
    return options,credential

def fresh_auth(page):
    csrf=login(page);return csrf,start(page,csrf)

def assert_no_secret_log():
    logs=''.join(p.read_text() for p in Path(os.environ['BLOC_REALM_SERVICE_LOGS']).glob('service-*.*'))
    for secret in ['a synthetic password','Alice@example.test','clientDataJSON','attestationObject','authenticatorData']:
        assert secret not in logs

with sync_playwright() as pw:
    browser=pw.chromium.launch(headless=True,channel='chromium',args=['--no-proxy-server','--host-resolver-rules=MAP bloc.example.test 127.0.0.1','--ignore-certificate-errors-spki-list='+os.environ['BLOC_TEST_SPKI']])
    engine_version=browser.version
    context=browser.new_context(viewport={'width':1440,'height':1000});page=context.new_page()
    cdp=context.new_cdp_session(page);cdp.send('WebAuthn.enable')
    aid=cdp.send('WebAuthn.addVirtualAuthenticator',{'options':{'protocol':'ctap2','transport':'internal','hasResidentKey':True,'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True,'defaultBackupEligibility':True,'defaultBackupState':True}})['authenticatorId']
    csrf=login(page)
    if MODE=='c29':
        plain=browser.new_context(java_script_enabled=False);plain.add_cookies(context.cookies());p=plain.new_page();p.goto(BASE+'/account/security/webauthn/setup')
        guidance = 'Passkeys require JavaScript. Use an allowed enrolled authenticator app or an enabled recovery path. The policy is unchanged.'
        expect(p.locator('main#content').get_by_text('Passkeys require JavaScript.', exact=False)).to_have_count(1)
        expect(p.get_by_text(guidance, exact=True)).to_be_visible()
        expect(p.get_by_role('link', name='Use another method', exact=True)).to_be_visible()
        expect(p.locator('[data-webauthn-form]')).to_be_hidden()
        assert active_count()==session_count()==0
        unsupported=browser.new_context();unsupported.add_cookies(context.cookies());unsupported.add_init_script('window.PublicKeyCredential=undefined');p=unsupported.new_page();p.goto(BASE+'/account/security/webauthn/setup')
        expect(p.get_by_role('heading',name='Passkey unavailable',exact=True)).to_be_visible();expect(p.locator('[data-webauthn-status]')).to_contain_text('can’t complete');expect(p.locator('[data-webauthn-submit]')).to_be_hidden();assert active_count()==session_count()==0
    elif MODE=='c30':
        page.goto(BASE+'/account/security/webauthn/setup');before=parent()
        page.evaluate("()=>{navigator.credentials.create=async()=>{throw new DOMException('Canceled','NotAllowedError')};}")
        page.locator('[name=label]').fill('Canceled laptop');page.get_by_role('button',name='Create passkey',exact=True).click()
        expect(page.locator('[data-webauthn-status]')).to_contain_text('Canceled the prompt?')
        assert parent()==before and active_count()==session_count()==0
        assert sql("SELECT count(*) FROM bloc.realm_mfa_flow WHERE purpose='webauthn_registration'")=='1'
    else:
        if MODE in ('c28','c31'):
            page.goto(BASE+'/account/security/webauthn/setup');page.locator('[name=label]').fill('Personal laptop')
            page.get_by_role('button',name='Create passkey',exact=True).click();page.wait_for_url(BASE+'/account/security/recovery-codes')
            expect(page.get_by_role('heading',name='Save your recovery codes',exact=True)).to_be_visible()
            assert len(page.locator('#recovery-codes').input_value().splitlines())==10 and session_count()==0
            page.locator('[name=saved]').check();page.get_by_role('button',name='Finish setup',exact=True).click();page.wait_for_url(BASE+'/account/profile')
            assert active_count()==session_count()==1
            row=json.loads(sql("SELECT row_to_json(t) FROM (SELECT a.label,a.kind,w.record_format_version,w.public_credential IS NOT NULL AS public,w.realm_id::text,w.user_id::text FROM bloc.realm_user_factor a JOIN bloc.realm_webauthn_factor w ON w.factor_id=a.id) t"))
            assert row==dict(label='Personal laptop',kind='webauthn',record_format_version=1,public=True,realm_id=REALM,user_id='22222222-2222-4222-8222-222222222222')
            assert 'private' not in sql("SELECT convert_from(public_credential,'UTF8') FROM bloc.realm_webauthn_factor").lower()
            csrf=login(page);page.goto(BASE+'/mfa/webauthn');page.get_by_role('button',name='Use passkey',exact=True).click();page.wait_for_url(BASE+'/account/profile')
            assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'")=='2'
            if MODE=='c31':
                page.goto(BASE+'/account/security')
                expect(page.get_by_role('heading',name='Account security',exact=True)).to_be_visible()
                expect(page.locator('table').get_by_text('Personal laptop',exact=False)).to_be_visible()
                expect(page.locator('table').get_by_text('Passkey or security key',exact=False)).to_be_visible()
                assert 'public_credential' not in page.content() and 'credential_id' not in page.content()
                page.get_by_role('link',name='Add passkey or security key',exact=True).click()
                page.locator('[name=current_password]').fill('a synthetic password');page.get_by_role('button',name='Verify and continue',exact=True).click();page.wait_for_url(BASE+'/mfa')
                page.goto(BASE+'/mfa/webauthn');page.get_by_role('button',name='Use passkey',exact=True).click();page.wait_for_url(BASE+'/account/security/continue')
                page.get_by_role('link',name='Add a passkey or security key',exact=True).click()
                # The same authenticator correctly refuses an excluded credential. Use an independent device for the added factor.
                cdp.send('WebAuthn.removeVirtualAuthenticator',{'authenticatorId':aid})
                aid=cdp.send('WebAuthn.addVirtualAuthenticator',{'options':{'protocol':'ctap2','transport':'internal','hasResidentKey':True,'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True,'defaultBackupEligibility':True,'defaultBackupState':True}})['authenticatorId']
                page.locator('[name=label]').fill('Backup security key')
                page.get_by_role('button',name='Create passkey',exact=True).click();page.wait_for_url(BASE+'/account/profile')
                page.goto(BASE+'/account/security');expect(page.locator('table').get_by_text('Backup security key',exact=False)).to_be_visible()
                assert sql(f"SELECT count(*) FROM bloc.realm_user_factor WHERE realm_id='{REALM}' AND revoked_at IS NULL")=='2'
                assert sql(f"SELECT count(*) FROM bloc.realm_user_session WHERE realm_id='{REALM}' AND revoked_at IS NULL")=='1'
                old_id=sql(f"SELECT id::text FROM bloc.realm_user_factor WHERE realm_id='{REALM}' AND label='Personal laptop'")
                page.locator('tbody tr').filter(has_text='Personal laptop').get_by_role('link',name='Replace',exact=True).click()
                page.locator('[name=current_password]').fill('a synthetic password');page.get_by_role('button',name='Verify and continue',exact=True).click();page.wait_for_url(BASE+'/mfa')
                page.goto(BASE+'/mfa/webauthn');page.get_by_role('button',name='Use passkey',exact=True).click();page.wait_for_url(BASE+'/account/security/continue')
                page.get_by_role('link',name='Add a passkey or security key',exact=True).click()
                assert sql(f"SELECT revoked_at IS NULL FROM bloc.realm_user_factor WHERE id='{old_id}'")=='t'
                cdp.send('WebAuthn.removeVirtualAuthenticator',{'authenticatorId':aid})
                aid=cdp.send('WebAuthn.addVirtualAuthenticator',{'options':{'protocol':'ctap2','transport':'internal','hasResidentKey':True,'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True,'defaultBackupEligibility':True,'defaultBackupState':True}})['authenticatorId']
                page.locator('[name=label]').fill('Replacement laptop');page.get_by_role('button',name='Create passkey',exact=True).click();page.wait_for_url(BASE+'/account/profile')
                assert sql(f"SELECT revoked_at IS NOT NULL FROM bloc.realm_user_factor WHERE id='{old_id}'")=='t'
                assert sql(f"SELECT count(*) FROM bloc.realm_user_factor WHERE realm_id='{REALM}' AND revoked_at IS NULL")=='2'
                page.goto(BASE+'/account/security');expect(page.locator('table').get_by_text('Replacement laptop',exact=False)).to_be_visible()
                expect(page.locator('table').get_by_text('Personal laptop',exact=False)).to_have_count(0)
                # Optional unenrolled account creates its first factor under account-browser authority.
                # Recovery handoff must retain that browser binding after revoking the ordinary session.
                sql(f"UPDATE bloc.realm_authentication_settings SET mfa_mode='optional' WHERE realm_id='{OTHER}'")
                otherbase=f'{ORIGIN}/realms/{OTHER}'
                page.goto(otherbase+'/login');page.locator('[name=email]').fill('Alice@example.test');page.locator('[name=password]').fill('a synthetic password')
                page.get_by_role('button',name='Sign in',exact=True).click();page.wait_for_url(otherbase+'/account/profile')
                page.goto(otherbase+'/account/security');page.get_by_role('link',name='Add passkey or security key',exact=True).click()
                page.locator('[name=current_password]').fill('a synthetic password');page.get_by_role('button',name='Verify and continue',exact=True).click();page.wait_for_url(otherbase+'/account/security/continue')
                page.get_by_role('link',name='Add a passkey or security key',exact=True).click()
                unicode_label='😀'*64
                page.locator('[name=label]').fill(unicode_label);assert page.locator('[name=label]').input_value()==unicode_label
                page.get_by_role('button',name='Create passkey',exact=True).click();page.wait_for_url(otherbase+'/account/security/recovery-codes')
                expect(page.get_by_role('heading',name='Save your recovery codes',exact=True)).to_be_visible()
                assert len(page.locator('#recovery-codes').input_value().splitlines())==10
                assert sql(f"SELECT count(*) FROM bloc.realm_user_session WHERE realm_id='{OTHER}' AND revoked_at IS NULL")=='0'
                page.locator('[name=saved]').check();page.get_by_role('button',name='Finish setup',exact=True).click();page.wait_for_url(otherbase+'/account/profile')
                page.goto(otherbase+'/account/security');expect(page.locator('table').get_by_text(unicode_label,exact=False)).to_be_visible()
                assert sql('SELECT count(DISTINCT user_handle) FROM bloc.realm_webauthn_identity')=='2'
        else:
            sql('UPDATE bloc.realm_authentication_settings SET mfa_recovery_codes_enabled=false')
            if MODE=='c34':
                options=start(page,csrf,True);credential=signed(page,options,True)
                registration_cookies=context.cookies()
                class RegistrationCookies:
                    def cookies(self):return registration_cookies
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    registrations=list(pool.map(lambda _:finish(RegistrationCookies(),csrf,options,credential,True),range(2)))
                assert sorted(r[0] for r in registrations)==[303,409],[(r[0],r[2]) for r in registrations]
                assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_factor_enroll'")=='1'
            else:options,credential=enroll_direct(page,csrf)
            assert active_count()==1
            # Existing parent remains consumed after enrollment; new password proof starts login.
            if MODE=='c32':
                csrf,options=fresh_auth(page)
                status,_,_=request(context,f'/realms/{REALM}/mfa/webauthn/options',dict(csrf=csrf),{'Origin':'https://wrong.example.test'});assert status==403
                status,_,_=request(context,f'/realms/{REALM}/mfa/webauthn/options',dict(csrf='invalid'));assert status==403
                status,_,_=request(context,f'/realms/{REALM}/mfa/webauthn/finish',dict(csrf=csrf,ceremony_id=options['ceremony_id'],credential='x'*65536));assert status==413
                status,_,_=request(context,f'/realms/{REALM}/mfa/webauthn/options',dict(csrf=csrf,label='x'*16384));assert status==413
                # A finish body between16/64KiB reaches proof validation; other forms keep16KiB.
                nested={'extra':'x'*18000}
                status,_,_=finish(context,csrf,options,nested);assert status==422
                assert request(context,f'/realms/{REALM}/mfa/cancel',dict(csrf=csrf))[0]==303
                cases=['origin','rp','user','uv','challenge','ceremony']
                csrf=login(page)
                for index,case in enumerate(cases):
                    if index==3:
                        assert request(context,f'/realms/{REALM}/mfa/cancel',dict(csrf=csrf))[0]==303
                        csrf=login(page)
                    options=start(page,csrf)
                    if case=='uv':
                        cdp.send('WebAuthn.setUserVerified',{'authenticatorId':aid,'isUserVerified':False});options['publicKey']['userVerification']='discouraged'
                    credential=signed(page,options)
                    if case=='uv':cdp.send('WebAuthn.setUserVerified',{'authenticatorId':aid,'isUserVerified':True})
                    if case=='origin':
                        client=json.loads(base64.urlsafe_b64decode(credential['response']['clientDataJSON']+'=='));client['origin']='https://wrong.example.test';credential['response']['clientDataJSON']=base64.urlsafe_b64encode(json.dumps(client).encode()).decode().rstrip('=')
                    elif case=='rp':
                        raw=bytearray(base64.urlsafe_b64decode(credential['response']['authenticatorData']+'=='));raw[0]^=1;credential['response']['authenticatorData']=base64.urlsafe_b64encode(raw).decode().rstrip('=')
                    elif case=='user':credential['response']['userHandle']=base64.urlsafe_b64encode(bytes([127]*32)).decode().rstrip('=')
                    elif case=='challenge':options=start(page,csrf)
                    elif case=='ceremony':
                        status,_,_=finish(context,csrf,options,credential,True);assert status==409
                        continue
                    if case in ('origin','rp'):credential=resign(page,cdp,aid,credential)
                    status,_,body=finish(context,csrf,options,credential);assert status==422,(case,status,body)
                assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'")=='1'
                options=start(page,csrf);credential=signed(page,options)
                # The signed assertion stays intact. Its ignored member controls
                # the total container depth, including the credential object.
                nested = 0
                for _ in range(15):
                    nested = [nested]
                over_limit = {**credential, 'extra': [nested]}
                at_limit = {**credential, 'extra': nested}
                assert finish(context,csrf,options,over_limit)[0]==422
                status, headers, _ = finish(context,csrf,options,at_limit)
                assert (status, headers.get('location')) == (303, f'/realms/{REALM}/account')
                assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'")=='2'
                other=browser.new_context();p=other.new_page();othercsrf=login(p,OTHER)
                def other_budget():
                    return int(sql(f"SELECT coalesce((SELECT cardinality(admitted_at) FROM bloc.mfa_admission_bucket WHERE scope='account' AND subject_digest=sha256(uuid_send('{OTHER}'::uuid)||uuid_send('44444444-4444-4444-8444-444444444444'::uuid))),0)"))
                assert other_budget()==0
                endpoint=f'/realms/{OTHER}/account/security/webauthn/register/finish'
                assert request(other,endpoint,dict(csrf='invalid',ceremony_id='invalid',credential='{}'))[0]==403
                assert other_budget()==0
                for index,reference in enumerate(['invalid','99999999-9999-4999-8999-999999999999','invalid','99999999-9999-4999-8999-999999999999','invalid']):
                    status,headers,_=request(other,endpoint,dict(csrf=othercsrf,ceremony_id=reference,credential='{}'))
                    assert status==([422,409,422,409,429][index]),(index,status)
                    if index==4:assert headers['retry-after']=='60'
                assert sql(f"SELECT failed_attempts::text||'|'||(consumed_at IS NOT NULL)::text FROM bloc.realm_mfa_flow WHERE realm_id='{OTHER}' AND parent_id IS NULL ORDER BY created_at DESC LIMIT 1")=='5|true'
                assert other_budget()==5
                assert sql(f"SELECT count(*) FROM bloc.realm_user_factor WHERE realm_id='{OTHER}'")=='0'
                assert sql(f"SELECT count(*) FROM bloc.realm_user_session WHERE realm_id='{OTHER}'")=='0'
                othercsrf=login(p,OTHER);assert other_budget()==5
                assert request(other,endpoint,dict(csrf=othercsrf,ceremony_id='invalid',credential='{}'))[0]==422
                assert other_budget()==6
            elif MODE=='c33':
                csrf,options=fresh_auth(page);credential=signed(page,options)
                other=browser.new_context();p=other.new_page();othercsrf=login(p,OTHER)
                status,_,_=finish(other,othercsrf,options,credential,False,OTHER);assert status==409
                status,_,_=request(other,f'/realms/{OTHER}/mfa/webauthn/options',dict(csrf=othercsrf));assert status==409
                status,_,_=finish(context,csrf,options,credential,False,OTHER);assert status in (403,409)
                assert sql(f"SELECT count(*) FROM bloc.realm_webauthn_factor WHERE realm_id='{OTHER}'")=='0'
            elif MODE=='c34':
                # First registration already succeeded; replay is fenced by consumed parent.
                status,_,_=finish(context,csrf,options,credential,True);assert status==409
                csrf,options=fresh_auth(page);credential=signed(page,options)
                # Copy cookies once; two simultaneous TLS requests reach independently assembled serving processes.
                cookies=context.cookies()
                class Cookies:
                    def cookies(self):return cookies
                with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(lambda _:finish(Cookies(),csrf,options,credential),range(2)))
                assert sorted(r[0] for r in results)==[303,409],[(r[0],r[2]) for r in results]
                assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'")=='2'
                assert sql("SELECT count(*) FROM bloc.realm_webauthn_factor")=='1'
            elif MODE=='c35':
                # Synthetic zero-counter persisted profile, matching the binding spike. The authenticator signs real zero assertions.
                sql("UPDATE bloc.realm_webauthn_factor SET public_credential=convert_to(jsonb_set(convert_from(public_credential,'UTF8')::jsonb,'{payload,cred,counter}','0')::text,'UTF8')")
                assert json.loads(sql("SELECT convert_from(public_credential,'UTF8') FROM bloc.realm_webauthn_factor"))['payload']['cred']['counter']==0
                cred=cdp.send('WebAuthn.getCredentials',{'authenticatorId':aid})['credentials'][0]
                def counter(value):
                    cdp.send('WebAuthn.removeCredential',{'authenticatorId':aid,'credentialId':cred['credentialId']});cred['signCount']=value;cdp.send('WebAuthn.addCredential',{'authenticatorId':aid,'credential':cred})
                for _ in range(2):
                    counter(4294967295);csrf,options=fresh_auth(page);credential=signed(page,options)
                    assert int.from_bytes(base64.urlsafe_b64decode(credential['response']['authenticatorData']+'==')[33:37],'big')==0
                    status,_,body=finish(context,csrf,options,credential);assert status==303,(status,body)
                # Nonzero updates persist; fresh state with the same signed nonzero counter is rejected by library.
                counter(0);csrf,options=fresh_auth(page);credential=signed(page,options);assert finish(context,csrf,options,credential)[0]==303
                counter(0);csrf,options=fresh_auth(page);credential=signed(page,options);assert finish(context,csrf,options,credential)[0]==422
                assert json.loads(sql("SELECT convert_from(public_credential,'UTF8') FROM bloc.realm_webauthn_factor"))['payload']['cred']['counter']==1
                assert sql("SELECT count(*) FROM bloc.security_audit_event WHERE action='realm_mfa_sign_in'")=='4'
    assert_no_secret_log();browser.close()
record={'mode':MODE,'production_https_two_replicas':True,'engine':'Chromium CDP virtual authenticator','engine_version':engine_version,'native_device_qualification':False,'result':'pass'}
if os.environ.get('BLOC_DIRECTORY_BROWSER_EVIDENCE'):
    evidence=Path(os.environ['BLOC_DIRECTORY_BROWSER_EVIDENCE']);evidence.mkdir(parents=True,exist_ok=True)
    (evidence/f'webauthn-{MODE}.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
