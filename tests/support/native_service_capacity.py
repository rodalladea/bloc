"""Run the actual Linux/glibc service natively with 1 CPU/512MiB/no swap.

No emulation is accepted. Run on each native CI architecture; write evidence to
an external directory. This is deliberately separate from the primitive spike.
"""
import argparse, concurrent.futures, http.client, json, os, platform
from pathlib import Path
import math, subprocess, sys, tempfile, threading, time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from support import postgres
from run_storage import ROLES

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('--image',default='bloc-native-service-capacity:local')
parser.add_argument('--skip-build',action='store_true')
parser.add_argument('--realm-auth', action='store_true',
                    help='Measure mixed administrator and realm authentication workload')
args=parser.parse_args()
args.output.mkdir(parents=True,exist_ok=False)
def preserve_failure(kind,error,traceback):
    (args.output/'failure.json').write_text(json.dumps({'error_category':kind.__name__,'source_tree_sha256':globals().get('source_tree_sha256'),'architecture':globals().get('arch'),'attempts':globals().get('attempts',[]),'credential_latency_seconds':globals().get('latency',[]),'health':globals().get('health',[])},indent=2)+'\n')
    sys.__excepthook__(kind,error,traceback)
sys.excepthook=preserve_failure

arch={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}.get(platform.machine().lower())
daemon=json.loads(postgres.command('docker','info','--format','{{json .}}'))
assert {'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}.get(daemon['Architecture'])==arch,'native host and daemon architecture required'
from application_fingerprint import source_fingerprint
source_tree_sha256=source_fingerprint()
working_tree_dirty=bool(postgres.command('git','status','--porcelain'))
if not args.skip_build:subprocess.run(['docker','build','--label','org.bloc.source-tree-sha256='+source_tree_sha256,'-t',args.image,'.'],check=True)
identity=json.loads(postgres.command('docker','image','inspect',args.image))[0]
assert source_fingerprint()==source_tree_sha256,'source changed during Docker build; evidence invalid'
assert identity['Config'].get('Labels',{}).get('org.bloc.source-tree-sha256')==source_tree_sha256,'image context fingerprint mismatch'
assert identity['Architecture']==arch and identity['Os']=='linux','emulated or non-Linux image refused'
containers=[]
with tempfile.TemporaryDirectory(prefix='bloc-native-service-') as temp:
    directory=Path(temp)
    try:
        postgres.certificate(directory,'ca');postgres.certificate(directory,'matching','127.0.0.1')
        db=postgres.command('docker','create','--publish','127.0.0.1::5432','--publish','127.0.0.1::3000','--env','POSTGRES_USER=probe','--env','POSTGRES_DB=probe','--env','POSTGRES_PASSWORD=synthetic-probe-only','--entrypoint','sh',postgres.IMAGES[0],'-c','chown postgres:postgres /tmp/probe.key && chmod 600 /tmp/probe.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/probe.crt -c ssl_key_file=/tmp/probe.key')
        containers.append(db)
        for source,target in [('matching.crt','probe.crt'),('matching.key','probe.key')]:postgres.command('docker','cp',str(directory/source),db+':/tmp/'+target)
        postgres.command('docker','start',db)
        for _ in range(240):
            if subprocess.run(['docker','exec',db,'pg_isready','-h','127.0.0.1','-U','probe'],capture_output=True).returncode==0:break
            time.sleep(.25)
        else:raise RuntimeError('primary unavailable')
        subprocess.run(['docker','exec','-i',db,'psql','-U','probe','-d','probe','-v','ON_ERROR_STOP=1'],input=ROLES+'\nCREATE DATABASE capacity OWNER migrator_user;',text=True,capture_output=True,check=True)
        for role in ['runtime','operator','migrator']:(directory/(role+'-url')).write_text('postgres://'+role+'_user:synthetic-setup-only@127.0.0.1:5432/capacity')
        (directory/'abuse-key').write_bytes(os.urandom(32))
        for path in directory.iterdir():path.chmod(0o644)
        directory.chmod(0o755)
        shared=['--network','container:'+db,'--mount','type=bind,src='+str(directory)+',dst=/run/bloc,readonly','--env','BLOC_DATABASE_CA_FILE=/run/bloc/ca.crt']
        def operation(role,*words):
            return subprocess.run(['docker','run','--rm',*shared,'--env','BLOC_DATABASE_URL_FILE=/run/bloc/'+role+'-url',args.image,*words],capture_output=True,text=True,check=True).stdout
        operation('migrator','database','migrate')
        service=postgres.command('docker','create',*shared,'--cpus','1','--memory','512m','--memory-swap','512m','--env','MALLOC_MMAP_THRESHOLD_=131072','--env','BLOC_DATABASE_URL_FILE=/run/bloc/runtime-url','--env','BLOC_ABUSE_KEY_FILE=/run/bloc/abuse-key','--env','BLOC_CANONICAL_ORIGIN=https://capacity.example.test','--env','BLOC_TRUSTED_PROXY_CIDRS=0.0.0.0/0','--env','BLOC_BIND_ADDR=0.0.0.0:3000',args.image)
        containers.append(service);postgres.command('docker','start',service)
        port=int(json.loads(postgres.command('docker','inspect',db))[0]['NetworkSettings']['Ports']['3000/tcp'][0]['HostPort'])
        def request(method,path,body=None,cookie=None,source="192.0.2.1"):
            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
            headers={'Host':'capacity.example.test','Origin':'https://capacity.example.test','X-Forwarded-Proto':'https','X-Forwarded-For':source,'Content-Type':'application/x-www-form-urlencoded'}
            if cookie:headers['Cookie']=cookie
            start=time.monotonic();connection.request(method,path,body,headers);response=connection.getresponse();output=response.read().decode();result=(response.status,output,response.getheaders(),time.monotonic()-start);connection.close();return result
        for _ in range(200):
            try:
                if request('GET','/readyz')[0]==200:break
            except OSError:pass
            time.sleep(.1)
        else:raise RuntimeError('service readiness failed')
        def state(path,source="192.0.2.1"):
            status,html,headers,_=request('GET',path,source=source);assert status==200
            cookie='; '.join(value.split(';')[0] for key,value in headers if key.lower()=='set-cookie')
            token=html.split('name="csrf" value="')[1].split('"')[0]
            return cookie,token
        from urllib.parse import urlencode
        setup=operation('operator','admin','setup-code').splitlines()[0].split('=',1)[1]
        cookie,token=state('/admin/setup')
        assert request('POST','/admin/setup',urlencode({'csrf':token,'code':setup,'email':'Owner@example.test','password':'a synthetic password','password_confirmation':'a synthetic password'}),cookie)[0]==303
        realm_path = '/realms/11111111-1111-4111-8111-111111111111/login'
        secrets = [setup, 'a synthetic password', 'Owner@example.test']
        def sql(statement):
            return postgres.command('docker', 'exec', db, 'psql', '-U', 'probe',
                                    '-d', 'capacity', '-v', 'ON_ERROR_STOP=1', '-Atc', statement)
        if args.realm_auth:
            # The fixture owns this disposable database; no runtime capability is bypassed in requests.
            sql("""BEGIN;
                INSERT INTO bloc.realm(id,name,created_at,updated_at)
                VALUES('11111111-1111-4111-8111-111111111111','Capacity realm',clock_timestamp(),clock_timestamp());
                INSERT INTO bloc.realm_authentication_settings(realm_id)
                VALUES('11111111-1111-4111-8111-111111111111') ON CONFLICT DO NOTHING;
                INSERT INTO bloc.realm_user(id,realm_id,email,created_at,updated_at)
                SELECT ('22222222-2222-4222-8222-'||lpad(i::text,12,'0'))::uuid,
                    '11111111-1111-4111-8111-111111111111','Capacity'||i||'@example.test',clock_timestamp(),clock_timestamp()
                FROM generate_series(1,20) i;
                INSERT INTO bloc.realm_user_credential(realm_id,user_id,password_hash,credential_version,password_changed_at)
                SELECT u.realm_id,u.id,a.password_hash,1,clock_timestamp()
                FROM bloc.realm_user u CROSS JOIN bloc.installation_administrator a;
                COMMIT;""")
            secrets += [f'Capacity{i}@example.test' for i in range(1,21)]
        def workload(number):
            if args.realm_auth and number % 2:
                return realm_path, f'Capacity{number + 1}@example.test', 'realm'
            return '/admin/login', 'Owner@example.test', 'administrator'
        admission_samples = []
        stop=threading.Event();health=[];attempts=[]
        def probes():
            while not stop.is_set():
                try:health.append(request('GET','/healthz')[0])
                except Exception:health.append(0)
                stop.wait(.1)
        probe=threading.Thread(target=probes);probe.start();started=time.monotonic()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                for batch in range(20):
                    states=[]
                    for number in range(20):
                        source='192.0.'+str(batch+1)+'.'+str(number+1)
                        path,email,principal=workload(number)
                        cookie,token=state(path,source)
                        secrets += [token, *[part.split('=',1)[1] for part in cookie.split('; ')]]
                        body=urlencode({'csrf':token,'email':email,'password':'a synthetic password'})
                        states.append((cookie,body,source,path,principal))
                    barrier=threading.Barrier(20)
                    def attempt(number):
                        cookie,body,source,path,principal=states[number]
                        barrier.wait()
                        status,_,headers,elapsed=request('POST',path,body,cookie,source)
                        secrets.extend(value.split(';',1)[0].split('=',1)[1]
                                       for key,value in headers if key.lower()=='set-cookie')
                        return {'principal':principal,'status':status,'seconds':elapsed,'retry_after':dict((k.lower(),v) for k,v in headers).get('retry-after')}
                    attempts.extend(pool.map(attempt,range(20)))
                    if args.realm_auth:
                        sample = json.loads(sql("""SELECT json_build_object(
                            'all_hash_work', (SELECT count(*) FROM bloc.administrator_admission_bucket b,
                                unnest(b.admitted_at) e WHERE b.scope='hash_work' AND e>clock_timestamp()-interval '60 seconds'),
                            'realm_hash_work', (SELECT count(*) FROM bloc.realm_admission_bucket b,
                                unnest(b.admitted_at) e WHERE b.scope='public_work' AND e>clock_timestamp()-interval '60 seconds'))"""))
                        assert sample['all_hash_work'] <= 30 and sample['realm_hash_work'] <= 20, sample
                        admission_samples.append(sample)
                    (args.output/'raw.json').write_text(json.dumps({'attempts':attempts,'health':health},indent=2)+'\n')
                    remaining=started+(batch+1)*3-time.monotonic()
                    if remaining>0:time.sleep(remaining)
        finally:stop.set();probe.join()
        elapsed=time.monotonic()-started
        # Separate successful complete-credential latency samples from overloaded
        # burst requests. Wait for the declared rolling allowances; do not relax them.
        time.sleep(61)
        latency=[];latency_principals=[]
        latency_started=time.monotonic()
        for sample in range(20):
            path,email,principal=workload(sample)
            cookie,token=state(path,'192.0.2.2')
            body=urlencode({'csrf':token,'email':email,'password':'a synthetic password'})
            status,_,_,seconds=request('POST',path,body,cookie,'192.0.2.2')
            assert status==303,('latency sample not a complete successful sign-in',status)
            latency.append(seconds)
            latency_principals.append(principal)
            remaining=latency_started+(sample+1)*6.1-time.monotonic()
            if remaining>0:time.sleep(remaining)
        inspect=json.loads(postgres.command('docker','inspect',service))[0]
        peak=int(postgres.command('docker','exec',service,'cat','/sys/fs/cgroup/memory.peak'))
        successes=sorted(latency)
        assert successes,'no complete credential work observed'
        p95=successes[min(len(successes)-1,math.ceil(len(successes)*.95)-1)]
        raw=args.output/'raw.json';raw.write_text(json.dumps({'attempts':attempts,'credential_latency_seconds':latency,'health':health,'docker_state':inspect['State']},indent=2))
        record={'source_tree_sha256':source_tree_sha256,'working_tree_dirty':working_tree_dirty,'credential_sample_count':len(latency),'architecture':arch,'native':True,'service':True,'cpu_limit':1,'memory_limit_bytes':512*1024*1024,'swap_bytes':0,'simultaneous_submissions':20,'duration_seconds':elapsed,'peak_bytes':peak,'credential_p95_seconds':p95,'oom':inspect['State']['OOMKilled'],'failed_health_probes':sum(s!=200 for s in health),'immediate_overload':any(a['status']==503 for a in attempts) and all(a['seconds']<1 and a['retry_after'] for a in attempts if a['status']==503),'bounded_admission':all(a['status'] in [303,429,503] for a in attempts) and any(a['status']==429 for a in attempts),'raw_evidence':str(raw),'binary_sha256':postgres.command('docker','run','--rm','--entrypoint','/usr/bin/sha256sum',args.image,'/usr/local/bin/bloc').split()[0],'source_revision':postgres.command('git','rev-parse','HEAD')}
        if args.realm_auth:
            logs = subprocess.run(['docker','logs',service], check=True, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
            audit = sql('SELECT row_to_json(e) FROM bloc.security_audit_event e')
            assert all(secret not in logs and secret not in audit for secret in secrets if secret), 'secret redaction failed'
            assert {a['principal'] for a in attempts} == {'realm','administrator'}
            assert set(latency_principals) == {'realm','administrator'}
            assert any(s['realm_hash_work'] > 0 for s in admission_samples), 'realm admission not exercised'
            assert any(s['all_hash_work'] > s['realm_hash_work'] for s in admission_samples), 'shared administrator work not observed'
            record.update(realm_authentication=True, redaction=True, admission_samples=admission_samples,
                          credential_sample_principals=latency_principals)
        assert source_fingerprint()==source_tree_sha256,'source changed during capacity measurement; evidence invalid'
        (args.output/'record.json').write_text(json.dumps(record,indent=2)+'\n')
        assert peak<=384*1024*1024 and p95<1 and not record['oom'] and record['failed_health_probes']==0 and record['immediate_overload'] and record['bounded_admission'],record
        print(json.dumps(record))
    finally:
        for container in reversed(containers):subprocess.run(['docker','rm','--force','--volumes',container],capture_output=True,check=True)
