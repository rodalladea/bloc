"""Synthetic authority fixtures for packaging checks; never production secrets."""
import contextlib,ipaddress,json,os,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from support import postgres
from run_storage import ROLES

def assigned_address(container,network='kind'):
    value=container.get('NetworkSettings',{}).get('Networks',{}).get(network,{}).get('IPAddress')
    try:
        address=ipaddress.ip_address(value)
    except (ValueError,TypeError):
        raise ValueError('authority requires a Docker-assigned IPv4 address') from None
    if address.version!=4 or address.is_unspecified or address.is_multicast:
        raise ValueError('authority requires a Docker-assigned IPv4 address')
    return str(address)

@contextlib.contextmanager
def docker_primary(network='kind'):
    """Own one TLS primary; Docker reserves its address before certificate issuance."""
    container=None
    with tempfile.TemporaryDirectory(prefix='bloc-cluster-authority-') as temporary:
        directory=Path(temporary)
        try:
            startup=("remaining=240; while [ ! -f /tmp/bloc-authority-ready ]; do "
                     "[ \"$remaining\" -gt 0 ] || { echo 'authority material unavailable' >&2; exit 1; }; "
                     "remaining=$((remaining-1)); sleep .25; done; "
                     "chown postgres:postgres /tmp/probe.key && chmod 600 /tmp/probe.key && "
                     "exec docker-entrypoint.sh postgres -c ssl=on "
                     "-c ssl_cert_file=/tmp/probe.crt -c ssl_key_file=/tmp/probe.key")
            container=postgres.command('docker','create','--network',network,
                '--env','POSTGRES_USER=probe','--env','POSTGRES_DB=probe',
                '--env','POSTGRES_PASSWORD=synthetic-probe-only',
                '--entrypoint','sh',postgres.IMAGES[0],'-c',startup)
            postgres.command('docker','start',container)
            address=assigned_address(json.loads(postgres.command('docker','inspect',container))[0],network)
            postgres.certificate(directory,'ca');postgres.certificate(directory,'matching',address)
            for source,target in [('matching.crt','probe.crt'),('matching.key','probe.key'),('ca.crt','probe-ca.crt')]:
                postgres.command('docker','cp',str(directory/source),container+':/tmp/'+target)
            postgres.command('docker','exec',container,'touch','/tmp/bloc-authority-ready')
            for _ in range(240):
                if subprocess.run(['docker','exec',container,'pg_isready','-h','127.0.0.1','-U','probe'],capture_output=True).returncode==0:break
                time.sleep(.25)
            else:raise RuntimeError('cluster primary unavailable')
            subprocess.run(['docker','exec','-i',container,'psql','-U','probe','-d','probe','-v','ON_ERROR_STOP=1'],input=ROLES+'\nCREATE DATABASE bloc OWNER migrator_user;',text=True,capture_output=True,check=True)
            yield container,address,directory
        finally:
            if container:subprocess.run(['docker','rm','--force','--volumes',container],capture_output=True,check=True)

@contextlib.contextmanager
def source_configuration():
    with tempfile.TemporaryDirectory(prefix='bloc-source-config-') as temporary:
        directory=Path(temporary)
        postgres.certificate(directory,'ca')
        (directory/'url').write_text('postgres://runtime_user:synthetic-setup-only@127.0.0.1:1/unavailable')
        (directory/'abuse').write_bytes(bytes(range(32)))
        yield {
            'BLOC_DATABASE_URL_FILE':str(directory/'url'),
            'BLOC_DATABASE_CA_FILE':str(directory/'ca.crt'),
            'BLOC_ABUSE_KEY_FILE':str(directory/'abuse'),
            'BLOC_CANONICAL_ORIGIN':'https://bloc.example.test',
            'BLOC_TRUSTED_PROXY_CIDRS':'127.0.0.1/32',
        }

@contextlib.contextmanager
def configuration():
    with tempfile.TemporaryDirectory(prefix='bloc-container-config-') as temporary:
        directory=Path(temporary)
        postgres.certificate(directory,'ca')
        (directory/'url').write_text('postgres://runtime_user:synthetic-setup-only@127.0.0.1:1/unavailable')
        (directory/'abuse').write_bytes(bytes(range(32)))
        directory.chmod(0o755)
        for path in directory.iterdir():path.chmod(0o644)
        yield ['--mount','type=bind,src='+str(directory)+',dst=/run/bloc,readonly','--env','BLOC_DATABASE_URL_FILE=/run/bloc/url','--env','BLOC_DATABASE_CA_FILE=/run/bloc/ca.crt','--env','BLOC_ABUSE_KEY_FILE=/run/bloc/abuse','--env','BLOC_CANONICAL_ORIGIN=https://bloc.example.test','--env','BLOC_TRUSTED_PROXY_CIDRS=127.0.0.1/32']

@contextlib.contextmanager
def cluster_authority(kube,namespace,image):
    def k(*args,input=None):return subprocess.run([kube,'-n',namespace,*args],input=input,text=True,capture_output=True,check=True)
    with docker_primary() as (_,address,directory):
        for role in ['runtime','migrator','operator','maintenance']:(directory/(role+'-url')).write_text('postgres://'+role+'_user:synthetic-setup-only@'+address+':5432/bloc')
        (directory/'abuse-key').write_bytes(bytes(range(32)))
        files=['--from-file='+role+'-url='+str(directory/(role+'-url')) for role in ['runtime','migrator','operator','maintenance']]
        k('create','secret','generic','bloc-database',*files,'--from-file=ca.crt='+str(directory/'ca.crt'),'--from-file=abuse-key='+str(directory/'abuse-key'))
        pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':'bloc-fixture-migrate'},'spec':{'restartPolicy':'Never','automountServiceAccountToken':False,'containers':[{'name':'migration','image':image,'args':['database','migrate'],'env':[{'name':'BLOC_DATABASE_URL_FILE','value':'/run/bloc/migrator-url'},{'name':'BLOC_DATABASE_CA_FILE','value':'/run/bloc/ca.crt'}],'volumeMounts':[{'name':'authority','mountPath':'/run/bloc','readOnly':True}]}],'volumes':[{'name':'authority','secret':{'secretName':'bloc-database','items':[{'key':'migrator-url','path':'migrator-url'},{'key':'ca.crt','path':'ca.crt'}]}}]}}
        k('apply','-f','-',input=json.dumps(pod))
        try:k('wait','--for=jsonpath={.status.phase}=Succeeded','pod/bloc-fixture-migrate','--timeout=180s')
        except subprocess.CalledProcessError:
            print(k('logs','bloc-fixture-migrate').stdout)
            raise
        k('delete','pod','bloc-fixture-migrate','--wait=true')
        yield
