#!/usr/bin/env python3
"""Real-cluster acceptance exercise; only a disposable kind context is allowed."""
import argparse
import contextlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

from chart import INVALID
from authority import cluster_authority


def command(*args, check=True, env=None):
    result=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    if result.returncode:
        result.stdout += result.stderr
    if check and result.returncode:
        raise RuntimeError(' '.join(args)+'\n'+result.stdout)
    return result


def wait_for(predicate, timeout=180):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if predicate():
            return
        time.sleep(1)
    raise AssertionError('timed out waiting for cluster condition')


@contextlib.contextmanager
def forwarding(kube, namespace):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port=sock.getsockname()[1]
    process=subprocess.Popen([kube,'-n',namespace,'port-forward','service/fixture-bloc',f'{port}:80'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def healthy():
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz',timeout=2) as response:
                return response.status==200 and response.read()==b'ok\n'
        except OSError:
            return False
    try:
        wait_for(healthy)
        yield healthy
    finally:
        process.terminate()
        process.wait(timeout=10)


def failed_upgrade_arguments(package, values):
    # Only intentionally unavailable images use this shorter fixture budget.
    return ['upgrade', 'fixture', package, '--version', '0.0.2', '--values', str(values),
            '--wait=watcher', '--timeout', '60s', '--rollback-on-failure']


def exercise(args):
    helm,kube=args.helm,args.kubectl
    context=command(kube,'config','current-context').stdout.strip()
    assert context.startswith('kind-'), 'only a disposable kind context is permitted'
    version=json.loads(command(kube,'version','-o','json').stdout)
    assert version['serverVersion']['gitVersion']=='v1.36.5',version
    assert command(helm,'version','--short').stdout.startswith('v4.3.1'), 'wrong Helm baseline'
    repository,digest_a=args.image.rsplit('@',1)
    _,digest_b=args.image_b.rsplit('@',1)
    assert digest_a!=digest_b, 'A and B must have distinguishable image digests'
    namespace='bloc-test-'+str(os.getpid())
    command(kube,'create','namespace',namespace)
    checks=set(args.check or [f'C{i}' for i in range(9,22)])
    def k(*arguments):
        return command(kube,'-n',namespace,*arguments)
    def get(resource):
        return json.loads(k('get',resource,'-o','json').stdout)
    def h(*arguments,check=True,env=None):
        return command(helm,*arguments,'--namespace',namespace,check=check,env=env)
    def deployment():
        return get('deployment/fixture-bloc')
    def ready():
        dep=deployment()
        return dep['status'].get('availableReplicas',0)==dep['spec']['replicas'] and dep['status'].get('updatedReplicas',0)==dep['spec']['replicas']
    def verify_http():
        with forwarding(kube,namespace) as healthy:
            assert healthy()
    passed=[]
    authority=cluster_authority(kube,namespace,args.image)
    try:
        authority.__enter__()
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            values=tmp/'operator.json'
            values.write_text(json.dumps({'image':{'repository':repository}}))
            packages={}
            for name,version_number in [('A','0.0.1'),('B','0.0.2')]:
                chart=tmp/name
                shutil.copytree('charts/bloc',chart)
                text=re.sub(r'^(version|appVersion):.*$', lambda match: match[1]+': "'+version_number+'"', (chart/'Chart.yaml').read_text(), flags=re.M)
                (chart/'Chart.yaml').write_text(text)
                (chart/'values.yaml').write_text((chart/'values.yaml').read_text().replace('digest: \"\"','digest: '+(digest_a if name=='A' else digest_b)))
                command(helm,'package',str(chart),'--destination',str(tmp))
                packages[name]=str(tmp/f'bloc-{version_number}.tgz')
            if 'C17' in checks:
                # Exercise the published scaffold separately from the local A/B fixtures.
                predecessor=tmp/'predecessor'
                predecessor.mkdir()
                command(helm,'pull','oci://ghcr.io/rodalladea/charts/bloc',
                        '--version','0.0.1','--destination',str(predecessor))
                h('install','fixture',str(predecessor/'bloc-0.0.1.tgz'),
                  '--wait=watcher','--timeout','5m')
                previous='ghcr.io/rodalladea/bloc@sha256:35fe08468d867beec22d2530f69e008329db06a7455f55f5e75628864d5fa42e'
                assert deployment()['spec']['template']['spec']['containers'][0]['image']==previous
                verify_http()
                h('upgrade','fixture',packages['A'],'--values',str(values),
                  '--wait=watcher','--timeout','5m','--rollback-on-failure')
                assert deployment()['spec']['template']['spec']['containers'][0]['image']==repository+'@'+digest_a
                assert ready()
                verify_http()
                h('rollback','fixture','1','--wait=watcher','--timeout','5m')
                assert deployment()['spec']['template']['spec']['containers'][0]['image']==previous
                verify_http()
                h('uninstall','fixture','--wait=watcher','--timeout','5m')
                print('Published v0.0.1 predecessor: install, upgrade to administrator image and rollback passed')
            h('install','fixture',packages['A'],'--version','0.0.1','--values',str(values),'--wait=watcher','--timeout','5m')
            verify_http()
            dep=deployment(); spec=dep['spec']['template']['spec']; container=spec['containers'][0]
            assert dep['spec']['replicas']==1 and ready()
            service=get('service/fixture-bloc')['spec']
            assert service['type']=='ClusterIP' and service['ports'][0]['port']==80 and service['ports'][0]['targetPort']==3000
            assert get('ingress')['items']==[]
            rendered=h('get','manifest','fixture').stdout
            assert 'ClusterRole' not in rendered and 'Namespace' not in rendered
            passed.append('C9')
            assert spec['securityContext']=={'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,'seccompProfile':{'type':'RuntimeDefault'}}
            assert not spec['automountServiceAccountToken']
            assert container['securityContext']=={'readOnlyRootFilesystem':True,'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}}
            assert container['resources']=={'requests':{'cpu':'100m','memory':'128Mi'},'limits':{'cpu':'1','memory':'512Mi'}}
            passed.append('C10')
            if 'C13' in checks:
                before=deployment()['metadata']['resourceVersion']
                for fixture,key in INVALID:
                    invalid={'image':{'repository':repository,'digest':digest_a}}
                    for field,value in fixture.items():
                        if field=='image': invalid['image'].update(value)
                        else: invalid[field]=value
                    path=tmp/'invalid.json'; path.write_text(json.dumps(invalid))
                    result=h('upgrade','fixture',packages['A'],'--version','0.0.1','--values',str(path),'--wait=watcher','--timeout','5m','--rollback-on-failure',check=False)
                    assert result.returncode and key in result.stdout,(fixture,result.stdout)
                    assert deployment()['metadata']['resourceVersion']==before
                passed.append('C13')
            if 'C16' in checks:
                for probe in ['readinessProbe','livenessProbe']:
                    actual=container[probe]
                    assert actual['httpGet']['path']==('/readyz' if probe=='readinessProbe' else '/healthz') and actual['httpGet']['port']==3000
                    assert [actual[k] for k in ['periodSeconds','timeoutSeconds','failureThreshold']]==[10,2,3]
                pod=get('pods')['items'][0]
                name=pod['metadata']['name']; restarts=pod['status']['containerStatuses'][0]['restartCount']
                # PID 1 ignores an in-namespace STOP; inject from the disposable
                # kind node's parent namespace, without changing the workload.
                runtime_id=pod['status']['containerStatuses'][0]['containerID'].split('://',1)[1]
                node_name=pod['spec']['nodeName']
                runtime=json.loads(command('docker','exec',node_name,'crictl','inspect',runtime_id).stdout)
                command('docker','exec',node_name,'kill','-STOP',str(runtime['info']['pid']))
                def excluded():
                    endpoints=get('endpointslices')['items']
                    return any(not endpoint.get('conditions',{}).get('ready',True) for item in endpoints for endpoint in item.get('endpoints',[]))
                wait_for(excluded,90)
                wait_for(lambda:get('pod/'+name)['status']['containerStatuses'][0]['restartCount']>restarts,180)
                wait_for(ready)
                events=get('events')['items']
                assert any('Liveness probe failed' in e.get('message','') for e in events)
                assert any('Readiness probe failed' in e.get('message','') for e in events)
                verify_http(); passed.append('C16')
            if checks & {'C11','C12','C17','C20'}:
                node=json.loads(command(kube,'get','nodes','-o','json').stdout)['items'][0]['metadata']['name']
                saved={'replicaCount':2,'image':{'repository':repository},'logLevel':'debug','resources':{'requests':{'cpu':'200m','memory':'96Mi'},'limits':{'cpu':'1','memory':'192Mi'}},'nodeSelector':{'kubernetes.io/hostname':node},'tolerations':[{'key':'bloc-test','operator':'Exists','effect':'NoSchedule'}],'affinity':{'nodeAffinity':{'requiredDuringSchedulingIgnoredDuringExecution':{'nodeSelectorTerms':[{'matchExpressions':[{'key':'kubernetes.io/hostname','operator':'In','values':[node]}]}]}}}}
                values.write_text(json.dumps(saved))
                h('upgrade','fixture',packages['A'],'--version','0.0.1','--values',str(values),'--wait=watcher','--timeout','5m','--rollback-on-failure')
                assert json.loads(h('get','values','fixture','-o','json').stdout)==saved
                assert deployment()['spec']['template']['spec']['containers'][0]['image']==repository+'@'+digest_a
                h('upgrade','fixture',packages['B'],'--version','0.0.2','--values',str(values),'--wait=watcher','--timeout','5m','--rollback-on-failure')
                verify_http(); dep=deployment(); spec=dep['spec']['template']['spec']; container=spec['containers'][0]
                assert dep['spec']['strategy']=={'type':'RollingUpdate','rollingUpdate':{'maxUnavailable':0,'maxSurge':1}}
                assert spec['terminationGracePeriodSeconds']==30
                assert container['image']==repository+'@'+digest_b and dep['spec']['replicas']==2 and ready()
                for key in ['nodeSelector','tolerations','affinity']:
                    assert spec[key]==saved[key]
                assert container['resources']==saved['resources']
                assert {'name':'RUST_LOG','value':'debug'} in container['env']
                assert {'name':'BLOC_BIND_ADDR','value':'0.0.0.0:3000'} in container['env']
                assert json.loads(h('get','values','fixture','-o','json').stdout)==saved
                history=json.loads(h('history','fixture','-o','json').stdout)
                assert len(history)==3 and history[-1]['chart']=='bloc-0.0.2'
                passed.extend(['C11','C17'])
                mirror=repository+'-mirror'
                mirrored={**saved,'image':{'repository':mirror,'digest':digest_b}}
                values.write_text(json.dumps(mirrored))
                h('upgrade','fixture',packages['B'],'--version','0.0.2','--values',str(values),'--wait=watcher','--timeout','5m','--rollback-on-failure')
                verify_http()
                assert deployment()['spec']['template']['spec']['containers'][0]['image']==mirror+'@'+digest_b
                assert ready() and deployment()['spec']['replicas']==2
                passed.append('C12')
                h('rollback','fixture','1','--wait=watcher','--timeout','5m')
                assert deployment()['spec']['template']['spec']['containers'][0]['image']==repository+'@'+digest_a
                verify_http(); passed.append('C20')
            if 'C18' in checks:
                failed=tmp/'failed.json'; failed.write_text(json.dumps({'image':{'repository':repository,'digest':'sha256:'+'f'*64}}))
                result=h(*failed_upgrade_arguments(packages['B'], failed),check=False)
                assert result.returncode!=0 and 'has been rolled back' in result.stdout.lower(), result.stdout
                assert deployment()['spec']['template']['spec']['containers'][0]['image']==repository+'@'+digest_a
                verify_http(); passed.append('C18')
            if 'C19' in checks:
                # A local API proxy lets the test sever this Helm operation's
                # connection after B was applied, without harming the cluster.
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1',0)); proxy_port=sock.getsockname()[1]
                proxy=subprocess.Popen([kube,'proxy',f'--port={proxy_port}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                config=json.loads(command(kube,'config','view','--minify','--raw','-o','json').stdout)
                for cluster in config['clusters']:
                    cluster['cluster']={'server':f'http://127.0.0.1:{proxy_port}'}
                disconnected=tmp/'disconnected.json'; disconnected.write_text(json.dumps(config))
                environment={**os.environ,'KUBECONFIG':str(disconnected)}
                failed=tmp/'failed.json'; failed.write_text(json.dumps({'image':{'repository':repository,'digest':'sha256:'+'e'*64}}))
                operation=None
                try:
                    wait_for(lambda:command(kube,'--kubeconfig',str(disconnected),'get','namespace',namespace,check=False).returncode==0,30)
                    operation=subprocess.Popen([helm,*failed_upgrade_arguments(packages['B'], failed),'--namespace',namespace],env=environment,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                    wait_for(lambda:deployment()['spec']['template']['spec']['containers'][0]['image']==repository+'@sha256:'+'e'*64)
                    proxy.terminate(); proxy.wait(timeout=10)
                    output=operation.communicate(timeout=180)[0]
                    assert operation.returncode and 'original upgrade error' in output.lower(), output
                    assert 'an error occurred while finding last successful release' in output.lower(), output
                    assert 'refused' in output or 'unreachable' in output, output
                    print('C19: upgrade failed and recovery failed with disconnected API; inspect Helm history, Pods and events after reconnecting')
                finally:
                    if operation is not None and operation.poll() is None:
                        operation.terminate(); operation.wait(timeout=10)
                    if proxy.poll() is None:
                        proxy.terminate(); proxy.wait(timeout=10)
                assert deployment()['spec']['template']['spec']['containers'][0]['image']==repository+'@sha256:'+'e'*64
                h('rollback','fixture','1','--wait=watcher','--timeout','5m')
                verify_http()
                passed.append('C19')
            if checks & {'C14','C15'}:
                if not args.ingress_url:
                    raise RuntimeError('C14/C15 require an existing controller, TLS secret and ingress endpoint; pass --ingress-url and --tls-cert/--tls-key')
                k('create','secret','tls','operator-tls','--cert',args.tls_cert,'--key',args.tls_key)
                ingress={'image':{'repository':repository,'digest':digest_a},'ingress':{'enabled':True,'className':args.ingress_class,'hostname':'bloc.example.test','annotations':{'bloc.example.test/fixture':'true'},'tlsSecretName':'operator-tls'}}
                values.write_text(json.dumps(ingress))
                h('upgrade','fixture',packages['A'],'--version','0.0.1','--values',str(values),'--wait=watcher','--timeout','5m','--rollback-on-failure')
                resource=get('ingress/fixture-bloc')
                assert resource['spec']['rules'][0]['http']['paths'][0]['backend']['service']['port']['number']==80
                assert resource['spec']['tls'][0]['secretName']=='operator-tls'
                hostport=args.ingress_url.split(':')
                curl=['curl','--noproxy','*','--connect-timeout','3','--max-time','5','--fail','--silent','--show-error','--cacert',args.tls_cert,'--resolve',f'bloc.example.test:{hostport[1]}:{hostport[0]}',f'https://bloc.example.test:{hostport[1]}/healthz']
                wait_for(lambda:command(*curl,check=False).stdout=='ok\n')
                assert resource['spec']['ingressClassName']==args.ingress_class
                assert resource['metadata']['annotations']['bloc.example.test/fixture']=='true'
                assert resource['spec']['rules'][0]['http']['paths'][0]['path']=='/'
                passed.append('C14')
                k('delete','secret','operator-tls')
                assert command(kube,'-n',namespace,'get','secret','operator-tls',check=False).returncode
                wait_for(lambda:command(*curl,check=False).returncode!=0)
                verify_http()
                print('C15: missing operator TLS secret prevents trusted HTTPS while Pods remain healthy')
                k('create','secret','tls','operator-tls','--cert',args.tls_cert,'--key',args.tls_key)
                wait_for(lambda:command(*curl,check=False).stdout=='ok\n')
                k('patch','ingress','fixture-bloc','--type=merge','-p',json.dumps({'spec':{'ingressClassName':'bloc-no-controller'}}))
                assert command(kube,'get','ingressclass','bloc-no-controller',check=False).returncode
                wait_for(lambda:command(*curl,check=False).returncode!=0)
                verify_http()
                print('C15: missing matching controller prevents routing while Pods remain healthy')
                k('patch','ingress','fixture-bloc','--type=merge','-p',json.dumps({'spec':{'ingressClassName':args.ingress_class}}))
                wait_for(lambda:command(*curl,check=False).stdout=='ok\n')
                dns=command('curl','--noproxy','*','--connect-timeout','3','--max-time','5','--fail','--silent','--show-error',f'https://bloc.example.test:{hostport[1]}/healthz',check=False)
                assert dns.returncode==6, dns.stdout
                verify_http()
                print('C15: missing DNS fails name resolution while Pods and explicitly resolved HTTPS remain healthy')
                manifest=h('get','manifest','fixture').stdout
                assert 'kind: Secret' not in manifest and 'kind: Certificate' not in manifest
                assert manifest.count('kind: Deployment')==1
                passed.append('C15')
            else:
                k('create','secret','generic','operator-tls','--from-literal=fixture=not-a-credential')
            h('uninstall','fixture','--wait=watcher','--timeout','5m')
            assert get('deployments')['items']==[] and get('services')['items']==[] and get('ingress')['items']==[]
            assert get('secret/operator-tls')['metadata']['name']=='operator-tls'
            if checks & {'C14','C15'}:
                assert command(kube,'get','ingressclass',args.ingress_class).returncode==0
                assert command(*curl,check=False).returncode!=0
            passed.append('C21')
            missing=checks-set(passed)
            assert not missing,missing
            print(json.dumps({'passed':passed,'helm':'4.3.1','kubernetes':'1.36.5','context':context}))
    finally:
        authority.__exit__(None,None,None)
        k('get','events','--sort-by=.metadata.creationTimestamp')
        command(kube,'delete','namespace',namespace,'--wait=false',check=False)


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--image',required=True)
    p.add_argument('--image-b',default=os.environ.get('BLOC_TEST_IMAGE_B'))
    p.add_argument('--helm',default='helm')
    p.add_argument('--kubectl',default='kubectl')
    p.add_argument('--check',action='append')
    p.add_argument('--ingress-url',default=os.environ.get('BLOC_TEST_INGRESS_URL'))
    p.add_argument('--ingress-class',default=os.environ.get('BLOC_TEST_INGRESS_CLASS','bloc-test-traefik'))
    p.add_argument('--tls-cert',default=os.environ.get('BLOC_TEST_TLS_CERT'))
    p.add_argument('--tls-key',default=os.environ.get('BLOC_TEST_TLS_KEY'))
    args=p.parse_args()
    if not args.image_b:
        p.error('--image-b or BLOC_TEST_IMAGE_B must identify a distinct reachable local fixture')
    exercise(args)
