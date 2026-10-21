#!/usr/bin/env python3
"""Exercise exact OCI bytes and Helm consumption against an isolated local registry."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts/distribution'))
from candidate import chart_layout, verify_chart
from oci import Layout, Registry, digest, verify_image
from release import publish


class Completion:
    def __init__(self):
        self.value=None
        self.writes=0

    def get(self,tag):
        return self.value

    def create(self,tag,identities,notes):
        self.value=identities
        self.writes+=1


def exercise(layout_path,revision,helm):
    version=tomllib.loads(Path("Cargo.toml").read_text())["package"]["version"]
    tag="v"+version
    image=Layout(layout_path)
    image_digest=verify_image(image,revision)
    with tempfile.TemporaryDirectory() as directory:
        directory=Path(directory)
        os.environ['HELM']=helm
        chart=chart_layout(Path('charts/bloc'),directory,image_digest,revision,version)
        verify_chart(chart,image_digest,revision,version)
        # The host is deliberately fixed to loopback; this command cannot publish GHCR.
        prefix='localhost:5001/rehearsal-'+str(os.getpid())
        images=Registry(prefix+'/bloc',insecure=True)
        charts=Registry(prefix+'/charts/bloc',insecure=True)
        anonymous_image=Registry(prefix+'/bloc',insecure=True)
        anonymous_chart=Registry(prefix+'/charts/bloc',insecure=True)
        record={'version':version,'revision':revision,'image':image_digest,
                'chart':chart.root()['digest'],'helm':'4.3.1','kubernetes':'1.36.5'}
        completion=Completion()
        original_publish=charts.publish
        def fail_chart(*args):
            raise RuntimeError('injected local chart upload failure')
        charts.publish=fail_chart
        try:
            publish(record,image,chart,images,charts,anonymous_image,anonymous_chart,completion)
        except RuntimeError as error:
            assert 'injected local' in str(error)
        else:
            raise AssertionError('injected upload failure must propagate')
        before=images.manifest(tag)
        assert digest(before)==image_digest and completion.writes==0
        charts.publish=original_publish
        publish(record,image,chart,images,charts,anonymous_image,anonymous_chart,completion)
        assert images.manifest(tag)==before and completion.writes==1
        publish(record,image,chart,images,charts,anonymous_image,anonymous_chart,completion)
        assert images.manifest(tag)==before and completion.writes==1
        env=dict(os.environ,HELM_REGISTRY_CONFIG=str(directory/'anonymous.json'),DOCKER_CONFIG=str(directory/'docker'))
        env['DOCKER_HOST']=subprocess.check_output(['docker','context','inspect','--format','{{.Endpoints.docker.Host}}'],text=True).strip()
        env.pop('DOCKER_CONTEXT',None)
        for platform in ['linux/amd64','linux/arm64']:
            subprocess.run(['docker','pull','--platform',platform,prefix+'/bloc:'+tag],env=env,check=True)
        destination=directory/'download'
        destination.mkdir()
        subprocess.run([helm,'pull','oci://'+prefix+'/charts/bloc','--version',version,'--plain-http','--destination',str(destination)],env=env,check=True)
        assert (destination/f'bloc-{version}.tgz').read_bytes()==(directory/f'bloc-{version}.tgz').read_bytes()
        # A conflicting chart is detected before attempting a missing image upload.
        altered=dict(record,revision='b'*40)
        try:
            publish(altered,image,chart,images,charts,anonymous_image,anonymous_chart,completion)
        except ValueError as error:
            assert 'identity conflict' in str(error)
        else:
            raise AssertionError('completion source conflict must fail')
        print(json.dumps({'local_registry':'passed','image':image_digest,'chart':record['chart'],
            'checks':['C25','C26-local-only','C28','C29','C30','C31']}))


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--layout',required=True,type=Path)
    p.add_argument('--revision',required=True)
    p.add_argument('--helm',default='helm')
    a=p.parse_args()
    exercise(a.layout,a.revision,a.helm)
