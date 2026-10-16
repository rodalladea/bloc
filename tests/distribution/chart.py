#!/usr/bin/env python3
"""Schema and rendered API checks using the actual pinned Helm client."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

INVALID = [({'replicaCount':-1}, 'replicaCount'), ({'replicaCount':'two'}, 'replicaCount'), ({'image':{'digest':'latest'}}, 'digest'), ({'image':{'repository':''}}, 'repository'), ({'ingress':{'enabled':'true'}}, 'enabled'), ({'ingress':{'enabled':True,'tlsSecretName':'test'}}, 'hostname'), ({'ingress':{'enabled':True,'hostname':'bloc.example.test'}}, 'tlsSecretName'), ({'nodeSelector':[]}, 'nodeSelector'), ({'tolerations':{}}, 'tolerations'), ({'affinity':[]}, 'affinity'), ({'bindAddress':'0.0.0.0:4000'}, 'bindAddress'), ({'resources':[]}, 'resources')]


def check(helm):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)/'values.json'
        for fixture, key in INVALID:
            values = {'image': {'digest': 'sha256:'+'1'*64}}
            for name, value in fixture.items():
                if name == 'image':
                    values['image'].update(value)
                else:
                    values[name] = value
            path.write_text(json.dumps(values))
            result = subprocess.run([helm,'template','test','charts/bloc','-f',str(path)],text=True,capture_output=True)
            assert result.returncode != 0 and key in result.stderr, (fixture,result.stdout,result.stderr)
        result = subprocess.run([helm,'lint','charts/bloc','--strict','--set','image.digest=sha256:'+'1'*64],text=True,capture_output=True)
        assert result.returncode == 0, result.stdout+result.stderr
    print('C13: all 12 malformed values rejected; chart lint passed')


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--helm',default='helm')
    check(parser.parse_args().helm)
