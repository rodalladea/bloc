#!/usr/bin/env python3
"""Serve a retained platform OCI layout locally and smoke-test those exact bytes."""
import argparse
import json
import subprocess
from pathlib import Path
from oci import Layout, Registry

def exercise(layout_path, platform, capacity_output=None):
    registry=Registry('localhost:5001/bloc',insecure=True)
    layout=Layout(layout_path)
    registry.publish(layout,'test')
    registry.verify(layout,'test')
    image='localhost:5001/bloc@'+layout.root()['digest']
    subprocess.run(['docker','pull','--platform',platform,image],check=True)
    checks=[argument for check in range(1,7) for argument in ('--check',f'C{check}')]
    subprocess.run(['python3','tests/distribution/container.py','--image',image,'--platform',platform,*checks],check=True)
    if capacity_output is not None:
        subprocess.run(['python3','tests/support/native_service_capacity.py',
                        '--image',image,'--skip-build','--output',str(capacity_output)],check=True)
        record_path=Path(capacity_output)/'record.json'
        record=json.loads(record_path.read_text())
        index=json.loads(layout.read(layout.root()['digest']))
        manifests=[entry['digest'] for entry in index['manifests']
                   if entry.get('platform',{}).get('os','')+'/'+entry.get('platform',{}).get('architecture','')==platform]
        if len(manifests)!=1:
            raise ValueError('exactly one measured platform manifest required')
        record['image_manifest_digest']=manifests[0]
        record_path.write_text(json.dumps(record,indent=2)+'\n')


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--layout',type=Path,required=True)
    p.add_argument('--platform',required=True)
    p.add_argument('--capacity-output',type=Path)
    a=p.parse_args()
    exercise(a.layout, a.platform, a.capacity_output)
