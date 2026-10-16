#!/usr/bin/env python3
"""Serve a retained platform OCI layout locally and smoke-test those exact bytes."""
import argparse
import subprocess
from pathlib import Path
from oci import Layout, Registry

p=argparse.ArgumentParser()
p.add_argument('--layout',type=Path,required=True)
p.add_argument('--platform',required=True)
a=p.parse_args()
registry=Registry('localhost:5001/bloc',insecure=True)
layout=Layout(a.layout)
registry.publish(layout,'test')
registry.verify(layout,'test')
image='localhost:5001/bloc@'+layout.root()['digest']
subprocess.run(['docker','pull','--platform',a.platform,image],check=True)
checks=[argument for check in range(1,7) for argument in ('--check',f'C{check}')]
subprocess.run(['python3','tests/distribution/container.py','--image',image,'--platform',a.platform,*checks],check=True)
