#!/usr/bin/env python3
"""Complete candidate evidence only after independent validation and native proofs."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

from candidate import verify_chart
from oci import Layout, verify_image
from release import REQUIRED


def complete(bundle, measurements, revision, version):
    if (bundle/'evidence.json').exists():
        raise ValueError('candidate evidence already completed')
    record=json.loads((bundle/'validation.json').read_text())
    if record['revision']!=revision or record['version']!=version:
        raise ValueError('validation source/version conflict')
    if set(record['passed'])!=REQUIRED-{'linux/amd64','linux/arm64'}:
        raise ValueError('source/cluster validation incomplete')
    image=Layout(bundle/'image')
    if verify_image(image,revision)!=record['image']:
        raise ValueError('validated image digest conflict')
    chart=Layout(bundle/'chart')
    if chart.root()['digest']!=record['chart']:
        raise ValueError('validated chart digest conflict')
    verify_chart(chart,record['image'],revision,version)
    if record['helm']!='4.3.1' or record['kubernetes']!='1.36.5':
        raise ValueError('validation baseline disagreement')
    output=bundle/'evidence'
    output.mkdir(exist_ok=True)
    # This is the same validator invoked by the ignored Rust capacity wrapper.
    subprocess.run([sys.executable,'tests/support/combine_native_service_evidence.py',
                    str(measurements),str(output/'native-service.json')],check=True)
    index=json.loads(image.read(image.root()['digest']))
    manifests={entry['platform']['architecture']:entry['digest'] for entry in index['manifests']
               if entry.get('platform',{}).get('os')=='linux'}
    for arch in ('amd64','arm64'):
        measurement=measurements/arch
        native=json.loads((measurement/'service-capacity/record.json').read_text())
        if (native['architecture']!=arch or native['source_revision']!=revision
                or native['image_manifest_digest']!=manifests[arch]):
            raise ValueError('native measurement does not match the candidate: '+arch)
    for arch in ('amd64','arm64'):
        shutil.copytree(measurements/arch,output/arch,dirs_exist_ok=True)
    record['passed']=sorted(REQUIRED)
    (bundle/'evidence.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',required=True,type=Path)
    parser.add_argument('--measurements',required=True,type=Path)
    args=parser.parse_args()
    revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    version=tomllib.loads(Path('Cargo.toml').read_text())['package']['version']
    complete(args.bundle,args.measurements,revision,version)
