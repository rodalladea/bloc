#!/usr/bin/env python3
"""Assemble content-addressed release candidates from already tested platform images."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from oci import INDEX, MANIFEST, Layout, descriptor, encode, verify_image


def chart_layout(source, destination, image_digest, revision, version):
    destination.mkdir(parents=True,exist_ok=True)
    helm=os.environ.get('HELM','helm')
    with tempfile.TemporaryDirectory() as temporary:
        chart=Path(temporary)/'bloc'
        shutil.copytree(source,chart)
        values=chart/'values.yaml'
        text=values.read_text()
        if 'digest: ""' not in text:
            raise ValueError('source chart must not contain a stale release digest')
        values.write_text(text.replace('digest: ""','digest: "'+image_digest+'"'))
        subprocess.run([helm,'package',str(chart),'--destination',str(destination)],check=True)
    layer=(destination/f'bloc-{version}.tgz').read_bytes()
    config=encode({'name':'bloc','version':version,'appVersion':version,
                   'description':'Dependency-free bloc HTTP scaffold; identity is not implemented.',
                   'apiVersion':'v2','type':'application'})
    layout=Layout(destination/'chart')
    layout.put(config); layout.put(layer)
    layout.set_root(encode({'schemaVersion':2,'mediaType':MANIFEST,
        'config':descriptor(config,'application/vnd.cncf.helm.config.v1+json'),
        'layers':[descriptor(layer,'application/vnd.cncf.helm.chart.content.v1.tar+gzip')],
        'annotations':{'org.opencontainers.image.source':'https://github.com/rodalladea/bloc',
                       'org.opencontainers.image.revision':revision,'org.opencontainers.image.version':version}}))
    return layout


def combine(sources, destination, revision):
    result=Layout(destination)
    manifests=[]
    for path in sources:
        source=Layout(path)
        root=json.loads(source.read(source.root()['digest']))
        manifests.extend(root['manifests'])
        for blob in (source.path/'blobs/sha256').iterdir():
            result.put(source.read('sha256:'+blob.name))
    result.set_root(encode({'schemaVersion':2,'mediaType':INDEX,'manifests':manifests}))
    verify_image(result,revision)
    return result


def verify_chart(layout, image_digest, revision, version):
    manifest=json.loads(layout.read(layout.root()['digest']))
    if manifest['annotations']['org.opencontainers.image.revision']!=revision:
        raise ValueError('chart source revision conflict')
    config=json.loads(layout.read(manifest['config']['digest']))
    if config['version']!=version or config['appVersion']!=version:
        raise ValueError('chart version conflict')
    import io
    with tarfile.open(fileobj=io.BytesIO(layout.read(manifest['layers'][0]['digest']))) as archive:
        values=archive.extractfile('bloc/values.yaml').read().decode()
        metadata=archive.extractfile('bloc/Chart.yaml').read().decode()
    if f'digest: "{image_digest}"' not in values:
        raise ValueError('chart image digest conflict')
    if f'version: {version}' not in metadata or f'appVersion: "{version}"' not in metadata:
        # Helm package normalizes quoting; metadata config is also checked above.
        import re
        fields=dict(re.findall(r'^(version|appVersion):\s*"?([^"\n]+)"?$',metadata,re.M))
        if fields!={'version':version,'appVersion':version}:
            raise ValueError('packaged chart version conflict')


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--platform',action='append',required=True,type=Path)
    p.add_argument('--destination',type=Path,default=Path('candidate'))
    p.add_argument('--revision',required=True)
    p.add_argument('--version',required=True)
    a=p.parse_args()
    image=combine(a.platform,a.destination/'image',a.revision)
    chart=chart_layout(Path('charts/bloc'),a.destination,image.root()['digest'],a.revision,a.version)
    print(json.dumps({'image':image.root()['digest'],'chart':chart.root()['digest']}))
