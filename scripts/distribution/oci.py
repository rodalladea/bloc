#!/usr/bin/env python3
"""Small OCI distribution adapter; every transferred blob is content-verified."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
ACCEPT = ', '.join([INDEX, MANIFEST, 'application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.docker.distribution.manifest.v2+json'])


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(req.full_url).scheme == 'https' and urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('registry redirect would downgrade HTTPS')
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header('Authorization')
        return redirected


HTTP = urllib.request.build_opener(PublicRedirect())


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def descriptor(data, media):
    return {'mediaType':media, 'digest':digest(data), 'size':len(data)}


class Layout:
    def __init__(self, path):
        self.path = Path(path)

    def read(self, identity):
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', identity):
            raise ValueError('invalid content digest')
        data = (self.path/'blobs'/'sha256'/identity[7:]).read_bytes()
        if digest(data) != identity:
            raise ValueError('corrupted blob: '+identity)
        return data

    def put(self, data):
        identity = digest(data)
        path = self.path/'blobs'/'sha256'/identity[7:]
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            self.read(identity)
        else:
            path.write_bytes(data)
        return identity

    def root(self):
        return json.loads((self.path/'index.json').read_bytes())['manifests'][0]

    def set_root(self, data):
        identity = self.put(data)
        root = descriptor(data, json.loads(data)['mediaType'])
        (self.path/'index.json').write_bytes(encode({'schemaVersion':2, 'manifests':[root]}))
        marker = self.path/'oci-layout'
        if marker.exists():
            if json.loads(marker.read_bytes()) != {'imageLayoutVersion':'1.0.0'}:
                raise ValueError('unsupported OCI layout version')
        else:
            marker.write_bytes(encode({'imageLayoutVersion':'1.0.0'}))
        return identity


def children(document):
    if 'manifests' in document:
        return document['manifests']
    return [document['config'], *document['layers']]


def verify_image(layout, revision):
    root = json.loads(layout.read(layout.root()['digest']))
    platforms = set()
    subjects = set()
    attestations = {}
    for entry in root['manifests']:
        manifest = json.loads(layout.read(entry['digest']))
        for child in children(manifest):
            layout.read(child['digest'])
        platform = entry.get('platform', {})
        if platform.get('os') == 'unknown':
            kinds = {json.loads(layout.read(layer['digest']))['predicateType'] for layer in manifest['layers']}
            subject = entry['annotations']['vnd.docker.reference.digest']
            attestations[subject] = kinds
        else:
            platforms.add(platform.get('os','')+'/'+platform.get('architecture',''))
            subjects.add(entry['digest'])
            config = json.loads(layout.read(manifest['config']['digest']))
            labels = config['config']['Labels']
            if labels.get('org.opencontainers.image.revision') != revision or labels.get('org.opencontainers.image.source') != 'https://github.com/rodalladea/bloc':
                raise ValueError('image source/revision disagreement')
    if platforms != {'linux/amd64','linux/arm64'}:
        raise ValueError('executable platforms must be exactly linux/amd64 and linux/arm64')
    for subject in subjects:
        kinds = attestations.get(subject,set())
        if not any('slsa.dev/provenance/' in kind for kind in kinds) or 'https://spdx.dev/Document' not in kinds:
            raise ValueError('missing provenance or SBOM for '+subject)
    return layout.root()['digest']


class Registry:
    def __init__(self, repository, token=None, username=None, insecure=False):
        self.host, self.repository = repository.split('/',1)
        self.base = ('http' if insecure else 'https')+'://'+self.host
        self.token = token
        self.username = username
        self.bearer = None

    def request(self, method, path, data=None, headers=None, missing=False, authenticated=False):
        url = urllib.parse.urljoin(self.base, path)
        # Do not forward credentials to an upload location outside this registry.
        if (urllib.parse.urlsplit(url).netloc != self.host
                or urllib.parse.urlsplit(url).scheme != urllib.parse.urlsplit(self.base).scheme):
            raise ValueError('registry redirected upload outside its origin')
        hdr = {'Accept':ACCEPT, **(headers or {})}
        if self.bearer:
            hdr['Authorization'] = 'Bearer '+self.bearer
        req = urllib.request.Request(url,data=data,headers=hdr,method=method)
        try:
            with HTTP.open(req, timeout=120) as response:
                return response.read(), response.headers
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing:
                return None, error.headers
            if error.code != 401 or authenticated:
                raise
            challenge = error.headers.get('WWW-Authenticate','')
            fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
            realm = fields.get('realm','')
            if urllib.parse.urlsplit(realm).netloc != self.host:
                raise ValueError('registry authentication realm is outside its origin')
            if urllib.parse.urlsplit(realm).scheme != 'https' and not self.base.startswith('http:'):
                raise ValueError('insecure registry authentication realm')
            query = {'service':fields.get('service',''), 'scope':fields.get('scope',f'repository:{self.repository}:pull')}
            auth_headers = {}
            if self.token:
                auth_headers['Authorization'] = 'Basic '+base64.b64encode(f'{self.username}:{self.token}'.encode()).decode()
            with HTTP.open(urllib.request.Request(realm+'?'+urllib.parse.urlencode(query),headers=auth_headers),timeout=30) as response:
                auth = json.load(response)
            self.bearer = auth.get('token',auth.get('access_token'))
            return self.request(method,path,data,headers,missing,authenticated=True)

    def manifest(self, ref):
        data, _ = self.request('GET',f'/v2/{self.repository}/manifests/{ref}',missing=True)
        return data

    def upload_blob(self, identity, data):
        if digest(data) != identity:
            raise ValueError('blob digest mismatch')
        exists, _ = self.request('HEAD',f'/v2/{self.repository}/blobs/{identity}',missing=True)
        if exists is not None:
            return
        _, headers = self.request('POST',f'/v2/{self.repository}/blobs/uploads/',b'')
        location = headers['Location']
        location += ('&' if '?' in location else '?')+urllib.parse.urlencode({'digest':identity})
        self.request('PUT',location,data,{'Content-Type':'application/octet-stream'})

    def publish(self, layout, ref):
        def upload(desc):
            data = layout.read(desc['digest'])
            if desc['mediaType'] in [INDEX,MANIFEST]:
                document = json.loads(data)
                for child in children(document):
                    upload(child)
                self.request('PUT',f'/v2/{self.repository}/manifests/{desc["digest"]}',data,{'Content-Type':desc['mediaType']})
            else:
                self.upload_blob(desc['digest'],data)
        root = layout.root()
        upload(root)
        self.request('PUT',f'/v2/{self.repository}/manifests/{ref}',layout.read(root['digest']),{'Content-Type':root['mediaType']})

    def verify(self, layout, ref):
        data = self.manifest(ref)
        if data is None or digest(data) != layout.root()['digest']:
            raise ValueError('remote artifact identity mismatch or inaccessible: '+ref)
        def fetch(desc):
            kind = 'manifests' if desc['mediaType'] in [INDEX, MANIFEST] else 'blobs'
            actual, _ = self.request('GET',f'/v2/{self.repository}/{kind}/{desc["digest"]}')
            if digest(actual) != desc['digest'] or len(actual) != desc['size']:
                raise ValueError('remote content mismatch')
            if kind == 'manifests':
                for child in children(json.loads(actual)):
                    fetch(child)
        fetch(layout.root())


if __name__ == '__main__':
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument('layout')
    p.add_argument('--revision', required=True)
    args=p.parse_args()
    print(verify_image(Layout(args.layout), args.revision))
