#!/usr/bin/env python3
"""Execute the configured administrator packaging contract against a real container (C1–C8)."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from authority import configuration


def run(*args, check=True):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


def request(port, path):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}{path}', timeout=3) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def wait(port):
    for _ in range(90):
        try:
            if request(port, '/healthz')[0] == 200:
                return
        except OSError:
            pass
        time.sleep(1)
    raise AssertionError('container never became healthy')


def exercise(image, platform, checks, revision=None, authority=None):
    metadata = json.loads(run('docker', 'image', 'inspect', image).stdout)[0]
    config = metadata['Config']
    assert config['User'] not in ['', '0', 'root'], config['User']
    assert config['Entrypoint'] == ['/usr/local/bin/bloc']
    container = run('docker', 'run', '-d', '--platform', platform, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '-p', '127.0.0.1::3000', *authority, image).stdout.strip()
    try:
        port = run('docker', 'port', container, '3000').stdout.strip().rsplit(':', 1)[1]
        wait(port)
        if 'C1' in checks:
            routes = [('/assets/admin.css', 'text/css', b'.ui'), ('/assets/ui.css', 'text/css', b'--ui-canvas'), ('/assets/ui.js', 'text/javascript', b'data-ui-theme'), ('/assets/htmx.min.js', 'text/javascript', b'htmx'), ('/healthz', 'text/plain', b'ok\n')]
            routes += [(path, None, b'') for path in ['/.well-known/openid-configuration', '/oauth/token', '/saml', '/missing']]
            for path, content_type, body in routes:
                status, headers, actual = request(port, path)
                assert status == (404 if path in ['/.well-known/openid-configuration', '/oauth/token', '/saml', '/missing'] else 200), (path, status)
                if content_type:assert headers['Content-Type'].startswith(content_type)
                assert body in actual, (path, body)
                if path == '/healthz':
                    assert actual == body
                for key, value in {'cache-control':'no-store', 'x-content-type-options':'nosniff', 'referrer-policy':'same-origin', 'x-frame-options':'DENY', 'content-security-policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"}.items():
                    assert headers[key] == value, (path, key)
        if 'C2' in checks:
            assert 'BLOC_BIND_ADDR=0.0.0.0:3000' in config['Env']
            assert 'RUST_LOG=info' in config['Env']
            assert 'bloc listening' in run('docker', 'logs', container).stdout
        if 'C4' in checks:
            invalid = run('docker', 'run', '--rm', '--platform', platform, '-e', 'BLOC_BIND_ADDR=not-an-address', *authority, image, check=False)
            assert invalid.returncode != 0 and 'Error' in invalid.stdout
            occupied = run('docker', 'run', '--rm', '--platform', platform, '--network', f'container:{container}', *authority, image, check=False)
            assert occupied.returncode != 0 and 'Address' in occupied.stdout, occupied.stdout
        if 'C5' in checks:
            state = json.loads(run('docker', 'inspect', container).stdout)[0]
            assert state['HostConfig']['ReadonlyRootfs'] and all(not mount['RW'] for mount in state['Mounts'])
            assert request(port, '/readyz')[0] == 503
            assert request(port, '/healthz')[2] == b'ok\n'
        if 'C8' in checks:
            labels = config['Labels']
            assert labels['org.opencontainers.image.source'] == 'https://github.com/rodalladea/bloc'
            assert labels['org.opencontainers.image.revision'] == revision
            bases=re.findall(r'^FROM (\S+)',Path('Dockerfile').read_text(),re.M)
            assert len(bases)==2
            for base in bases:
                assert re.search(r'@sha256:[0-9a-f]{64}$',base),base
                index=json.loads(run('docker','buildx','imagetools','inspect','--raw',base).stdout)
                supported={entry.get('platform',{}).get('os','')+'/'+entry.get('platform',{}).get('architecture','') for entry in index['manifests']}
                assert {'linux/amd64','linux/arm64'} <= supported,base
            for path in ['/usr/share/licenses/bloc/LICENSE', '/usr/share/licenses/bloc/THIRD_PARTY_NOTICES.md', '/usr/share/licenses/bloc/htmx-LICENSE']:
                assert run('docker', 'exec', container, 'cat', path).stdout.strip()
            assert run('docker', 'exec', container, 'sh', '-c', '! command -v rustc && ! command -v cargo').returncode == 0
        if 'C6' in checks:
            start = time.monotonic()
            run('docker', 'stop', '--time', '30', container)
            assert time.monotonic() - start < 30
            state = json.loads(run('docker', 'inspect', container).stdout)[0]['State']
            assert state['ExitCode'] == 0 and not state['OOMKilled'], state
    finally:
        run('docker', 'rm', '-f', container, check=False)
    if 'C3' in checks:
        container = run('docker', 'run', '-d', '--platform', platform, '-e', 'BLOC_BIND_ADDR=0.0.0.0:4000', '-e', 'RUST_LOG=off', '-p', '127.0.0.1::4000', *authority, image).stdout.strip()
        try:
            port = run('docker', 'port', container, '4000').stdout.strip().rsplit(':', 1)[1]
            wait(port)
            assert 'bloc listening' not in run('docker', 'logs', container).stdout
        finally:
            run('docker', 'rm', '-f', container, check=False)
    print(json.dumps({'checks': checks, 'platform': platform, 'host':run('docker', 'info', '--format', '{{.Architecture}}').stdout.strip(), 'result':'passed'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--platform', required=True)
    parser.add_argument('--check', action='append')
    parser.add_argument('--oci-layout', default=os.environ.get('BLOC_TEST_LAYOUT'))
    parser.add_argument('--revision', default=os.environ.get('BLOC_TEST_REVISION'))
    args = parser.parse_args()
    checks = args.check or [f'C{i}' for i in range(1,9) if i != 7]
    if 'C7' in checks or 'C8' in checks:
        if not args.oci_layout or not args.revision:
            raise SystemExit('C7/C8 require --oci-layout and --revision (or BLOC_TEST_LAYOUT/BLOC_TEST_REVISION)')
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts/distribution'))
        from oci import Layout, verify_image
        verify_image(Layout(args.oci_layout),args.revision)
    if 'C7' in checks:
        unsupported=run('docker','pull','--platform','linux/s390x',args.image,check=False)
        assert unsupported.returncode and 'no matching manifest' in unsupported.stdout,unsupported.stdout
    with configuration() as authority:
        exercise(args.image, args.platform, checks,args.revision,authority)
