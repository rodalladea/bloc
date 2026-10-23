#!/usr/bin/env python3
"""Admit tags and promote retained, verified artifacts without replacement."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from oci import Layout, Registry, digest, verify_image

REQUIRED = {'format','lint','test','documentation','audit','linux/amd64','linux/arm64','chart-schema','cluster'}


def run(*command):
    return subprocess.check_output(command,text=True).strip()


def admit(tag, revision, main='origin/main', root=Path('.')):
    if not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',tag):
        raise ValueError('tag must be a complete numeric vX.Y.Z version')
    version = tag[1:]
    cargo = tomllib.loads((root/'Cargo.toml').read_text())['package']['version']
    lock = next(p['version'] for p in tomllib.loads((root/'Cargo.lock').read_text())['package'] if p['name']=='bloc')
    chart = dict(re.findall(r'^(version|appVersion):\s*"?([^"\n]+)"?$',(root/'charts/bloc/Chart.yaml').read_text(),re.M))
    if set([cargo,lock,chart.get('version'),chart.get('appVersion')]) != {version}:
        raise ValueError('version disagreement between tag, Cargo, lockfile and chart')
    if subprocess.run(['git','merge-base','--is-ancestor',revision,main],cwd=root).returncode:
        raise ValueError('tag revision is outside main ancestry')
    return version


def evidence(bundle, revision, version):
    record = json.loads((bundle/'evidence.json').read_text())
    if record['revision'] != revision or record['version'] != version:
        raise ValueError('original evidence source/version conflict; use a new version')
    if set(record['passed']) != REQUIRED:
        raise ValueError('required validation evidence missing; use a new version')
    image = Layout(bundle/'image')
    chart = Layout(bundle/'chart')
    if verify_image(image,revision) != record['image'] or chart.root()['digest'] != record['chart']:
        raise ValueError('original artifact digest conflict; use a new version')
    from candidate import verify_chart
    verify_chart(chart, record['image'], revision, version)
    if record.get('helm') != '4.3.1' or record.get('kubernetes') != '1.36.5':
        raise ValueError('validation baseline disagreement')
    return record, image, chart


def publish(record, image, chart, image_registry, chart_registry, anonymous_image, anonymous_chart, completion, consume=None):
    """Inspection is before either upload; caller serializes this whole operation."""
    tag = 'v'+record['version']
    existing_release = completion.get(tag)
    expected = {'image':record['image'],'chart':record['chart'],'revision':record['revision'],'version':record['version']}
    if existing_release is not None and existing_release != expected:
        raise ValueError('completed release identity conflict; use a new version')
    targets = [(image_registry,image,tag),(chart_registry,chart,record['version'])]
    missing = []
    for registry, layout, ref in targets:
        existing = registry.manifest(ref)
        if existing is None:
            if existing_release is not None:
                raise ValueError('completed release artifact missing; use a new version')
            missing.append((registry,layout,ref))
        elif digest(existing) != layout.root()['digest']:
            raise ValueError('same-version artifact digest conflict; use a new version')
        else:
            registry.verify(layout,ref)
    for registry,layout,ref in missing:
        print('Publishing missing artifact '+registry.repository+':'+ref,flush=True)
        registry.publish(layout,ref)
    # These clients have no token or credential configuration. Fetch every blob,
    # not just HEAD metadata, so private layers cannot masquerade as public access.
    anonymous_image.verify(image,tag)
    anonymous_chart.verify(chart,record['version'])
    if consume:
        consume(record, chart)
    if existing_release is None:
        completion.create(tag,expected,notes(record))
    return expected


def pull_image(record, platform, env):
    output = subprocess.check_output(
        ['docker','pull','--platform',platform,'ghcr.io/rodalladea/bloc:v'+record['version']],
        env=env, text=True)
    print(output, end='', flush=True)
    # RepoDigests can become empty when a second platform replaces the local tag.
    if re.findall(r'^Digest: (sha256:[0-9a-f]{64})$', output, re.M) != [record['image']]:
        raise ValueError('anonymous Docker pull digest disagreement')


def anonymous_consumption(record, chart):
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        env = dict(os.environ)
        endpoint = run('docker','context','inspect','--format','{{.Endpoints.docker.Host}}')
        env['DOCKER_HOST'] = env.get('DOCKER_HOST', endpoint)
        env.pop('DOCKER_CONTEXT', None)
        for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'DOCKER_AUTH_CONFIG'):
            env.pop(key, None)
        env['DOCKER_CONFIG'] = temporary
        env['HELM_REGISTRY_CONFIG'] = str(Path(temporary)/'registry.json')
        for platform in ('linux/amd64', 'linux/arm64'):
            pull_image(record, platform, env)
        subprocess.run(['helm','pull','oci://ghcr.io/rodalladea/charts/bloc','--version',record['version'],'--destination',temporary],env=env,check=True)
        manifest=json.loads(chart.read(chart.root()['digest']))
        package=(Path(temporary)/('bloc-'+record['version']+'.tgz')).read_bytes()
        if digest(package)!=manifest['layers'][0]['digest']:
            raise ValueError('anonymous Helm package digest disagreement')


def notes(record):
    version=record['version']
    return f'''bloc {version} — installation administrator access

Installation administrator setup, sign-in, sessions, password changes and operator
recovery use shared PostgreSQL. This release is for development and evaluation.
Tenant and user directory management is available at /admin/tenants. Directory
records do not authenticate users. Explicit migration 0003_directory.sql is
required; coordinate rollout because old and new binary/schema contracts cannot
serve together. See docs/tenant-user-management.md at this revision.
MFA is required before production authentication use. Application-user identity,
OIDC/OAuth token issuance and SAML are not implemented.
Source revision: {record['revision']}
Platforms: linux/amd64, linux/arm64
Tested Helm: {record['helm']}; Kubernetes: {record['kubernetes']}
Image: ghcr.io/rodalladea/bloc@{record['image']}
Chart OCI digest: {record['chart']}

Save operator configuration in values.yaml. Requires an operator-managed cluster,
PostgreSQL 17 or 18 with verified TLS and separate runtime/migrator/operator/
maintenance roles, explicit migrations, canonical HTTPS origin and trusted proxy
configuration. Follow docs/administrator-access.md at this revision before install.

```sh
helm install bloc oci://ghcr.io/rodalladea/charts/bloc --version {version} --namespace bloc --create-namespace --values values.yaml --wait=watcher --timeout 5m
kubectl -n bloc port-forward service/bloc-bloc 8080:80
curl --fail http://127.0.0.1:8080/healthz
helm upgrade bloc oci://ghcr.io/rodalladea/charts/bloc --version {version} --namespace bloc --values values.yaml --wait=watcher --timeout 5m --rollback-on-failure
helm history bloc --namespace bloc
# Replace PREVIOUS_SUCCESSFUL_REVISION with an inspected successful revision:
helm rollback bloc PREVIOUS_SUCCESSFUL_REVISION --namespace bloc --wait=watcher --timeout 5m
```

Failed upgrades remain failures even after recovery. Verify HTTP after recovery;
if recovery fails, inspect Helm history, Pods and events before retrying.
See docs/install.md at this revision for ingress prerequisites, recovery and uninstall.
No automatic deployment or database provisioning; no production-readiness or
universal Kubernetes compatibility claim.
'''


class GitHubCompletion:
    def __init__(self, repository):
        self.repository=repository

    def get(self, tag):
        # List endpoint distinguishes absence from permission/network errors.
        pages=json.loads(run('gh','api','--paginate','--slurp',f'repos/{self.repository}/releases?per_page=100'))
        releases=[item for page in pages for item in page]
        for release in releases:
            if release['tag_name']==tag:
                if release['draft']:
                    raise ValueError('unexpected draft release; inspect manually')
                match=re.search(r'<!-- bloc-identities (.*?) -->',release['body'])
                if not match:
                    raise ValueError('release has no original identity evidence; use a new version')
                return json.loads(match[1])
        return None

    def create(self, tag, identities, body):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w',suffix='.md') as file:
            file.write(body+'\n<!-- bloc-identities '+json.dumps(identities,sort_keys=True)+' -->\n')
            file.flush()
            run('gh','release','create',tag,'--repo',self.repository,'--verify-tag','--title',f'bloc {tag} — installation administrator access','--notes-file',file.name)


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['admit','publish'])
    parser.add_argument('--tag',required=True)
    parser.add_argument('--revision',required=True)
    parser.add_argument('--bundle',type=Path,default=Path('candidate'))
    args=parser.parse_args()
    try:
        version=admit(args.tag,args.revision)
        if args.action=='publish':
            record,image,chart=evidence(args.bundle,args.revision,version)
            token=os.environ['GH_TOKEN']
            actor=os.environ['GITHUB_ACTOR']
            publish(record,image,chart,Registry('ghcr.io/rodalladea/bloc',token,actor),Registry('ghcr.io/rodalladea/charts/bloc',token,actor),Registry('ghcr.io/rodalladea/bloc'),Registry('ghcr.io/rodalladea/charts/bloc'),GitHubCompletion('rodalladea/bloc'),anonymous_consumption)
    except Exception as error:
        print(f'Release incomplete: {error}. Preserve original artifacts and evidence; do not replace published versions.',file=sys.stderr)
        sys.exit(1)
