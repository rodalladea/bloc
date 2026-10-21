"""Publication policy tests; live registry/CLI evidence is recorded separately."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/distribution'))
import release
from oci import Layout, MANIFEST, descriptor, encode


class Store:
    def __init__(self, layout, repository):
        self.repository, self.layout = repository, layout
        self.data = None
        self.entries = {}
        self.writes = 0
        self.fail = False
        self.private = False

    def manifest(self, ref):
        return self.entries.get(ref, self.data if not self.entries else None)

    def publish(self, layout, ref):
        if self.fail:
            raise RuntimeError('chart upload failed')
        self.data = layout.read(layout.root()['digest'])
        self.entries[ref] = self.data
        self.writes += 1

    def verify(self, layout, ref):
        if self.private:
            raise PermissionError('anonymous access denied')
        if self.data != layout.read(layout.root()['digest']):
            raise ValueError('identity mismatch')


class Completion:
    def __init__(self):
        self.record = None
        self.writes = 0
        self.records = {}

    def get(self, tag):
        return self.records.get(tag)

    def create(self, tag, expected, body):
        self.record = expected
        self.records[tag] = expected
        self.writes += 1


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        layouts = []
        for name in ('image', 'chart'):
            layout = Layout(self.root/name)
            config = encode({'name':name})
            layout.put(config)
            layout.set_root(encode({'schemaVersion':2,'mediaType':MANIFEST,
                'config':descriptor(config,'application/vnd.oci.image.config.v1+json'),'layers':[]}))
            layouts.append(layout)
        self.image, self.chart = layouts
        self.record = {'version':'0.0.1','revision':'a'*40,
            'image':self.image.root()['digest'],'chart':self.chart.root()['digest'],
            'helm':'4.3.1','kubernetes':'1.36.5','passed':sorted(release.REQUIRED)}
        self.images, self.charts = Store(self.image,'bloc'), Store(self.chart,'charts/bloc')
        self.completion = Completion()

    def publish(self):
        return release.publish(self.record,self.image,self.chart,self.images,self.charts,
                               self.images,self.charts,self.completion)

    def workflow(self):
        return (ROOT/'.github/workflows/distribution.yml').read_text()

    def test_c22_pull_requests_have_no_publication_writes(self):
        workflow = self.workflow()
        self.assertNotIn('pull_request:', workflow)
        self.assertIn('workflow_dispatch:', workflow)
        self.assertIn("github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')", workflow)
        validate = workflow.split('  validate:')[1].split('  publish:')[0]
        self.assertNotIn('packages: write', validate)
        self.assertNotIn('contents: write', validate)
        self.assertIn('scripts/distribution/validate.sh', validate)

    def test_c23_admission_rejects_invalid_versions_and_ancestry(self):
        (self.root/'charts/bloc').mkdir(parents=True)
        (self.root/'Cargo.toml').write_text('[package]\nversion="0.0.1"\n')
        (self.root/'Cargo.lock').write_text('[[package]]\nname="bloc"\nversion="0.0.1"\n')
        (self.root/'charts/bloc/Chart.yaml').write_text('version: 0.0.1\nappVersion: "0.0.1"\n')
        for tag in ('v0.0','v0.0.1-rc.1','v00.0.1'):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError,'numeric'):
                release.admit(tag,'a'*40,root=self.root)
        (self.root/'Cargo.toml').write_text('[package]\nversion="0.1.0"\n')
        with self.assertRaisesRegex(ValueError,'version disagreement'):
            release.admit('v0.0.1','a'*40,root=self.root)
        (self.root/'Cargo.toml').write_text('[package]\nversion="0.0.1"\n')
        with patch('release.subprocess.run',return_value=subprocess.CompletedProcess([],1)):
            with self.assertRaisesRegex(ValueError,'outside main'):
                release.admit('v0.0.1','a'*40,root=self.root)
        with patch('release.subprocess.run',return_value=subprocess.CompletedProcess([],0)):
            self.assertEqual(release.admit('v0.0.1','a'*40,root=self.root),'0.0.1')

    def test_c24_each_required_failure_blocks_evidence(self):
        self.assertEqual(release.REQUIRED, {'format','lint','test','documentation','audit',
            'linux/amd64','linux/arm64','chart-schema','cluster'})
        for check in release.REQUIRED:
            record = dict(self.record, passed=sorted(release.REQUIRED-{check}))
            (self.root/'evidence.json').write_text(json.dumps(record))
            with self.subTest(check=check), self.assertRaisesRegex(ValueError,'validation evidence'):
                release.evidence(self.root,'a'*40,'0.0.1')
        self.assertIn('needs: [prepare, validate]', self.workflow())

    def test_c25_unified_version_and_packaged_digest(self):
        import tomllib
        self.assertEqual(tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version'],'0.0.1')
        bloc = next(p for p in tomllib.loads((ROOT/'Cargo.lock').read_text())['package'] if p['name']=='bloc')
        self.assertEqual(bloc['version'],'0.0.1')
        self.assertIn('version: 0.0.1', (ROOT/'charts/bloc/Chart.yaml').read_text())
        self.assertIn('appVersion: "0.0.1"', (ROOT/'charts/bloc/Chart.yaml').read_text())
        from candidate import chart_layout
        with patch.dict(os.environ, {'HELM':os.environ.get('HELM','helm')}):
            chart_layout(ROOT/'charts/bloc',self.root/'package',self.record['image'],'a'*40,'0.0.1')
        import tarfile
        with tarfile.open(self.root/'package/bloc-0.0.1.tgz') as archive:
            values=archive.extractfile('bloc/values.yaml').read().decode()
            self.assertEqual(archive.extractfile('bloc/LICENSE').read(),(ROOT/'LICENSE').read_bytes())
        self.assertIn(self.record['image'], values)
        self.assertNotIn('digest: ""',values)

    def test_c26_completion_follows_both_anonymous_verifications(self):
        calls=[]
        for store in (self.images,self.charts):
            original=store.verify
            store.verify=lambda layout,ref,s=store,f=original: (calls.append(s.repository),f(layout,ref))[-1]
        original=self.completion.create
        def create(*args):
            self.assertEqual(calls,['bloc','charts/bloc'])
            return original(*args)
        self.completion.create=create
        self.publish()
        self.assertEqual(self.completion.writes,1)

    def test_c27_private_package_prevents_completion(self):
        for store in (self.images,self.charts):
            store.private=True
            with self.assertRaises(PermissionError):
                self.publish()
            self.assertIsNone(self.completion.record)
            store.private=False

    def test_c26_pull_verifies_reported_digest_without_local_repo_digests(self):
        output = 'Digest: '+self.record['image']+'\nStatus: Downloaded newer image\n'
        with patch('release.subprocess.check_output', return_value=output):
            release.pull_image(self.record, 'linux/arm64', {})

    def test_c26_pull_rejects_missing_or_conflicting_digest(self):
        for output in ('Status: Downloaded newer image\n', 'Digest: sha256:'+'0'*64+'\n'):
            with self.subTest(output=output):
                with patch('release.subprocess.check_output', return_value=output):
                    with self.assertRaisesRegex(ValueError, 'digest disagreement'):
                        release.pull_image(self.record, 'linux/arm64', {})

    def test_c28_partial_upload_is_preserved(self):
        self.charts.fail=True
        with self.assertRaisesRegex(RuntimeError,'chart upload'):
            self.publish()
        self.assertEqual(self.images.writes,1)
        self.assertIsNotNone(self.images.data)
        self.assertEqual(self.completion.writes,0)

    def test_c29_retry_reuses_original_artifacts(self):
        self.charts.fail=True
        with self.assertRaises(RuntimeError): self.publish()
        original=self.images.data
        self.charts.fail=False
        self.publish()
        self.assertEqual(self.images.data,original)
        self.assertEqual((self.images.writes,self.charts.writes,self.completion.writes),(1,1,1))

    def test_c30_conflict_or_missing_evidence_refuses_writes(self):
        self.charts.data=b'conflicting chart'
        with self.assertRaisesRegex(ValueError,'digest conflict'):
            self.publish()
        self.assertEqual((self.images.writes,self.charts.writes,self.completion.writes),(0,0,0))
        with self.assertRaises(FileNotFoundError):
            release.evidence(self.root,'a'*40,'0.0.1')
        (self.root/'evidence.json').write_text(json.dumps(dict(self.record,revision='b'*40)))
        with self.assertRaisesRegex(ValueError,'source/version conflict'):
            release.evidence(self.root,'a'*40,'0.0.1')

    def test_c31_completed_retry_does_not_mutate(self):
        self.publish()
        before=copy.deepcopy(self.completion.record)
        self.publish()
        self.assertEqual(self.completion.record,before)
        self.assertEqual((self.images.writes,self.charts.writes,self.completion.writes),(1,1,1))

    def test_c32_version_concurrency_covers_inspection_and_publication(self):
        text=self.workflow()
        self.assertIn('group: distribution-${{ github.ref }}',text)
        self.assertIn('cancel-in-progress: false',text)
        self.assertLess(text.index('concurrency:'), text.index('jobs:'))

    def test_c33_pinned_actions_and_scoped_writes(self):
        import re
        workflow=self.workflow()
        for action in re.findall(r'uses:\s*(\S+)',workflow):
            if action == './.github/workflows/administrator-service-capacity.yml':
                local = ROOT / action[2:]
                self.assertTrue(local.is_file())
                contract=local.read_text()
                self.assertIn('  workflow_call:',contract)
                self.assertIn('      contents: read',contract)
                self.assertNotIn('contents: write',contract)
                self.assertNotIn('packages: write',contract)
                for nested in re.findall(r'uses:\s*(\S+)',contract):
                    self.assertRegex(nested,r'^[\w/-]+@[0-9a-f]{40}$')
            else:
                self.assertRegex(action,r'^[\w/-]+@[0-9a-f]{40}$')
        self.assertEqual(workflow.count('packages: write'),1)
        self.assertEqual(workflow.count('contents: write'),1)
        self.assertIn('GH_TOKEN: ${{ github.token }}',workflow)
        self.assertNotIn('secrets.',workflow)

    def test_c34_notes_contain_identities_and_recovery(self):
        notes=release.notes(self.record)
        for value in ('scaffold','linux/amd64','linux/arm64','4.3.1','1.36.5','a'*40,
                      self.record['image'], self.record['chart'],'--version 0.0.1','--values',
                      '--rollback-on-failure','helm rollback','recovery fails'):
            self.assertIn(value,notes)

    def test_c35_no_floating_alias_or_replacement(self):
        self.publish()
        original_image=self.images.entries['v0.0.1']
        original_chart=self.charts.entries['0.0.1']
        self.record=dict(self.record,version='0.0.2')
        self.assertEqual(self.images.writes,1)
        self.assertEqual(self.charts.writes,1)
        self.publish()
        self.assertEqual(set(self.images.entries), {'v0.0.1','v0.0.2'})
        self.assertEqual(set(self.charts.entries), {'0.0.1','0.0.2'})
        self.assertEqual(self.images.entries['v0.0.1'],original_image)
        self.assertEqual(self.charts.entries['0.0.1'],original_chart)
        self.assertEqual(set(self.completion.records), {'v0.0.1','v0.0.2'})
        source=(ROOT/'scripts/distribution/release.py').read_text()
        self.assertNotIn("publish(layout,'latest')",source)
        self.assertNotIn("'DELETE'",source)
        self.assertIn("tag = 'v'+record['version']",source)

    def test_c36_publisher_has_no_cluster_access(self):
        publish=self.workflow().split('  publish:')[1]
        self.assertNotIn('kubectl',publish)
        self.assertNotIn('KUBECONFIG',publish)
        self.assertNotIn('helm upgrade',publish)
        self.assertIn('release.py publish',publish)


if __name__=='__main__':
    unittest.main(verbosity=2)
