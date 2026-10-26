"""Run the actual native-build shell with a disposable BuildKit boundary."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT=Path(__file__).resolve().parents[2]


class BuildCacheTests(unittest.TestCase):
    def build(self, hit, fail=False):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work=Path(temporary.name)
        for directory in ('bin','tests/support'):
            (work/directory).mkdir(parents=True)
        (work/'Cargo.toml').write_text('[package]\nversion="0.4.2"\n')
        (work/'tests/support/application_fingerprint.py').write_text('def source_fingerprint(): return "fixture-fingerprint"\n')
        old=work/'buildkit-cache'
        if hit:
            old.mkdir()
            (old/'old-cache').touch()
        docker=work/'bin/docker'
        docker.write_text(f'#!{sys.executable}\n'+'''
import io,json,os,pathlib,sys,tarfile
args=sys.argv[1:]
with open('commands.jsonl','a') as output: output.write(json.dumps(args)+'\\n')
if args[:2]==['buildx','build']:
    if '--cache-to' in args:
        options=dict(item.split('=',1) for item in args[args.index('--cache-to')+1].split(','))
        export=pathlib.Path(options['dest']); export.mkdir()
        (export/'new-cache').touch()
    if os.environ['FAIL_BUILD']=='true': raise SystemExit(7)
    destination=args[args.index('--output')+1].split('dest=',1)[1]
    with tarfile.open(destination,'w') as archive:
        content=b'{"imageLayoutVersion":"1.0.0"}'
        entry=tarfile.TarInfo('oci-layout'); entry.size=len(content)
        archive.addfile(entry,io.BytesIO(content))
''')
        docker.chmod(0o755)
        job=yaml.safe_load((ROOT/'.github/workflows/build-images.yml').read_text())['jobs']['build']
        build=next(step for step in job['steps'] if 'docker buildx build' in step.get('run',''))
        cache=next(step for step in job['steps'] if step.get('uses','').startswith('actions/cache@'))
        self.assertEqual(build['env'].get('CACHE_HIT'),
                         '${{ steps.'+cache.get('id','')+'.outputs.cache-hit }}')
        result=subprocess.run(['bash','-e','-o','pipefail','-c',build['run']],cwd=work,
            env={**os.environ,'PATH':str(work/'bin')+os.pathsep+os.environ['PATH'],
                 'RUNNER_TEMP':str(work),'ARCH':'amd64','GITHUB_SHA':'a'*40,
                 'CACHE_HIT':hit,'FAIL_BUILD':str(fail).lower()},
            text=True,capture_output=True,timeout=10)
        commands=[json.loads(line) for line in (work/'commands.jsonl').read_text().splitlines()]
        command=next(command for command in commands if command[:2]==['buildx','build'])
        return work,result,command

    def test_exact_hit_preserves_cache_and_still_exports_attested_image(self):
        work,result,command=self.build('true')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('--cache-to',command)
        self.assertIn('--cache-from',command)
        self.assertTrue((work/'buildkit-cache/old-cache').exists())
        self.assertFalse((work/'buildkit-cache-new').exists())
        self.assertTrue((work/'platform/image/oci-layout').exists())
        self.assertIn('--provenance=mode=max',command)
        self.assertTrue(command[command.index('--attest')+1].startswith('type=sbom,'))
        self.assertIn('REVISION='+'a'*40,command)
        self.assertIn('org.bloc.source-tree-sha256=fixture-fingerprint',command)
        self.assertEqual(command[command.index('--platform')+1],'linux/amd64')

    def test_partial_or_missing_cache_is_replaced_after_success(self):
        for hit in ('false',''):
            with self.subTest(hit=hit):
                work,result,command=self.build(hit)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('--cache-to',command)
                self.assertTrue((work/'buildkit-cache/new-cache').exists())
                self.assertFalse((work/'buildkit-cache/old-cache').exists())
                self.assertFalse((work/'buildkit-cache-new').exists())

    def test_build_failure_does_not_promote_partial_cache(self):
        work,result,_=self.build('false',fail=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue((work/'buildkit-cache/old-cache').exists())
        self.assertFalse((work/'buildkit-cache/new-cache').exists())
        self.assertFalse((work/'platform/image/oci-layout').exists())


if __name__=='__main__':
    unittest.main(verbosity=2)
