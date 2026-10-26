"""Node cache hits avoid rebuilding; corrupt caches and build failures stop validation."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class NodeImageTests(unittest.TestCase):
    def test_absent_cached_present_and_failed_node_images(self):
        for case in ('absent','cached','present','bad-cache','build-failure'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                work=Path(temporary)
                (work/'bin').mkdir()
                script=f'#!{sys.executable}\n'+'''
import os, pathlib, sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with open('commands','a') as log: log.write(name+' '+' '.join(args)+'\\n')
if name=='docker':
    if args[:2]==['image','inspect']: raise SystemExit(0 if pathlib.Path('image').exists() else 1)
    if args[0]=='save': print('synthetic-node')
    if args[0]=='load':
        if sys.stdin.read().strip()!='synthetic-node': raise SystemExit(1)
        pathlib.Path('image').touch()
elif name=='kind':
    if os.environ['NODE_CASE']=='build-failure': raise SystemExit(1)
    pathlib.Path('image').touch()
elif name=='zstd':
    if '--decompress' in args: print(pathlib.Path(args[-1]).read_text())
    else: pathlib.Path(args[args.index('-o')+1]).write_text(sys.stdin.read())
'''
                for tool in ('docker','kind','zstd'):
                    path=work/'bin'/tool
                    path.write_text(script)
                    path.chmod(0o755)
                archive=work/'node-image/node.tar.zst'
                if case in ('cached','bad-cache'):
                    archive.parent.mkdir()
                    archive.write_text('synthetic-node' if case=='cached' else 'corrupt')
                if case=='present': (work/'image').touch()
                result=subprocess.run(['bash',str(ROOT/'scripts/distribution/node-image.sh')],
                    cwd=work,env={**os.environ,'RUNNER_TEMP':str(work),'NODE_CASE':case,
                                  'PATH':str(work/'bin')+os.pathsep+os.environ['PATH']},
                    text=True,capture_output=True,timeout=10)
                self.assertEqual(result.returncode,1 if case in ('bad-cache','build-failure') else 0,result.stderr)
                commands=(work/'commands').read_text()
                self.assertEqual('kind build' in commands,case in ('absent','build-failure'))
                self.assertEqual('docker load' in commands,case in ('cached','bad-cache'))
                if case=='absent': self.assertEqual(archive.read_text().strip(),'synthetic-node')
                if case=='build-failure': self.assertFalse(archive.exists())


if __name__=='__main__':
    unittest.main(verbosity=2)
