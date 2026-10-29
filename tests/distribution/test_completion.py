"""Native evidence must match both validated manifests before completion."""
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/distribution'))
sys.path.insert(0,str(ROOT/'tests/support'))
from application_fingerprint import source_fingerprint
from complete import complete
from oci import INDEX, Layout, encode
from release import REQUIRED


class CompletionTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.bundle=self.root/'candidate'
        self.measurements=self.root/'measurements'
        self.revision='a'*40
        image=Layout(self.bundle/'image')
        image.set_root(encode({'mediaType':INDEX,'manifests':[
            {'platform':{'os':'linux','architecture':arch},'digest':'sha256:'+char*64}
            for arch,char in [('amd64','b'),('arm64','c')]]}))
        chart=Layout(self.bundle/'chart')
        chart.set_root(encode({'mediaType':INDEX}))
        self.record={'revision':self.revision,'version':'0.4.1',
                     'image':image.root()['digest'],'chart':chart.root()['digest'],
                     'helm':'4.3.1','kubernetes':'1.36.5',
                     'passed':sorted(REQUIRED-{'linux/amd64','linux/arm64'})}
        self.validation=self.bundle/'validation.json'
        self.validation.write_text(json.dumps(self.record))
        for arch,char in [('amd64','b'),('arm64','c')]:
            directory=self.measurements/arch/'service-capacity'
            directory.mkdir(parents=True)
            native={'architecture':arch,'source_tree_sha256':source_fingerprint(),
                    'credential_sample_count':20,'native':True,'service':True,
                    'cpu_limit':1,'memory_limit_bytes':512*1024*1024,'swap_bytes':0,
                    'simultaneous_submissions':20,'duration_seconds':60,
                    'peak_bytes':384*1024*1024,'credential_p95_seconds':0.5,
                    'oom':False,'failed_health_probes':0,'immediate_overload':True,
                    'bounded_admission':True,'raw_evidence':'raw.json',
                    'binary_sha256':'d'*64,'source_revision':self.revision,
                    'image_manifest_digest':'sha256:'+char*64}
            (directory/'record.json').write_text(json.dumps(native))
            (directory/'raw.json').write_text('{"synthetic":true}')
            (directory.parent/'smoke.log').write_text('synthetic smoke passed')
        # OCI verification itself has separate artifact/publication tests.
        self.image_check=patch('complete.verify_image',return_value=image.root()['digest'])
        self.image_check.start()
        self.addCleanup(self.image_check.stop)
        self.chart_check=patch('complete.verify_chart')
        self.chart_check.start()
        self.addCleanup(self.chart_check.stop)

    def finish(self):
        complete(self.bundle,self.measurements,self.revision,'0.4.1')

    def test_completion_requires_both_bounds_and_current_manifest_identities(self):
        for arch in ('amd64','arm64'):
            path=self.measurements/arch/'service-capacity/record.json'
            original=json.loads(path.read_text())
            for field,value in [('architecture','other'),('source_revision','e'*40),
                                ('image_manifest_digest','sha256:'+'f'*64),
                                ('source_tree_sha256','f'*64),('credential_p95_seconds',2),
                                ('native',False),('oom',True)]:
                with self.subTest(arch=arch,field=field):
                    path.write_text(json.dumps({**original,field:value}))
                    with self.assertRaises((ValueError,AssertionError, subprocess.CalledProcessError)):
                        self.finish()
                    self.assertFalse((self.bundle/'evidence.json').exists())
                path.write_text(json.dumps(original))
        self.finish()
        record=json.loads((self.bundle/'evidence.json').read_text())
        self.assertEqual(set(record['passed']),REQUIRED)
        self.assertEqual(record['image'],self.record['image'])
        for arch in ('amd64','arm64'):
            self.assertTrue((self.bundle/f'evidence/{arch}/service-capacity/raw.json').is_file())
            self.assertTrue((self.bundle/f'evidence/{arch}/smoke.log').is_file())

    def test_completed_candidate_cannot_be_overwritten(self):
        self.finish()
        original=(self.bundle/'evidence.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'already completed'):
            self.finish()
        self.assertEqual((self.bundle/'evidence.json').read_bytes(),original)

    def test_missing_measurement_or_failed_validation_never_completes(self):
        native=self.measurements/'arm64/service-capacity/record.json'
        native.unlink()
        with self.assertRaises(subprocess.CalledProcessError):
            self.finish()
        self.assertFalse((self.bundle/'evidence.json').exists())
        for field,value in [('revision','f'*40),('version','0.0.0'),('passed',[]),
                            ('image','sha256:'+'0'*64),('chart','sha256:'+'0'*64),
                            ('helm','other'),('kubernetes','other')]:
            with self.subTest(field=field):
                self.validation.write_text(json.dumps({**self.record,field:value}))
                with self.assertRaises(ValueError):
                    self.finish()
                self.assertFalse((self.bundle/'evidence.json').exists())


if __name__=='__main__':
    unittest.main(verbosity=2)
