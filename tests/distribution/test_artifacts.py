"""Trust-boundary tests for retained evidence and registry credentials."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts/distribution'))
from oci import Layout, PublicRedirect
from prepare import original_artifact


class ArtifactTests(unittest.TestCase):
    def test_recovery_ignores_pull_request_and_wrong_revision(self):
        artifact={'name':'candidate-v0.0.1-abc','expired':False,'workflow_run':{'id':12}}
        base={'event':'push','head_sha':'abc','path':'.github/workflows/distribution.yml',
              'head_repository':{'full_name':'rodalladea/bloc'}}
        for field,value in [('event','pull_request'),('head_sha','other'),
                            ('path','.github/workflows/other.yml'),
                            ('head_repository',{'full_name':'attacker/bloc'})]:
            with self.subTest(field=field), patch('prepare.api',side_effect=[{'artifacts':[artifact]},dict(base,**{field:value})]):
                self.assertIsNone(original_artifact('rodalladea/bloc',artifact['name'],'abc'))
        with patch('prepare.api',side_effect=[{'artifacts':[artifact]},base]):
            self.assertEqual(original_artifact('rodalladea/bloc',artifact['name'],'abc'),12)

    def test_recovery_ignores_expired_original(self):
        with patch('prepare.api',return_value={'artifacts':[{'name':'candidate','expired':True}]}):
            self.assertIsNone(original_artifact('rodalladea/bloc','candidate','abc'))

    def test_blob_corruption_and_digest_path_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            layout=Layout(temporary)
            identity=layout.put(b'original')
            (Path(temporary)/'blobs/sha256'/identity[7:]).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'corrupted blob'):
                layout.read(identity)
            with self.assertRaisesRegex(ValueError,'invalid content digest'):
                layout.read('../../credentials')

    def test_reusing_readonly_oci_metadata_preserves_content(self):
        from oci import encode, MANIFEST
        with tempfile.TemporaryDirectory() as temporary:
            layout=Layout(temporary)
            payload=encode({'mediaType':MANIFEST,'schemaVersion':2})
            identity=layout.set_root(payload)
            blob=Path(temporary)/'blobs/sha256'/identity[7:]
            marker=Path(temporary)/'oci-layout'
            blob.chmod(0o444)
            marker.chmod(0o444)
            self.assertEqual(layout.set_root(payload),identity)
            self.assertEqual(layout.read(identity),payload)

    def test_blob_redirect_drops_registry_credentials(self):
        request=urllib.request.Request('https://ghcr.io/v2/owner/image/blobs/sha256:abc',headers={'Authorization':'Bearer synthetic'})
        result=PublicRedirect().redirect_request(request,None,302,'Found',{},'https://storage.example.test/blob')
        self.assertFalse(result.has_header('Authorization'))
        same=PublicRedirect().redirect_request(request,None,302,'Found',{},'https://ghcr.io/blob')
        self.assertEqual(same.get_header('Authorization'),'Bearer synthetic')
        with self.assertRaisesRegex(ValueError,'downgrade HTTPS'):
            PublicRedirect().redirect_request(request,None,302,'Found',{},'http://ghcr.io/blob')


if __name__=='__main__':
    unittest.main(verbosity=2)
