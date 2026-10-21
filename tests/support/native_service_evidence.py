"""Validate full-service native records, never primitive or emulated measurements."""
import json,sys
from application_fingerprint import source_fingerprint
records=json.load(open(sys.argv[1]))
assert {r['architecture'] for r in records}=={'amd64','arm64'}
assert {r['source_tree_sha256'] for r in records}=={source_fingerprint()},'native records must measure the current identical application source'
for r in records:
    assert r['credential_sample_count']>=20 and r['source_tree_sha256']
    assert r['native'] is True and r['service'] is True
    assert r['cpu_limit']==1 and r['memory_limit_bytes']==512*1024*1024 and r['swap_bytes']==0
    assert r['simultaneous_submissions']==20 and r['duration_seconds']>=60
    assert r['peak_bytes']<=384*1024*1024 and r['credential_p95_seconds']<1
    assert r['oom'] is False and r['failed_health_probes']==0
    assert r['immediate_overload'] is True and r['bounded_admission'] is True
    assert r['raw_evidence'] and r['binary_sha256'] and r['source_revision']
print('Native full-service amd64+arm64 capacity records satisfy the declared bounds')
