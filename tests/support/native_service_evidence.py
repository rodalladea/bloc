"""Validate full-service native records, never primitive or emulated measurements."""
import hashlib
import json
import math
from pathlib import Path
import sys
from application_fingerprint import source_fingerprint


def mfa_workload_fingerprint():
    digest = hashlib.sha256()
    for name in sorted(('tests/support/native_service_capacity.py',
                        'tests/support/native_service_evidence.py',
                        'examples/mfa_capacity_fixture.rs')):
        digest.update(name.encode() + b'\0' + Path(name).read_bytes() + b'\0')
    return digest.hexdigest()


def completed_mfa(witness):
    assert witness['method'] == 'totp'
    assert witness['password_status'] == 303 and witness['challenge_status'] == 200
    assert witness['proof_status'] == 303 and witness['account_status'] == 200
    assert witness['ordinary_cookie_before_proof'] is False
    assert witness['ordinary_cookie_after_proof'] is True
    assert math.isfinite(witness['db_clock_drift_seconds']) and 0 <= witness['db_clock_drift_seconds'] < 1
    assert type(witness['user_index']) is int and 1 <= witness['user_index'] <= 420
    assert math.isfinite(witness['journey_seconds']) and witness['journey_seconds'] > 0


def validate(records, realm_auth=False, realm_mfa=False):
    realm_auth = realm_auth or realm_mfa
    assert len(records) == 2 and {r['architecture'] for r in records} == {'amd64', 'arm64'}
    assert {r['source_tree_sha256'] for r in records} == {source_fingerprint()}, 'native records must measure the current identical application source'
    for r in records:
        assert r['credential_sample_count'] >= 20 and r['source_tree_sha256']
        assert r['native'] is True and r['service'] is True
        assert r['cpu_limit'] == 1 and r['memory_limit_bytes'] == 512 * 1024 * 1024 and r['swap_bytes'] == 0
        assert r['simultaneous_submissions'] == 20 and math.isfinite(r['duration_seconds']) and r['duration_seconds'] >= 60
        assert r['peak_bytes'] <= 384 * 1024 * 1024 and math.isfinite(r['credential_p95_seconds']) and 0 < r['credential_p95_seconds'] < 1
        assert r['oom'] is False and r['failed_health_probes'] == 0
        assert r['immediate_overload'] is True and r['bounded_admission'] is True
        assert r['raw_evidence'] and r['binary_sha256'] and r['source_revision']
        if realm_auth:
            assert r.get('realm_authentication') is True and r.get('redaction') is True
            principals = r['credential_sample_principals']
            assert principals.count('realm') >= 10 and principals.count('administrator') >= 10
            samples = r['admission_samples']
            assert len(samples) >= 20
            assert all(0 <= s['realm_hash_work'] <= 20 and s['realm_hash_work'] <= s['all_hash_work'] <= 30 for s in samples)
            assert any(s['realm_hash_work'] > 0 for s in samples)
            assert any(s['all_hash_work'] > s['realm_hash_work'] for s in samples)
        if realm_mfa:
            assert r.get('realm_mfa') is True, 'password-only realm records cannot establish MFA capacity'
            assert type(r['mfa_workload_version']) is int and r['mfa_workload_version'] == 1
            assert r['mfa_workload_sha256'] == mfa_workload_fingerprint(), 'stale MFA workload'
            assert r['mfa_seeded_users'] == 420 and r['mfa_replay_floor_resets'] == r['mfa_admission_resets'] == 0
            assert r['service_os'] == 'linux' and r['native_host_architecture'] == r['architecture']
            assert r['collector_host_os'] in ('Linux', 'Darwin')
            assert len(r['mfa_helper_binary_sha256']) == 64 and all(c in '0123456789abcdef' for c in r['mfa_helper_binary_sha256'])
            assert r['credential_sample_count'] == 20 and len(principals) == 20
            assert principals.count('realm') == principals.count('administrator') == 10
            witnesses = r['mfa_latency_witnesses']
            assert len(witnesses) == 10
            assert {w['user_index'] for w in witnesses} == set(range(402, 421, 2))
            for w in witnesses:
                completed_mfa(w)
            latency = r['mfa_latency_seconds']
            assert len(latency) == 20 and all(math.isfinite(t) and t > 0 for t in latency)
            assert r['credential_p95_seconds'] == sorted(latency)[18]
            for sample, w in enumerate(witnesses):
                assert w['journey_seconds'] == latency[sample * 2 + 1]
            attempts = r['mfa_attempts']
            assert len(attempts) == 400
            assert all(a['status'] in (303,429,503) and math.isfinite(a['seconds']) and a['seconds'] > 0 for a in attempts)
            assert any(a['status'] == 429 for a in attempts) and any(a['status'] == 503 for a in attempts)
            assert all(a['seconds'] < 1 and a['retry_after'] for a in attempts if a['status'] == 503)
            assert sum(a['principal'] == 'realm' for a in attempts) == sum(a['principal'] == 'administrator' for a in attempts) == 200
            assert all(math.isfinite(a['journey_seconds']) and a['journey_seconds'] >= a['seconds'] for a in attempts if a['principal'] == 'realm' and a['status'] == 503)
            realm_indices = [a['user_index'] for a in attempts if a['principal'] == 'realm']
            assert len(realm_indices) == len(set(realm_indices)) and set(realm_indices) == set(range(2,401,2))
            completed = [a for a in attempts if a['principal'] == 'realm' and a['status'] == 303]
            indices = []
            for a in completed:
                completed_mfa(a)
                assert a['user_index'] <= 400 and a['user_index'] % 2 == 0
                indices.append(a['user_index'])
            assert len(indices) == len(set(indices))
            successes = len(completed) + len(witnesses)
            assert r['mfa_database'] == dict(factor_sessions=successes, sign_in_audits=successes, distinct_users=successes)
    return True


def main():
    validate(json.loads(Path(sys.argv[1]).read_text()), '--realm-auth' in sys.argv[2:], '--realm-mfa' in sys.argv[2:])
    print('Native full-service amd64+arm64 capacity records satisfy the declared bounds')


if __name__ == '__main__':
    main()
