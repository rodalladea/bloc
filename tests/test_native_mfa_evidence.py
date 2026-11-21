"""Truthful synthetic validator regression records; these are NOT capacity evidence."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parent / 'support'))
import native_service_evidence as evidence
real_workload_fingerprint = evidence.mfa_workload_fingerprint


def witness(index):
    return dict(method='totp',password_status=303,challenge_status=200,proof_status=303,account_status=200,ordinary_cookie_before_proof=False,ordinary_cookie_after_proof=True,user_index=index,db_clock_drift_seconds=.01,journey_seconds=.2)


def records():
    result=[]
    for architecture in ('amd64','arm64'):
        attempts=[]
        for i in range(400):
            principal='realm' if i%2 else 'administrator'
            status=303 if principal=='realm' and i<40 else 503 if i==0 else 429
            attempt=dict(principal=principal,status=status,seconds=.2,retry_after='60')
            if principal=='realm':attempt['user_index']=i+1
            if principal=='realm' and status==303:attempt.update(witness(i+1))
            attempts.append(attempt)
        result.append(dict(architecture=architecture,source_tree_sha256='source',credential_sample_count=20,native=True,service=True,cpu_limit=1,memory_limit_bytes=512*1024*1024,swap_bytes=0,simultaneous_submissions=20,duration_seconds=60,peak_bytes=200*1024*1024,credential_p95_seconds=.2,oom=False,failed_health_probes=0,immediate_overload=True,bounded_admission=True,raw_evidence='SYNTHETIC UNIT FIXTURE, NOT MEASUREMENT',binary_sha256='0'*64,source_revision='synthetic',realm_authentication=True,redaction=True,credential_sample_principals=['administrator','realm']*10,admission_samples=[dict(realm_hash_work=20,all_hash_work=30)]*20,realm_mfa=True,mfa_workload_version=1,mfa_workload_sha256='workload',mfa_seeded_users=420,mfa_replay_floor_resets=0,mfa_admission_resets=0,collector_host_os='Darwin',service_os='linux',native_host_architecture=architecture,mfa_helper_binary_sha256='1'*64,mfa_latency_witnesses=[witness(i) for i in range(402,421,2)],mfa_attempts=attempts,mfa_database=dict(factor_sessions=30,sign_in_audits=30,distinct_users=30),mfa_latency_seconds=[.2]*20))
    return result


class NativeMfaEvidence(unittest.TestCase):
    def setUp(self):
        self.source=patch.object(evidence,'source_fingerprint',return_value='source');self.source.start()
        self.workload=patch.object(evidence,'mfa_workload_fingerprint',return_value='workload');self.workload.start()
        self.addCleanup(self.source.stop);self.addCleanup(self.workload.stop)
    def rejected(self, data):
        with self.assertRaises((AssertionError,KeyError,TypeError,ValueError)):
            evidence.validate(data,realm_mfa=True)
    def test_complete_synthetic_shape_and_password_mode_backwards_compatibility(self):
        self.assertTrue(evidence.validate(records(),realm_mfa=True))
        old=records()
        for r in old:
            for key in list(r):
                if key.startswith('mfa_') or key in ('realm_mfa','service_os','collector_host_os','native_host_architecture'):del r[key]
        self.assertTrue(evidence.validate(old,realm_auth=True))
        self.rejected(old)
    def test_terminal_overload_is_distinct_from_total_rejected_journey(self):
        data=records()
        data[0]['mfa_attempts'][41].update(status=503,seconds=.01,journey_seconds=1.5,overload_seconds=.01)
        self.assertTrue(evidence.validate(data,realm_mfa=True))
        data[0]['mfa_attempts'][41]['seconds']=1.01
        self.rejected(data)

    def test_workload_fingerprint_binds_collector_helper_and_validator(self):
        names=('tests/support/native_service_capacity.py','tests/support/native_service_evidence.py','examples/mfa_capacity_fixture.rs')
        payloads={name:name.encode() for name in names}
        with patch.object(Path,'read_bytes',lambda path:payloads[str(path)]):
            baseline=real_workload_fingerprint()
            for name in names:
                original=payloads[name];payloads[name]=original+b'changed'
                self.assertNotEqual(real_workload_fingerprint(),baseline)
                payloads[name]=original

    def test_both_native_architectures_and_current_source_required(self):
        self.rejected(records()[:1])
        for key,value in [('architecture','amd64'),('source_tree_sha256','stale')]:
            data=records();data[1][key]=value;self.rejected(data)
    def test_existing_resource_slo_and_admission_bounds_preserved(self):
        cases={'native':False,'service':False,'cpu_limit':2,'memory_limit_bytes':1024**3,'swap_bytes':1,'simultaneous_submissions':19,'duration_seconds':59,'peak_bytes':384*1024*1024+1,'credential_p95_seconds':1,'oom':True,'failed_health_probes':1,'immediate_overload':False,'bounded_admission':False,'redaction':False,'credential_sample_count':19}
        for key,value in cases.items():
            with self.subTest(key=key):
                data=records();data[0][key]=value;self.rejected(data)
        for key in ('duration_seconds','credential_p95_seconds'):
            for value in (float('nan'),float('inf')):
                data=records();data[0][key]=value;self.rejected(data)
        data=records();data[0]['admission_samples'][0]={'realm_hash_work':21,'all_hash_work':31};self.rejected(data)
    def test_workload_cannot_relabel_password_only_or_reset_authority(self):
        for key,value in {'realm_mfa':False,'realm_authentication':False,'mfa_workload_version':2,'mfa_workload_sha256':'stale','mfa_seeded_users':20,'mfa_replay_floor_resets':1,'mfa_admission_resets':1,'service_os':'darwin','native_host_architecture':'wrong','mfa_helper_binary_sha256':'no'}.items():
            with self.subTest(key=key):
                data=records();data[0][key]=value;self.rejected(data)
    def test_real_full_journey_and_cookie_sequence_required(self):
        for key,value in {'method':'password','password_status':200,'challenge_status':303,'proof_status':422,'account_status':403,'ordinary_cookie_before_proof':True,'ordinary_cookie_after_proof':False,'user_index':1,'db_clock_drift_seconds':1,'journey_seconds':0}.items():
            with self.subTest(key=key):
                data=records();data[0]['mfa_latency_witnesses'][0][key]=value;self.rejected(data)
        data=records();data[0]['mfa_latency_witnesses'].pop();self.rejected(data)
        data=records();data[0]['mfa_latency_witnesses'][0]['db_clock_drift_seconds']=float('nan');self.rejected(data)
    def test_complete_bursts_unique_users_corresponding_database_and_latency(self):
        for key in ('factor_sessions','sign_in_audits','distinct_users'):
            data=records();data[0]['mfa_database'][key]+=1;self.rejected(data)
        data=records();data[0]['mfa_attempts'].pop();self.rejected(data)
        data=records();data[0]['mfa_attempts'][3]['user_index']=2;self.rejected(data)
        data=records();data[0]['mfa_attempts'][1]['ordinary_cookie_before_proof']=True;self.rejected(data)
        data=records();data[0]['mfa_latency_seconds'][1]=.3;self.rejected(data)
        data=records();data[0]['mfa_attempts'][0]['seconds']=1;self.rejected(data)
        data=records();data[0]['mfa_attempts'][0].update(seconds=1.01,overload_seconds=.01);self.rejected(data)


if __name__=='__main__':unittest.main()
