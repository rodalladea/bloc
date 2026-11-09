"""Operator contract and rendered Secret boundaries; no fixture key material."""
import json
import os
from pathlib import Path
import subprocess
import unittest
import yaml
ROOT = Path(__file__).resolve().parents[1]

class MfaOperationsDocumentation(unittest.TestCase):
    def test_existing_secret_mount_boundaries(self):
        helm = os.environ.get("BLOC_HELM", "helm")
        output = subprocess.check_output([helm, "template", "bloc", str(ROOT / "charts/bloc"), "--set", "image.digest=sha256:"+"a"*64, "--set", "access.operatorPod=true", "--set", "access.migrationJob=true", "--set", "access.maintenanceJob=true", "--set", "mfa.keyringSecretName=operator-provided", "--set", "mfa.keyringSecretKey=mfa.json"], text=True)
        documents = [d for d in yaml.safe_load_all(output) if d]
        self.assertFalse(any(d["kind"] == "Secret" for d in documents))
        for d in documents:
            kind=d["kind"]
            if kind not in ("Deployment", "Pod", "Job", "CronJob"):
                continue
            spec=d["spec"] if kind == "Pod" else d["spec"]["jobTemplate"]["spec"]["template"]["spec"] if kind == "CronJob" else d["spec"]["template"]["spec"]
            env={e["name"]:e.get("value") for e in spec["containers"][0].get("env", [])}
            keys=[v for v in spec.get("volumes", []) if v.get("secret", {}).get("secretName") == "operator-provided"]
            if kind in ("Deployment", "Pod"):
                self.assertEqual(env["BLOC_MFA_KEYRING_FILE"], "/run/bloc-mfa/keyring.json")
                self.assertEqual(keys[0]["secret"]["items"], [{"key":"mfa.json", "path":"keyring.json"}])
            else:
                self.assertNotIn("BLOC_MFA_KEYRING_FILE", env)
                self.assertEqual(keys, [])

    def test_operator_recovery_and_trust_contract(self):
        text=(ROOT / "docs/realm-mfa-operations.md").read_text()
        for literal in ("--confirm-replicas-restarted", "--confirm-backup-escrow", "completion time step plus one", "Runtime compromise", "Binary-only rollback"):
            self.assertIn(literal.lower(), text.lower())
        schema=json.loads((ROOT / "charts/bloc/values.schema.json").read_text())
        self.assertIn("mfa",schema["required"])
        self.assertFalse(schema["properties"]["mfa"]["additionalProperties"])
