"""Keep realm authentication scenario mappings resolvable as proof names change."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RealmAuthenticationDocumentation(unittest.TestCase):
    def test_every_scenario_proof_exists(self):
        agreement = (ROOT / 'docs/behaviors/realm-user-authentication.md').read_text()
        source = '\n'.join(p.read_text() for p in (
            ROOT / 'tests/realm_authentication.rs',
            *sorted((ROOT / 'tests/support').glob('realm_authentication_*.rs'))))
        functions = set(re.findall(r'\bfn (\w+)\s*\(', source))
        for number in range(1,64):
            name = f'realm_auth_c{number:02}'
            with self.subTest(proof=name):
                self.assertIn(f'`{name}`', agreement)
                self.assertIn(name, functions)
        for name in ('realm_auth_upgrade_roles', 'administrator_policy_unchanged', 'realm_auth_native_capacity'):
            with self.subTest(proof=name):
                self.assertIn(f'`{name}`', agreement)
                self.assertIn(name, functions)

    def test_decision_and_threat_model_are_linked(self):
        adr = (ROOT / 'docs/adr/0007-realm-user-authentication.md').read_text()
        for target in ('../behaviors/realm-user-authentication.md', '../realm-authentication-threat-model.md', '../realm-user-authentication.md'):
            self.assertIn(f']({target})', adr)
        for identifier in ('8fc565a08878652aad8b6a5ceae0dc5e8eaf638f4a5a6dec', '807a88ce48c15761920b6b779b78e892a4ea5ab866ed6ca8', 'f2dcc634f47b5e7acb784ccca96a5730a348d6f2329a84e8'):
            self.assertIn(f'?file={identifier}', adr)
        threat = (ROOT / 'docs/realm-authentication-threat-model.md').read_text()
        self.assertIn('MFA', threat)
        self.assertIn('production-security', threat)
        self.assertIn('realm_auth_c50', threat)
        self.assertIn('realm_auth_c39', threat)


if __name__ == '__main__':
    unittest.main()
