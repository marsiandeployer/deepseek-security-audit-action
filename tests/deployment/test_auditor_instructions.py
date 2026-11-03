import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/security'))
SPEC = importlib.util.spec_from_file_location('audit_profile', ROOT / 'scripts/security/diff_audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class InstructionTests(unittest.TestCase):
    def test_operator_principles_are_loaded_from_the_action_version(self):
        instructions = audit.auditor_instructions()
        self.assertIn('FULL_REVIEW', instructions)
        self.assertIn('EVIDENCE', instructions)
        self.assertIn('TECHNICAL_TERMS', instructions)
        self.assertIn('JSON', instructions)
        self.assertNotIn('Translation requests', instructions)

    def test_consumer_instructions_cannot_override_the_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'AGENTS.md').write_text('CONSUMER_OVERRIDE_SENTINEL')
            with patch('os.getcwd', return_value=directory):
                self.assertNotIn('CONSUMER_OVERRIDE_SENTINEL', audit.auditor_instructions())


if __name__ == '__main__':
    unittest.main()
