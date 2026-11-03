import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / 'scripts/security'))
SPEC = importlib.util.spec_from_file_location('context', ROOT / 'scripts/security/action_context.py')
context = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(context)


class ContextTests(unittest.TestCase):
    def test_pr_metadata_is_data_and_consumer_repository_is_not_hardcoded(self):
        data = {'base': {'sha': 'a'*40}, 'head': {'sha': 'b'*40}, 'number': 7,
                'title': '$(touch /tmp/never)'}
        with tempfile.TemporaryDirectory() as directory, patch.object(context, 'fetch_pr', return_value=data):
            result = context.resolve_context('another-owner/python-service', '7', directory)
        self.assertEqual(result['repository'], 'another-owner/python-service')
        self.assertEqual(result['head'], 'b'*40)
        self.assertNotIn('title', result)
        self.assertTrue(result['checkout_path'].startswith('__security_audit_'))

    def test_invalid_repository_number_and_server_sha_are_rejected(self):
        for repo, number in [('owner/repo/../../x','1'),('owner/repo','7; echo x')]:
            with self.assertRaises(ValueError):
                context.resolve_context(repo, number, '/tmp')
        with patch.object(context, 'fetch_pr', return_value={'base': {'sha':'HEAD'}, 'head':{'sha':'b'*40}}):
            with self.assertRaises(ValueError):
                context.resolve_context('owner/repo','7','/tmp')

    def test_action_uses_its_own_code_and_never_executes_consumer_code(self):
        action = (ROOT / 'action.yml').read_text()
        self.assertIn('using: composite', action)
        self.assertIn('github.action_path', action)
        self.assertIn('persist-credentials: false', action)
        self.assertIn('repository: ${{ steps.context.outputs.repository }}', action)
        self.assertNotIn('composer install', action)
        self.assertNotIn('python3 candidate/', action)
        self.assertNotIn('statuses/', action)
        self.assertIn('deepseek-api-key:', action)

    def test_runtime_settings_are_validated_before_yaml_generation(self):
        with patch.dict(os.environ, {'SECURITY_REASONING_EFFORT': 'low', 'SECURITY_MAX_OUTPUT_TOKENS':'32768'}):
            config = context.runtime_settings()
        self.assertEqual(config['effort'], 'low')
        with patch.dict(os.environ, {'SECURITY_REASONING_EFFORT': 'high\nmalicious: true'}):
            with self.assertRaises(ValueError):
                context.runtime_settings()


if __name__ == '__main__':
    unittest.main()
