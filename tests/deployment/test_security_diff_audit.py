"""Trust boundaries, full coverage, and informational PR reporting."""
import importlib.util
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / 'scripts/security'))
SPEC = importlib.util.spec_from_file_location('diff_audit', ROOT / 'scripts/security/diff_audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class DiffAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        summary = patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(self.repo / 'test-summary.md')})
        summary.start()
        self.addCleanup(summary.stop)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.repo / 'a.php').write_text('<?php\necho "safe";\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD')
        (self.repo / 'a.php').write_text('<?php\necho $_GET["input"];\n')
        self.git('commit', '-qam', 'change')
        self.head = self.git('rev-parse', 'HEAD')
        self.scope = audit.collect_diff(self.repo, self.base, self.head)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True).strip()

    def response(self, **updates):
        result = {'complete': True, 'reviewed_files': ['a.php'], 'findings': []}
        result.update(updates)
        return json.dumps(result)

    def finding(self, **updates):
        finding = dict(path='a.php', side='new', line=2, severity='high',
                       title='Reflected XSS', evidence='Unescaped GET input reaches HTML',
                       impact='Script runs in visitor origin', fix='Escape for HTML context')
        finding.update(updates)
        return finding

    def test_exact_commit_diff_and_changed_line_evidence(self):
        self.assertIn('+echo $_GET', self.scope['diff'])
        self.assertEqual(self.scope['base'], self.base)
        self.assertEqual(self.scope['head'], self.head)
        self.assertIn(2, self.scope['lines']['a.php']['new'])
        self.assertNotIn(1, self.scope['lines']['a.php']['new'])

    def test_rejects_refs_and_binary_changes_instead_of_truncating(self):
        with self.assertRaises(audit.AuditError):
            audit.collect_diff(self.repo, 'HEAD~1', self.head)
        (self.repo / 'blob').write_bytes(b'\0\1\2')
        self.git('add', '.')
        self.git('commit', '-qm', 'binary')
        scope = audit.collect_diff(self.repo, self.base, self.git('rev-parse', 'HEAD'))
        self.assertIn('blob', scope['file_errors'])
        self.assertIn('a.php', scope['file_diffs'])

    def test_large_diff_fails_without_silent_truncation(self):
        with patch.object(audit, 'MAX_DIFF_BYTES', 4):
            scope = audit.collect_diff(self.repo, self.base, self.head)
            self.assertIn('a.php', scope['file_errors'])

    def test_split_parts_preserve_every_changed_line(self):
        (self.repo / 'a.php').write_text('<?php\n' + 'echo $_GET["x"];\n' * 400)
        self.git('commit', '-qam', 'large source')
        scope = audit.collect_diff(self.repo, self.base, self.git('rev-parse', 'HEAD'))
        parts = audit.build_parts(scope, limit=1500)
        self.assertGreater(len(parts), 1)
        for side in ('old', 'new'):
            covered = set().union(*(part['lines']['a.php'][side] for part in parts))
            self.assertEqual(covered, scope['lines']['a.php'][side])

    def test_full_run_continues_after_first_error_and_first_finding(self):
        for name in ('b.php', 'c.php'):
            (self.repo / name).write_text('<?php echo 1;\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'three files')
        scope = audit.collect_diff(self.repo, self.base, self.git('rev-parse', 'HEAD'))
        responses = [self.response(findings=[self.finding()]), audit.AuditError('test failure'),
                     self.response(reviewed_files=['c.php']),
                     self.response(reviewed_files=['a.php', 'b.php', 'c.php']),
                     json.dumps({'decisions':[{'index':0,'confirmed':True,'reason':'Confirmed source to sink'}]})]
        runner = unittest.mock.Mock(side_effect=responses)
        report = audit.audit_parts(scope, Path('/cli'), 'test-key', runner=runner, workers=1)
        self.assertEqual(runner.call_count, 5)
        self.assertEqual(len(report['parts']), 4)
        self.assertEqual(report['status'], 'PARTIAL')
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['parts'][2]['status'], 'CLEAN')
        self.assertEqual(report['reviewed_files'], ['a.php', 'c.php'])
        self.assertEqual(report['parts'][-1]['path'], '[cross-file]')

    def test_incomplete_part_still_preserves_and_verifies_its_finding(self):
        runner = unittest.mock.Mock(side_effect=[self.response(complete=False, findings=[self.finding()]),
            json.dumps({'decisions':[{'index':0,'confirmed':True,'reason':'Confirmed source to sink'}]})])
        report = audit.audit_parts(self.scope, Path('/cli'), 'test-key', runner=runner, workers=1)
        self.assertEqual(report['status'], 'PARTIAL')
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['reviewed_files'], [])

    def test_binary_marker_words_in_source_are_not_binary_diff_headers(self):
        (self.repo / 'a.php').write_text('<?php\n// Binary files a and b differ\n// GIT binary patch\n')
        self.git('commit', '-qam', 'ordinary source mentions binary markers')
        result = audit.collect_diff(self.repo, self.base, self.git('rev-parse', 'HEAD'))
        self.assertIn('+// GIT binary patch', result['diff'])

    def test_valid_complete_clean_response(self):
        self.assertEqual(audit.validate_review(self.response(), self.scope)['findings'], [])

    def test_incomplete_malformed_and_invented_evidence_fail(self):
        bad = ['not JSON', self.response(complete=False), self.response(reviewed_files=[]),
               self.response(findings=[self.finding(path='unrelated.php')]),
               self.response(findings=[self.finding(line=1)]),
               self.response(findings=[self.finding(severity='none')]),
               self.response(findings=[self.finding(evidence='')])]
        for response in bad:
            with self.subTest(response=response):
                with self.assertRaises(audit.AuditError):
                    audit.validate_review(response, self.scope)

    def test_deleted_lines_are_reviewable(self):
        result = audit.validate_review(self.response(findings=[self.finding(side='old')]), self.scope)
        self.assertEqual(result['findings'][0]['side'], 'old')

    def test_second_pass_can_confirm_or_reject_but_cannot_omit_candidates(self):
        first = audit.validate_review(self.response(findings=[self.finding()]), self.scope)
        for confirmed in (True, False):
            raw = json.dumps({'decisions': [{'index': 0, 'confirmed': confirmed,
                                            'reason': 'Source and reachable input checked'}]})
            findings = audit.validate_verification(raw, first['findings'])
            self.assertEqual(len(findings), int(confirmed))
        with self.assertRaises(audit.AuditError):
            audit.validate_verification('{"decisions":[]}', first['findings'])

    def test_harness_receives_no_github_or_deploy_credentials(self):
        env = audit.harness_environment(Path('/tmp/isolated'), 'test-key')
        self.assertEqual(env['DEEPSEEK_API_KEY'], 'test-key')
        self.assertNotIn('GITHUB_TOKEN', env)
        self.assertNotIn('FTP_PASSWORD', env)
        self.assertEqual(env['DSH_PERMISSION_MODE'], 'read-only')
        self.assertEqual(env['DSH_TELEMETRY_DISABLED'], '1')

    def test_provider_diagnostics_only_disclose_allowlisted_codes(self):
        for raw, expected in [
            ('dsh: AUTH: provider rejected test-sensitive-value', 'AUTH'),
            ('dsh: DeepSeek Messages failed (HTTP 402): test-sensitive-value', 'HTTP_402'),
            ('dsh: CLIENT_UPGRADE_REQUIRED: upgrade needed', 'CLIENT_UPGRADE_REQUIRED'),
            ('dsh: secret-code: test-sensitive-value', 'UNKNOWN')]:
            self.assertEqual(audit.provider_failure_code(raw), expected)

    def test_private_failure_detail_redacts_key_and_excludes_reasoning(self):
        secret = 'sk-private-test-value'
        stream = '\n'.join([json.dumps({'type': 'thinking', 'text': 'private reasoning'}),
                            json.dumps({'type': 'error', 'message': 'Rejected ' + secret})])
        result = audit.safe_failure_diagnostics(stream, 'dsh: rejected ' + secret, secret, 1)
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn('private reasoning', json.dumps(result))
        self.assertIn('[REDACTED]', result['detail'])

    def test_harness_events_require_completed_turn_and_forbid_tools(self):
        completed = json.dumps({'type': 'status', 'phase': 'turn_end', 'reason': {'kind': 'completed'}})
        final = json.dumps({'type': 'final', 'text': self.response()})
        self.assertEqual(audit.parse_harness_events(completed + '\n' + final, 0, ''), self.response())
        for events in [final, completed, completed + '\n' + final + '\n' + final,
                       json.dumps({'type': 'tool_call', 'tool': 'unexpected'}) + '\n' + completed + '\n' + final]:
            with self.assertRaises(audit.AuditError):
                audit.parse_harness_events(events, 0, '')
        error = json.dumps({'type': 'status', 'phase': 'turn_end', 'reason': {
            'kind': 'error', 'error': {'code': 'AUTH', 'message': 'test-sensitive-value'}}})
        with self.assertRaisesRegex(audit.AuditError, r'\(AUTH\)'):
            audit.parse_harness_events(error, 1, '')



    def test_cli_failure_and_missing_key_never_pass(self):
        with patch.dict(os.environ, {'DEEPSEEK_API_KEY': ''}):
            result = subprocess.run(['python3', str(ROOT / 'scripts/security/diff_audit.py'),
                                     '--repo', str(self.repo), '--base', self.base, '--head', self.head,
                                     '--cli', '/nonexistent', '--out', str(self.repo / 'report')],
                                    capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads((self.repo / 'report/report.json').read_text())['status'], 'PARTIAL')
        with patch.object(audit.subprocess, 'run', side_effect=subprocess.TimeoutExpired('dsh', 480)):
            with self.assertRaisesRegex(audit.AuditError, 'timed out'):
                audit.run_harness('review', Path('/nonexistent'), 'test-key')

    def test_gate_pass_fail_and_error_are_distinct(self):
        cases = [([self.response()], 0, 'PASS'),
                 ([self.response(findings=[self.finding()]), json.dumps({'decisions': [
                     {'index': 0, 'confirmed': True, 'reason': 'GET to raw HTML confirmed'}]})], 0, 'FINDINGS'),
                 (['truncated JSON'], 0, 'PARTIAL')]
        for responses, expected_code, expected_status in cases:
            with self.subTest(status=expected_status):
                args = ['diff_audit.py', '--repo', str(self.repo), '--base', self.base,
                        '--head', self.head, '--cli', '/test-cli', '--out', str(self.repo / 'gate')]
                with patch('sys.argv', args), patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'test-key'}), \
                        patch.object(audit, 'run_harness', side_effect=responses):
                    self.assertEqual(audit.main(), expected_code)
                self.assertEqual(json.loads((self.repo / 'gate/report.json').read_text())['status'], expected_status)

    @unittest.skipUnless(os.environ.get('DSH_TEST_CLI'), 'Set DSH_TEST_CLI for real CLI / fake API test')
    def test_real_harness_transport_has_no_tools_or_extra_telemetry(self):
        requests = []
        reject = []
        answer = self.response()

        class API(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"data":[{"id":"deepseek-flash"}]}')

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append((self.path, body))
                if reject:
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"error":{"type":"authentication_error","message":"test-sensitive-value"}}')
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.end_headers()
                events = [
                    ('message_start', dict(type='message_start', message=dict(
                        id='msg_test', type='message', role='assistant', model='deepseek-flash',
                        content=[], usage=dict(input_tokens=10, output_tokens=0)))),
                    ('content_block_start', dict(type='content_block_start', index=0,
                                                content_block=dict(type='text', text=''))),
                    ('content_block_delta', dict(type='content_block_delta', index=0,
                                                delta=dict(type='text_delta', text=answer))),
                    ('content_block_stop', dict(type='content_block_stop', index=0)),
                    ('message_delta', dict(type='message_delta', delta=dict(stop_reason='end_turn'),
                                          usage=dict(output_tokens=30))),
                    ('message_stop', dict(type='message_stop'))]
                for event, data in events:
                    self.wfile.write(('event: ' + event + '\ndata: ' + json.dumps(data) + '\n\n').encode())

        server = ThreadingHTTPServer(('127.0.0.1', 0), API)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        original = audit.harness_environment

        def environment(home, key):
            return {**original(home, key), 'DEEPSEEK_BASE_URL': f'http://127.0.0.1:{server.server_port}'}

        try:
            with patch.object(audit, 'harness_environment', side_effect=environment):
                raw = audit.run_harness(audit.review_prompt(self.scope), Path(os.environ['DSH_TEST_CLI']), 'test-key')
            self.assertEqual(audit.validate_review(raw, self.scope)['findings'], [])
            self.assertEqual(len(requests), 1)
            body = requests[0][1]
            self.assertFalse(body.get('tools'))
            self.assertNotIn('dsh_session_log', body)
            self.assertNotIn('dsh_plugin_packages', body)
            self.assertIn('FULL_REVIEW', json.dumps(body.get('system')))
            self.assertIn('UNTRUSTED DIFF', json.dumps(body))
            reject.append(True)
            with patch.object(audit, 'harness_environment', side_effect=environment):
                with self.assertRaisesRegex(audit.AuditError, r'\(AUTH\)'):
                    audit.run_harness('review', Path(os.environ['DSH_TEST_CLI']), 'test-key')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
