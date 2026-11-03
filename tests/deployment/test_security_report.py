import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('security_report', ROOT / 'scripts/security/publish_report.py')
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class ReportTests(unittest.TestCase):
    def test_running_comment_does_not_claim_no_findings(self):
        body = '\n'.join(report.render_comments(dict(status='RUNNING', head='a'*40), ''))
        self.assertIn('RUNNING', body)
        self.assertNotIn('Не выявлены', body)

    def test_report_contains_all_findings_errors_and_unverified_candidates(self):
        finding = dict(path='a.php', side='new', line=3, severity='high', title='XSS @someone <script>',
                       evidence='GET reaches HTML', impact='Script execution', fix='Escape output')
        data = dict(status='PARTIAL', head='a'*40, base='b'*40, total_parts=3, completed_parts=2,
                    findings=[finding], parts=[dict(id=1, path='a.php', status='FINDINGS', findings=[finding]),
                    dict(id=2, path='b.php', status='CLEAN', findings=[]),
                    dict(id=3, path='c.php', status='ERROR', findings=[], candidates=[dict(finding, title='Not yet verified')],
                         error='Provider timeout')])
        text = '\n'.join(report.render_comments(data, 'https://github.com/example/repo/actions/runs/1'))
        for value in ['a.php', 'b.php', 'c.php', 'GET reaches HTML', 'Provider timeout', 'Not yet verified', '2/3']:
            self.assertIn(value, text)
        self.assertNotIn('@someone', text)
        self.assertNotIn('<script>', text)
        self.assertIn('информационный', text.lower())

    def test_long_report_is_split_without_omitting_findings(self):
        findings = [dict(path='a.php', side='new', line=i+1, severity='low', title=f'Finding-{i}',
                         evidence='x'*3000, impact='impact', fix='fix') for i in range(40)]
        comments = report.render_comments(dict(status='FINDINGS', head='a'*40, base='b'*40,
                                                findings=findings, parts=[]), '')
        self.assertGreater(len(comments), 1)
        self.assertTrue(all(len(comment) < 60000 for comment in comments))
        text = '\n'.join(comments)
        for i in range(40):
            self.assertIn(f'Finding-{i}', text)


if __name__ == '__main__':
    unittest.main()
