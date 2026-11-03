"""Regression: a malformed consumer submodule must not prevent inert diff review."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/security'))
from fetch_source import fetch_objects
from diff_audit import collect_diff


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], stderr=subprocess.DEVNULL).decode().strip()


class FetchTests(unittest.TestCase):
    def test_gitlink_without_gitmodules_is_reviewable_without_checkout_or_stored_token(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory)/'source', Path(directory)/'objects'
            source.mkdir()
            git(source, 'init', '-q')
            git(source, 'config', 'user.email', 'test@example.invalid')
            git(source, 'config', 'user.name', 'Test')
            (source/'app.txt').write_text('before\n')
            git(source, 'add', 'app.txt')
            git(source, 'commit', '-qm', 'base')
            base = git(source, 'rev-parse', 'HEAD')
            git(source, 'update-index', '--add', '--cacheinfo', '160000,'+base+',docs/broken-submodule')
            (source/'app.txt').write_text('after\n')
            git(source, 'add', 'app.txt')
            git(source, 'commit', '-qm', 'head')
            head = git(source, 'rev-parse', 'HEAD')
            fetch_objects(target, str(source), base, head, 'test-token-never-persist')
            scope = collect_diff(target, base, head)
            self.assertEqual(set(scope['files']), {'app.txt','docs/broken-submodule'})
            self.assertIn('+after', scope['file_diffs']['app.txt'])
            self.assertEqual(git(target, 'rev-parse', '--is-bare-repository'), 'true')
            self.assertFalse((target/'app.txt').exists())
            self.assertNotIn('test-token-never-persist', (target/'config').read_text())
            self.assertFalse((target/'hooks/post-checkout').exists())

    def test_invalid_sha_is_rejected_before_creating_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'objects'
            with self.assertRaises(ValueError):
                fetch_objects(target, 'unused', '--upload-pack=bad', 'a'*40, 'token')
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
