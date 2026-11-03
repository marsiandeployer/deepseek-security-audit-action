"""Fetch immutable consumer Git objects without checking out or traversing submodules."""
import base64
import os
from pathlib import Path
import re
import subprocess


def fetch_objects(target, remote, base, head, token):
    if not all(re.fullmatch(r'[0-9a-f]{40}', sha) for sha in (base, head)):
        raise ValueError('Full source commit SHAs are required')
    target = Path(target)
    # The runner may have Git credential/config state. Do not inherit it or persist ours.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('GIT_', 'SSH_')) and key not in ('GH_TOKEN','GITHUB_TOKEN','DEEPSEEK_API_KEY')}
    auth = base64.b64encode(('x-access-token:' + token).encode()).decode()
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               GIT_TERMINAL_PROMPT='0', GIT_CONFIG_COUNT='3',
               GIT_CONFIG_KEY_0='http.extraHeader', GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + auth,
               GIT_CONFIG_KEY_1='core.hooksPath', GIT_CONFIG_VALUE_1=os.devnull,
               GIT_CONFIG_KEY_2='fetch.recurseSubmodules', GIT_CONFIG_VALUE_2='false')
    def run(*args):
        result = subprocess.run(['git', *args], env=env, capture_output=True, timeout=300)
        if result.returncode:
            # Never echo command/environment/stderr: transport diagnostics can contain credentials.
            raise RuntimeError('Cannot fetch exact consumer Git objects (exit ' + str(result.returncode) + ')')
    if target.exists():
        raise ValueError('Source object directory already exists')
    run('init', '--bare', '--quiet', str(target))
    run('-C', str(target), 'remote', 'add', 'origin', remote)
    run('-C', str(target), 'fetch', '--no-tags', '--no-recurse-submodules', 'origin', base, head)


def main():
    repo = os.environ['SOURCE_REPOSITORY']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('Invalid source repository')
    fetch_objects(os.environ['SOURCE_DIRECTORY'], 'https://github.com/' + repo + '.git',
                  os.environ['AUDIT_BASE'], os.environ['AUDIT_HEAD'], os.environ['GH_TOKEN'])


if __name__ == '__main__':
    main()
