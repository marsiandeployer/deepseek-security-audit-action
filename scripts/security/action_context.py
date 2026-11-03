"""Consumer-independent inputs and immutable PR snapshot for the composite action."""
import os
from pathlib import Path
import re
import uuid
from publish_report import api


def runtime_settings():
    model = os.environ.get('SECURITY_MODEL', 'deepseek-flash')
    effort = os.environ.get('SECURITY_REASONING_EFFORT', 'high')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', model) or effort not in ('off', 'low', 'high', 'max'):
        raise ValueError('Invalid model or reasoning effort')
    def number(name, default, minimum, maximum):
        value = int(os.environ.get(name, str(default)))
        if not minimum <= value <= maximum:
            raise ValueError('Out-of-range setting: ' + name)
        return value
    return dict(model=model, effort=effort,
                max_tokens=number('SECURITY_MAX_OUTPUT_TOKENS', 65536, 4096, 65536),
                timeout=number('SECURITY_TIMEOUT_SECONDS', 480, 30, 600),
                workers=number('SECURITY_WORKERS', 3, 1, 4))


def fetch_pr(repo, number):
    return api(repo, '/pulls/' + number)


def resolve_context(repo, number, temporary_root):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or not re.fullmatch(r'[0-9]+', number):
        raise ValueError('Invalid repository or PR number')
    data = fetch_pr(repo, number)
    base, head = data['base']['sha'], data['head']['sha']
    if not all(re.fullmatch(r'[0-9a-f]{40}', value) for value in (base, head)):
        raise ValueError('GitHub did not return exact commit SHAs')
    identity = uuid.uuid4().hex
    report_dir = Path(temporary_root) / ('security-report-' + identity)
    report_dir.mkdir(parents=True)
    return dict(repository=repo, pr=number, base=base, head=head,
                checkout_path='__security_audit_' + identity, report_dir=str(report_dir))


def main():
    runtime_settings()
    result = resolve_context(os.environ['GITHUB_REPOSITORY'], os.environ['AUDIT_PR'], os.environ['RUNNER_TEMP'])
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for key, value in result.items():
            output.write(f'{key}={value}\n')


if __name__ == '__main__':
    main()
