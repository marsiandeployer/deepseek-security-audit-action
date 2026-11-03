#!/usr/bin/env python3
"""Publish an informational audit report; never creates required merge statuses."""
import argparse
import html
import json
import os
from pathlib import Path
import re
import urllib.request

MARKER = '<!-- deepseek-security-diff-report -->'


def text(value):
    value = html.escape(str(value), quote=False).replace('@', '＠')
    return re.sub(r'([\\`*{}\[\]()#|!>])', r'\\\1', value)


def render_comments(report, run_url):
    if report.get('status') == 'RUNNING':
        return [MARKER + '\n<!-- part:1 -->\n## Информационный аудит diff: RUNNING\n\n'
                f'Коммит: `{text(report.get("head", "unknown"))}`.\n\n'
                'Выполняется полный прогон; итоговый отчёт появится в этом комментарии. '
                'Аудит не блокирует merge.\n\n' + (f'[Actions]({run_url})' if run_url else '')]
    blocks = [f'## Информационный аудит безопасности diff: {text(report.get("status", "NOT RUN"))}\n\n'
              f'Коммит: `{text(report.get("head", "unknown"))}`. '
              f'Завершено частей: {report.get("completed_parts", 0)}/{report.get("total_parts", 0)}.\n\n'
              'Отчёт не блокирует merge. Это статический анализ изменений, а не полный аудит production. '
              'PARTIAL/ERROR означает неполную проверку и не подтверждает отсутствие уязвимостей.\n\n'
              + (f'[Actions: полный JSON и диагностика]({run_url})\n' if run_url else '')]
    if report.get('error'):
        blocks.append('Ошибка запуска: ' + text(report['error']) + '\n')
    if report.get('transport_check') not in (None, 'success', 'local'):
        blocks.append('Самопроверка транспорта: ' + text(report['transport_check']) + '\n')
    parts = report.get('parts', [])
    if parts:
        blocks.append('### Покрытие\n\n| Часть | Файл | Результат |\n|---|---|---|\n' + ''.join(
            f'| {text(p["id"])} | {text(p["path"])} | {text(p["status"])} |\n' for p in parts))
    findings = report.get('findings', [])
    blocks.append('### Находки после повторной проверки моделью\n\n' + ('Не выявлены в завершённых частях.\n' if not findings else ''))
    for index, finding in enumerate(findings, 1):
        blocks.append(f'**{index}. {text(finding["title"])} — {text(finding["severity"])}**\n\n'
                      f'{text(finding["path"])}: {text(finding["side"])}:{finding["line"]}\n\n'
                      f'Доказательство: {text(finding["evidence"])}\n\n'
                      f'Последствия: {text(finding["impact"])}\n\nИсправление: {text(finding["fix"])}\n')
    for part in parts:
        if part.get('error'):
            blocks.append(f'### Ошибка части {text(part["id"])}: {text(part["path"])}\n\n{text(part["error"])}\n')
            for candidate in part.get('candidates', []):
                if candidate not in part.get('findings', []):
                    blocks.append(f'**Не подтверждено: {text(candidate["title"])}**\n\n'
                                  f'{text(candidate["path"])}:{candidate["line"]}. '
                                  f'{text(candidate["evidence"])}\n')
        for decision in part.get('verification', {}).get('decisions', []):
            if not decision['confirmed']:
                candidate = part['candidates'][decision['index']]
                blocks.append(f'Отклонённый кандидат: {text(candidate["path"])}:{candidate["line"]}, '
                              f'{text(candidate["title"])}. Причина: {text(decision["reason"])}\n')
    comments, current = [], ''
    for block in (line for block in blocks for line in (block + '\n').splitlines(keepends=True)):
        if len(current) + len(block) > 50_000 and current:
            comments.append(current)
            current = ''
        current += block
    if current:
        comments.append(current)
    return [MARKER + f'\n<!-- part:{i} -->\n' + body for i, body in enumerate(comments, 1)]


def api(repo, suffix, method='GET', payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request('https://api.github.com/repos/' + repo + suffix,
        data=body, method=method, headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--pr', required=True)
    parser.add_argument('--pending', action='store_true')
    args = parser.parse_args()
    repo = os.environ['GITHUB_REPOSITORY']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or not args.pr.isdecimal():
        raise ValueError('Invalid repository or PR number')
    report = dict(status='RUNNING', head=os.environ.get('AUDIT_HEAD', 'unknown')) if args.pending else json.loads(args.report.read_text()) if args.report.exists() else dict(
        status='ERROR', head=os.environ.get('AUDIT_HEAD', 'unknown'),
        error='Audit did not finish; inspect workflow logs. No clean result is claimed.')
    if not args.pending and not args.report.exists():
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    run_url = f'https://github.com/{repo}/actions/runs/{os.environ["GITHUB_RUN_ID"]}'
    comments = render_comments(report, run_url)
    current_head = api(repo, '/pulls/' + args.pr)['head']['sha']
    existing = []
    if current_head == report.get('head'):
        for page in range(1, 21):
            rows = api(repo, f'/issues/{args.pr}/comments?per_page=100&page={page}')
            existing.extend(row for row in rows if row['user']['login'] == 'github-actions[bot]'
                            and row.get('body', '').startswith(MARKER))
            if len(rows) < 100:
                break
    for index, body in enumerate(comments, 1):
        match = next((row for row in existing if f'<!-- part:{index} -->' in row['body']), None)
        if match:
            api(repo, '/issues/comments/' + str(match['id']), 'PATCH', {'body': body})
        else:
            api(repo, '/issues/' + args.pr + '/comments', 'POST', {'body': body})
    for row in existing:
        match = re.search(r'<!-- part:(\d+) -->', row['body'])
        if match and int(match[1]) > len(comments):
            api(repo, '/issues/comments/' + str(row['id']), 'PATCH',
                {'body': MARKER + '\nПредыдущая часть отчёта заменена актуальным отчётом выше.'})
    print('Informational audit report published to PR #' + args.pr)


if __name__ == '__main__':
    main()
