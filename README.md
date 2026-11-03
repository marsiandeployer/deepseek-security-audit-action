# DeepSeek security audit Action

A reusable GitHub composite Action that reviews PR diffs with official DeepSeek
Harness and posts an informational report. It has no dependency on the consumer's
language, framework, directory layout, test runner, or deployment pipeline.
Supported runner: GitHub-hosted Ubuntu with Python 3 and Git; the action sets up Node 22.

## Use from another repository

```yaml
name: Security report
on:
  pull_request_target:
    types: [opened, synchronize, reopened, ready_for_review]
permissions:
  contents: read
  pull-requests: write
concurrency:
  group: security-${{ github.event.pull_request.number }}
  cancel-in-progress: false
jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: marsiandeployer/deepseek-security-audit-action@v1.0.0
        with:
          deepseek-api-key: ${{ secrets.DEEPSEEK_API_KEY }}
```

Pin the action to a reviewed full commit SHA in production. No checkout of the
consumer is needed before this step. Add `DEEPSEEK_API_KEY` to each caller's
Actions secrets; the central action repository does not need or store that key.
The caller token needs only `contents: read` and `pull-requests: write`.

This repository is private. Its Actions sharing policy permits other private
repositories owned by the same account to download this generic tool. It contains
no application code or deployment credentials. Private action sharing does not
permit arbitrary external accounts or public callers; those require an explicitly
chosen distribution/access policy.

## Behavior

The controller obtains the current PR's exact base/head SHAs through GitHub API.
It downloads consumer source into a separate directory solely for Git diff.
Consumer scripts, dependencies, workflows, AGENTS and plugins are never executed.
The auditor and its pinned Harness are loaded from this action's immutable version,
not from the PR. Each model process has an empty HOME/DSH_HOME/cwd, no tools,
no telemetry, and no GitHub/deployment credential in its environment.

Diff parts are reviewed independently, with overlap and original source positions.
A finding or failed part never cancels other parts. All well-formed candidates
receive a second model verification pass. An additional pass checks interactions
between source files. Lockfiles remain fully represented in their own parts.
Binary/non-UTF-8/oversized inputs and resource limits are reported explicitly.

One bot-owned progress comment is updated with the full result. Long reports are
split into comments without dropping findings. Human comments are never modified.
A JSON artifact retains coverage, all candidates, verification decisions, errors,
and bounded redacted CLI diagnostics. Reasoning and request bodies are not published.

`PASS` means all parts completed without model-confirmed findings; `FINDINGS`
means completed with findings; `PARTIAL` means some parts did not complete;
`ERROR` means analysis could not start. Severity and confirmation are model output,
not proof of exploitation or a replacement for human review. Successful job exit
means report delivery, not a clean security result. This action creates no required
commit status, approves/merges nothing, and does not block merge.

The model receives source diffs through DeepSeek API. Calls consume the caller's
API quota. Default limits: 500 KB per file, about 30 KB per part with 20-line
overlap, 40 parts, three concurrent workers, 120 KB combined cross-file context.
Unfinished coverage is never silently reported as clean.

## Inputs and outputs

| Input | Default |
|---|---|
| `deepseek-api-key` | Required caller secret |
| `github-token` | `github.token`, caller repository only |
| `pr-number` | Pull request event number; pass explicitly for manual runs |
| `model` | `deepseek-flash` |
| `reasoning-effort` | `high`; `off`, `low`, `high`, `max` accepted |
| `max-output-tokens` | 65536, includes reasoning and final answer |
| `timeout-seconds` | 480 per call |
| `workers` | 3, allowed range 1–4 |

Output `report-status` is `PASS`, `FINDINGS`, `PARTIAL`, or `ERROR`.
`report-path` points to the complete local JSON report. Inputs that affect model
configuration are validated; do not derive them from untrusted PR text.
Manual workflows should run from a trusted default branch and pass a PR number,
keeping the workflow/auditor revision separate from the revision under review.

## Dependencies and tests

The Harness lockfile belongs in Git: `npm ci` uses its exact versions and integrity
hashes. `node_modules`, generated reports and credentials are ignored. The pinned
Harness is 0.2.1-rc.5; compatible dependency overrides fix advisory-affected Zod,
Undici, fflate and MCP client versions. Both fake-API transport success and HTTP 401
are checked against the real installed CLI after dependency changes.

```bash
npm ci --prefix scripts/security/harness --ignore-scripts --no-audit --no-fund
DSH_TEST_CLI="$PWD/scripts/security/harness/node_modules/@deepseek-ai/dsh/lib/bin.js" \
  python3 -m unittest discover -s tests/deployment -v
npm audit --prefix scripts/security/harness --omit=dev --ignore-scripts
```

CI performs the advisory scan even if another check fails and preserves its JSON.
Advisory results are informational. The scan covers this tool's dependencies;
it does not claim to be a language-specific dependency scanner for every consumer.

## References

- [Official composite Action guide](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action): action-owned code via `github.action_path` and reuse across repositories.
- [DeepSeek Harness Action](https://github.com/Lixiaoyiao/DSH-action/tree/v0.13.0): execution/publication separation, structured results, pins, and bot-owned progress comments.
- [Claude Code Action security](https://github.com/anthropics/claude-code-action/blob/main/docs/security.md): trusted workflow code, untrusted PR data, minimal credentials.
- [PR-Agent compression](https://docs.pr-agent.ai/core-abilities/compression_strategy/): context budgeting; this action preserves deletions and reports missing coverage rather than dropping files.
- [Gemini PR review](https://github.com/google-github-actions/run-gemini-cli/tree/main/examples/workflows/pr-review): reusable review job and failure reporting.

## Auditor instruction profile

The versioned [security auditor profile](instructions/security-auditor.md) applies
the operator's requested engineering principles to this task: inspect the complete
scope, collect all findings, require concrete source-to-sink evidence, calibrate
severity and distinguish assumptions from observed facts. Adversarial component
names alone are not findings. Output remains the controller's structured JSON.
The general translation and creative-writing portions of the supplied operating
specification are outside this static review role.

The profile is loaded from the pinned Action, installed as the Harness system
persona, and fingerprinted in the JSON report. Consumer `AGENTS.md` or embedded
policies cannot replace it. Tools, credential access and publication authority
remain controller-owned. [Copyable consumer workflow](examples/security-audit.yml)
contains the entire per-repository integration in one file; pin its action version
before use. All runtime files and the npm lockfile stay here.
