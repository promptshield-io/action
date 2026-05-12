# PromptShield Action

This GitHub Action integrates the [PromptShield CLI](https://promptshield.js.org/docs/cli/overview/) into your CI/CD pipeline, acting as an "ESLint for Prompts". It scans your repository for prompt injection vulnerabilities, dangerous configurations, and security risks in your AI integrations.

## Features

- **ESLint for Prompts**: Treat AI security like code quality. Catch vulnerabilities before they reach production.
- **Two Execution Modes**:
  - **Gatekeeper Mode**: Fast, short-circuiting scan that fails the build immediately if threats are found.
  - **Audit Mode**: Detailed scan that generates a comprehensive Markdown report and can post it as a PR comment.

## Usage

### Gatekeeper Mode (Fast)

Use Gatekeeper mode for rapid feedback. It uses the `--check` flag to fail the workflow as soon as a threat matching your severity threshold is found, without generating reports.

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  promptshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PromptShield
        uses: promptshield-io/action@v1
        with:
          report: 'false' # Enables Gatekeeper mode
```

### Audit Mode (Detailed with PR Comments)

Audit mode performs a full scan, generates a `.promptshield/workspace-report.md`, and if a `token` is provided, posts the results directly as a pull request comment.

```yaml
name: Security Scan
on: [pull_request]

jobs:
  promptshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PromptShield Audit
        uses: promptshield-io/action@v1
        with:
          report: 'true'
          token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `patterns` | Glob patterns to specify which files to scan. | `**/*` |
| `min-severity` | Minimum severity threshold to report (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). | `LOW` |
| `no-inline-ignore` | Ignore inline suppression comments. | `true` |
| `report` | If `true`, runs Audit mode. If `false`, runs Gatekeeper mode. | `true` |
| `scan-mode` | Mode of scanning: `"auto"`, `"diff"`, or `"full"`. `"auto"` scans only changed files for PR and push events. | `auto` |
| `token` | A `GITHUB_TOKEN` to post PR comments in Audit mode. | `null` |
