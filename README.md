# PromptShield Action

GitHub Action for integrating [PromptShield CLI](https://promptshield.js.org/docs/cli/overview/) into CI/CD pipelines — effectively an **ESLint for prompts**.
It scans repositories for prompt injection risks, insecure AI patterns, jailbreak attempts, and unsafe LLM configurations before they reach production. 🛡️

## Features

* **ESLint for Prompts**
  Shift AI security left. Detect prompt vulnerabilities during CI, not after deployment.

* **Two Execution Modes**

  * **Gatekeeper Mode** → Fast, fail-fast security checks for CI enforcement.
  * **Audit Mode** → Full repository analysis with Markdown reports and optional PR comments.

* **PR-Aware Scanning**
  Automatically scans only changed files for pull requests and pushes when using `scan-mode: auto`.

* **Developer-Friendly Reports**
  Generates actionable findings with severity levels and remediation guidance.

---

# Usage

## Gatekeeper Mode ⚡ (Fast Fail)

Best for strict CI enforcement.

Gatekeeper mode uses `--check` internally and exits immediately when findings match the configured severity threshold.

```yaml
name: Security Scan

on: [push, pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  promptshield:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run PromptShield
        uses: promptshield-io/action@v1
        with:
          report: 'false'
```

---

## Audit Mode 📋 (Detailed Reports + PR Comments)

Best for security reviews and pull request workflows.

Audit mode performs a complete scan, generates `.promptshield/workspace-report.md`, and can automatically post findings as a PR comment.

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

---

# Inputs

| Input              | Description                                                                                        | Default |
| ------------------ | -------------------------------------------------------------------------------------------------- | ------- |
| `patterns`         | Glob patterns specifying files to scan.                                                            | `**/*`  |
| `min-severity`     | Minimum severity threshold to report (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).                        | `LOW`   |
| `no-inline-ignore` | Disables inline suppression comments.                                                              | `true`  |
| `report`           | Enables Audit mode when `true`. Uses Gatekeeper mode when `false`.                                 | `true`  |
| `scan-mode`        | Scan strategy: `auto`, `diff`, or `full`. `auto` scans changed files for PRs/pushes when possible. | `auto`  |
| `token`            | `GITHUB_TOKEN` used for posting PR comments in Audit mode.                                         | `null`  |

---

# Recommended Setup

For most repositories:

```yaml
with:
  report: 'true'
  scan-mode: 'auto'
  min-severity: 'MEDIUM'
```

This provides:

* Fast incremental scans
* Actionable reports
* Reduced CI noise
* Reasonable security enforcement

---

# Why PromptShield?

Traditional security scanners understand code.
PromptShield understands **LLM attack surfaces**.

It helps detect:

* Prompt injection vectors
* Jailbreak instructions
* Dangerous system prompt overrides
* Unsafe tool invocation patterns
* Risky AI configurations
* Hidden prompt manipulation attempts

Because `"ignore previous instructions"` should never reach production 😄
