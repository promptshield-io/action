import * as fs from "node:fs";
import * as path from "node:path";
import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as github from "@actions/github";

const cliVersion = "1.1.1";

interface Threat {
  severity: string;
  message?: string;
  rule?: string;
  name?: string;
  description?: string;
  line?: number;
  column?: number;
  loc?: { start?: { line: number; column: number }; line?: number; column?: number };
}

// Updated to match workspace-report.json structure
type ReportSchema = Record<string, { threats: Threat[] }>;

// --- Utilities ---
const getChangedFiles = async (token: string): Promise<string[]> => {
  const { context } = github;

  if (context.eventName === "pull_request" && context.payload.pull_request) {
    if (token) {
      try {
        const octokit = github.getOctokit(token);
        const { data: files } = await octokit.rest.pulls.listFiles({
          owner: context.repo.owner,
          repo: context.repo.repo,
          pull_number: context.payload.pull_request.number,
          per_page: 100,
        });
        return files.map((f) => f.filename);
      } catch (e) {
        core.warning(
          `API fetch failed, falling back to Git: ${e instanceof Error ? e.message : e}`,
        );
      }
    }

    const base = context.payload.pull_request?.base?.sha;
    const head = context.payload.pull_request?.head?.sha;

    if (base && head) {
      try {
        let output = "";
        await exec.exec("git", ["diff", "--name-only", base, head], {
          listeners: {
            stdout: (data) => {
              output += data.toString();
            },
          },
        });
        return output
          .split("\n")
          .map((f) => f.trim())
          .filter(Boolean);
      } catch (e) {
        core.warning(`Git diff fallback failed: ${e instanceof Error ? e.message : e}`);
      }
    }
  }

  if (context.eventName === "push") {
    const before = context.payload.before;
    const after = context.payload.after;

    if (before === "0000000000000000000000000000000000000000") {
      core.info("Zero SHA detected (new branch). Bypassing diff.");
      return [];
    }

    try {
      let output = "";
      await exec.exec("git", ["diff", "--name-only", before, after], {
        listeners: {
          stdout: (data) => {
            output += data.toString();
          },
        },
      });
      return output
        .split("\n")
        .map((f) => f.trim())
        .filter(Boolean);
    } catch (e) {
      core.warning(`Git push diff failed: ${e instanceof Error ? e.message : e}`);
    }
  }
  return [];
};

const processReport = (reportJsonPath: string) => {
  const counts = { CRITICAL: 0, HIGH: 0, LOW: 0 };
  let threatsFound = false;

  try {
    const reportData: ReportSchema = JSON.parse(fs.readFileSync(reportJsonPath, "utf8"));

    for (const [file, data] of Object.entries(reportData)) {
      for (const threat of data.threats || []) {
        const severity = (threat.severity || "LOW").toUpperCase();
        const message =
          threat.message || threat.description || threat.rule || threat.name || "Threat Detected";
        const line = threat.line || threat.loc?.start?.line || threat.loc?.line || 1;
        const col = threat.column || threat.loc?.start?.column || threat.loc?.column || 1;

        const props = {
          title: `PromptShield: ${severity}`,
          file,
          startLine: line,
          startColumn: col,
        };

        if (severity === "CRITICAL" || severity === "HIGH") {
          counts[severity]++;
          core.error(message, props);
          threatsFound = true;
        } else {
          counts.LOW++;
          core.warning(message, props);
          threatsFound = true;
        }
      }
    }
  } catch (e) {
    core.warning(`Failed to parse workspace-report.json: ${e instanceof Error ? e.message : e}`);
  }

  return { counts, threatsFound };
};

const upsertPRComment = async (token: string, body: string) => {
  const { context } = github;
  if (!context.payload.pull_request) return;

  const octokit = github.getOctokit(token);
  const signature =
    "🛡️ [PromptShield](https://github.com/promptshield-io/promptshield) — Found an edge case? [Report it](https://github.com/promptshield-io/promptshield/issues). Love the shield? ⭐ [Star the repo](https://github.com/promptshield-io/promptshield).";
  const finalBody = `${body}\n\n${signature}`;

  const safeBody =
    finalBody.length > 65000
      ? `${finalBody.substring(0, 64500)}\n\n*...Report truncated due to GitHub size limits...*\n\n${signature}`
      : finalBody;

  try {
    const { data: comments } = await octokit.rest.issues.listComments({
      ...context.repo,
      issue_number: context.payload.pull_request.number,
    });

    const existingComment = comments.find((c) => c.body?.includes(signature));

    if (existingComment) {
      await octokit.rest.issues.updateComment({
        ...context.repo,
        comment_id: existingComment.id,
        body: safeBody,
      });
      core.info("Updated existing PR comment.");
    } else {
      await octokit.rest.issues.createComment({
        ...context.repo,
        issue_number: context.payload.pull_request.number,
        body: safeBody,
      });
      core.info("Created new PR comment.");
    }
  } catch (e) {
    core.warning(`Failed to post/update PR comment: ${e instanceof Error ? e.message : e}`);
  }
};

// --- Main Execution ---
const run = async (): Promise<void> => {
  try {
    const rawPatterns = core.getInput("patterns");
    const parsedPatterns = rawPatterns ? rawPatterns.split(/[\s\n]+/).filter(Boolean) : ["**/*"];

    const minSeverity = core.getInput("min-severity") || "LOW";
    const noInlineIgnore = core.getInput("no-inline-ignore") === "true";
    const report = core.getInput("report") === "true";
    const token = core.getInput("token");
    const baseUrl = core.getInput("base-url");
    const reportFileName = core.getInput("report-file-name") || "workspace-report";
    let scanMode = core.getInput("scan-mode") || "auto";

    if (scanMode === "auto") {
      scanMode = ["pull_request", "push"].includes(github.context.eventName) ? "diff" : "full";
    }

    let filesToScan: string[] = [];

    if (scanMode === "diff") {
      const changedFiles = await getChangedFiles(token);
      if (changedFiles.length > 0) {
        filesToScan = changedFiles;
        core.info(`Diff mode: scanning ${changedFiles.length} changed files.`);
      } else {
        core.info("Diff resolved 0 files. Exiting.");
        return;
      }
    } else {
      filesToScan = parsedPatterns;
    }

    const args = [
      "--yes",
      `@promptshield/cli@${cliVersion}`,
      "scan",
      ...filesToScan,
      `--min-severity=${minSeverity}`,
      "--cache-mode=single",
    ];
    if (noInlineIgnore) args.push("--no-inline-ignore");

    let finalBaseUrl = baseUrl;
    if (!finalBaseUrl && github.context.repo) {
      const { owner, repo } = github.context.repo;
      const sha = github.context.payload.pull_request?.head?.sha || github.context.sha;
      finalBaseUrl = `https://github.com/${owner}/${repo}/blob/${sha}`;
    }

    if (finalBaseUrl) args.push(`--base-url=${finalBaseUrl}`);
    if (reportFileName) args.push(`--report-file-name=${reportFileName}`);

    if (!report) {
      args.push("--check");
      core.info(`Running Gatekeeper Mode (v${cliVersion})...`);
      try {
        await exec.exec("npx", args);
        core.info("Scan completed successfully with no threats found.");
      } catch (error) {
        core.setFailed("Gatekeeper scan failed. Lexical threats detected.");
      }
      return;
    }

    args.push("--report", "--json");
    core.info(`Running Audit Mode (v${cliVersion}) with args: ${args.join(" ")}`);

    let exitCode = 0;
    const execOptions: exec.ExecOptions = {
      ignoreReturnCode: true,
      listeners: {
        stdout: (data: Buffer) => {
          process.stdout.write(data.toString());
        },
        stderr: (data: Buffer) => {
          process.stderr.write(data.toString());
        },
      },
    };

    try {
      exitCode = await exec.exec("npx", args, execOptions);
    } catch (e) {
      core.error(`Exec exception: ${e instanceof Error ? e.message : e}`);
      exitCode = 1;
    }

    const reportPath = path.join(process.cwd(), `.promptshield/${reportFileName}.md`);
    const reportJsonPath = path.join(process.cwd(), `.promptshield/${reportFileName}.json`);
    const jsonExists = fs.existsSync(reportJsonPath);

    if (exitCode === 0 && !jsonExists) {
      core.info("✅ Zero threats detected.");

      if (token && report) {
        const successMsg = `## 🛡️ PromptShield Scan: Success\n\n✅ No lexical threats detected in the scanned files. (v${cliVersion})`;
        await upsertPRComment(token, successMsg);
      }

      await core.summary
        .addHeading("PromptShield Security Report")
        .addRaw("✅ **No threats found.** All files passed the lexical integrity check.")
        .write();

      return;
    }

    if (exitCode !== 0 && !jsonExists) {
      core.setFailed(
        "❌ Forensic failure: CLI crashed or encountered an environment error. Check logs.",
      );
      return;
    }

    if (token && fs.existsSync(reportPath)) {
      const reportContent = fs.readFileSync(reportPath, "utf8");
      await upsertPRComment(token, reportContent);
    }

    const { counts, threatsFound } = processReport(reportJsonPath);

    await core.summary
      .addHeading("PromptShield Security Report")
      .addTable([
        [
          { data: "Severity", header: true },
          { data: "Count", header: true },
        ],
        ["CRITICAL", counts.CRITICAL.toString()],
        ["HIGH", counts.HIGH.toString()],
        ["LOW / MEDIUM", counts.LOW.toString()],
      ])
      .write();

    if (threatsFound) {
      core.setFailed(
        `Lexical Integrity Compromised: ${counts.CRITICAL} Critical, ${counts.HIGH} High, ${counts.LOW} Low/Medium.`,
      );
    } else {
      core.info("No threats found.");
    }
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
};

run();
