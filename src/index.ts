import * as core from '@actions/core';
import * as github from '@actions/github';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import * as path from 'path';

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

interface CacheEntry {
  results: {
    threats: Threat[];
    ignoredBySeverity: Record<string, number>;
  };
}

interface CacheSchema {
  entries: Record<string, CacheEntry>;
}

// --- Utilities ---
const getChangedFiles = async (token: string): Promise<string[]> => {
  const context = github.context;

  if (token && context.eventName === 'pull_request') {
    try {
      const octokit = github.getOctokit(token);
      const { data: files } = await octokit.rest.pulls.listFiles({
        owner: context.repo.owner,
        repo: context.repo.repo,
        pull_number: context.payload.pull_request!.number,
        per_page: 100,
      });
      return files.map((f) => f.filename);
    } catch (e) {
      core.warning(`Failed to fetch PR files via API: ${e instanceof Error ? e.message : e}`);
    }
  }

  // Fallback for Push events
  if (context.eventName === 'push') {
    try {
      let output = '';
      await exec.exec('git', ['diff', '--name-only', context.payload.before, context.payload.after], {
        listeners: { stdout: (data) => { output += data.toString(); } },
      });
      return output.split('\n').map((f) => f.trim()).filter(Boolean);
    } catch (e) {
      core.warning(`Git diff fallback failed: ${e instanceof Error ? e.message : e}`);
    }
  }
  return [];
};

const processCache = (cachePath: string) => {
  const counts = { CRITICAL: 0, HIGH: 0, LOW: 0 };
  let threatsFound = false;

  if (!fs.existsSync(cachePath)) {
    core.info('cache.json not found, assuming no threats or scan failed.');
    return { counts, threatsFound };
  }

  try {
    const cacheData: CacheSchema = JSON.parse(fs.readFileSync(cachePath, 'utf8'));

    Object.entries(cacheData.entries || {}).forEach(([file, data]) => {
      data.results?.threats?.forEach((threat) => {
        const severity = (threat.severity || 'LOW').toUpperCase();
        const message = threat.message || threat.description || threat.rule || threat.name || 'Threat Detected';
        const line = threat.line || threat.loc?.start?.line || threat.loc?.line || 1;
        const col = threat.column || threat.loc?.start?.column || threat.loc?.column || 1;

        const props = { title: `PromptShield: ${severity}`, file, startLine: line, startColumn: col };

        if (severity === 'CRITICAL' || severity === 'HIGH') {
          counts[severity]++;
          core.error(message, props);
          threatsFound = true;
        } else {
          counts.LOW++; // Groups LOW and MEDIUM
          core.warning(message, props);
          threatsFound = true;
        }
      });
    });
  } catch (e) {
    core.warning(`Failed to parse cache.json deterministically: ${e instanceof Error ? e.message : e}`);
  }

  return { counts, threatsFound };
};

// --- Main Execution ---
const run = async (): Promise<void> => {
  try {
    const patterns = core.getInput('patterns') || '**/*';
    const minSeverity = core.getInput('min-severity') || 'LOW';
    const noInlineIgnore = core.getInput('no-inline-ignore') === 'true';
    const report = core.getInput('report') === 'true';
    const token = core.getInput('token');
    let scanMode = core.getInput('scan-mode') || 'auto';

    if (scanMode === 'auto') {
      scanMode = ['pull_request', 'push'].includes(github.context.eventName) ? 'diff' : 'full';
    }

    const args = ['--yes', '@promptshield/cli', 'scan', `--min-severity=${minSeverity}`];
    if (noInlineIgnore) args.push('--no-inline-ignore');

    if (scanMode === 'diff') {
      const changedFiles = await getChangedFiles(token);
      if (changedFiles.length > 0) {
        args.push(...changedFiles);
        core.info(`Diff mode: scanning ${changedFiles.length} changed files.`);
      } else {
        core.info('No changed files found. Falling back to full scan.');
        args.push(patterns);
      }
    } else {
      args.push(patterns);
    }

    if (!report) {
      // Gatekeeper Mode
      args.push('--check');
      core.info(`Running Gatekeeper Mode...`);
      try {
        await exec.exec('npx', args); // Safer execution, arguments auto-escaped
        core.info('Scan completed successfully with no threats found.');
      } catch (error) {
        core.setFailed(`Gatekeeper scan failed. Threats detected.`);
      }
      return; // Exit early
    }

    // Audit Mode
    args.push('--report');
    core.info(`Running Audit Mode...`);
    
    try {
      await exec.exec('npx', args, { ignoreReturnCode: true }); // We evaluate success based on cache, not exit code
    } catch (e) {
      core.info('CLI execution finished.');
    }

    const reportPath = path.join(process.cwd(), '.promptshield/workspace-report.md');
    const cachePath = path.join(process.cwd(), '.promptshield/cache.json');

    // Handle PR Comment
    if (token && fs.existsSync(reportPath) && github.context.payload.pull_request) {
      const octokit = github.getOctokit(token);
      await octokit.rest.issues.createComment({
        ...github.context.repo,
        issue_number: github.context.payload.pull_request.number,
        body: fs.readFileSync(reportPath, 'utf8'),
      });
      core.info('Posted report as PR comment.');
    }

    // Parse Cache & Annotate
    const { counts, threatsFound } = processCache(cachePath);

    // Generate Summary
    await core.summary
      .addHeading('PromptShield Security Report')
      .addTable([
        [{ data: 'Severity', header: true }, { data: 'Count', header: true }],
        ['CRITICAL', counts.CRITICAL.toString()],
        ['HIGH', counts.HIGH.toString()],
        ['LOW / MEDIUM', counts.LOW.toString()],
      ])
      .write();

    if (threatsFound) {
      core.setFailed(`Threats found: ${counts.CRITICAL} Critical, ${counts.HIGH} High, ${counts.LOW} Low/Medium.`);
    } else {
      core.info('No threats found.');
    }
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
};

run();
