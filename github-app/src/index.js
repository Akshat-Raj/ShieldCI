require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const { createAppAuth } = require("@octokit/auth-app");
const { Octokit } = require("octokit");
const { Webhooks } = require("@octokit/webhooks");
const { scanRepository } = require("./scanner");

const app = express();
const PORT = process.env.PORT || 3001;

// ── GitHub App Authentication ──

const APP_ID = process.env.GITHUB_APP_ID;
const PRIVATE_KEY = require("fs").readFileSync(
  process.env.GITHUB_PRIVATE_KEY_PATH,
  "utf8"
);
const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

const webhooks = new Webhooks({ secret: WEBHOOK_SECRET });

/** Get an authenticated Octokit client for a specific installation */
async function getInstallationOctokit(installationId) {
  return new Octokit({
    authStrategy: createAppAuth,
    auth: {
      appId: APP_ID,
      privateKey: PRIVATE_KEY,
      installationId,
    },
  });
}

// ── Webhook Handlers ──

webhooks.on("pull_request.opened", handlePullRequest);
webhooks.on("pull_request.synchronize", handlePullRequest);
webhooks.on("push", handlePush);

async function handlePullRequest({ payload }) {
  const installationId = payload.installation.id;
  const repo = payload.repository;
  const pr = payload.pull_request;

  console.log(
    `[PR] ${repo.full_name}#${pr.number} — ${pr.head.sha.substring(0, 7)}`
  );

  const octokit = await getInstallationOctokit(installationId);

  // Create a check run (shows in the PR checks tab)
  const check = await octokit.rest.checks.create({
    owner: repo.owner.login,
    repo: repo.name,
    name: "ShieldCI Security Scan",
    head_sha: pr.head.sha,
    status: "in_progress",
    started_at: new Date().toISOString(),
    output: {
      title: "Security scan in progress...",
      summary: "ShieldCI is scanning your code for vulnerabilities.",
    },
  });

  try {
    // Clone & scan
    const results = await scanRepository({
      cloneUrl: repo.clone_url,
      sha: pr.head.sha,
      branch: pr.head.ref,
      repoFullName: repo.full_name,
      installationId,
    });

    // Update check run with results
    const conclusion =
      results.status === "Clean" ? "success" : "action_required";
    const annotations = results.vulnerabilities
      .filter((v) => v.file && v.line > 0)
      .slice(0, 50) // GitHub allows max 50 annotations per update
      .map((v) => ({
        path: v.file,
        start_line: v.line,
        end_line: v.line,
        annotation_level:
          v.severity === "Critical" || v.severity === "High"
            ? "failure"
            : "warning",
        message: `[${v.severity}] ${v.vuln_type}: ${v.description}`,
        title: v.vuln_type,
      }));

    await octokit.rest.checks.update({
      owner: repo.owner.login,
      repo: repo.name,
      check_run_id: check.data.id,
      status: "completed",
      conclusion,
      completed_at: new Date().toISOString(),
      output: {
        title:
          results.status === "Clean"
            ? "No vulnerabilities found"
            : `${results.vulnerabilities.length} issue(s) found`,
        summary: results.report_markdown.substring(0, 65535),
        annotations,
      },
    });

    // Post a PR comment with findings summary
    if (results.vulnerabilities.length > 0) {
      const commentBody = buildPRComment(results);
      await octokit.rest.issues.createComment({
        owner: repo.owner.login,
        repo: repo.name,
        issue_number: pr.number,
        body: commentBody,
      });
    }
  } catch (err) {
    console.error(`[ERROR] Scan failed for ${repo.full_name}:`, err.message);
    await octokit.rest.checks.update({
      owner: repo.owner.login,
      repo: repo.name,
      check_run_id: check.data.id,
      status: "completed",
      conclusion: "failure",
      completed_at: new Date().toISOString(),
      output: {
        title: "Scan failed",
        summary: `ShieldCI encountered an error: ${err.message}`,
      },
    });
  }
}

async function handlePush({ payload }) {
  // Only scan pushes to default branch
  const repo = payload.repository;
  const defaultBranch = `refs/heads/${repo.default_branch}`;
  if (payload.ref !== defaultBranch) return;

  const installationId = payload.installation.id;
  const sha = payload.after;

  console.log(`[PUSH] ${repo.full_name}@${sha.substring(0, 7)}`);

  const octokit = await getInstallationOctokit(installationId);

  const check = await octokit.rest.checks.create({
    owner: repo.owner.login,
    repo: repo.name,
    name: "ShieldCI Security Scan",
    head_sha: sha,
    status: "in_progress",
    started_at: new Date().toISOString(),
    output: {
      title: "Security scan in progress...",
      summary: "ShieldCI is scanning the latest push.",
    },
  });

  try {
    const results = await scanRepository({
      cloneUrl: repo.clone_url,
      sha,
      branch: repo.default_branch,
      repoFullName: repo.full_name,
      installationId,
    });

    const conclusion =
      results.status === "Clean" ? "success" : "action_required";

    await octokit.rest.checks.update({
      owner: repo.owner.login,
      repo: repo.name,
      check_run_id: check.data.id,
      status: "completed",
      conclusion,
      completed_at: new Date().toISOString(),
      output: {
        title:
          results.status === "Clean"
            ? "No vulnerabilities found"
            : `${results.vulnerabilities.length} issue(s) found`,
        summary: results.report_markdown.substring(0, 65535),
      },
    });
  } catch (err) {
    console.error(`[ERROR] Push scan failed for ${repo.full_name}:`, err.message);
    await octokit.rest.checks.update({
      owner: repo.owner.login,
      repo: repo.name,
      check_run_id: check.data.id,
      status: "completed",
      conclusion: "failure",
      completed_at: new Date().toISOString(),
      output: {
        title: "Scan failed",
        summary: `ShieldCI encountered an error: ${err.message}`,
      },
    });
  }
}

// ── PR Comment Builder ──

function buildPRComment(results) {
  const critical = results.vulnerabilities.filter(
    (v) => v.severity === "Critical"
  );
  const high = results.vulnerabilities.filter((v) => v.severity === "High");
  const medium = results.vulnerabilities.filter(
    (v) => v.severity === "Medium"
  );
  const low = results.vulnerabilities.filter((v) => v.severity === "Low");

  let body = `## 🛡️ ShieldCI Security Report\n\n`;
  body += `| Severity | Count |\n|----------|-------|\n`;
  if (critical.length) body += `| 🔴 Critical | ${critical.length} |\n`;
  if (high.length) body += `| 🟠 High | ${high.length} |\n`;
  if (medium.length) body += `| 🟡 Medium | ${medium.length} |\n`;
  if (low.length) body += `| 🔵 Low | ${low.length} |\n`;
  body += `\n`;

  // Top 10 findings detail
  const top = results.vulnerabilities.slice(0, 10);
  for (const v of top) {
    body += `### ${v.severity}: ${v.vuln_type}\n`;
    if (v.file) body += `📍 \`${v.file}\``;
    if (v.line > 0) body += `:${v.line}`;
    body += `\n`;
    body += `${v.description}\n\n`;
    if (v.fix_snippet) {
      body += `<details><summary>Suggested fix</summary>\n\n\`\`\`\n${v.fix_snippet}\n\`\`\`\n</details>\n\n`;
    }
  }

  if (results.vulnerabilities.length > 10) {
    body += `\n_...and ${results.vulnerabilities.length - 10} more. See full report in Checks tab._\n`;
  }

  body += `\n---\n_Powered by [ShieldCI](https://shieldci.dev) — the first CI tool that actually tries to hack your app._`;
  return body;
}

// ── Express Server with Webhook Verification ──

app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const signature = req.headers["x-hub-signature-256"];
    const event = req.headers["x-github-event"];
    const deliveryId = req.headers["x-github-delivery"];

    try {
      await webhooks.verifyAndReceive({
        id: deliveryId,
        name: event,
        payload: req.body.toString(),
        signature,
      });
      res.status(200).send("OK");
    } catch (err) {
      console.error("Webhook verification failed:", err.message);
      res.status(401).send("Signature mismatch");
    }
  }
);

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "shieldci-github-app" });
});

app.listen(PORT, () => {
  console.log(`ShieldCI GitHub App listening on port ${PORT}`);
});
