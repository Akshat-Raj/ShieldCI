/**
 * scanner.js — Orchestrates ShieldCI scans triggered by the GitHub App.
 *
 * Cloud tier: dispatches scan to K8s sandbox via dispatcher API.
 * Local/dev tier: falls back to Docker container on local infrastructure.
 */
const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const http = require("http");
const https = require("https");
const { verifyScope } = require("./scope");

const SCAN_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes max per scan
const POLL_INTERVAL_MS = 5000;           // 5 seconds between status checks

// Dispatcher API URL — set to enable K8s mode
const DISPATCHER_URL = process.env.SHIELDCI_DISPATCHER_URL || "";

/**
 * Clone a repo, run ShieldCI scan, return structured results.
 * @param {Object} opts
 * @param {string} opts.cloneUrl - HTTPS clone URL
 * @param {string} opts.sha - Commit SHA to scan
 * @param {string} opts.branch - Branch name
 * @param {string} opts.repoFullName - owner/repo
 * @param {number} opts.installationId - GitHub App installation ID
 * @returns {Promise<{status: string, vulnerabilities: Array, report_markdown: string}>}
 */
async function scanRepository(opts) {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "shieldci-"));

  try {
    // Step 1: Clone repo to check for config + scope verification
    await exec("git", ["clone", "--depth", "1", "--branch", opts.branch, opts.cloneUrl, workDir]);

    // Step 2: Check for shieldci.yml — required for scanning
    const configPath = path.join(workDir, "shieldci.yml");
    if (!fs.existsSync(configPath)) {
      return {
        status: "Clean",
        vulnerabilities: [],
        report_markdown:
          "No `shieldci.yml` found in repository root. Add one to enable scanning.",
      };
    }

    // Step 2.5: Scope verification — ensure we're authorized to scan the target
    const scopeResult = await verifyScope(configPath, opts.repoFullName);
    if (!scopeResult.authorized) {
      return {
        status: "Clean",
        vulnerabilities: [],
        report_markdown: `**Scan blocked**: ${scopeResult.reason}\n\n` +
          `To authorize scanning, add a DNS TXT record or well-known file. ` +
          `See [ShieldCI docs](https://shieldci.dev/docs/authorization) for details.`,
      };
    }

    // Step 3: Dispatch scan — K8s dispatcher or local Docker
    if (DISPATCHER_URL) {
      return await dispatchToK8s(opts);
    } else {
      return await runLocalDocker(workDir);
    }
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

/**
 * K8s mode: POST scan request to dispatcher, poll for results.
 */
async function dispatchToK8s(opts) {
  // Extract port from config if available
  const appPort = opts.appPort || 3000;

  // Submit scan job to dispatcher
  const submitRes = await httpJson("POST", `${DISPATCHER_URL}/api/scans`, {
    repoFullName: opts.repoFullName,
    cloneUrl: opts.cloneUrl,
    branch: opts.branch || "main",
    sha: opts.sha,
    tenantId: opts.repoFullName.split("/")[0],
    appPort,
  });

  if (!submitRes.jobId) {
    throw new Error(`Dispatcher returned no jobId: ${JSON.stringify(submitRes)}`);
  }

  const jobId = submitRes.jobId;

  // Poll for completion
  const deadline = Date.now() + SCAN_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await sleep(POLL_INTERVAL_MS);

    const status = await httpJson("GET", `${DISPATCHER_URL}/api/scans/${jobId}`);

    if (status.status === "completed") {
      return status.result || {
        status: "Clean",
        vulnerabilities: [],
        report_markdown: "Scan completed but no structured results available.",
      };
    }

    if (status.status === "failed") {
      throw new Error(`Scan job failed: ${status.failedReason || "unknown"}`);
    }
    // "active", "waiting", "delayed" — keep polling
  }

  throw new Error(`Scan timed out after ${SCAN_TIMEOUT_MS / 1000}s (job: ${jobId})`);
}

/**
 * Local Docker mode: run scan in Docker container (dev / self-hosted).
 */
async function runLocalDocker(workDir) {
  const resultsPath = path.join(workDir, "shield_results.json");
  await exec("docker", [
    "run", "--rm",
    "--cpus", "2",
    "--memory", "2g",
    "--network", "shieldci-scan-net",
    "-v", `${workDir}:/app/tests`,
    "-e", `OLLAMA_HOST=${process.env.OLLAMA_HOST || "http://host.docker.internal:11434"}`,
    "shieldci-allinone:latest",
  ], { timeout: SCAN_TIMEOUT_MS });

  if (!fs.existsSync(resultsPath)) {
    throw new Error("Scan completed but no results file was produced");
  }

  return JSON.parse(fs.readFileSync(resultsPath, "utf8"));
}

/** HTTP JSON request helper */
function httpJson(method, url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const client = parsed.protocol === "https:" ? https : http;
    const postData = body ? JSON.stringify(body) : null;

    const reqOpts = {
      method,
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      headers: { "Content-Type": "application/json" },
      timeout: 30000,
    };

    if (postData) {
      reqOpts.headers["Content-Length"] = Buffer.byteLength(postData);
    }

    const req = client.request(reqOpts, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error(`Invalid JSON from dispatcher: ${data.substring(0, 200)}`));
        }
      });
    });

    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")); });

    if (postData) req.write(postData);
    req.end();
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Promise wrapper around child_process.execFile */
function exec(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const timeout = opts.timeout || SCAN_TIMEOUT_MS;
    execFile(cmd, args, { timeout, maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout;
        err.stderr = stderr;
        reject(err);
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
}

module.exports = { scanRepository };
