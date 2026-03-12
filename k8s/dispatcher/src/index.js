/**
 * ShieldCI Job Dispatcher
 *
 * Receives scan requests (from GitHub App or API), creates ephemeral K8s
 * namespaces with engine + target pods, monitors completion, and cleans up.
 *
 * Architecture:
 *   API/webhook → Redis queue (BullMQ) → Dispatcher worker → K8s API
 */
require("dotenv").config();
const express = require("express");
const { Queue, Worker } = require("bullmq");
const IORedis = require("ioredis");
const pino = require("pino");
const { ScanOrchestrator } = require("./orchestrator");

const logger = pino({ level: process.env.LOG_LEVEL || "info" });
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3002;
const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

// ── Redis connection ──
const redis = new IORedis(REDIS_URL, { maxRetriesPerRequest: null });

// ── BullMQ Queue ──
const scanQueue = new Queue("shieldci-scans", { connection: redis });

// ── API: Accept scan requests ──

app.post("/api/scans", async (req, res) => {
  const { repoFullName, cloneUrl, branch, sha, tenantId, appPort } = req.body;

  if (!repoFullName || !cloneUrl || !sha) {
    return res.status(400).json({ error: "Missing required fields: repoFullName, cloneUrl, sha" });
  }

  const job = await scanQueue.add("scan", {
    repoFullName,
    cloneUrl,
    branch: branch || "main",
    sha,
    tenantId: tenantId || repoFullName.split("/")[0],
    appPort: appPort || 3000,
    requestedAt: new Date().toISOString(),
  }, {
    attempts: 1,           // scans don't retry — they're not idempotent
    removeOnComplete: 100, // keep last 100 completed for debugging
    removeOnFail: 200,
  });

  logger.info({ jobId: job.id, repo: repoFullName, sha: sha.substring(0, 7) }, "Scan job queued");
  res.status(202).json({ jobId: job.id, status: "queued" });
});

app.get("/api/scans/:jobId", async (req, res) => {
  const job = await scanQueue.getJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: "Job not found" });

  const state = await job.getState();
  res.json({
    jobId: job.id,
    status: state,
    data: job.data,
    result: job.returnvalue,
    failedReason: job.failedReason,
  });
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "shieldci-dispatcher" });
});

// ── BullMQ Worker: process scan jobs ──

const orchestrator = new ScanOrchestrator(logger);

const worker = new Worker("shieldci-scans", async (job) => {
  const { repoFullName, cloneUrl, branch, sha, tenantId, appPort } = job.data;
  logger.info({ jobId: job.id, repo: repoFullName }, "Processing scan job");

  try {
    const result = await orchestrator.executeScan({
      scanId: job.id,
      repoFullName,
      cloneUrl,
      branch,
      sha,
      tenantId,
      appPort,
    });
    return result;
  } catch (err) {
    logger.error({ jobId: job.id, error: err.message }, "Scan failed");
    throw err;
  }
}, {
  connection: redis,
  concurrency: parseInt(process.env.MAX_CONCURRENT_SCANS || "5"),
  limiter: {
    max: 10,
    duration: 60000, // max 10 scans per minute
  },
});

worker.on("completed", (job) => {
  logger.info({ jobId: job.id }, "Scan completed");
});

worker.on("failed", (job, err) => {
  logger.error({ jobId: job?.id, error: err.message }, "Scan worker failed");
});

// ── Start ──

app.listen(PORT, () => {
  logger.info({ port: PORT }, "ShieldCI Dispatcher running");
});
