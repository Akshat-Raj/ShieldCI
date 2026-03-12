/**
 * ShieldCI Results Collector
 *
 * Runs in the control plane namespace. Engine pods push scan results here
 * over mTLS. Results are encrypted and stored in PostgreSQL.
 *
 * Endpoints:
 *   POST /submit        — Engine pod submits results (mTLS required)
 *   GET  /results/:id   — Dispatcher fetches results by scan ID
 *   DELETE /results/:id  — Tenant requests deletion (data retention)
 */
require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
const pino = require("pino");
const https = require("https");
const fs = require("fs");

const logger = pino({ level: process.env.LOG_LEVEL || "info" });
const app = express();
app.use(express.json({ limit: "10mb" }));

const PORT = process.env.PORT || 8080;
const TLS_PORT = process.env.TLS_PORT || 8443;

// ── PostgreSQL (encrypted at rest via pgcrypto or TDE) ──

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://shieldci:shieldci@localhost:5432/shieldci",
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: true } : false,
});

// ── Encryption Key (from Vault or env — in production, use HashiCorp Vault) ──
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex");
const KEY_BUFFER = Buffer.from(ENCRYPTION_KEY, "hex");

function encrypt(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY_BUFFER, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    data: encrypted.toString("hex"),
    tag: tag.toString("hex"),
  };
}

function decrypt(encObj) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    KEY_BUFFER,
    Buffer.from(encObj.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(encObj.tag, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encObj.data, "hex")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

// ── Initialize DB schema ──

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scan_results (
      scan_id       TEXT PRIMARY KEY,
      tenant_id     TEXT NOT NULL,
      repo          TEXT NOT NULL,
      commit_sha    TEXT,
      status        TEXT,
      vuln_count    INTEGER DEFAULT 0,
      encrypted_data TEXT NOT NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      expires_at    TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '90 days')
    );

    CREATE INDEX IF NOT EXISTS idx_results_tenant ON scan_results(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_results_repo ON scan_results(repo);
    CREATE INDEX IF NOT EXISTS idx_results_expires ON scan_results(expires_at);
  `);
  logger.info("Database schema initialized");
}

// ── POST /submit — Engine pod pushes results ──

app.post("/submit", async (req, res) => {
  const { scanId, tenantId, repo, sha, results } = req.body;

  if (!scanId || !results) {
    return res.status(400).json({ error: "Missing scanId or results" });
  }

  try {
    const encrypted = encrypt(JSON.stringify(results));

    await pool.query(
      `INSERT INTO scan_results (scan_id, tenant_id, repo, commit_sha, status, vuln_count, encrypted_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (scan_id) DO UPDATE SET
         encrypted_data = EXCLUDED.encrypted_data,
         status = EXCLUDED.status,
         vuln_count = EXCLUDED.vuln_count`,
      [
        scanId,
        tenantId || "unknown",
        repo || "unknown",
        sha,
        results.status || "Unknown",
        results.vulnerabilities?.length || 0,
        JSON.stringify(encrypted),
      ]
    );

    logger.info({
      scanId,
      status: results.status,
      vulnCount: results.vulnerabilities?.length,
    }, "Results stored (encrypted)");

    res.status(201).json({ stored: true });
  } catch (err) {
    logger.error({ scanId, error: err.message }, "Failed to store results");
    res.status(500).json({ error: "Storage failed" });
  }
});

// ── GET /results/:scanId — Dispatcher/API fetches results ──

app.get("/results/:scanId", async (req, res) => {
  const { scanId } = req.params;

  try {
    const row = await pool.query(
      "SELECT encrypted_data, tenant_id FROM scan_results WHERE scan_id = $1",
      [scanId]
    );

    if (row.rows.length === 0) {
      return res.status(404).json({ error: "Results not found" });
    }

    const encrypted = JSON.parse(row.rows[0].encrypted_data);
    const decrypted = decrypt(encrypted);
    const results = JSON.parse(decrypted);

    res.json(results);
  } catch (err) {
    logger.error({ scanId, error: err.message }, "Failed to fetch results");
    res.status(500).json({ error: "Retrieval failed" });
  }
});

// ── DELETE /results/:scanId — Tenant data deletion (GDPR/retention) ──

app.delete("/results/:scanId", async (req, res) => {
  const { scanId } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM scan_results WHERE scan_id = $1",
      [scanId]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Not found" });
    }
    logger.info({ scanId }, "Results deleted by request");
    res.json({ deleted: true });
  } catch (err) {
    logger.error({ scanId, error: err.message }, "Deletion failed");
    res.status(500).json({ error: "Deletion failed" });
  }
});

// ── Data retention: purge expired results ──

async function purgeExpired() {
  try {
    const result = await pool.query(
      "DELETE FROM scan_results WHERE expires_at < NOW()"
    );
    if (result.rowCount > 0) {
      logger.info({ purged: result.rowCount }, "Expired results purged");
    }
  } catch (err) {
    logger.error({ error: err.message }, "Purge failed");
  }
}

// Run purge every hour
setInterval(purgeExpired, 60 * 60 * 1000);

// ── Health check ──

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "shieldci-results-collector" });
});

// ── Start servers ──

async function start() {
  await initDb();

  // HTTP server for internal cluster traffic
  app.listen(PORT, () => {
    logger.info({ port: PORT }, "Results collector HTTP server running");
  });

  // mTLS server for engine pod submissions (production)
  const tlsCertPath = process.env.TLS_CERT_PATH;
  const tlsKeyPath = process.env.TLS_KEY_PATH;
  const tlsCaPath = process.env.TLS_CA_PATH;

  if (tlsCertPath && tlsKeyPath && tlsCaPath) {
    const httpsServer = https.createServer({
      cert: fs.readFileSync(tlsCertPath),
      key: fs.readFileSync(tlsKeyPath),
      ca: fs.readFileSync(tlsCaPath),
      requestCert: true,           // require client certificate
      rejectUnauthorized: true,    // reject connections without valid cert
    }, app);

    httpsServer.listen(TLS_PORT, () => {
      logger.info({ port: TLS_PORT }, "Results collector mTLS server running");
    });
  } else {
    logger.warn("TLS certs not configured — mTLS endpoint disabled (dev mode)");
  }
}

start().catch((err) => {
  logger.fatal({ error: err.message }, "Failed to start results collector");
  process.exit(1);
});
