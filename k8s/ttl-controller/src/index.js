/**
 * ShieldCI Namespace TTL Controller
 *
 * Runs as a CronJob or long-running controller in the control plane.
 * Every 30 seconds, scans for namespaces with the shieldci.io/ttl annotation
 * and deletes any that have exceeded their TTL.
 *
 * This is the safety net — the dispatcher deletes namespaces on scan completion,
 * but this catches abandoned/crashed scans.
 */
const k8s = require("@kubernetes/client-node");
const pino = require("pino");

const logger = pino({ level: process.env.LOG_LEVEL || "info" });
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL_MS || "30000");

// Load kubeconfig
const kc = new k8s.KubeConfig();
if (process.env.KUBERNETES_SERVICE_HOST) {
  kc.loadFromCluster();
} else {
  kc.loadFromDefault();
}
const coreApi = kc.makeApiClient(k8s.CoreV1Api);

async function reconcile() {
  try {
    // List all namespaces managed by ShieldCI
    const res = await coreApi.listNamespace(
      undefined, undefined, undefined, undefined,
      "app.kubernetes.io/managed-by=shieldci"
    );

    const now = Date.now();
    let deleted = 0;

    for (const ns of res.body.items) {
      const name = ns.metadata.name;
      const annotations = ns.metadata.annotations || {};
      const createdAt = annotations["shieldci.io/created-at"];
      const ttlStr = annotations["shieldci.io/ttl"];

      if (!createdAt || !ttlStr) continue;

      const created = new Date(createdAt).getTime();
      const ttlMs = parseInt(ttlStr) * 1000;

      if (isNaN(created) || isNaN(ttlMs)) {
        logger.warn({ namespace: name }, "Invalid TTL annotations, skipping");
        continue;
      }

      const age = now - created;
      const remaining = ttlMs - age;

      if (remaining <= 0) {
        logger.info({
          namespace: name,
          ageSec: Math.round(age / 1000),
          ttlSec: parseInt(ttlStr),
          scanId: ns.metadata.labels?.["shieldci.io/scan-id"],
        }, "Namespace TTL expired, deleting");

        try {
          await coreApi.deleteNamespace(name);
          deleted++;
        } catch (err) {
          if (err.statusCode === 404 || err.statusCode === 409) {
            // Already deleting or gone
            continue;
          }
          logger.error({ namespace: name, error: err.message }, "Failed to delete namespace");
        }
      } else {
        logger.debug({
          namespace: name,
          remainingSec: Math.round(remaining / 1000),
        }, "Namespace still within TTL");
      }
    }

    if (deleted > 0) {
      logger.info({ deleted }, "TTL sweep completed");
    }
  } catch (err) {
    logger.error({ error: err.message }, "Reconciliation loop failed");
  }
}

// ── Main loop ──

logger.info({ pollInterval: POLL_INTERVAL }, "ShieldCI TTL Controller started");

async function run() {
  while (true) {
    await reconcile();
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
  }
}

run().catch((err) => {
  logger.fatal({ error: err.message }, "TTL Controller crashed");
  process.exit(1);
});
