/**
 * ScanOrchestrator — Creates ephemeral K8s namespaces for each scan.
 *
 * Lifecycle:
 *   1. Verify scope (ownership proof + blocklist)
 *   2. Create build namespace → run Kaniko to build target image
 *   3. Create scan namespace → deploy engine + target pods
 *   4. Wait for engine pod to complete
 *   5. Collect results from results-collector service
 *   6. Delete both namespaces (TTL controller also cleans up as safety net)
 */
const k8s = require("@kubernetes/client-node");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const yaml = require("js-yaml");
const { verifyScanScope } = require("./scope-check");

const TEMPLATES_DIR = path.resolve(__dirname, "../../templates");
const DEFAULT_TTL = 1800;    // 30 minutes
const BUILD_TIMEOUT = 600;   // 10 minutes for image build
const POLL_INTERVAL = 5000;  // 5 seconds between status checks

class ScanOrchestrator {
  constructor(logger) {
    this.logger = logger;

    // Load kubeconfig (in-cluster when deployed, local for dev)
    const kc = new k8s.KubeConfig();
    if (process.env.KUBERNETES_SERVICE_HOST) {
      kc.loadFromCluster();
    } else {
      kc.loadFromDefault();
    }
    this.coreApi = kc.makeApiClient(k8s.CoreV1Api);
    this.networkApi = kc.makeApiClient(k8s.NetworkingV1Api);
  }

  async executeScan(opts) {
    const {
      scanId: rawScanId,
      repoFullName,
      cloneUrl,
      branch,
      sha,
      tenantId,
      appPort,
    } = opts;

    // Sanitize scan ID for K8s naming (lowercase alphanum + hyphens, max 63 chars)
    const scanId = this._sanitizeK8sName(rawScanId || uuidv4());
    const scanNs = `scan-${scanId}`;
    const buildNs = `build-${scanId}`;
    const registryHost = process.env.REGISTRY_HOST || "registry.shieldci-control-plane.svc.cluster.local:5000";
    const engineImage = process.env.ENGINE_IMAGE || "shieldci/kali-engine:latest";
    const targetImage = `${registryHost}/shieldci-builds/${scanId}:latest`;

    const vars = {
      SCAN_ID: scanId,
      TENANT_ID: tenantId,
      REPO_FULL_NAME: repoFullName,
      CREATED_AT: new Date().toISOString(),
      TTL_SECONDS: String(DEFAULT_TTL),
      COMMIT_SHA: sha,
      BRANCH: branch,
      CLONE_URL: cloneUrl,
      ENGINE_IMAGE: engineImage,
      TARGET_IMAGE: targetImage,
      APP_PORT: String(appPort),
      REGISTRY_HOST: registryHost,
    };

    this.logger.info({ scanId, repo: repoFullName }, "Starting scan orchestration");

    try {
      // ── Phase 0: Scope verification — verify target ownership ──
      const scopeResult = await verifyScanScope({
        repoFullName,
        cloneUrl,
        tenantId,
        appPort,
        logger: this.logger,
      });
      if (!scopeResult.authorized) {
        this.logger.warn({ scanId, reason: scopeResult.reason }, "Scan blocked by scope verification");
        return {
          status: "Blocked",
          vulnerabilities: [],
          report_markdown: `**Scan blocked**: ${scopeResult.reason}`,
        };
      }
      this.logger.info({ scanId, scopeMethod: scopeResult.method }, "Scope verification passed");

      // ── Phase 1: Build the target app image ──
      await this._createFromTemplate("kaniko-build.yaml", vars);
      this.logger.info({ scanId }, "Build namespace created, waiting for Kaniko...");
      await this._waitForPodCompletion(buildNs, `build-${scanId}`, BUILD_TIMEOUT);
      this.logger.info({ scanId }, "Target image built successfully");

      // ── Phase 2: Create scan namespace with full isolation ──
      await this._createFromTemplate("namespace.yaml", vars);
      await this._createFromTemplate("rbac-quota.yaml", vars);
      await this._createFromTemplate("network-policy.yaml", vars);

      // Create mTLS secret for results submission
      await this._createScanTlsSecret(scanNs, scanId);

      // ── Phase 3: Deploy target app + engine pods ──
      await this._createFromTemplate("target-pod.yaml", vars);
      this.logger.info({ scanId }, "Target app pod deployed, waiting for readiness...");
      await this._waitForPodReady(scanNs, "target-app", 120);

      await this._createFromTemplate("engine-pod.yaml", vars);
      this.logger.info({ scanId }, "Engine pod deployed, scan running...");

      // ── Phase 4: Wait for engine to complete ──
      const engineResult = await this._waitForPodCompletion(scanNs, "shieldci-engine", DEFAULT_TTL);

      // ── Phase 5: Fetch results from collector ──
      const results = await this._fetchResults(scanId);

      this.logger.info({
        scanId,
        status: results?.status,
        vulnCount: results?.vulnerabilities?.length,
      }, "Scan completed");

      return results;

    } finally {
      // ── Phase 6: Cleanup — delete both namespaces ──
      // TTL controller also handles this as a safety net
      await this._deleteNamespace(scanNs);
      await this._deleteNamespace(buildNs);
      this.logger.info({ scanId }, "Scan namespaces deleted");
    }
  }

  // ── Template rendering and K8s object creation ──

  async _createFromTemplate(templateName, vars) {
    const templatePath = path.join(TEMPLATES_DIR, templateName);
    let content = fs.readFileSync(templatePath, "utf8");

    // Replace all {{VARIABLE}} placeholders
    for (const [key, value] of Object.entries(vars)) {
      content = content.replaceAll(`{{${key}}}`, value);
    }

    // Parse multi-document YAML (separated by ---)
    const docs = yaml.loadAll(content);
    for (const doc of docs) {
      if (!doc) continue;
      await this._applyK8sObject(doc);
    }
  }

  async _applyK8sObject(manifest) {
    const kind = manifest.kind;
    const ns = manifest.metadata?.namespace;
    const name = manifest.metadata?.name;

    try {
      switch (kind) {
        case "Namespace":
          await this.coreApi.createNamespace(manifest);
          break;
        case "Pod":
          await this.coreApi.createNamespacedPod(ns, manifest);
          break;
        case "Service":
          await this.coreApi.createNamespacedService(ns, manifest);
          break;
        case "ServiceAccount":
          await this.coreApi.createNamespacedServiceAccount(ns, manifest);
          break;
        case "ResourceQuota":
          await this.coreApi.createNamespacedResourceQuota(ns, manifest);
          break;
        case "LimitRange":
          await this.coreApi.createNamespacedLimitRange(ns, manifest);
          break;
        case "Secret":
          await this.coreApi.createNamespacedSecret(ns, manifest);
          break;
        case "NetworkPolicy":
          await this.networkApi.createNamespacedNetworkPolicy(ns, manifest);
          break;
        default:
          this.logger.warn({ kind, name }, "Unknown K8s kind, skipping");
      }
      this.logger.debug({ kind, name, ns }, "K8s object created");
    } catch (err) {
      // 409 = already exists — safe to ignore on retries
      if (err.statusCode === 409) {
        this.logger.debug({ kind, name }, "Already exists, skipping");
      } else {
        throw err;
      }
    }
  }

  // ── Pod lifecycle watchers ──

  async _waitForPodReady(namespace, podName, timeoutSec) {
    const deadline = Date.now() + timeoutSec * 1000;
    while (Date.now() < deadline) {
      try {
        const res = await this.coreApi.readNamespacedPod(podName, namespace);
        const conditions = res.body.status?.conditions || [];
        const ready = conditions.find((c) => c.type === "Ready" && c.status === "True");
        if (ready) return;
      } catch (err) {
        // Pod might not exist yet
      }
      await this._sleep(POLL_INTERVAL);
    }
    throw new Error(`Pod ${namespace}/${podName} not ready after ${timeoutSec}s`);
  }

  async _waitForPodCompletion(namespace, podName, timeoutSec) {
    const deadline = Date.now() + timeoutSec * 1000;
    while (Date.now() < deadline) {
      try {
        const res = await this.coreApi.readNamespacedPod(podName, namespace);
        const phase = res.body.status?.phase;
        if (phase === "Succeeded") return { exitCode: 0 };
        if (phase === "Failed") {
          const reason = res.body.status?.containerStatuses?.[0]?.state?.terminated?.reason || "Unknown";
          throw new Error(`Pod ${podName} failed: ${reason}`);
        }
      } catch (err) {
        if (err.message?.includes("failed")) throw err;
      }
      await this._sleep(POLL_INTERVAL);
    }
    throw new Error(`Pod ${namespace}/${podName} timed out after ${timeoutSec}s`);
  }

  // ── Results fetching ──

  async _fetchResults(scanId) {
    const collectorUrl = process.env.RESULTS_COLLECTOR_URL ||
      "http://results-collector.shieldci-control-plane.svc.cluster.local:8080";

    const url = `${collectorUrl}/results/${scanId}`;
    const maxRetries = 5;

    for (let i = 0; i < maxRetries; i++) {
      try {
        const res = await fetch(url);
        if (res.ok) return await res.json();
        if (res.status === 404) {
          // Results not yet submitted, wait and retry
          await this._sleep(3000);
          continue;
        }
        throw new Error(`Results collector returned ${res.status}`);
      } catch (err) {
        if (i === maxRetries - 1) throw err;
        await this._sleep(3000);
      }
    }
    throw new Error(`Results not found for scan ${scanId} after ${maxRetries} retries`);
  }

  // ── mTLS secret creation ──

  async _createScanTlsSecret(namespace, scanId) {
    // In production, use cert-manager to issue short-lived certs.
    // For now, create a placeholder that the engine pod mounts.
    const secret = {
      apiVersion: "v1",
      kind: "Secret",
      metadata: {
        name: `scan-${scanId}-tls`,
        namespace,
      },
      type: "kubernetes.io/tls",
      data: {
        // These would be generated by cert-manager in production
        "client.crt": Buffer.from("PLACEHOLDER_CERT").toString("base64"),
        "client.key": Buffer.from("PLACEHOLDER_KEY").toString("base64"),
      },
    };
    await this._applyK8sObject(secret);
  }

  // ── Namespace cleanup ──

  async _deleteNamespace(namespace) {
    try {
      await this.coreApi.deleteNamespace(namespace);
    } catch (err) {
      if (err.statusCode === 404) return; // already gone
      this.logger.warn({ namespace, error: err.message }, "Failed to delete namespace");
    }
  }

  // ── Helpers ──

  _sanitizeK8sName(name) {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
      .substring(0, 53); // leave room for scan-/build- prefix
  }

  _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

module.exports = { ScanOrchestrator };
