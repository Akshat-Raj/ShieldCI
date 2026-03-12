/**
 * scope.js — Target authorization verification for cloud-tier scans.
 *
 * Before scanning, verify the target URL in shieldci.yml is actually
 * owned by the user. For localhost targets, always allow. For external
 * targets, require DNS TXT or well-known file proof.
 */
const fs = require("fs");
const { URL } = require("url");
const { execFile } = require("child_process");
const crypto = require("crypto");
const https = require("https");
const http = require("http");
const dns = require("dns");
const net = require("net");

const VERIFY_SECRET = process.env.SHIELDCI_VERIFY_SECRET || "change-me-in-production";

// ── IP / hostname blocklist (mirrors scope_verify.py) ──
// Prevents SSRF via cloud metadata endpoints, private networks, K8s internals
const BLOCKED_CIDRS = [
  // AWS / cloud metadata
  { prefix: "169.254.169.254", mask: 32 },
  // RFC1918 private ranges
  { prefix: "10.0.0.0", mask: 8 },
  { prefix: "172.16.0.0", mask: 12 },
  { prefix: "192.168.0.0", mask: 16 },
  // Link-local
  { prefix: "169.254.0.0", mask: 16 },
  // Loopback (except explicitly allowed)
  { prefix: "127.0.0.0", mask: 8 },
  // IPv6 link-local
  { prefix: "fe80::", mask: 10 },
  // IPv6 loopback
  { prefix: "::1", mask: 128 },
];

const BLOCKED_HOSTNAMES = [
  "metadata.google.internal",
  "metadata.internal",
  "kubernetes.default",
  "kubernetes.default.svc",
  "kubernetes.default.svc.cluster.local",
  "169.254.169.254",
];

/** Check if an IPv4 address falls within a CIDR block */
function ipInCidr(ip, prefix, maskBits) {
  if (!net.isIPv4(ip) || !net.isIPv4(prefix)) return false;
  const ipNum = ip.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
  const prefNum = prefix.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipNum & mask) === (prefNum & mask);
}

/** Resolve hostname and check against blocklist. Returns null if safe, reason string if blocked. */
async function checkBlocklist(hostname) {
  // Direct hostname check
  const lowerHost = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.includes(lowerHost)) {
    return `Hostname '${hostname}' is on the blocklist (infrastructure protection)`;
  }
  if (lowerHost.endsWith(".svc.cluster.local") || lowerHost.endsWith(".pod.cluster.local")) {
    return `Hostname '${hostname}' targets K8s internal services`;
  }

  // Resolve and check IPs
  try {
    const addresses = await new Promise((resolve, reject) => {
      dns.resolve4(hostname, (err, addrs) => {
        if (err) reject(err);
        else resolve(addrs);
      });
    });

    for (const addr of addresses) {
      for (const cidr of BLOCKED_CIDRS) {
        if (ipInCidr(addr, cidr.prefix, cidr.mask)) {
          return `Target '${hostname}' resolves to blocked IP ${addr} (${cidr.prefix}/${cidr.mask})`;
        }
      }
    }
  } catch {
    // DNS resolution failure is not a blocklist issue — let it pass to the actual scan
  }

  return null;
}

/**
 * Generate a deterministic verification token for an org + domain pair.
 */
function generateToken(orgId, domain) {
  return crypto
    .createHmac("sha256", VERIFY_SECRET)
    .update(`${orgId}:${domain}`)
    .digest("hex")
    .substring(0, 32);
}

/**
 * Parse shieldci.yml to extract target URL and scope config, then verify authorization.
 * @param {string} configPath - Path to shieldci.yml
 * @param {string} repoFullName - owner/repo (used as org ID for token generation)
 * @returns {Promise<{authorized: boolean, reason: string}>}
 */
async function verifyScope(configPath, repoFullName) {
  // Simple YAML parsing for the fields we need
  const content = fs.readFileSync(configPath, "utf8");

  // Extract port from build section
  const portMatch = content.match(/port:\s*(\d+)/);
  const port = portMatch ? parseInt(portMatch[1]) : 3000;

  // Extract scope config
  const scopeSection = content.match(/scope:\s*\n([\s\S]*?)(?=\n\S|\Z)/);
  const authProof = content.match(/authorization_proof:\s*["']?(\w+)["']?/);
  const method = authProof ? authProof[1] : "none";

  // Determine target URL — check for explicit target_url in scope config
  const targetUrlMatch = content.match(/target_url:\s*["']?([^\s"']+)["']?/);
  const targetUrl = targetUrlMatch ? targetUrlMatch[1] : `http://127.0.0.1:${port}`;
  const parsed = new URL(targetUrl);
  const host = parsed.hostname;

  // Localhost targets are always allowed (self-hosted / local scanning)
  const LOCAL_HOSTS = ["localhost", "127.0.0.1", "host.docker.internal"];
  if (LOCAL_HOSTS.includes(host)) {
    return { authorized: true, reason: "Local target — always allowed" };
  }

  // Blocklist check for external targets — prevents SSRF via internal endpoints
  const blockReason = await checkBlocklist(host);
  if (blockReason) {
    return { authorized: false, reason: blockReason };
  }

  // External targets require proof
  if (method === "none") {
    return {
      authorized: false,
      reason: `External target '${host}' requires authorization. Set scope.authorization_proof to 'dns' or 'file' in shieldci.yml.`,
    };
  }

  const token = generateToken(repoFullName, host);

  if (method === "dns") {
    return verifyDns(host, token);
  } else if (method === "file") {
    return verifyWellKnown(targetUrl, token);
  }

  return { authorized: false, reason: `Unknown verification method: ${method}` };
}

/**
 * Verify DNS TXT record: shieldci-verify=<token>
 */
function verifyDns(domain, expectedToken) {
  return new Promise((resolve) => {
    execFile("dig", ["+short", "TXT", domain], { timeout: 10000 }, (err, stdout) => {
      if (err) {
        resolve({ authorized: false, reason: `DNS lookup failed for ${domain}: ${err.message}` });
        return;
      }
      const expected = `shieldci-verify=${expectedToken}`;
      if (stdout.includes(expected)) {
        resolve({ authorized: true, reason: `DNS TXT record verified for ${domain}` });
      } else {
        resolve({
          authorized: false,
          reason: `DNS TXT record 'shieldci-verify=${expectedToken}' not found on ${domain}`,
        });
      }
    });
  });
}

/**
 * Verify well-known file at /.well-known/shieldci-verify
 */
function verifyWellKnown(targetUrl, expectedToken) {
  return new Promise((resolve) => {
    const parsed = new URL(targetUrl);
    const verifyUrl = `${parsed.protocol}//${parsed.host}/.well-known/shieldci-verify`;
    const client = parsed.protocol === "https:" ? https : http;

    const req = client.get(verifyUrl, { timeout: 10000 }, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        if (body.trim() === expectedToken) {
          resolve({ authorized: true, reason: `Verification file confirmed at ${verifyUrl}` });
        } else {
          resolve({
            authorized: false,
            reason: `File at ${verifyUrl} exists but token doesn't match`,
          });
        }
      });
    });

    req.on("error", (err) => {
      resolve({ authorized: false, reason: `Could not reach ${verifyUrl}: ${err.message}` });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({ authorized: false, reason: `Timeout reaching ${verifyUrl}` });
    });
  });
}

module.exports = { verifyScope, generateToken };
