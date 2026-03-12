"""
scope_verify.py — Authorization proof verification for ShieldCI cloud-tier scans.

Before scanning a target URL in cloud mode, verify the user actually owns/controls it.
Supports two proof methods:
  1. DNS TXT record: User adds a TXT record like "shieldci-verify=<token>" to their domain
  2. File upload: User places a file at /.well-known/shieldci-verify containing the token

Usage:
  from scope_verify import verify_target_ownership, generate_verification_token

  token = generate_verification_token(org_id, target_domain)
  # ... user sets up DNS or file ...
  result = verify_target_ownership(target_url, token, method="dns")
"""

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse

# Secret used to generate deterministic verification tokens per org
_HMAC_SECRET = os.environ.get("SHIELDCI_VERIFY_SECRET", "change-me-in-production")

# ── Blocked IP ranges — NEVER scan these regardless of scope config ──
# Prevents abuse against cloud metadata, private networks, K8s internals
BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),   # AWS/GCP/Azure metadata endpoint
    ipaddress.ip_network("169.254.0.0/16"),        # Link-local
    ipaddress.ip_network("10.0.0.0/8"),            # Private (RFC 1918)
    ipaddress.ip_network("172.16.0.0/12"),         # Private (RFC 1918)
    ipaddress.ip_network("192.168.0.0/16"),        # Private (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),         # Carrier-grade NAT
    ipaddress.ip_network("fc00::/7"),              # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),             # IPv6 link-local
    ipaddress.ip_network("::1/128"),               # IPv6 loopback
]

BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.internal",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    "kubernetes",
}


def check_blocklist(target_url: str) -> dict:
    """
    Check if a target URL resolves to a blocked IP range.
    Returns {"blocked": bool, "reason": str}
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if not hostname:
        return {"blocked": True, "reason": "Invalid target URL — no hostname"}

    # Check hostname blocklist
    if hostname.lower() in BLOCKED_HOSTNAMES:
        return {"blocked": True, "reason": f"Hostname '{hostname}' is on the blocklist (infrastructure target)"}

    # Resolve hostname to IP and check against blocked networks
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return {
                    "blocked": True,
                    "reason": f"Target resolves to {ip_str} which is in blocked range {network} "
                              f"(cloud metadata / private network / K8s internal)"
                }
    except socket.gaierror:
        # Can't resolve — could be a K8s service name, defer to network policy
        pass

    return {"blocked": False, "reason": "Target not in any blocked range"}


def generate_verification_token(org_id: str, target_domain: str) -> str:
    """Generate a deterministic verification token for an org + domain pair."""
    msg = f"{org_id}:{target_domain}".encode()
    return hmac.new(_HMAC_SECRET.encode(), msg, hashlib.sha256).hexdigest()[:32]


def verify_target_ownership(target_url: str, token: str, method: str = "dns") -> dict:
    """
    Verify that the scan target is authorized.
    Checks blocklist first, then ownership proof.

    Returns: {"verified": bool, "method": str, "detail": str}
    """
    parsed = urlparse(target_url)
    domain = parsed.hostname

    if not domain:
        return {"verified": False, "method": method, "detail": "Invalid target URL"}

    # Always allow localhost/internal targets (self-hosted mode)
    if domain in ("localhost", "127.0.0.1", "host.docker.internal"):
        return {"verified": True, "method": "localhost", "detail": "Local targets are always allowed"}

    # ── Blocklist check — runs BEFORE ownership verification ──
    block_result = check_blocklist(target_url)
    if block_result["blocked"]:
        return {"verified": False, "method": "blocklist", "detail": block_result["reason"]}

    if method == "dns":
        return _verify_dns(domain, token)
    elif method == "file":
        return _verify_wellknown_file(target_url, token)
    else:
        return {"verified": False, "method": method, "detail": f"Unknown method: {method}"}


def _verify_dns(domain: str, expected_token: str) -> dict:
    """Check for a TXT record: shieldci-verify=<token>"""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=10
        )
        txt_records = result.stdout.strip()
        expected = f"shieldci-verify={expected_token}"
        if expected in txt_records:
            return {"verified": True, "method": "dns", "detail": f"TXT record found on {domain}"}
        return {
            "verified": False,
            "method": "dns",
            "detail": f"Expected TXT record '{expected}' not found. Got: {txt_records[:200]}"
        }
    except Exception as e:
        return {"verified": False, "method": "dns", "detail": f"DNS lookup failed: {e}"}


def _verify_wellknown_file(target_url: str, expected_token: str) -> dict:
    """Check for a file at /.well-known/shieldci-verify containing the token."""
    parsed = urlparse(target_url)
    verify_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/shieldci-verify"

    try:
        req = urllib.request.Request(verify_url, method="GET")
        req.add_header("User-Agent", "ShieldCI-Verifier/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8").strip()
            if body == expected_token:
                return {"verified": True, "method": "file", "detail": f"Verification file found at {verify_url}"}
            return {
                "verified": False,
                "method": "file",
                "detail": f"File exists but token mismatch. Expected: {expected_token[:8]}..., Got: {body[:8]}..."
            }
    except urllib.error.HTTPError as e:
        return {"verified": False, "method": "file", "detail": f"HTTP {e.code} at {verify_url}"}
    except Exception as e:
        return {"verified": False, "method": "file", "detail": f"Could not reach {verify_url}: {e}"}


def validate_scope(target_url: str, allowed_targets: list) -> dict:
    """
    Ensure the target URL is within the allowed scope from shieldci.yml.
    Prevents scanning arbitrary hosts.
    """
    parsed = urlparse(target_url)
    target_host = parsed.hostname

    if not target_host:
        return {"in_scope": False, "detail": "Invalid target URL"}

    # Localhost always in scope (for local/self-hosted scanning)
    if target_host in ("localhost", "127.0.0.1", "host.docker.internal"):
        return {"in_scope": True, "detail": "Local target"}

    if not allowed_targets:
        return {"in_scope": False, "detail": "No allowed_targets defined in scope config"}

    for allowed in allowed_targets:
        # Support wildcards: *.example.com matches sub.example.com
        if allowed.startswith("*."):
            suffix = allowed[1:]  # .example.com
            if target_host.endswith(suffix) or target_host == allowed[2:]:
                return {"in_scope": True, "detail": f"Matched wildcard {allowed}"}
        elif target_host == allowed:
            return {"in_scope": True, "detail": f"Exact match {allowed}"}

    return {
        "in_scope": False,
        "detail": f"Host '{target_host}' not in allowed_targets: {allowed_targets}"
    }


if __name__ == "__main__":
    # CLI usage for testing
    import sys
    if len(sys.argv) < 3:
        print("Usage: python scope_verify.py <org_id> <target_url> [method]")
        print("  method: dns | file (default: dns)")
        sys.exit(1)

    org_id = sys.argv[1]
    target = sys.argv[2]
    method = sys.argv[3] if len(sys.argv) > 3 else "dns"

    parsed = urlparse(target)
    domain = parsed.hostname
    token = generate_verification_token(org_id, domain)

    print(f"Org: {org_id}")
    print(f"Target: {target}")
    print(f"Domain: {domain}")
    print(f"Verification token: {token}")
    print(f"Method: {method}")

    if method == "dns":
        print(f"\nTo verify, add this DNS TXT record to {domain}:")
        print(f"  shieldci-verify={token}")
    else:
        print(f"\nTo verify, create this file at:")
        print(f"  {parsed.scheme}://{parsed.netloc}/.well-known/shieldci-verify")
        print(f"  Contents: {token}")

    print(f"\nVerifying...")
    result = verify_target_ownership(target, token, method)
    print(json.dumps(result, indent=2))
