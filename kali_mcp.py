from mcp.server.fastmcp import FastMCP
import subprocess
import os
import json
import shutil

mcp = FastMCP("ShieldCI-Arsenal")

_LOCAL_MODE = os.environ.get("SHIELDCI_LOCAL_TOOLS") == "1"

def _resolve_host(url: str) -> str:
    """In Docker multi-container mode, rewrite to host.docker.internal. In local mode, keep as-is."""
    if _LOCAL_MODE:
        return url
    return url.replace("127.0.0.1", "host.docker.internal")

def run_cmd(cmd, timeout=120):
    """Helper to run shell commands safely and return output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
    except subprocess.TimeoutExpired:
        return f"Execution Error: Command timed out after {timeout}s"
    except Exception as e:
        return f"Execution Error: {str(e)}"

# ── Original Tools ──

@mcp.tool()
def sqlmap_scan(url: str):
    """Deep SQL injection testing. Best for login forms and search bars."""
    target = _resolve_host(url)
    return run_cmd(["sqlmap", "-u", target, "--batch", "--random-agent", "--level=1"])

@mcp.tool()
def nmap_scan(target: str):
    """Port scanner. Use this first to find what services are running."""
    host = _resolve_host(target)
    return run_cmd(["nmap", "-sV", "-T4", host])

@mcp.tool()
def nikto_scan(url: str):
    """Web server vulnerability scanner. Finds outdated software and dangerous files."""
    target = _resolve_host(url)
    return run_cmd(["nikto", "-h", target, "-Tuning", "1,2,3,b"])

@mcp.tool()
def gobuster_scan(url: str):
    """Directory brute-forcer. Finds hidden /admin, /config, or /.env files."""
    target = _resolve_host(url)
    wordlist = "/usr/share/dirb/wordlists/common.txt"
    return run_cmd(["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "-z"])

@mcp.tool()
def check_headers(url: str):
    """Quick check for missing security headers like CSP or X-Frame-Options."""
    target = _resolve_host(url)
    return run_cmd(["curl", "-I", "-s", target])

# ── Phase 1 New Tools ──

@mcp.tool()
def nuclei_scan(url: str, severity: str = "critical,high,medium"):
    """Advanced vulnerability scanner with 8000+ community templates. Far more accurate than nikto.
    Covers: CVEs, misconfigs, exposed panels, default creds, XSS, SSRF, IDOR, tech detection.
    severity: comma-separated filter (critical,high,medium,low,info). Default: critical,high,medium."""
    target = _resolve_host(url)
    cmd = [
        "nuclei", "-u", target,
        "-severity", severity,
        "-jsonl",               # structured output for parsing
        "-silent",              # suppress banner
        "-timeout", "10",       # per-request timeout
        "-rate-limit", "100",   # requests/sec cap
    ]
    raw = run_cmd(cmd, timeout=300)

    # Parse JSONL results into a structured summary
    findings = []
    for line in raw.split("\n"):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
            findings.append({
                "template": entry.get("template-id", ""),
                "name": entry.get("info", {}).get("name", ""),
                "severity": entry.get("info", {}).get("severity", ""),
                "matched": entry.get("matched-at", ""),
                "type": entry.get("type", ""),
                "description": entry.get("info", {}).get("description", "")[:200],
            })
        except json.JSONDecodeError:
            continue

    if findings:
        summary = f"Nuclei found {len(findings)} issue(s):\n"
        for f in findings:
            summary += f"  [{f['severity'].upper()}] {f['name']} — {f['matched']}\n"
            if f['description']:
                summary += f"    {f['description']}\n"
        return summary + "\n\nRaw output:\n" + raw
    return raw

@mcp.tool()
def semgrep_scan(path: str, config: str = "auto"):
    """Static Application Security Testing (SAST). Scans source code for vulnerabilities
    without running the app. Finds: SQL injection, XSS, insecure crypto, hardcoded secrets,
    path traversal, command injection, and more. Uses OWASP and community rulesets.
    path: directory or file to scan. config: ruleset ('auto', 'p/owasp-top-ten', 'p/security-audit')."""
    cmd = [
        "semgrep", "scan",
        "--config", config,
        "--json",              # structured output
        "--quiet",             # suppress progress
        "--timeout", "60",     # per-rule timeout
        "--max-target-bytes", "1000000",
        path,
    ]
    raw = run_cmd(cmd, timeout=300)

    # Parse JSON results
    try:
        stdout_part = raw.split("STDOUT:\n", 1)[1].split("\n\nSTDERR:")[0] if "STDOUT:" in raw else raw
        data = json.loads(stdout_part)
        results = data.get("results", [])
        if results:
            summary = f"Semgrep found {len(results)} issue(s):\n"
            for r in results:
                check_id = r.get("check_id", "")
                msg = r.get("extra", {}).get("message", "")
                sev = r.get("extra", {}).get("severity", "WARNING")
                filepath = r.get("path", "")
                start = r.get("start", {}).get("line", 0)
                end = r.get("end", {}).get("line", 0)
                code = r.get("extra", {}).get("lines", "")
                summary += f"\n  [{sev}] {check_id}\n"
                summary += f"    File: {filepath}:{start}-{end}\n"
                summary += f"    {msg}\n"
                if code:
                    summary += f"    Code: {code.strip()}\n"
            return summary
        return "Semgrep: No issues found.\n\n" + raw
    except (json.JSONDecodeError, IndexError):
        return raw

@mcp.tool()
def trivy_scan(path: str, scan_type: str = "fs"):
    """Software Composition Analysis (SCA). Scans dependencies for known CVEs.
    Checks: npm (package-lock.json), pip (requirements.txt), cargo (Cargo.lock), etc.
    path: directory to scan. scan_type: 'fs' for filesystem, 'image' for Docker images."""
    cmd = [
        "trivy", scan_type,
        "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM",
        "--timeout", "5m",
        path,
    ]
    raw = run_cmd(cmd, timeout=300)

    try:
        stdout_part = raw.split("STDOUT:\n", 1)[1].split("\n\nSTDERR:")[0] if "STDOUT:" in raw else raw
        data = json.loads(stdout_part)
        results = data.get("Results", [])
        total_vulns = 0
        summary = ""
        for result in results:
            target_name = result.get("Target", "")
            vulns = result.get("Vulnerabilities", [])
            if not vulns:
                continue
            total_vulns += len(vulns)
            summary += f"\n  {target_name} ({len(vulns)} vulnerabilities):\n"
            for v in vulns[:20]:  # cap at 20 per target
                vid = v.get("VulnerabilityID", "")
                pkg = v.get("PkgName", "")
                installed = v.get("InstalledVersion", "")
                fixed = v.get("FixedVersion", "")
                sev = v.get("Severity", "")
                title = v.get("Title", "")
                summary += f"    [{sev}] {vid} in {pkg}@{installed}"
                if fixed:
                    summary += f" (fix: {fixed})"
                summary += f"\n      {title}\n"
        if total_vulns:
            return f"Trivy found {total_vulns} vulnerable dependency(s):\n{summary}"
        return "Trivy: No vulnerable dependencies found.\n\n" + raw
    except (json.JSONDecodeError, IndexError):
        return raw

@mcp.tool()
def zap_scan(url: str, scan_type: str = "baseline"):
    """OWASP ZAP Dynamic Application Security Testing (DAST). Crawls and attacks a running web app.
    Finds: XSS, CSRF, IDOR, auth bypasses, injection flaws that nikto misses.
    scan_type: 'baseline' (fast passive scan), 'full' (active attack scan)."""
    target = _resolve_host(url)
    if scan_type == "full":
        script = "zap-full-scan.py"
    else:
        script = "zap-baseline.py"
    cmd = [
        script,
        "-t", target,
        "-J", "/tmp/zap_results.json",  # JSON report
        "-I",                             # don't return failure codes for findings
    ]
    raw = run_cmd(cmd, timeout=600)

    # Try to read structured results
    try:
        with open("/tmp/zap_results.json", "r") as f:
            data = json.load(f)
        alerts = data.get("site", [{}])[0].get("alerts", [])
        if alerts:
            summary = f"ZAP found {len(alerts)} alert type(s):\n"
            for a in alerts:
                risk = a.get("riskdesc", "")
                name = a.get("alert", "")
                count = a.get("count", "")
                summary += f"  [{risk}] {name} ({count} instance(s))\n"
                for inst in a.get("instances", [])[:3]:
                    summary += f"    {inst.get('method', '')} {inst.get('uri', '')}\n"
            return summary
        return "ZAP: No alerts found.\n\n" + raw
    except (FileNotFoundError, json.JSONDecodeError, IndexError):
        return raw

if __name__ == "__main__":
    mcp.run()