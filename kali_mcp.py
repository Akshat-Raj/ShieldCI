from mcp.server.fastmcp import FastMCP
import subprocess
import os

mcp = FastMCP("ShieldCI-Arsenal")

def run_cmd(cmd):
    """Helper to run shell commands safely and return output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
    except Exception as e:
        return f"Execution Error: {str(e)}"

@mcp.tool()
def sqlmap_scan(url: str):
    """Deep SQL injection testing. Best for login forms and search bars."""
    target = url.replace("127.0.0.1", "host.docker.internal")
    return run_cmd(["sqlmap", "-u", target, "--batch", "--random-agent", "--level=1"])

@mcp.tool()
def nmap_scan(target: str):
    """Port scanner. Use this first to find what services are running."""
    host = target.replace("127.0.0.1", "host.docker.internal")
    return run_cmd(["nmap", "-sV", "-T4", host])

@mcp.tool()
def nikto_scan(url: str):
    """Web server vulnerability scanner. Finds outdated software and dangerous files."""
    target = url.replace("127.0.0.1", "host.docker.internal")
    return run_cmd(["nikto", "-h", target, "-Tuning", "1,2,3,b"])

@mcp.tool()
def gobuster_scan(url: str):
    """Directory brute-forcer. Finds hidden /admin, /config, or /.env files."""
    target = url.replace("127.0.0.1", "host.docker.internal")
    # Using a common small wordlist included in Kali
    wordlist = "/usr/share/dirb/wordlists/common.txt"
    return run_cmd(["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "-z"])

@mcp.tool()
def check_headers(url: str):
    """Quick check for missing security headers like CSP or X-Frame-Options."""
    target = url.replace("127.0.0.1", "host.docker.internal")
    return run_cmd(["curl", "-I", "-s", target])

if __name__ == "__main__":
    mcp.run()