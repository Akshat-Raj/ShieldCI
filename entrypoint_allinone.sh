#!/bin/bash
set -e

# ── ShieldCI All-in-One Entrypoint ──
# The /app/tests volume should contain:
#   • repo/        — the target repository to scan
#   • shieldci.yml — (optional) scan configuration

cd /app/tests

# Install target-app dependencies if a repo is mounted
if [ -d "repo" ]; then
    echo "📂 Target repo detected at /app/tests/repo"
fi

# Hand off to the Rust orchestrator
exec /app/shield-ci
