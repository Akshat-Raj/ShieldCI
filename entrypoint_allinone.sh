#!/bin/bash
set -e

echo "🛡️  ShieldCI All-in-One Container"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verify we're in a repo directory
if [ ! -f "shieldci.yml" ] && [ ! -f "package.json" ] && [ ! -f "requirements.txt" ] && [ ! -f "Cargo.toml" ]; then
    echo "⚠️  No project files found in /workspace."
    echo "   Mount your target repo: docker run -v /path/to/repo:/workspace shieldci"
    exit 1
fi

# Check Ollama connectivity
OLLAMA_URL="${OLLAMA_HOST:-http://host.docker.internal:11434}"
echo "🔗 Checking Ollama at ${OLLAMA_URL}..."
if curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
    echo "✅ Ollama is reachable"
else
    echo "⚠️  Ollama not reachable at ${OLLAMA_URL}"
    echo "   LLM adaptive strikes will use fallback defaults."
    echo "   Fix: run 'ollama serve' on your host."
fi

echo ""
echo "🚀 Starting scan..."
echo ""

# Run the orchestrator
exec /app/shield-ci "$@"
