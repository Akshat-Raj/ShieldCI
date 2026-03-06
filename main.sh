#!/bin/bash
set -e  # exit on any error

source ./pipeline/utils.sh
source ./pipeline/detector.sh
source ./pipeline/scanner.sh
source ./pipeline/ai_fixer.sh
source ./pipeline/git_handler.sh
source ./pipeline/reporter.sh

REPO_PATH="${1:-.}"
REPORT_FILE="security_report.json"
FIXES_APPLIED=0

log_info "🔐 AI Pentesting Pipeline Starting..."
log_info "📁 Scanning repo: $REPO_PATH"

# ── Step 1: Detect repo profile ──────────────
log_info "🔍 Detecting repository profile..."
detect_repo "$REPO_PATH"
log_info "Languages found: ${LANGUAGES[*]}"
log_info "Frameworks found: ${FRAMEWORKS[*]}"
log_info "Databases found: ${DATABASES[*]}"

# ── Step 2: Run scanners ─────────────────────
log_info "🛡️  Running security scanners..."
run_scanners "$REPO_PATH"

# ── Step 3: AI Analysis + Fix ────────────────
log_info "🤖 Running AI analysis and fixes..."
run_ai_fixes "$REPO_PATH"

# ── Step 4: Generate report ──────────────────
log_info "📊 Generating security report..."
generate_report

# ── Step 5: Push fixes to Git ────────────────
log_info "📤 Creating PR with fixes..."
create_pull_request

log_success "✅ Pipeline complete!"