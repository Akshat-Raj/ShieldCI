#!/bin/bash

# Global arrays to store detected info
declare -a LANGUAGES
declare -a FRAMEWORKS
declare -a DATABASES
declare -a ARCHITECTURE
declare -a PACKAGE_MANAGERS
IS_CONTAINERIZED=false
CLOUD_PROVIDER="none"
HAS_API=false

detect_repo() {
    local repo_path="$1"

    # ── Detect Languages ─────────────────────
    detect_languages "$repo_path"

    # ── Detect Frameworks ────────────────────
    detect_frameworks "$repo_path"

    # ── Detect Databases ─────────────────────
    detect_databases "$repo_path"

    # ── Detect Infrastructure ────────────────
    detect_infrastructure "$repo_path"

    # ── Detect Cloud ─────────────────────────
    detect_cloud "$repo_path"

    # ── Detect API ───────────────────────────
    detect_api "$repo_path"

    # ── Export profile as JSON ───────────────
    export_profile
}

detect_languages() {
    local path="$1"

    # Python
    if find "$path" -name "*.py" -o \
                    -name "requirements.txt" -o \
                    -name "pyproject.toml" | grep -q .; then
        LANGUAGES+=("python")
        PACKAGE_MANAGERS+=("pip")
    fi

    # JavaScript
    if find "$path" -name "*.js" -o \
                    -name "package.json" | grep -q .; then
        LANGUAGES+=("javascript")
        PACKAGE_MANAGERS+=("npm")
    fi

    # TypeScript
    if find "$path" -name "*.ts" -o \
                    -name "tsconfig.json" | grep -q .; then
        LANGUAGES+=("typescript")
    fi

    # Java
    if find "$path" -name "*.java" -o \
                    -name "pom.xml" -o \
                    -name "build.gradle" | grep -q .; then
        LANGUAGES+=("java")
        PACKAGE_MANAGERS+=("maven")
    fi

    # Go
    if find "$path" -name "*.go" -o \
                    -name "go.mod" | grep -q .; then
        LANGUAGES+=("go")
        PACKAGE_MANAGERS+=("go_modules")
    fi

    # Ruby
    if find "$path" -name "*.rb" -o \
                    -name "Gemfile" | grep -q .; then
        LANGUAGES+=("ruby")
        PACKAGE_MANAGERS+=("bundler")
    fi

    # PHP
    if find "$path" -name "*.php" -o \
                    -name "composer.json" | grep -q .; then
        LANGUAGES+=("php")
        PACKAGE_MANAGERS+=("composer")
    fi

    # Rust
    if find "$path" -name "*.rs" -o \
                    -name "Cargo.toml" | grep -q .; then
        LANGUAGES+=("rust")
        PACKAGE_MANAGERS+=("cargo")
    fi
}

detect_frameworks() {
    local path="$1"

    # Search all text files for framework indicators
    local all_content
    all_content=$(find "$path" -type f \
        \( -name "*.py" -o -name "*.js" -o \
           -name "*.ts" -o -name "*.json" -o \
           -name "*.txt" -o -name "*.toml" \) \
        -not -path "*/.git/*" \
        -not -path "*/node_modules/*" \
        -exec cat {} \; 2>/dev/null)

    # Python frameworks
    echo "$all_content" | grep -qi "from flask"     && FRAMEWORKS+=("flask")
    echo "$all_content" | grep -qi "import django"  && FRAMEWORKS+=("django")
    echo "$all_content" | grep -qi "from fastapi"   && FRAMEWORKS+=("fastapi")

    # JS frameworks
    echo "$all_content" | grep -qi "require.*express" && FRAMEWORKS+=("express")
    echo "$all_content" | grep -qi "from.*react"      && FRAMEWORKS+=("react")
    echo "$all_content" | grep -qi "from.*next"       && FRAMEWORKS+=("nextjs")
    echo "$all_content" | grep -qi "from.*vue"        && FRAMEWORKS+=("vue")

    # Java frameworks
    echo "$all_content" | grep -qi "SpringApplication" && FRAMEWORKS+=("spring")
    echo "$all_content" | grep -qi "quarkus"           && FRAMEWORKS+=("quarkus")
}

detect_databases() {
    local path="$1"

    local all_content
    all_content=$(find "$path" -type f \
        \( -name "*.py" -o -name "*.js" -o \
           -name "*.env*" -o -name "*.yml" -o \
           -name "*.toml" -o -name "*.txt" \) \
        -not -path "*/.git/*" \
        -exec cat {} \; 2>/dev/null)

    echo "$all_content" | grep -qi "postgresql\|psycopg2\|pg" && DATABASES+=("postgresql")
    echo "$all_content" | grep -qi "mysql\|pymysql"           && DATABASES+=("mysql")
    echo "$all_content" | grep -qi "mongodb\|pymongo\|mongoose" && DATABASES+=("mongodb")
    echo "$all_content" | grep -qi "sqlite"                   && DATABASES+=("sqlite")
    echo "$all_content" | grep -qi "redis"                    && DATABASES+=("redis")
}

detect_infrastructure() {
    local path="$1"

    [[ -f "$path/Dockerfile" ]] && {
        IS_CONTAINERIZED=true
        ARCHITECTURE+=("docker")
    }

    [[ -f "$path/docker-compose.yml" ]] && {
        ARCHITECTURE+=("docker_compose")
    }

    find "$path" -name "*.yaml" -o -name "*.yml" | \
        xargs grep -l "kubernetes\|apiVersion" 2>/dev/null | \
        grep -q . && ARCHITECTURE+=("kubernetes")

    find "$path" -name "*.tf" | grep -q . && \
        ARCHITECTURE+=("terraform")
}

detect_cloud() {
    local path="$1"

    local all_content
    all_content=$(find "$path" -type f -not -path "*/.git/*" \
        -exec cat {} \; 2>/dev/null)

    echo "$all_content" | grep -qi "boto3\|aws-sdk\|lambda_handler\|amazonaws" && \
        CLOUD_PROVIDER="aws"
    echo "$all_content" | grep -qi "google-cloud\|firebase\|gcloud" && \
        CLOUD_PROVIDER="gcp"
    echo "$all_content" | grep -qi "azure\|microsoft.azure" && \
        CLOUD_PROVIDER="azure"
}

detect_api() {
    local path="$1"

    find "$path" -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" \) \
        -not -path "*/.git/*" \
        -exec grep -l "@app.route\|@router\|app.get\|app.post\|RestController" {} \; \
        2>/dev/null | grep -q . && HAS_API=true
}

export_profile() {
    # Convert bash arrays to JSON
    LANGS_JSON=$(printf '%s\n' "${LANGUAGES[@]}" | \
        jq -R . | jq -s .)
    FRAMEWORKS_JSON=$(printf '%s\n' "${FRAMEWORKS[@]}" | \
        jq -R . | jq -s .)
    DATABASES_JSON=$(printf '%s\n' "${DATABASES[@]}" | \
        jq -R . | jq -s .)
    ARCH_JSON=$(printf '%s\n' "${ARCHITECTURE[@]}" | \
        jq -R . | jq -s .)

    # Write profile to file for other scripts to read
    cat > /tmp/repo_profile.json << EOF
{
  "languages":      $LANGS_JSON,
  "frameworks":     $FRAMEWORKS_JSON,
  "databases":      $DATABASES_JSON,
  "architecture":   $ARCH_JSON,
  "containerized":  $IS_CONTAINERIZED,
  "cloud_provider": "$CLOUD_PROVIDER",
  "has_api":        $HAS_API
}
EOF

    log_info "📋 Profile saved to /tmp/repo_profile.json"
}