use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use walkdir::WalkDir;

// ── YAML config structs ──

#[derive(Deserialize, Debug, Default)]
struct ShieldConfig {
    project: Option<ProjectConfig>,
    build: Option<BuildConfig>,
    endpoints: Option<Vec<EndpointConfig>>,
    database: Option<DatabaseConfig>,
    auth: Option<AuthConfig>,
    files: Option<Vec<String>>,
    scope: Option<ScopeConfig>,
    sast: Option<SastConfig>,
    sca: Option<ScaConfig>,
}

#[derive(Deserialize, Debug, Default)]
struct ProjectConfig {
    name: Option<String>,
    framework: Option<String>,
    language: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct BuildConfig {
    command: Option<String>,
    run: Option<String>,
    port: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct EndpointConfig {
    path: String,
    method: Option<String>,
    params: Option<Vec<ParamConfig>>,
    description: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ParamConfig {
    name: String,
    #[serde(rename = "type")]
    param_type: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct DatabaseConfig {
    #[serde(rename = "type")]
    db_type: Option<String>,
    orm: Option<bool>,
}

#[derive(Deserialize, Debug, Default)]
struct AuthConfig {
    enabled: Option<bool>,
    token: Option<String>,
    cookie: Option<String>,
    api_key: Option<String>,
    header_name: Option<String>,
}

// ── Scope & Authorization ──

#[derive(Deserialize, Debug, Default)]
struct ScopeConfig {
    allowed_targets: Option<Vec<String>>,
    authorization_proof: Option<String>,  // "dns" | "file" | "none"
}

// ── SAST config ──

#[derive(Deserialize, Debug, Default)]
struct SastConfig {
    enabled: Option<bool>,
    config: Option<String>,  // semgrep ruleset
}

#[derive(Deserialize, Debug, Default)]
struct ScaConfig {
    enabled: Option<bool>,
}

#[derive(Debug)]
struct TargetConfig {
    framework: String,
    build_command: String,
    run_command: String,
    target_url: String,
}

#[derive(Deserialize, Debug)]
struct ToolCall {
    tool: String,
    target: String,
    #[serde(default)]
    extra_args: HashMap<String, String>,
}

// ── Structured output for frontend API ──

#[derive(Serialize, Debug)]
struct ScanOutput {
    status: String,
    vulnerabilities: Vec<VulnOutput>,
    report_markdown: String,
}

#[derive(Serialize, Debug)]
struct VulnOutput {
    file: String,
    line: u32,
    #[serde(rename = "type")]
    vuln_type: String,
    severity: String,
    description: String,
    #[serde(rename = "codeSnippet")]
    code_snippet: String,
    #[serde(rename = "fixSnippet")]
    fix_snippet: String,
}

fn load_shield_config() -> Option<ShieldConfig> {
    let yaml_path = Path::new("shieldci.yml");
    if yaml_path.exists() {
        let content = fs::read_to_string(yaml_path).ok()?;
        let config: ShieldConfig = serde_yaml::from_str(&content).ok()?;
        println!("Loaded shieldci.yml configuration");
        Some(config)
    } else {
        println!("No shieldci.yml found, falling back to auto-detection");
        None
    }
}

fn config_from_yaml(shield: &ShieldConfig) -> TargetConfig {
    let build = shield.build.as_ref();
    let project = shield.project.as_ref();
    let port = build.and_then(|b| b.port).unwrap_or(3000);

    TargetConfig {
        framework: project.and_then(|p| p.framework.clone()).unwrap_or_else(|| "Unknown".to_string()),
        build_command: build.and_then(|b| b.command.clone()).unwrap_or_default(),
        run_command: build.and_then(|b| b.run.clone()).unwrap_or_default(),
        target_url: format!("http://127.0.0.1:{}", port),
    }
}

fn fetch_config_from_shell() -> TargetConfig {
    println!("🔍 Calling run.sh to scout the repository...");
    if !Path::new("run.sh").exists() {
        return TargetConfig {
            framework: "Node.js".to_string(),
            build_command: "npm install".to_string(),
            run_command: "node app.js".to_string(),
            target_url: "http://127.0.0.1:3000".to_string(),
        };
    }

    let output = Command::new("bash").arg("run.sh").output().expect("Failed to execute run.sh");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut config_map = HashMap::new();
    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            config_map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    TargetConfig {
        framework: config_map.get("FRAMEWORK").unwrap_or(&"Node.js".to_string()).clone(),
        build_command: config_map.get("BUILD_CMD").unwrap_or(&"npm install".to_string()).clone(),
        run_command: config_map.get("RUN_CMD").unwrap_or(&"node app.js".to_string()).clone(),
        target_url: config_map.get("TARGET_URL").unwrap_or(&"http://127.0.0.1:3000".to_string()).clone(),
    }
}

fn launch_sandbox(config: &TargetConfig) {
    if !config.build_command.is_empty() {
        println!("Running build: {}", config.build_command);
        let parts: Vec<&str> = config.build_command.split_whitespace().collect();
        let _ = Command::new(parts[0]).args(&parts[1..]).status();
    }

    println!("Launching {} server", config.framework);
    let run_parts: Vec<&str> = config.run_command.split_whitespace().collect();
    Command::new(run_parts[0])
        .args(&run_parts[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start the target application server");
}

async fn wait_for_target(url: &str, max_retries: u8) -> Result<(), String> {
    println!("Waiting for target to come online");
    let client = Client::builder().timeout(Duration::from_secs(2)).build().unwrap();
    for _ in 1..=max_retries {
        if client.get(url).send().await.is_ok() {
            println!("Target is up and responding");
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    Err(format!("Target failed to respond."))
}

fn build_endpoint_context(config: &ShieldConfig, base_url: &str) -> String {
    let docker_base = base_url.replace("127.0.0.1", "host.docker.internal");
    let mut info = String::from("Known API endpoints (from shieldci.yml):\n");

    if let Some(ref endpoints) = config.endpoints {
        for ep in endpoints {
            let method = ep.method.as_deref().unwrap_or("GET");
            let desc = ep.description.as_deref().unwrap_or("");
            info.push_str(&format!("  {} {} - {}\n", method, ep.path, desc));

            if let Some(ref params) = ep.params {
                for p in params {
                    let ptype = p.param_type.as_deref().unwrap_or("string");
                    let pdesc = p.description.as_deref().unwrap_or("");
                    info.push_str(&format!("    param: {}({}) - {}\n", p.name, ptype, pdesc));
                }
                // Build example attack URL
                let param_str: Vec<String> = params.iter().map(|p| format!("{}=test", p.name)).collect();
                info.push_str(&format!(
                    "    attack URL: {}{}?{}\n",
                    docker_base, ep.path, param_str.join("&")
                ));
            }
        }
    }
    info
}

fn flatten_codebase(dir: &str) -> String {
    println!("Recursively flattening codebase for full context...");
    let mut full_code = String::new();
    let skip_dirs = ["node_modules", ".git", "target", "dist", "build", "__pycache__", ".next"];

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !skip_dirs.iter().any(|d| name == *d)
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() && (path.extension().map_or(false, |ext| ext == "js" || ext == "py" || ext == "ts")) {
            if let Ok(content) = fs::read_to_string(path) {
                full_code.push_str(&format!("\n--- FILE: {:?} ---\n", path));
                full_code.push_str(&content);
            }
        }
    }
    full_code
}

fn get_ollama_url() -> String {
    std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".to_string())
}

fn is_local_tools() -> bool {
    std::env::var("SHIELDCI_LOCAL_TOOLS").unwrap_or_default() == "1"
}

async fn ask_llm(system_prompt: &str) -> ToolCall {
    let ollama = get_ollama_url();
    println!("Invoking ShieldCI LLM at {}", ollama);
    let client = Client::new();
    let req_body = serde_json::json!({
        "model": "llama3.1",
        "prompt": system_prompt,
        "stream": false,
        "format": "json"
    });

    let url = format!("{}/api/generate", ollama.trim_end_matches('/'));
    let res = client.post(&url).json(&req_body).send().await.expect("Ollama error");
    let res_json: serde_json::Value = res.json().await.unwrap();
    let response_text = res_json["response"].as_str().unwrap_or("{}");
    
    // Safety check for empty JSON
    if !response_text.contains("\"tool\"") {
        return ToolCall { 
            tool: "sqlmap_scan".to_string(), 
            target: "http://host.docker.internal:3000/login?username=test".to_string(),
            extra_args: HashMap::new(),
        };
    }

    serde_json::from_str(response_text).unwrap_or(ToolCall { 
        tool: "sqlmap_scan".to_string(), 
        target: "http://host.docker.internal:3000/login?username=test".to_string(),
        extra_args: HashMap::new(),
    })
}

async fn execute_mcp_tool_stdio(tool_call: &ToolCall) -> Result<String, Box<dyn std::error::Error>> {
    println!("Initiating MCP Handshake & Strike: {}", tool_call.tool);

    let local = is_local_tools();
    let mut child = if local {
        // All-in-one mode: kali tools installed locally, call kali_mcp.py directly
        let mcp_path = std::env::var("SHIELDCI_MCP_CMD")
            .unwrap_or_else(|_| "python3 /app/kali_mcp.py".to_string());
        let parts: Vec<&str> = mcp_path.split_whitespace().collect();
        Command::new(parts[0])
            .args(&parts[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?
    } else {
        // Docker mode: spin up the Kali container
        Command::new("docker")
            .args(["run", "-i", "--rm", "shieldci-kali-image"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?
    };

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout);

    // Step 1: Initialize
    let init = r#"{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "shieldci", "version": "1.0"}}}"#;
    writeln!(stdin, "{}", init)?;
    let mut line = String::new();
    reader.read_line(&mut line)?;

    // Step 2: Call Tool — nmap_scan uses "target" param, others use "url"
    // In local/all-in-one mode, tools and target share the same network — keep 127.0.0.1
    // In docker mode, tools are in a separate container — rewrite to host.docker.internal
    let target_url = if local {
        tool_call.target.replace("host.docker.internal", "127.0.0.1")
    } else {
        tool_call.target.replace("127.0.0.1", "host.docker.internal")
    };
    let mcp_args = if tool_call.tool == "nmap_scan" {
        serde_json::json!({ "target": target_url })
    } else {
        tool_call.target.replace("127.0.0.1", "host.docker.internal")
    };
    let mcp_args = match tool_call.tool.as_str() {
        "nmap_scan" => serde_json::json!({ "target": target_url }),
        "semgrep_scan" => {
            let config = tool_call.extra_args.get("config").cloned().unwrap_or_else(|| "auto".to_string());
            serde_json::json!({ "path": target_url, "config": config })
        }
        "trivy_scan" => {
            let scan_type = tool_call.extra_args.get("scan_type").cloned().unwrap_or_else(|| "fs".to_string());
            serde_json::json!({ "path": target_url, "scan_type": scan_type })
        }
        "nuclei_scan" => {
            let severity = tool_call.extra_args.get("severity").cloned().unwrap_or_else(|| "critical,high,medium".to_string());
            serde_json::json!({ "url": target_url, "severity": severity })
        }
        "zap_scan" => {
            let scan_type = tool_call.extra_args.get("scan_type").cloned().unwrap_or_else(|| "baseline".to_string());
            serde_json::json!({ "url": target_url, "scan_type": scan_type })
        }
        _ => serde_json::json!({ "url": target_url }),
    };
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": tool_call.tool, "arguments": mcp_args }
    });
    writeln!(stdin, "{}", call)?;
    drop(stdin);

    let mut output = String::new();
    reader.read_to_string(&mut output)?;
    Ok(output)
}

async fn generate_report(trace: &str, codebase: &str, success: bool) -> String {
    println!("Compiling final security assessment");
    let ollama = get_ollama_url();
    let client = Client::new();
    let status = if success { "VULNERABILITY DISCOVERED" } else { "NO VULNERABILITIES DETECTED" };
    
    let prompt = format!(
        r#"You are a senior security engineer writing a detailed penetration test report in Markdown.

Status: {status}

## Instructions
Write the report with these EXACT sections:

# ShieldCI Security Report

## Executive Summary
Brief overview of what was tested and the outcome.

## Scan Results
For each test that was run, describe:
- What tool was used and what it targeted
- What was found (quote key findings from the logs)
- Severity rating (Critical / High / Medium / Low / Info)

## Vulnerability Details
For EACH vulnerability found:
### [Vulnerability Name]
- **Severity**: Critical/High/Medium/Low
- **Location**: file path and line number
- **Description**: what the vulnerability is

#### Vulnerable Code
```
(paste the exact vulnerable code snippet from the source)
```

#### Recommended Fix
```
(write the corrected code snippet that fixes the vulnerability)
```

#### Explanation
Why the original code is vulnerable and how the fix resolves it.

## Security Headers & Configuration
List any missing security headers or misconfigurations found.

## Recommendations
Numbered list of actionable security improvements.

---

## Raw Data

Tool scan logs:
{trace}

Application source code:
{codebase}

IMPORTANT: You MUST include actual code snippets from the source code showing vulnerable lines, and write corrected versions. Do NOT skip the code sections."#
    );

    let req_body = serde_json::json!({"model": "llama3.1", "prompt": prompt, "stream": false});
    let url = format!("{}/api/generate", ollama.trim_end_matches('/'));
    let res = client.post(&url).json(&req_body).send().await.expect("Ollama error");
    let res_json: serde_json::Value = res.json().await.unwrap();
    res_json["response"].as_str().unwrap_or("Report failed.").to_string()
}

/// Generate a dynamic test plan based on the repo's YAML config.
/// Each test is a (phase_name, tool, target, extra_args) tuple.
fn generate_test_plan(shield_config: &Option<ShieldConfig>, docker_url: &str) -> Vec<(String, String, String, HashMap<String, String>)> {
    let mut plan: Vec<(String, String, String, HashMap<String, String>)> = Vec::new();
    let empty = HashMap::new();

    // Phase 1: Recon
    plan.push(("RECON: Port Scan".into(), "nmap_scan".into(), docker_url.into(), empty.clone()));
    plan.push(("RECON: Security Headers".into(), "check_headers".into(), docker_url.into(), empty.clone()));

    // Phase 2: SAST — static analysis of source code (runs before the app is even up)
    let sast_enabled = shield_config.as_ref()
        .and_then(|sc| sc.sast.as_ref())
        .and_then(|s| s.enabled)
        .unwrap_or(true); // on by default
    if sast_enabled {
        let sast_config = shield_config.as_ref()
            .and_then(|sc| sc.sast.as_ref())
            .and_then(|s| s.config.clone())
            .unwrap_or_else(|| "auto".to_string());
        let mut args = HashMap::new();
        args.insert("config".to_string(), sast_config);
        plan.push(("SAST: Source Code Analysis".into(), "semgrep_scan".into(), ".".into(), args));
    }

    // Phase 3: SCA — dependency vulnerability scanning
    let sca_enabled = shield_config.as_ref()
        .and_then(|sc| sc.sca.as_ref())
        .and_then(|s| s.enabled)
        .unwrap_or(true); // on by default
    if sca_enabled {
        plan.push(("SCA: Dependency Vulnerabilities".into(), "trivy_scan".into(), ".".into(), empty.clone()));
    }

    // Phase 4: Nuclei — replaces nikto with 8000+ templates
    plan.push(("DAST: Nuclei Template Scan".into(), "nuclei_scan".into(), docker_url.into(), empty.clone()));

    // Phase 5: Legacy web vuln scanning (still useful as a complement)
    plan.push(("DAST: Web Server Scan".into(), "nikto_scan".into(), docker_url.into(), empty.clone()));

    // Phase 6: Directory discovery
    plan.push(("DISCOVERY: Hidden Paths".into(), "gobuster_scan".into(), docker_url.into(), empty.clone()));

    // Phase 7: ZAP DAST — crawl + passive scan
    plan.push(("DAST: ZAP Baseline".into(), "zap_scan".into(), docker_url.into(), empty.clone()));

    // Phase 8: Endpoint-specific attacks from YAML config
    if let Some(ref sc) = shield_config {
        let uses_raw_sql = sc.database.as_ref()
            .map(|db| db.orm.unwrap_or(true) == false)
            .unwrap_or(false);

        if let Some(ref endpoints) = sc.endpoints {
            for ep in endpoints {
                if let Some(ref params) = ep.params {
                    if params.is_empty() { continue; }

                    let param_str: Vec<String> = params.iter()
                        .map(|p| format!("{}=test", p.name))
                        .collect();
                    let attack_url = format!("{}{}?{}", docker_url, ep.path, param_str.join("&"));

                    if uses_raw_sql {
                        plan.push((
                            format!("SQLi: {} {}", ep.method.as_deref().unwrap_or("GET"), ep.path),
                            "sqlmap_scan".into(),
                            attack_url.clone(),
                            empty.clone(),
                        ));
                    }

                    let has_user_input = params.iter().any(|p| {
                        let name = p.name.to_lowercase();
                        let desc = p.description.as_deref().unwrap_or("").to_lowercase();
                        name.contains("user") || name.contains("pass") || name.contains("search")
                            || name.contains("query") || name.contains("id") || name.contains("name")
                            || name.contains("email") || name.contains("token")
                            || desc.contains("database") || desc.contains("sql")
                    });

                    if has_user_input && !uses_raw_sql {
                        plan.push((
                            format!("SQLi: {} {}", ep.method.as_deref().unwrap_or("GET"), ep.path),
                            "sqlmap_scan".into(),
                            attack_url,
                            empty.clone(),
                        ));
                    }
                }
            }
        }
    }

    plan.dedup_by(|a, b| a.1 == b.1 && a.2 == b.2);
    plan
}

#[tokio::main]
async fn main() {
    println!("🛡️ Booting ShieldCI Orchestrator...");

    let shield_config = load_shield_config();
    let config = if let Some(ref sc) = shield_config {
        config_from_yaml(sc)
    } else {
        fetch_config_from_shell()
    };

    launch_sandbox(&config);
    let _ = wait_for_target(&config.target_url, 15).await;

    let codebase = flatten_codebase(".");
    // In local mode tools are co-located — keep 127.0.0.1
    // In docker mode tools need host.docker.internal to reach the host
    let docker_url = if is_local_tools() {
        config.target_url.clone()
    } else {
        config.target_url.replace("127.0.0.1", "host.docker.internal")
    };

    // ── Generate dynamic test plan ──
    let test_plan = generate_test_plan(&shield_config, &docker_url);
    println!("\nTest Plan ({} tests):", test_plan.len());
    for (i, (phase, tool, target, _)) in test_plan.iter().enumerate() {
        println!("  {}. [{}] {} → {}", i + 1, phase, tool, target);
    }

    let mut attack_trace = String::new();
    let mut exploit_found = false;
    let total = test_plan.len();

    // ── Execute each planned test ──
    for (i, (phase, tool, target, extra_args)) in test_plan.iter().enumerate() {
        println!("\nTest {}/{}: {}", i + 1, total, phase);

        let tool_call = ToolCall { tool: tool.clone(), target: target.clone(), extra_args: extra_args.clone() };
        let output = execute_mcp_tool_stdio(&tool_call).await.unwrap_or_else(|e| e.to_string());

        attack_trace.push_str(&format!(
            "\n## Test {}: {} ({})\nTool: {} | Target: {}\n{}\n",
            i + 1, phase, if output.to_lowercase().contains("vulnerable") || output.to_lowercase().contains("payload") { "VULNERABLE" } else { "OK" },
            tool, target, output
        ));

        if output.to_lowercase().contains("vulnerable") || output.to_lowercase().contains("payload") {
            exploit_found = true;
            println!("Vulnerability detected in: {}", phase);
        }
    }

    // ── LLM-guided adaptive test: let the LLM pick additional attacks based on results ──
    let endpoint_info = if let Some(ref sc) = shield_config {
        build_endpoint_context(sc, &config.target_url)
    } else {
        String::new()
    };

    let db_info = if let Some(ref sc) = shield_config {
        if let Some(ref db) = sc.database {
            let db_type = db.db_type.as_deref().unwrap_or("unknown");
            let uses_orm = db.orm.unwrap_or(true);
            if uses_orm {
                format!("Database: {} (uses ORM)\n", db_type)
            } else {
                format!("Database: {} (raw SQL queries - HIGH RISK for SQL injection!)\n", db_type)
            }
        } else { String::new() }
    } else { String::new() };

    let adaptive_prompt = format!(
        "You are an expert penetration tester following PTES (Penetration Testing Execution Standard) \
and OWASP Testing Guide v4.2 methodology. Target: {docker_url}\n\
\n\
## Your Role: Result Correlation & Attack Chaining\n\
Do NOT just pick another tool randomly. Analyze the results below and identify:\n\
1. Attack chains: e.g., gobuster found /admin → try default creds with sqlmap or brute-force\n\
2. Unexplored surfaces: e.g., nmap found port 8443 → scan that too\n\
3. Findings that need validation: e.g., nuclei flagged XSS → confirm with targeted payload\n\
4. Missing OWASP Top 10 coverage: check which categories haven't been tested yet\n\
\n\
## Previous Scan Results (ANALYZE THESE CAREFULLY):\n{attack_trace}\n\
\n\
{db_info}\
{endpoint_info}\
\n\
## Application Source Code (look for patterns the scanners missed):\n{codebase}\n\
\n\
## Available tools (use EXACT names):\n\
- nmap_scan: target = \"{docker_url}\" — port scanning\n\
- check_headers: target = \"{docker_url}\" — security header check\n\
- nikto_scan: target = \"{docker_url}\" — legacy web vuln scanner\n\
- gobuster_scan: target = \"{docker_url}\" — directory brute-force\n\
- sqlmap_scan: target = URL with query params like \"{docker_url}/login?username=test\"\n\
- nuclei_scan: target = \"{docker_url}\" — 8000+ vulnerability templates\n\
- semgrep_scan: target = \".\" — static source code analysis\n\
- trivy_scan: target = \".\" — dependency CVE scanner\n\
- zap_scan: target = \"{docker_url}\" — OWASP ZAP DAST crawler\n\
\n\
## Instructions:\n\
Based on correlating ALL results above, pick the ONE most valuable next test.\n\
Explain your reasoning in 1 sentence, then respond with ONLY a JSON object:\n\
{{\"tool\": \"<tool_name>\", \"target\": \"<url_or_path>\"}}"
    );

    for i in 1..=2 {
        println!("\n--- Adaptive Strike {} (LLM-correlated) ---", i);
        let mut tool_call = ask_llm(&adaptive_prompt).await;
        // Ensure extra_args exist for new tools
        if tool_call.extra_args.is_empty() {
            tool_call.extra_args = HashMap::new();
        }
        let output = execute_mcp_tool_stdio(&tool_call).await.unwrap_or_else(|e| e.to_string());

        attack_trace.push_str(&format!(
            "\n## Adaptive Strike {}: {} on {}\n{}\n",
            i, tool_call.tool, tool_call.target, output
        ));

        if output.to_lowercase().contains("vulnerable") || output.to_lowercase().contains("payload") {
            exploit_found = true;
            println!("Vulnerability detected by adaptive strike!");
        }
    }

    // ── Generate final report ──
    let report = generate_report(&attack_trace, &codebase, exploit_found).await;
    fs::write("SHIELD_REPORT.md", &report).expect("Unable to write report");
    println!("\n--- FINAL REPORT ---\n{}\n Saved to SHIELD_REPORT.md", report);

    // ── Write structured JSON output for frontend API ──
    let vulnerabilities = parse_vulns_from_trace(&attack_trace);
    let scan_output = ScanOutput {
        status: if exploit_found { "Issues Found".into() } else { "Clean".into() },
        vulnerabilities,
        report_markdown: report,
    };
    let json_output = serde_json::to_string_pretty(&scan_output).unwrap_or_default();

    // Write to local file (path from env or default)
    let results_path = std::env::var("SHIELDCI_RESULTS_FILE")
        .unwrap_or_else(|_| "shield_results.json".to_string());
    fs::write(&results_path, &json_output).expect("Unable to write results JSON");
    println!("Saved structured results to {}", results_path);

    // ── Push results to collector (K8s mode) ──
    if let Ok(endpoint) = std::env::var("SHIELDCI_RESULTS_ENDPOINT") {
        let scan_id = std::env::var("SHIELDCI_SCAN_ID").unwrap_or_default();
        let tenant_id = std::env::var("SHIELDCI_TENANT_ID").unwrap_or_default();
        push_results_to_collector(&endpoint, &scan_id, &tenant_id, &json_output).await;
    }
}

/// Push scan results to the results-collector service (K8s mode).
async fn push_results_to_collector(endpoint: &str, scan_id: &str, tenant_id: &str, json_output: &str) {
    println!("Pushing results to collector: {}", endpoint);

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(
            std::env::var("SHIELDCI_SKIP_TLS_VERIFY").unwrap_or_default() == "1"
        )
        .build()
        .unwrap_or_default();

    let payload = serde_json::json!({
        "scanId": scan_id,
        "tenantId": tenant_id,
        "results": serde_json::from_str::<serde_json::Value>(json_output).unwrap_or_default(),
    });

    match client.post(endpoint)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                println!("Results pushed successfully (HTTP {})", status);
            } else {
                let body = resp.text().await.unwrap_or_default();
                eprintln!("Results push failed (HTTP {}): {}", status, body);
            }
        }
        Err(e) => {
            eprintln!("Results push error: {}", e);
        }
    }
}

/// Extract vulnerability entries from the attack trace.
fn parse_vulns_from_trace(trace: &str) -> Vec<VulnOutput> {
    let mut vulns = Vec::new();
    let sections: Vec<&str> = trace.split("\n## ").collect();

    for section in sections {
        let lower = section.to_lowercase();
        let is_vuln = lower.contains("vulnerable") || lower.contains("payload");
        if !is_vuln {
            continue;
        }

        // Extract the test name from the first line
        let first_line = section.lines().next().unwrap_or("");

        // Determine vulnerability type from the test name
        let vuln_type = if lower.contains("sqli") || lower.contains("sql injection") || lower.contains("sqlmap") {
            "SQL Injection"
        } else if lower.contains("xss") {
            "XSS"
        } else if lower.contains("header") {
            "Missing Security Headers"
        } else if lower.contains("nikto") {
            "Web Server Vulnerability"
        } else if lower.contains("gobuster") || lower.contains("discovery") {
            "Exposed Path"
        } else if lower.contains("nmap") || lower.contains("port") {
            "Open Port"
        } else if lower.contains("nuclei") {
            "Nuclei Finding"
        } else if lower.contains("semgrep") || lower.contains("sast") {
            "SAST Finding"
        } else if lower.contains("trivy") || lower.contains("sca") || lower.contains("dependency") {
            "Vulnerable Dependency"
        } else if lower.contains("zap") || lower.contains("csrf") || lower.contains("idor") {
            "DAST Finding"
        } else {
            "Security Issue"
        };

        // Determine severity
        let severity = if lower.contains("sql injection") || lower.contains("sqlmap") || lower.contains("sqli") || lower.contains("critical") {
            "Critical"
        } else if lower.contains("xss") || lower.contains("auth") || lower.contains("high") {
            "High"
        } else if lower.contains("header") || lower.contains("nikto") || lower.contains("medium") {
            "Medium"
        } else {
            "Low"
        };

        // Extract target URL for file reference
        let file = section.lines()
            .find(|l| l.contains("Target:"))
            .map(|l| l.split("Target:").last().unwrap_or("").trim().to_string())
            .unwrap_or_default();

        let description = first_line.trim().to_string();

        vulns.push(VulnOutput {
            file,
            line: 0,
            vuln_type: vuln_type.into(),
            severity: severity.into(),
            description,
            code_snippet: String::new(),
            fix_snippet: String::new(),
        });
    }

    vulns
}
