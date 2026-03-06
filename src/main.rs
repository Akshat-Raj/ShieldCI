use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

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
}

fn fetch_config_from_shell() -> TargetConfig {
    println!("🔍 Calling detect.sh to scout the repository...");
    if !Path::new("detect.sh").exists() {
        return TargetConfig {
            framework: "Node.js".to_string(),
            build_command: "npm install".to_string(),
            run_command: "node app.js".to_string(),
            target_url: "http://127.0.0.1:3000".to_string(),
        };
    }

    let output = Command::new("bash").arg("detect.sh").output().expect("Failed to execute detect.sh");
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
        println!("⚙️  Running build: {}", config.build_command);
        let parts: Vec<&str> = config.build_command.split_whitespace().collect();
        let _ = Command::new(parts[0]).args(&parts[1..]).status();
    }

    println!("🚀 Launching {} server on {}...", config.framework, config.target_url);
    let run_parts: Vec<&str> = config.run_command.split_whitespace().collect();
    Command::new(run_parts[0])
        .args(&run_parts[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start the target application server");
}

async fn wait_for_target(url: &str, max_retries: u8) -> Result<(), String> {
    println!("⏳ Waiting for target {} to come online...", url);
    let client = Client::builder().timeout(Duration::from_secs(2)).build().unwrap();
    for _ in 1..=max_retries {
        if client.get(url).send().await.is_ok() {
            println!("✅ Target is up and responding!");
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    Err(format!("❌ Target {} failed to respond.", url))
}

fn flatten_codebase(dir: &str) -> String {
    println!("Recursively flattening codebase for full context...");
    let mut full_code = String::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
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

async fn ask_llm(system_prompt: &str) -> ToolCall {
    println!("🧠 Invoking local model via Ollama API...");
    let client = Client::new();
    let req_body = serde_json::json!({
        "model": "qwen2.5-coder:7b",
        "prompt": system_prompt,
        "stream": false,
        "format": "json"
    });

    let res = client.post("http://localhost:11434/api/generate").json(&req_body).send().await.expect("Ollama error");
    let res_json: serde_json::Value = res.json().await.unwrap();
    let response_text = res_json["response"].as_str().unwrap_or("{}");
    
    // Safety check for empty JSON
    if !response_text.contains("\"tool\"") {
        return ToolCall { 
            tool: "sqlmap_scan".to_string(), 
            target: "http://host.docker.internal:3000/login?username=test".to_string() 
        };
    }

    serde_json::from_str(response_text).unwrap_or(ToolCall { 
        tool: "sqlmap_scan".to_string(), 
        target: "http://host.docker.internal:3000/login?username=test".to_string() 
    })
}

async fn execute_mcp_tool_stdio(tool_call: &ToolCall) -> Result<String, Box<dyn std::error::Error>> {
    println!("🤝 Initiating MCP Handshake & Strike: {} on {}", tool_call.tool, tool_call.target);
    
    let mut child = Command::new("docker")
        .args(["run", "-i", "--rm", "--network", "host", "shieldci-kali-image"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout);

    // Step 1: Initialize
    let init = r#"{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "shieldci", "version": "1.0"}}}"#;
    writeln!(stdin, "{}", init)?;
    let mut line = String::new();
    reader.read_line(&mut line)?;

    // Step 2: Call Tool
    let mcp_args = serde_json::json!({ "url": tool_call.target.replace("127.0.0.1", "host.docker.internal") });
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
    println!("📝 Compiling final security assessment...");
    let client = Client::new();
    let status = if success { "VULNERABILITY DISCOVERED" } else { "NO VULNERABILITIES DETECTED" };
    
    let prompt = format!(
        "Generate a professional Markdown security report for status: {}.\nLogs:\n{}\nSource:\n{}",
        status, trace, codebase
    );

    let req_body = serde_json::json!({"model": "qwen2.5-coder:7b", "prompt": prompt, "stream": false});
    let res = client.post("http://localhost:11434/api/generate").json(&req_body).send().await.expect("Ollama error");
    let res_json: serde_json::Value = res.json().await.unwrap();
    res_json["response"].as_str().unwrap_or("Report failed.").to_string()
}

#[tokio::main]
async fn main() {
    println!("🛡️ Booting ShieldCI Orchestrator...");
    let config = fetch_config_from_shell();
    launch_sandbox(&config);
    let _ = wait_for_target(&config.target_url, 15).await;

    let codebase = flatten_codebase(".");
    let mut attack_trace = String::new();
    let mut exploit_found = false;

    let mut prompt = format!("You are an Elite Red Team Auditor. Target: http://host.docker.internal:3000. \
    Phase 1: RECON. Use nmap_scan or check_headers to understand the target. \
    Phase 2: VULNERABILITY RESEARCH. Use nikto_scan or gobuster_scan to find weak points. \
    Phase 3: EXPLOITATION. Use sqlmap_scan if you find database entry points. \
    
    Codebase context for logic flaws: {}\n\n\
    Return ONLY JSON with 'tool' and 'target'.", codebase
    );

    for i in 1..=3 {
        println!("\n--- Strike Iteration {} ---", i);
        let tool_call = ask_llm(&prompt).await;
        let output = execute_mcp_tool_stdio(&tool_call).await.unwrap_or_else(|e| e.to_string());
        
        attack_trace.push_str(&format!("\nIteration {}: {}\n", i, output));
        
        if output.to_lowercase().contains("vulnerable") || output.to_lowercase().contains("payload") {
            exploit_found = true;
            break;
        }
        prompt.push_str(&format!("\nObservation: {}", output));
    }

    let report = generate_report(&attack_trace, &codebase, exploit_found).await;
    fs::write("SHIELD_REPORT.md", &report).expect("Unable to write report");
    println!("\n--- FINAL REPORT ---\n{}\n✅ Saved to SHIELD_REPORT.md", report);
}