FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install core security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    sqlmap nmap nikto gobuster wpscan curl wget unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei (ProjectDiscovery) — 8000+ vulnerability templates
RUN wget -qO /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m | sed 's/x86_64/amd64/').zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates 2>/dev/null || true

# Install Semgrep (SAST) and Trivy (SCA)
RUN pip3 install semgrep --break-system-packages
RUN wget -qO- https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install the official MCP SDK
RUN pip3 install "mcp[cli]" --break-system-packages

WORKDIR /app
COPY kali_mcp.py .

# Expose the tools via our custom Python adapter
ENTRYPOINT ["python3", "kali_mcp.py"]