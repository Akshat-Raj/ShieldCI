FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install the "Big Five" of automated web security
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    sqlmap nmap nikto gobuster wpscan curl \
    && rm -rf /var/lib/apt/lists/*

# Install the official MCP SDK
RUN pip3 install "mcp[cli]" --break-system-packages

WORKDIR /app
COPY kali_mcp.py .

# Expose the tools via our custom Python adapter
ENTRYPOINT ["python3", "kali_mcp.py"]