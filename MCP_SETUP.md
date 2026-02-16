# Kafka-MCP Setup Guide

Step-by-step instructions for configuring Kafka-MCP in **Cursor** and **Microsoft Visual Studio Code**.

## Prerequisites

1. **Python 3.9+** installed and available on your PATH
2. **Install dependencies:**

```bash
cd /path/to/kafka-mcp
pip install -r requirements.txt
```

3. **Verify installation:**

```bash
python -c "from kafka_mcp.server import mcp; print(f'Kafka-MCP loaded: {len(mcp._tool_manager._tools)} tools')"
```

You should see: `Kafka-MCP loaded: 30 tools`

---

## Cursor Setup

### Quick Start (Clone and Go)

This repository is pre-configured for Cursor. Just clone it, install dependencies, and open as your workspace:

```bash
git clone https://github.com/gglessner/kafka-mcp.git
cd kafka-mcp
pip install -r requirements.txt
```

Then open the `kafka-mcp` directory as a project in Cursor. Everything is automatic:

- **`.cursor/mcp.json`** — registers the MCP server (30 tools appear immediately)
- **`.cursor/skills/kafka-mcp/SKILL.md`** — skill that teaches the AI assistant all tool usage, authentication options, and JSON argument formats

No manual configuration needed. The AI assistant will have full knowledge of all 30 Kafka tools as soon as you open the project.

### Verifying in Cursor

1. Open Cursor Settings (Ctrl+Shift+P > "Cursor Settings")
2. Navigate to the **MCP** section
3. You should see `kafka-mcp` listed with 30 tools
4. If it shows "Error", click the restart button next to the server name

### Using from a Different Project

If you want to use Kafka-MCP from a different workspace, add to that project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "kafka-mcp": {
      "command": "python",
      "args": ["run_kafka_mcp.py"],
      "cwd": "/absolute/path/to/kafka-mcp"
    }
  }
}
```

Optionally copy the `.cursor/skills/kafka-mcp/` directory into that project's `.cursor/skills/` so the AI assistant knows how to use the tools.

### Global Configuration (All Projects)

To make Kafka-MCP available across all Cursor projects, edit your global MCP config:

- **Windows:** `%APPDATA%\Cursor\mcp.json`
- **macOS:** `~/Library/Application Support/Cursor/mcp.json`
- **Linux:** `~/.config/Cursor/mcp.json`

---

## Visual Studio Code Setup

VS Code supports MCP servers through extensions that implement the MCP client protocol.

### Option A: Using a VS Code MCP Extension

1. Install an MCP-compatible extension from the VS Code marketplace (e.g., "Continue", "Cline", or any extension supporting MCP stdio transport)

2. Configure the extension to use Kafka-MCP. Most extensions read from a config file. Example for a typical MCP extension:

```json
{
  "mcpServers": {
    "kafka-mcp": {
      "command": "python",
      "args": ["run_kafka_mcp.py"],
      "cwd": "/absolute/path/to/kafka-mcp"
    }
  }
}
```

3. The config file location depends on the extension:
   - **Continue:** `.continue/config.json` in your workspace
   - **Cline:** `.cline/mcp_settings.json` in your workspace
   - Check your extension's documentation for the exact path

### Option B: Using VS Code's Built-in MCP Support

VS Code 1.99+ has built-in MCP support (as of early 2026):

1. Open Settings (Ctrl+,)
2. Search for "mcp"
3. Click "Edit in settings.json"
4. Add the Kafka-MCP server:

```json
{
  "mcp.servers": {
    "kafka-mcp": {
      "command": "python",
      "args": ["run_kafka_mcp.py"],
      "cwd": "/absolute/path/to/kafka-mcp"
    }
  }
}
```

### Option C: Workspace-level Configuration

Create `.vscode/mcp.json` in your workspace root:

```json
{
  "servers": {
    "kafka-mcp": {
      "command": "python",
      "args": ["run_kafka_mcp.py"],
      "cwd": "/absolute/path/to/kafka-mcp"
    }
  }
}
```

---

## Verifying the Setup

Once configured, test the connection from your AI assistant:

1. **Connect to a broker:**
   > "Connect to my Kafka broker at localhost:9092"

2. **With authentication:**
   > "Connect to Kafka at broker.example.com:9093 using SASL_SSL with SCRAM-SHA-256, username admin, password secret"

3. **Run a security audit:**
   > "Run a security audit on the connected broker"

4. **List topics:**
   > "Show me the cluster metadata"

---

## Troubleshooting

### "Error: Aborted" or server won't start

1. Check Python is on your PATH: `python --version`
2. Check dependencies are installed: `pip list | grep mcp`
3. Test manually: `cd /path/to/kafka-mcp && python run_kafka_mcp.py`

### Tools show 0 or server appears but no tools

1. Restart the MCP server (click restart button in Cursor MCP settings)
2. Verify the `cwd` path is correct and contains `run_kafka_mcp.py`

### "confluent-kafka not available" warnings

The 10 `kafka_hl_*` tools require the optional `confluent-kafka` package:

```bash
pip install confluent-kafka>=2.6.0
```

The 20 raw protocol tools (`kafka_*`) work without it.

### Connection hangs or times out

- Verify the Kafka broker is reachable: `python -c "import socket; s=socket.socket(); s.settimeout(5); s.connect(('host', 9092)); print('OK'); s.close()"`
- Check security protocol matches the broker's listener configuration
- For SASL brokers, ensure you pass `security_protocol="SASL_PLAINTEXT"` (or `SASL_SSL`)

### Windows-specific issues

- Use `python` not `python3` in the command field
- Ensure paths use forward slashes or escaped backslashes in JSON
- If using a virtual environment, use the full path to the Python executable:
  ```json
  "command": "C:/Users/yourname/venv/Scripts/python.exe"
  ```
