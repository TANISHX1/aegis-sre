# 🚀 Aegis-SRE Demo Walkthrough

Welcome to the **Aegis-Antigravity SRE** demo! This document outlines the "Golden Path" script to showcase the full capabilities of the agent.

---

## 1. Environment Setup

Ensure you have installed the required dependencies and that the Coral CLI is configured.

```bash
pip install -r requirements.txt

# Generate live telemetry (fetches real GitHub commits into crash logs)
python3 tools/generate_live_telemetry.py

# Register all Coral sources with correct paths
python3 setup_sources.py
```

Verify your `.env` file has at least one LLM API key set (`GEMINI_API_KEY`, `GROQ_API_KEY`, or `OPENAI_API_KEY`). If no key is set, the agent will operate in **Mock Simulation Mode** — still functional but without real AI reasoning.

## 2. Launching the App

Start the Reflex application locally:
```bash
reflex run
```

Open your browser to `http://localhost:3000`.

## 3. The Demo Script (Golden Path)

1. **Upload Logs**: On the UI, drag `logs/api_gateway_telemetry.parquet` (from the `logs/` directory) into the **Forensic Control** dropzone on the left sidebar.

2. **Trigger Investigation**: In the chat prompt at the bottom, enter the following query:
   > "We are seeing a massive spike in 500 errors in our production api-gateway. Scan our server logs, cross-reference with the OSV vulnerability database, check recent commits in the repository, and trigger a remediation alert if a root cause is found."

3. **Observe the Agent**:
   - The **Agent Cognitive Log Stream** panel will display real-time reasoning updates using the `yield` generator architecture.
   - You will see the agent construct a multi-hop `JOIN` query using Coral SQL.
   - It will query `local_file.api_gateway_logs`, `osv.packages`, and `github.commits`.
   - The query execution happens via the MCP protocol to Coral's built-in server.

4. **Dynamic Topology Update**:
   - The agent will use the `update_threat_topology` tool to redraw the **Blast Radius** SVG graph based on discovered microservice architecture.
   - Affected nodes will transition from "Healthy" to "Degraded" with smooth CSS animations.

5. **Automated Remediation**: 
   - The agent will identify the root cause (e.g., a vulnerable package version introduced in a recent commit).
   - The agent will use the `trigger_n8n_workflow` tool to dispatch a remediation action.
   - Check `n8n_data/incident_log.jsonl` for the audit trail, or visit your n8n dashboard at `http://localhost:5678`.

## 4. Alternative: CLI Test

For a non-UI demonstration, run the complete investigation pipeline from the terminal:

```bash
python3 test_runner.py
```

This executes the full agent loop with diagnostic output, showing every Coral SQL query, tool call, and final report.

## 5. Key Highlights to Emphasize to Judges

* **Zero-Warehouse Architecture**: We don't ingest Parquet files into Postgres or Snowflake. Coral queries them in place — no ETL pipeline, no warehouse costs.
* **MCP-Native Integration**: We communicate with Coral via its MCP server (`coral mcp-stdio`) over JSON-RPC 2.0, enabling persistent connections, runtime schema discovery, and structured responses.
* **6/6 Coral Features Used**: SQL, cross-source JOINs, schema learning, MCP integration, source management, and catalog discovery.
* **Three Agent Tools**: `execute_coral_query` (read), `trigger_n8n_workflow` (act), and `update_threat_topology` (visualize) — giving the agent a complete read-act-visualize loop.
* **Security & Isolation**: The Coral executor uses strict `subprocess.run(shell=False)` with bounded timeouts. File uploads are sandboxed with `os.path.basename()`.
* **Agentic Streaming**: The UI is never frozen. Python generators yield intermediate thoughts and tool executions to the frontend instantly via WebSocket.
* **Multi-Provider LLM Support**: Automatically supports Gemini (native SDK), Groq (Llama 3.3 70B), and OpenAI (GPT-4o) with graceful mock fallback.
* **Resilient Webhook Automation**: Auto-starts a local receiver if n8n isn't running, with Slack/Discord forwarding and JSONL audit trails.
