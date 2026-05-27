# 🚀 Aegis-SRE Demo Walkthrough

Welcome to the **Aegis-Antigravity SRE** demo! This document outlines the "Golden Path" script to showcase the capabilities of the agent for the hackathon.

## 1. Environment Setup

Ensure you have installed the required dependencies and that the Coral CLI is configured.

```bash
pip install -r requirements.txt
# Ensure mock Parquet data is generated
python3 scratch/generate_mock_parquet.py
```

Check your `.env` file to ensure the `OPENAI_API_KEY` is either set correctly (for OpenAI or Gemini) or leave it empty to trigger the fallback Mock AI behavior.

## 2. Launching the App

Start the Reflex application locally:
```bash
reflex run
```

Open your browser to `http://localhost:3000`.

## 3. The Demo Script (Golden Path)

1. **Upload Logs**: On the UI, upload the mock log file `server_telemetry.parquet` (located in the `logs/` directory).
2. **Trigger Investigation**: In the chat prompt, enter the following query:
   > "I'm seeing 500 errors from the api-gateway since this morning. Please investigate using the uploaded server telemetry, the OSV vulnerabilities database, and our GitHub commits. Pay special attention to any commits from TANISHX1."
3. **Observe the Agent**:
   - The UI will stream real-time updates using the `yield` generator architecture.
   - You will see the agent construct a multi-hop `JOIN` query using Coral.
   - It will query `local_file.logs`, `osv.packages`, and `github.commits`.
   - The query execution happens natively via the Coral CLI binary, securely isolated.
4. **Automated Remediation**: 
   - The agent will identify the root cause (`urllib3` CVE-2023-43804 introduced by TANISHX1).
   - The agent will use the `trigger_n8n_workflow` tool to dispatch a remediation action.
   - If n8n isn't running, it gracefully falls back to "Standby" mode and returns a 202 status.

## 4. Key Highlights to Emphasize to Judges
* **Zero-Warehouse Architecture**: We don't ingest the Parquet files into a Postgres or Snowflake DB. Coral queries them in place.
* **Security & Isolation**: The Coral executor uses strict `subprocess.run(shell=False)` with bounded timeouts to prevent shell-injection and compute starvation.
* **Agentic Streaming**: The UI is never frozen. By leveraging Python Generators, the LLM streams its intermediate thoughts and tool executions to the frontend instantly.
* **Dual LLM Native SDK Support**: Automatically supports native `google-genai` SDK and the standard OpenAI API format!
