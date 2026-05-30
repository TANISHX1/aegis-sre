# 🛡️ Aegis-SRE
### Zero-Warehouse Root-Cause Investigation & Cyber-Incident Remediation Agent
*Developed for **Track 1 (Enterprise Agent)** of the **"Pirates of the Coral-bean" Hackathon***

---

Aegis-SRE is a next-generation, high-performance incident response platform built entirely in **pure Python** using the Reflex framework. 

Operating on a strict **Zero-Warehouse** philosophy, Aegis enables cybersecurity teams to query, join, and inspect telemetric forensic logs locally, cross-reference vulnerabilities in real-time, trace security leaks back to specific git committers, and dispatch automated remediation protocols via resilient webhooks—**all without the overhead of heavy third-party datastores.**

It uses the **Coral CLI** to perform real-time, multi-hop federated `JOIN` operations across raw Parquet files, Google OSV vulnerability databases, and live GitHub commit histories.

---

## 🧭 High-Level System Architecture

Aegis-SRE utilizes a highly modular multi-hop cognitive layout where an AI Orchestrator acts as the "Brain", Coral acts as the "Data Layer", and the Webhook Receiver acts as the "Action Layer".

```mermaid
graph TD
    %% Core Nodes
    User["👨‍💻 Operator Console (Reflex UI)"]
    State["🧠 Application State (aegis_app.py)"]
    Brain["🤖 SRE Brain (Gemini / Groq / OpenAI)"]
    MCP["🔌 Coral MCP Client"]
    CoralServer["⚙️ Coral MCP Server (mcp-stdio)"]
    Webhook["⚡ Webhook Receiver (Auto-Start)"]
    
    %% Data Sources
    Parquet[("📄 local_file.* (.parquet)")]
    OSV[("🛡️ osv.packages")]
    Git[("🐙 github.commits (Live API)")]
    
    %% External Integrations
    Slack["💬 Slack"]
    Discord["🎮 Discord"]

    %% Execution Path
    User -->|Asks Question & Drops Log File| State
    State -->|Triggers @rx.background Generator| Brain
    
    %% MCP Query Path
    Brain -->|Step 1: Write SQL via Function Calling| MCP
    MCP -->|JSON-RPC 2.0 over stdio| CoralServer
    CoralServer -->|Federated Query| Parquet
    CoralServer -->|Cross-Reference JOIN| OSV
    CoralServer -->|Live GitHub API| Git
    
    %% Results Path
    Parquet -.->|Telemetry Records| CoralServer
    OSV -.->|Vulnerability Matches| CoralServer
    Git -.->|Real Commit History| CoralServer
    CoralServer -.->|Structured MCP Response| MCP
    MCP -.->|Parsed Results| Brain
    
    %% Remediation Path
    Brain -->|Step 2: Dispatch Remediation| Webhook
    Brain -->|Step 3: Update Topology| State
    Webhook -.->|Forward Alert| Slack
    Webhook -.->|Forward Alert| Discord
    Webhook -.->|Audit Log| User
    
    %% Styling
    classDef ui fill:#3b82f6,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef agent fill:#8b5cf6,stroke:#5b21b6,stroke-width:2px,color:#fff
    classDef mcp fill:#6366f1,stroke:#4338ca,stroke-width:2px,color:#fff
    classDef data fill:#10b981,stroke:#047857,stroke-width:2px,color:#fff
    classDef action fill:#ef4444,stroke:#b91c1c,stroke-width:2px,color:#fff
    classDef ext fill:#f59e0b,stroke:#d97706,stroke-width:2px,color:#fff
    
    class User,State ui
    class Brain agent
    class MCP,CoralServer mcp
    class Parquet,OSV,Git data
    class Webhook action
    class Slack,Discord ext
```

---

## 🔄 Sequence Workflows

### 1. Forensic SQL Generation & Execution
This workflow illustrates how the AI translates natural language into a fully federated Coral SQL query.

```mermaid
sequenceDiagram
    participant U as Operator
    participant UI as Reflex App
    participant AI as SRE Brain (Gemini)
    participant C as Coral MCP Server
    participant GH as GitHub API
    
    U->>UI: Upload 'api_gateway_telemetry.parquet'
    U->>UI: "Investigate 500 errors in api-gateway"
    UI->>AI: Trigger @rx.background forensic loop
    
    activate AI
    AI-->>UI: yield: "Analyzing SRE request..."
    AI->>AI: Introspect schemas (local_file, osv, github)
    AI->>C: Call tool 'execute_coral_query(SQL)'
    
    activate C
    C->>C: Scan local_file.api_gateway_logs
    C->>C: JOIN osv.packages
    C->>GH: JOIN github.commits (LIVE API)
    GH-->>C: Real commit data
    C-->>AI: JSON Result Array
    deactivate C
    
    AI-->>UI: yield: "Found CVE-2023-43804 in urllib3!"
    AI->>AI: Call 'update_threat_topology' to redraw graph
    AI-->>UI: yield: Topology nodes & edges → SVG redrawn
    deactivate AI
```

### 2. Automated Remediation Dispatch
This workflow demonstrates the auto-start webhook receiver and optional Slack/Discord forwarding.

```mermaid
sequenceDiagram
    participant AI as SRE Brain
    participant D as Dispatcher
    participant W as Webhook Receiver
    participant S as Slack/Discord
    participant F as Audit File
    
    AI->>D: Call 'trigger_n8n_workflow(Payload)'
    activate D
    D->>D: health_check() → Is receiver alive?
    
    alt Receiver Online
        D->>W: HTTP POST /webhook/aegis-sre-remediate
    else Receiver Offline
        D->>D: _auto_start_local_receiver()
        Note over D: Starts background Python server on :5678
        D->>W: HTTP POST /webhook/aegis-sre-remediate
    end
    
    activate W
    W->>F: Append to n8n_data/incident_log.jsonl
    W->>S: Forward (if SLACK/DISCORD_WEBHOOK_URL set)
    W-->>D: 200 OK
    deactivate W
    
    D-->>AI: Success
    deactivate D
```

### 3. Intelligent LLM Routing & Fallback

```mermaid
flowchart TD
    Start["SREBrain.__init__()"] --> CheckGemini{"GEMINI_API_KEY set?"}
    CheckGemini -->|Yes| GeminiSDK["Initialize google-genai Client"]
    CheckGemini -->|No| CheckGroq{"GROQ_API_KEY set?"}
    CheckGroq -->|Yes| GroqSDK["Initialize Groq Client (Llama 3.3 70B)"]
    CheckGroq -->|No| CheckOpenAI{"OPENAI_API_KEY set?"}
    CheckOpenAI -->|Yes| OpenAISDK["Initialize OpenAI Client"]
    CheckOpenAI -->|No| MockMode["🔧 Mock Simulation Mode"]
    
    GeminiSDK --> LiveLoop["run_gemini_native_loop()"]
    GroqSDK --> OpenAILoop["run_investigation_loop()"]
    OpenAISDK --> OpenAILoop
    
    LiveLoop -->|API Error/Rate Limit| Fallback["Graceful Mock Fallback"]
    OpenAILoop -->|API Error| Fallback
    Fallback --> MockMode
    MockMode --> Result["✅ Investigation Complete"]
    LiveLoop --> Result
    OpenAILoop --> Result
    
    style MockMode fill:#f59e0b,stroke:#d97706,color:#000
    style GeminiSDK fill:#4285f4,stroke:#1a73e8,color:#fff
    style GroqSDK fill:#f97316,stroke:#ea580c,color:#fff
    style OpenAISDK fill:#10a37f,stroke:#0d8c6d,color:#fff
```

---

## ✨ Core Engineering Innovations

### 1. MCP-Native Coral Integration (Model Context Protocol)
* **MCP-First Architecture**: Instead of shelling out to `coral sql`, we maintain a persistent MCP connection to Coral's built-in MCP server (`coral mcp-stdio`) via JSON-RPC 2.0 over stdin/stdout.
* **Runtime Schema Discovery**: The `discover_schema()` method auto-introspects all registered Coral sources at startup — the LLM learns table structures dynamically instead of from hardcoded prompts.
* **5 MCP Tools**: `sql`, `list_catalog`, `search_catalog`, `describe_table`, `list_columns` — all accessible through the persistent connection.
* **Three-Tier Fallback**: MCP → subprocess → mock simulation. If MCP fails, the system gracefully degrades without crashing.

### 2. Zero-Warehouse Federated Analytics & Live Telemetry
* **No Database Required**: All data is stored in localized Parquet files. We register these via Coral Source Manifests to run complex cross-source JOINs natively.
* **OSV Vulnerability Intelligence**: The `osv.packages` source provides a CVE cross-reference layer — crash logs are automatically matched against known package vulnerabilities.
* **Live Telemetry Injection**: The `tools/generate_live_telemetry.py` script fetches the latest real commit from your GitHub repository and dynamically injects it into crash logs, creating 100% authentic test scenarios without hardcoded mocks.

### 3. Live GitHub Integration
* **Real Commit Scanning**: When `GITHUB_TOKEN` is provided, the agent queries live GitHub commits via Coral's native GitHub plugin — no mocks needed.
* **Repository Targeting**: Specify `GITHUB_REPO=owner/repo` in `.env` to focus scans on any repository.
* **Dynamic Schema**: Real `github.commits` schema (sha, commit__message, commit__author__name, files, stats) auto-discovered via MCP.

### 4. Multi-Provider LLM Agent with Native Tool Calling
* **Gemini, Groq & OpenAI Support**: The `sre_brain.py` checks `GEMINI_API_KEY` first, then `GROQ_API_KEY`, then `OPENAI_API_KEY`. The Gemini path uses the native `google-genai` SDK with manual function calling (AFC disabled for UI streaming).
* **Three Agent Tools**: `execute_coral_query`, `trigger_n8n_workflow`, and `update_threat_topology` — giving the agent full read, act, and visualize capabilities.
* **Graceful Mock Fallback**: If API keys are missing OR the API returns an error (rate limits, etc.), the agent safely falls back to a hardcoded simulation loop.

### 5. Dynamic Threat Topology Visualization
* **Agent-Driven Architecture Mapping**: The `update_threat_topology` tool allows the LLM to dynamically redraw the Blast Radius SVG graph with real microservice nodes and edges discovered during investigation.
* **Reactive SVG Rendering**: All topology nodes and edges are state-driven — when the agent updates them, the UI smoothly transitions via CSS animations.

### 6. Resilient Webhook Automation
* **Dockerized n8n Integration**: Spin up a fully containerized n8n instance via our provided `docker-compose.yml`. Easily import the provided `n8n_workflow.json` to activate the SRE remediation webhook on port 5678.
* **Auto-Start Local Webhook Receiver**: If Docker isn't available, the dispatcher automatically boots a lightweight Python webhook server on port 5678 to ensure payloads are never dropped.
* **Audit Trail**: Every incident is securely logged to `n8n_data/incident_log.jsonl`.
* **Slack/Discord Forwarding**: Set `SLACK_WEBHOOK_URL` or `DISCORD_WEBHOOK_URL` in `.env` to forward real-time alerts with rich formatting (Slack Block Kit / Discord Embeds).

### 7. Non-Blocking Background Investigations
* **`@rx.background` Decorator**: The investigation loop runs in a background thread, keeping the Reflex WebSocket unblocked so the UI streams real-time thoughts without freezing.

---

## 🚀 Setting Up the Environment

### 1. Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Install Coral CLI
```bash
curl -fsSL https://withcoral.com/install.sh | sh
```

### 3. Configure Environment
Create a `.env` file in the project root:
```ini
# LLM API Key (pick one — Gemini recommended for native tool calling)
GEMINI_API_KEY=your-gemini-key-here
# GROQ_API_KEY=your-groq-key-here
# OPENAI_API_KEY=your-openai-key-here

# Live GitHub integration (optional but recommended)
GITHUB_TOKEN=your-github-pat-here
GITHUB_REPO=YourOrg/your-repo

# Webhook config (auto-configured, no changes needed)
N8N_WEBHOOK_URL=http://localhost:5678/webhook/aegis-sre-remediate

# Optional: Forward alerts to Slack/Discord
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK
# DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK
```

### 4. Setup Live Dependencies (Telemetry & n8n)
```bash
# Generate live telemetry logs injected with real GitHub commits
python3 tools/generate_live_telemetry.py

# (Optional) Spin up real n8n server on port 5678 via Docker
sudo docker-compose up -d
```
*Note: Once n8n is running, import `n8n_workflow.json` in the UI (`http://localhost:5678`) and click Publish!*

### 5. Register Coral Sources
```bash
python3 setup_sources.py
```
This single command:
- Generates 3 telemetry Parquet files (API Gateway, Auth Service, Payment Gateway)
- Creates OSV vulnerability mock data
- Creates GitHub commits mock data
- Generates YAML manifests with correct absolute paths for your machine
- Registers all sources with Coral CLI

### 6. Launch the Application
```bash
reflex run
```
Navigate to: 👉 **[http://localhost:3000](http://localhost:3000)**

---

## 🔍 The "Golden Path" Demo Script

Follow this script to demonstrate the app for the hackathon:

1. **Upload Telemetry**: Drag `logs/api_gateway_telemetry.parquet` into the **Forensic Control** dropzone.
2. **Launch Investigation**: Type this prompt:
   > *"We are seeing a massive spike in 500 errors in our production api-gateway. Scan our server logs, cross-reference with the OSV vulnerability database, check recent commits in the repository, and trigger a remediation alert if a root cause is found."*
3. **Watch the Agent Think**: The **Agent Cognitive Log** panel streams real-time thoughts as the AI writes and executes Coral `JOIN` statements.
4. **Observe Remediation**: The AI detects the CVE, traces it to a specific commit author, dynamically redraws the Blast Radius topology, and fires the remediation webhook to n8n. Check `n8n_data/incident_log.jsonl` or your n8n dashboard for the payload.

### CLI Test (Alternative)
```bash
python3 test_runner.py
```
Runs the complete investigation loop from the terminal with full diagnostic output.

---

## 📁 Project Structure
```
aegis-sre/
├── aegis_app/
│   └── aegis_app.py          # Reflex UI (glassmorphic dashboard)
├── agent/
│   └── sre_brain.py           # AI reasoning engine (Gemini/Groq/OpenAI + 3 tools)
├── tools/
│   ├── mcp_client.py          # Coral MCP client (JSON-RPC 2.0 over stdio)
│   ├── coral_executor.py      # Query executor (MCP → subprocess → mock)
│   ├── n8n_dispatcher.py      # Webhook dispatcher with auto-start & retry
│   ├── webhook_receiver.py    # Local webhook server (n8n replacement)
│   └── generate_live_telemetry.py  # Live GitHub commit → crash log injector
├── logs/                      # Parquet telemetry files
├── n8n_data/                  # Audit trail (auto-created)
├── setup_sources.py           # One-click Coral source registration
├── test_runner.py             # CLI diagnostic test
├── docker-compose.yml         # n8n container orchestration
├── n8n_workflow.json          # Pre-configured n8n webhook workflow
├── .env                       # API keys & config (gitignored)
├── requirements.txt           # Python dependencies
└── rxconfig.py                # Reflex compiler config
```
