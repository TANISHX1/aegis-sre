# 🛡️ Aegis-SRE: Capabilities & Proof of Working

> **Document Purpose**: This document provides a complete overview of all features, their current working status, and live proof outputs for contributors and hackathon judges.
>
> **Repo**: [Harshit7623/aegis-sre](https://github.com/Harshit7623/aegis-sre)

---

## 📋 Table of Contents

1. [What Aegis-SRE Does](#-what-aegis-sre-does)
2. [Architecture Overview](#-architecture-overview)
3. [Coral Features Used](#-coral-features-used-hackathon-scoring)
4. [Feature Matrix](#-feature-matrix)
5. [Proof of Working](#-proof-of-working)
6. [Project Statistics](#-project-statistics)
7. [How to Run](#-how-to-run)
8. [For Contributors](#-for-contributors)

---

## 🎯 What Aegis-SRE Does

Aegis-SRE is an **AI-powered SRE forensics agent** that investigates production incidents by:

1. **Ingesting crash logs** (Parquet format) from a company's server infrastructure
2. **Cross-referencing** those logs with known vulnerability databases (Google OSV)
3. **Scanning GitHub commits** to identify which commit and developer may have introduced the error
4. **Dynamically mapping** the affected microservice topology in a reactive SVG graph
5. **Dispatching remediation alerts** to Slack/Discord via webhooks
6. **Presenting findings** in a real-time dashboard with streaming agent reasoning

All of this is powered by **Coral** as the federated SQL engine and an **LLM** (Gemini/Groq/OpenAI) as the reasoning brain.

### The Flow

```
User drops log file → LLM writes SQL → Coral JOINs logs + vulns + commits → LLM reasons → Topology redrawn → Alert dispatched
```

---

## 🏗️ Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│                    AEGIS-SRE ARCHITECTURE                      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│   👨‍💻 Reflex UI (aegis_app.py)                                 │
│      │                                                         │
│      ▼                                                         │
│   🤖 SRE Brain (sre_brain.py)                                  │
│      │  Provider: Gemini > Groq > OpenAI > Mock                │
│      │  Model:    Gemini 3.1 Flash / Llama 3.3 70B / GPT-4o   │
│      │                                                         │
│      ├──► 🔌 Coral MCP Client (mcp_client.py)                  │
│      │       │  Protocol: JSON-RPC 2.0 over stdin/stdout       │
│      │       ▼                                                  │
│      │    ⚙️ Coral MCP Server (coral mcp-stdio)                │
│      │       ├── 📄 local_file.* (Parquet logs)                │
│      │       ├── 🛡️ osv.packages (Vulnerability DB)            │
│      │       └── 🐙 github.commits (Live GitHub API)           │
│      │                                                         │
│      ├──► ⚡ Webhook Dispatcher (n8n_dispatcher.py)             │
│      │       ├── 💬 Slack                                       │
│      │       ├── 🎮 Discord                                     │
│      │       └── 📝 Audit Log (JSONL)                           │
│      │                                                         │
│      └──► 🗺️ Threat Topology (update_threat_topology)          │
│              └── Dynamic SVG node/edge graph in Reflex UI       │
│                                                                │
│   Fallback Chain: MCP → Subprocess → Mock                      │
└────────────────────────────────────────────────────────────────┘
```

---

## 🪸 Coral Features Used (Hackathon Scoring)

| # | Coral Feature | Status | How We Use It |
|---|---|---|---|
| 1 | **SQL Interface** | ✅ Used | `coral sql` via MCP `tools/call` with structured JSON responses |
| 2 | **Cross-Source JOINs** | ✅ Used | JOINing `local_file.*` + `osv.packages` + `github.commits` in single queries |
| 3 | **Schema Learning** | ✅ Used | `discover_schema()` auto-introspects `coral.columns` via MCP at runtime |
| 4 | **MCP Integration** | ✅ Used | Persistent MCP client → `coral mcp-stdio` via JSON-RPC 2.0 |
| 5 | **Source Management** | ✅ Used | `coral source add/remove/list` in `setup_sources.py` |
| 6 | **Catalog Discovery** | ✅ Used | `list_catalog`, `search_catalog`, `describe_table`, `list_columns` MCP tools |

**Score: 6/6 features actively used** ✅

---

## ✅ Feature Matrix

| Feature | Status | File | Evidence |
|---|---|---|---|
| **MCP-Native Coral Client** | ✅ Working | `tools/mcp_client.py` | Persistent JSON-RPC connection to `coral mcp-stdio` |
| **Runtime Schema Discovery** | ✅ Working | `tools/mcp_client.py` | Auto-discovers 7 tables, 91+ columns across 3 sources |
| **Three-Tier Query Execution** | ✅ Working | `tools/coral_executor.py` | MCP → subprocess → mock fallback chain |
| **Live GitHub Commit Scanning** | ✅ Working | `agent/sre_brain.py` | Queries real `github.commits` via Coral GitHub plugin |
| **Cross-Source SQL JOINs** | ✅ Working | `agent/sre_brain.py` | LLM generates JOINs across log + vuln + commit tables |
| **OSV Vulnerability Scanning** | ✅ Working | `osv-source.yaml` | CVE cross-reference via `osv.packages` Coral source |
| **Dynamic Threat Topology** | ✅ Working | `agent/sre_brain.py` | `update_threat_topology` tool redraws SVG graph in real-time |
| **Gemini LLM (Native SDK)** | ✅ Working | `agent/sre_brain.py` | Native `google-genai` SDK with manual function calling (AFC disabled) |
| **Groq LLM (Llama 3.3 70B)** | ✅ Working | `agent/sre_brain.py` | Free API, OpenAI-compatible endpoint |
| **OpenAI LLM (GPT-4o)** | ✅ Ready | `agent/sre_brain.py` | Standard OpenAI + custom base_url support |
| **Glassmorphic Reflex UI** | ✅ Working | `aegis_app/aegis_app.py` | Real-time streaming dashboard with micro-animations |
| **Auto-Start Webhook Server** | ✅ Working | `tools/webhook_receiver.py` | Python HTTP server on :5678, auto-boots if nothing listening |
| **Slack/Discord Forwarding** | ✅ Ready | `tools/webhook_receiver.py` | Rich Block Kit (Slack) and Embed (Discord) formatting |
| **JSONL Audit Trail** | ✅ Working | `tools/webhook_receiver.py` | All incidents logged to `n8n_data/incident_log.jsonl` |
| **Live Telemetry Injection** | ✅ Working | `tools/generate_live_telemetry.py` | Fetches real GitHub commits into crash logs |
| **Mock Simulation Mode** | ✅ Working | `agent/sre_brain.py` | Full investigation loop without any API keys |
| **One-Click Source Setup** | ✅ Working | `setup_sources.py` | Registers all Coral sources with correct paths |

---

## 🔬 Proof of Working

All outputs below are from **live test runs**.

### Proof 1: MCP Connection to Coral

```
✅ MCP connected to Coral v0.3.0
Server: {"name": "coral", "version": "0.3.0"}
Protocol: JSON-RPC 2.0 over stdin/stdout
```

The MCP client maintains a persistent subprocess connection to `coral mcp-stdio`, eliminating ~300ms cold-start per query.

---

### Proof 2: Runtime Schema Discovery (7 Tables Auto-Discovered)

```
📦 local_file.api_gateway_logs:     7 columns
📦 local_file.auth_service_logs:    7 columns
📦 local_file.payment_gateway_logs: 7 columns
📦 osv.packages:                    6 columns
📦 github.commits:                 27 columns
📦 github.pulls:                   33 columns
📦 github.issues:                  18 columns
```

The `discover_schema()` method auto-introspects all registered Coral sources via MCP. The LLM learns table structures **dynamically at runtime** — no hardcoded schema definitions needed.

---

### Proof 3: Live GitHub Commit Scanning via MCP

**Query**: `SELECT sha, commit__author__name, commit__message FROM github.commits WHERE owner = 'Harshit7623' AND repo = 'aegis-sre' LIMIT 5`

```
Status: success, Rows: 5

0cfcf04e.. by Harshit Tiwari:  feat: integrate live github telemetry, gemini 3.1 flash-lite, and n8n webhook workflow
31b0875a.. by TANISH SHIVHARE: dynamic blast radius + fixed forensic playbooks
d46a1bba.. by Harshit Tiwari:  feat: add Groq LLM support with three-tier provider routing
137975d6.. by Harshit Tiwari:  docs: update README with MCP architecture diagrams
5f581575.. by Harshit Tiwari:  feat: add Coral MCP integration with runtime schema discovery
```

This is querying the **live GitHub API** through Coral's native GitHub plugin, not a mock.

---

### Proof 4: Local Log File Analysis via MCP

**Query**: `SELECT level, COUNT(*) as cnt FROM local_file.api_gateway_logs GROUP BY level`

```
Status: success, Rows: 2

INFO:   5 records
ERROR:  5 records
```

Parquet log files are queried via Coral's `local_file` source — zero database setup required.

---

### Proof 5: OSV Vulnerability Database Query

**Query**: `SELECT package_name, cve, severity FROM osv.packages`

```
Status: success, Rows: 3

cryptography: CVE-2023-49083 (HIGH)
urllib3:      CVE-2023-43804 (MEDIUM)
django:       CVE-2022-22818 (LOW)
```

---

### Proof 6: Full E2E Investigation (Real LLM Reasoning)

**Input Prompt**: *"We are seeing a massive spike in 500 errors in our production api-gateway. Scan our logs, find vulnerabilities, check recent commits, and trigger a remediation alert."*

**What the LLM did**:

1. ✅ Generated a cross-source SQL JOIN query:
   ```sql
   SELECT l.timestamp, l.service, l.message, l.response_code,
          o.package_name, o.cve, o.severity,
          g.sha, g.commit__author__name, g.commit__message
   FROM local_file.api_gateway_logs l
   JOIN osv.packages o ON l.message LIKE CONCAT('%', o.package_name, '%')
   JOIN github.commits g ON g.commit__message LIKE CONCAT('%', o.package_name, '%')
   WHERE g.owner = 'Harshit7623' AND g.repo = 'aegis-sre'
     AND l.response_code = 500
   ORDER BY l.timestamp DESC LIMIT 100
   ```

2. ✅ Self-corrected when first query used wrong table name
3. ✅ Executed via MCP with structured response
4. ✅ Identified root cause commit and CVE
5. ✅ Dispatched remediation alert:
   ```json
   {
     "incident_id": "INC-2026-001",
     "severity": "CRITICAL",
     "service": "api-gateway",
     "root_cause": "Vulnerable package version introduced in recent commit",
     "remediation_action": "Rollback commit and upgrade vulnerable package"
   }
   ```
6. ✅ Alert logged to `n8n_data/incident_log.jsonl`

---

## 📊 Project Statistics

| Metric | Value |
|---|---|
| **Total Source Lines** | ~3,200+ |
| **Data Sources** | 3 (local_file, osv, github) |
| **Tables Discovered** | 7 |
| **LLM Providers** | 4 (Gemini, Groq, OpenAI, Mock) |
| **Agent Tools** | 3 (execute_coral_query, trigger_n8n_workflow, update_threat_topology) |
| **MCP Tools Available** | 5 (sql, list_catalog, search_catalog, describe_table, list_columns) |

### File Breakdown

| File | Lines | Purpose |
|---|---|---|
| `aegis_app/aegis_app.py` | ~1,226 | Reflex UI (glassmorphic dashboard with micro-animations) |
| `agent/sre_brain.py` | 564 | AI reasoning engine with 3-tool function calling |
| `tools/mcp_client.py` | 402 | Coral MCP client (JSON-RPC 2.0) |
| `tools/webhook_receiver.py` | 283 | Local webhook server with Slack/Discord forwarding |
| `tools/coral_executor.py` | 274 | Query executor (MCP → subprocess → mock) |
| `tools/n8n_dispatcher.py` | 213 | Webhook dispatcher with auto-start & retry |
| `setup_sources.py` | 150 | One-click Coral source registration |
| `test_runner.py` | ~85 | CLI diagnostic test runner |

---

## 🚀 How to Run

### Prerequisites
- Python 3.10+
- [Coral CLI](https://withcoral.com) installed
- At least one LLM API key (Gemini recommended for native function calling)

### Quick Start

```bash
# 1. Clone
git clone https://github.com/Harshit7623/aegis-sre.git
cd aegis-sre

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env    # Edit with your API keys

# 4. Generate live telemetry & register Coral sources
python3 tools/generate_live_telemetry.py
python3 setup_sources.py

# 5. Run the dashboard
reflex run
# OR run the CLI test
python3 test_runner.py
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Recommended | Google AI Studio key (native function calling) |
| `GROQ_API_KEY` | Optional | Free Groq API key (Llama 3.3 70B) |
| `OPENAI_API_KEY` | Optional | OpenAI key (GPT-4o) |
| `GITHUB_TOKEN` | Yes | GitHub Personal Access Token for live commit scanning |
| `GITHUB_REPO` | Yes | Target repo (e.g., `YourOrg/your-repo`) |
| `SLACK_WEBHOOK_URL` | Optional | Forward alerts to Slack |
| `DISCORD_WEBHOOK_URL` | Optional | Forward alerts to Discord |

---

## 👥 For Contributors

### Key Architectural Decisions

1. **MCP over Subprocess**: We communicate with Coral via its MCP server (`coral mcp-stdio`) instead of shelling out to `coral sql`. This gives us persistent connections, structured responses, and automatic schema discovery.

2. **Multi-Provider LLM Routing**: `GEMINI_API_KEY → GROQ_API_KEY → OPENAI_API_KEY → Mock`. Gemini is first because it supports native function calling via the `google-genai` SDK. The system auto-detects which key is available.

3. **Graceful Degradation**: Every subsystem has a fallback chain. MCP fails → subprocess. Subprocess fails → mock. LLM fails → mock. Webhook server not running → auto-start. This means the system **never crashes** — it always produces output.

4. **Zero-Warehouse**: No databases. Logs are Parquet files, vulnerabilities are Parquet files, GitHub is live API. Coral federates all of them via SQL.

5. **AFC Disabled for Gemini**: Automatic Function Calling is explicitly disabled so all tool calls flow through our generator loop, enabling real-time UI streaming of tool events.

### Adding a New Data Source

```bash
# 1. Add the source to Coral
coral source add jira   # or any supported source

# 2. That's it! The MCP client will auto-discover the new tables
#    via discover_schema() — no code changes needed.
```

### Adding a New LLM Provider

Edit `agent/sre_brain.py` → `SREBrain.__init__()`. Add a new priority block following the Gemini/Groq/OpenAI pattern. Any OpenAI-compatible API works with zero additional code.

### Running Tests

```bash
# Full E2E investigation (requires at least one LLM key)
python3 test_runner.py

# MCP-only test (no LLM needed)
python3 -c "from tools.mcp_client import get_mcp_client; c = get_mcp_client(); print(c.sql('SELECT * FROM local_file.api_gateway_logs LIMIT 5'))"
```
