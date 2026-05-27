# 🛡️ Aegis-SRE: Capabilities & Proof of Working

> **Document Purpose**: This document provides a complete overview of all features, their current working status, and live proof outputs for contributors joining the project.
>
> **Last Updated**: May 27, 2026 | **Repo**: [Harshit7623/aegis-sre](https://github.com/Harshit7623/aegis-sre) | **Commit**: `d46a1bb`

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

1. **Ingesting crash logs** (Parquet format) from a company's server
2. **Cross-referencing** those logs with known vulnerability databases (OSV)
3. **Scanning GitHub commits** to identify which commit may have introduced the error
4. **Dispatching remediation alerts** to Slack/Discord via webhooks
5. **Presenting findings** in a real-time dashboard with streaming agent reasoning

All of this is powered by **Coral** as the federated SQL engine and an **LLM** (Groq/Gemini/OpenAI) as the reasoning brain.

### The Flow

```
User drops log file → LLM writes SQL → Coral JOINs logs + vulns + commits → LLM reasons about findings → Alert dispatched
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
│      │  Provider: Groq > Gemini > OpenAI > Mock                │
│      │  Model:    Llama 3.3 70B / Gemini 2.0 Flash / GPT-4o   │
│      │                                                         │
│      ├──► 🔌 Coral MCP Client (mcp_client.py)                  │
│      │       │  Protocol: JSON-RPC 2.0 over stdin/stdout       │
│      │       ▼                                                  │
│      │    ⚙️ Coral MCP Server (coral mcp-stdio)                │
│      │       ├── 📄 local_file.* (Parquet logs)                │
│      │       ├── 🛡️ osv.packages (Vulnerability DB)            │
│      │       └── 🐙 github.commits (Live GitHub API)           │
│      │                                                         │
│      └──► ⚡ Webhook Dispatcher (n8n_dispatcher.py)             │
│              ├── 💬 Slack                                       │
│              ├── 🎮 Discord                                     │
│              └── 📝 Audit Log (JSONL)                           │
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
| **Groq LLM (Llama 3.3 70B)** | ✅ Working | `agent/sre_brain.py` | Free API, no rate limits, OpenAI-compatible |
| **Gemini LLM (2.0 Flash)** | ⚠️ Rate-limited | `agent/sre_brain.py` | Works but free tier exhausts at 50 req/day |
| **OpenAI LLM (GPT-4o)** | ✅ Ready | `agent/sre_brain.py` | Standard OpenAI + custom base_url support |
| **Glassmorphic Reflex UI** | ✅ Working | `aegis_app/aegis_app.py` | Real-time streaming dashboard with log upload |
| **Auto-Start Webhook Server** | ✅ Working | `tools/webhook_receiver.py` | Python HTTP server on :5678, auto-boots if nothing listening |
| **Slack/Discord Forwarding** | ✅ Ready | `tools/n8n_dispatcher.py` | Set `SLACK_WEBHOOK_URL`/`DISCORD_WEBHOOK_URL` in `.env` |
| **JSONL Audit Trail** | ✅ Working | `tools/webhook_receiver.py` | All incidents logged to `n8n_data/incident_log.jsonl` |
| **Mock Simulation Mode** | ✅ Working | `agent/sre_brain.py` | Full investigation loop without any API keys |
| **One-Click Source Setup** | ✅ Working | `setup_sources.py` | Registers all Coral sources with correct paths |

---

## 🔬 Proof of Working

All outputs below are from **live test runs** on May 27, 2026.

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

d46a1bba.. by Harshit Tiwari:  feat: add Groq LLM support with three-tier provider routing
137975d6.. by Harshit Tiwari:  docs: update README with MCP architecture diagrams
5f581575.. by Harshit Tiwari:  feat: add Coral MCP integration with runtime schema discovery
b061f90b.. by Harshit Tiwari:  feat: deep audit fixes, live GitHub integration
6225cc5d.. by TANISHX1:        using real data for processing
```

This is querying the **live GitHub API** through Coral's native GitHub plugin, not a mock.

---

### Proof 4: Local Log File Analysis via MCP

**Query**: `SELECT level, COUNT(*) as cnt FROM local_file.api_gateway_logs GROUP BY level`

```
Status: success, Rows: 4

WARN:     2 records
INFO:     3 records
CRITICAL: 2 records
ERROR:    3 records
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

### Proof 6: LLM Provider Routing (Groq Active)

```
Provider:      groq
Model:         llama-3.3-70b-versatile
Client Type:   OpenAI (compatible API)
GitHub Target: Harshit7623/aegis-sre
```

LLM routing priority: **Groq → Gemini → OpenAI → Mock**. Currently using Groq's free tier with Llama 3.3 70B — no rate limit issues.

---

### Proof 7: Full E2E Investigation (Real LLM Reasoning)

**Input Prompt**: *"We are seeing a massive spike in 500 errors in our production api-gateway. Scan our logs, find vulnerabilities, check if TANISHX1 has made any recent commits, and trigger a remediation alert."*

**What the LLM did**:

1. ✅ Generated a cross-source SQL JOIN query:
   ```sql
   SELECT l.timestamp, l.service, l.message, l.response_code,
          o.package_name, o.cve, o.severity,
          g.sha, g.commit__author__name, g.commit__message
   FROM local_file.auth_service_logs l
   JOIN osv.packages o ON l.message LIKE CONCAT('%', o.package_name, '%')
   JOIN github.commits g ON g.commit__message LIKE CONCAT('%', o.package_name, '%')
   WHERE g.owner = 'Harshit7623' AND g.repo = 'aegis-sre'
     AND l.response_code = 500 AND g.author = 'TANISHX1'
   ORDER BY l.timestamp DESC LIMIT 100
   ```

2. ✅ Self-corrected when first query used wrong table name (`auth_errors` → `auth_service_logs`)
3. ✅ Executed via MCP with structured response
4. ✅ Dispatched remediation alert:
   ```json
   {
     "incident_id": "INC-2026-001",
     "severity": "CRITICAL",
     "service": "api-gateway",
     "root_cause": "Vulnerable package version committed by TANISHX1",
     "remediation_action": "Rollback commit and upgrade vulnerable package"
   }
   ```
5. ✅ Alert logged to `n8n_data/incident_log.jsonl`

---

## 📊 Project Statistics

| Metric | Value |
|---|---|
| **Total Source Lines** | 2,782 |
| **Total Commits** | 12 |
| **Contributors** | 2 (Harshit Tiwari, TANISHX1) |
| **Data Sources** | 3 (local_file, osv, github) |
| **Tables Discovered** | 7 |
| **LLM Providers** | 4 (Groq, Gemini, OpenAI, Mock) |
| **MCP Tools Available** | 5 (sql, list_catalog, search_catalog, describe_table, list_columns) |

### File Breakdown

| File | Lines | Purpose |
|---|---|---|
| `aegis_app/aegis_app.py` | 822 | Reflex UI (glassmorphic dashboard) |
| `agent/sre_brain.py` | 563 | AI reasoning engine with function calling |
| `tools/mcp_client.py` | 402 | Coral MCP client (JSON-RPC 2.0) |
| `tools/webhook_receiver.py` | 282 | Local webhook server |
| `tools/coral_executor.py` | 273 | Query executor (MCP → subprocess → mock) |
| `tools/n8n_dispatcher.py` | 212 | Webhook dispatcher with auto-start |
| `setup_sources.py` | 143 | One-click Coral source registration |
| `test_runner.py` | 85 | CLI diagnostic test runner |

---

## 🚀 How to Run

### Prerequisites
- Python 3.10+
- [Coral CLI](https://withcoral.com) installed
- At least one LLM API key (Groq recommended — free at [console.groq.com](https://console.groq.com))

### Quick Start

```bash
# 1. Clone
git clone https://github.com/Harshit7623/aegis-sre.git
cd aegis-sre

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env    # Edit with your API keys
# At minimum, set GROQ_API_KEY and GITHUB_TOKEN

# 4. Register Coral sources
python setup_sources.py

# 5. Run the dashboard
reflex run
# OR run the CLI test
python test_runner.py
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GROQ_API_KEY` | Recommended | Free Groq API key (Llama 3.3 70B) |
| `GEMINI_API_KEY` | Optional | Google AI Studio key (Gemini 2.0 Flash) |
| `OPENAI_API_KEY` | Optional | OpenAI key (GPT-4o) |
| `GITHUB_TOKEN` | Yes | GitHub Personal Access Token for live commit scanning |
| `GITHUB_REPO` | Yes | Target repo (e.g., `Harshit7623/aegis-sre`) |
| `SLACK_WEBHOOK_URL` | Optional | Forward alerts to Slack |
| `DISCORD_WEBHOOK_URL` | Optional | Forward alerts to Discord |

---

## 👥 For Contributors

### Key Architectural Decisions

1. **MCP over Subprocess**: We communicate with Coral via its MCP server (`coral mcp-stdio`) instead of shelling out to `coral sql`. This gives us persistent connections, structured responses, and automatic schema discovery.

2. **Three-Tier LLM Routing**: `GROQ_API_KEY → GEMINI_API_KEY → OPENAI_API_KEY → Mock`. Groq is first because it's free with generous rate limits. The system auto-detects which key is available.

3. **Graceful Degradation**: Every subsystem has a fallback chain. MCP fails → subprocess. Subprocess fails → mock. LLM fails → mock. Webhook server not running → auto-start. This means the system **never crashes** — it always produces output.

4. **Zero-Warehouse**: No databases. Logs are Parquet files, vulnerabilities are Parquet files, GitHub is live API. Coral federates all of them via SQL.

### Adding a New Data Source

```bash
# 1. Add the source to Coral
coral source add jira   # or any supported source

# 2. That's it! The MCP client will auto-discover the new tables
#    via discover_schema() — no code changes needed.
```

### Adding a New LLM Provider

Edit `agent/sre_brain.py` → `SREBrain.__init__()`. Add a new priority block following the Groq/Gemini/OpenAI pattern. Any OpenAI-compatible API works with zero additional code.

### Running Tests

```bash
# Full E2E investigation (requires at least one LLM key)
python test_runner.py

# MCP-only test (no LLM needed)
python -c "from tools.mcp_client import get_mcp_client; c = get_mcp_client(); print(c.sql('SELECT * FROM local_file.api_gateway_logs LIMIT 5'))"
```
