# Analysis Overview

## Project Context
Aegis‑Antigravity SRE is a hackathon‑driven, real‑time incident response platform built entirely in **pure Python** using the **Reflex** framework. It enables security operators to ingest forensic Parquet logs, run federated SQL queries, cross‑reference vulnerability data from Google OSV, trace offending commits, and automatically dispatch remediation webhooks via **n8n**.

## High‑Level Modules
| Module | Purpose | Key Files |
|--------|---------|-----------|
| **aegis_app** | Reflex UI application – renders the dashboard, topology view, and state management. | `aegis_app/aegis_app.py` |
| **agent** | Core cognitive brain – orchestrates multi‑hop analysis, calls tools, and streams thoughts. | `agent/sre_brain.py` |
| **tools** | Low‑level utilities:
- `coral_executor.py` runs the Coral CLI for SQL on Parquet logs.
- `n8n_dispatcher.py` sends resilient webhook calls. | `tools/coral_executor.py`, `tools/n8n_dispatcher.py` |
| **assets** | Static visual assets such as architecture diagrams. | `assets/*.png` |
| **logs** | Directory for uploaded forensic Parquet logs (runtime data). | `logs/` |

## Entry Points
1. **Reflex entry point** – `rxconfig.py` defines the Reflex project and boots the FastAPI backend.
2. **UI interaction** – Operator uses the web console (http://localhost:3000) to upload logs and issue queries.
3. **Brain loop** – `agent/sre_brain.py` receives the query, invokes tools, aggregates results, and updates UI state.
4. **Tool execution** – `tools/coral_executor.py` runs SQL against logs; `tools/n8n_dispatcher.py` posts remediation payloads.

## Data Flow Diagram
```mermaid
flowchart TD
    UI[Operator Console (Reflex)] --> State[State Management (aegis_app.py)]
    State --> Brain[Brain (agent/sre_brain.py)]
    Brain -->|Parse Logs| Executor[Coral Executor (tools/coral_executor.py)]
    Executor -->|SQL JSON| Brain
    Brain -->|Vuln Lookup| OSV[Google OSV API]
    OSV -->|Vuln Data| Brain
    Brain -->|Git Trace| Git[Git Repo Commits]
    Git -->|Author Info| Brain
    Brain -->|Update UI| State
    State -->|Render| UI
    Brain -->|Remediation| Webhook[n8n Webhook]
    Webhook -->|Result| UI
```

## Next Steps in Phase 1
- Verify the README now contains a concise project summary and tech stack.
- Add a link to this overview file in the README for easy navigation.
- Ensure the Mermaid diagram renders correctly in the markdown preview.
