"""
Aegis-Antigravity SRE: Cognitive AI Brain & Tool Coordinator
------------------------------------------------------------
This module acts as the Principal SRE reasoning agent, integrating raw OpenAI API calls 
with functional tools. It bypasses framework wrappers like LangChain to preserve raw control
over token consumption, latency, and function routing.

CRITICAL ARCHITECTURAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. Zero-Abstraction Native Tool Binding:
   Frameworks like LangChain add multiple layers of abstraction that obscure raw prompt injection,
   increase latency, and introduce complex dependency issues. By using the raw OpenAI API client, 
   we operate with minimum execution latency, explicit context-window control, and raw tool schemas, 
   which is essential for low-latency incident response.

2. Streaming Asynchronous Generator Pattern:
   Incident response requires a highly interactive UI. If the agent blocks the connection 
   until the complete multi-turn reasoning is finished, the Reflex UI would appear frozen. 
   By yielding structured step dictionaries (`{"type": "thought", ...}`, `{"type": "tool_call", ...}`),
   we enable the Reflex frontend to render real-time status updates (e.g., "Agent is executing Coral query...")
   and stream intermediate thoughts to the operator without freezing the main application event loop.

3. Detailed Context Injection (Federated Schema System Prompt):
   The SRE Brain is instructed via its system prompt on the precise SQL dialects and tables supported by Coral,
   particularly how to combine offline Parquet log logs with the Google OSV API namespace and git commits.
   This structural knowledge prevents syntax errors and guides the LLM to construct complex, 
   multi-hop SQL JOINs instead of running multiple simple queries.
"""

import os
import json
import logging
from typing import Dict, Any, List, Generator

# Resilience wrappers: Protect imports so mock dry-runs function without requiring pre-installed pip packages.
try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    OpenAI = None
    HAS_OPENAI = False

try:
    from dotenv import load_dotenv
    HAS_DOTENV = True
except ImportError:
    load_dotenv = lambda *args, **kwargs: None
    HAS_DOTENV = False

# Import our custom CLI executor and automation dispatcher
from tools.coral_executor import execute_coral_query
from tools.n8n_dispatcher import trigger_n8n_workflow

# Initialize dotenv to load local secrets (e.g., OPENAI_API_KEY) in a sandboxed, environment-agnostic manner.
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SREBrain")

# Configure the System Prompt containing the federated architecture instructions.
# Why? Explicit schema definitions and join patterns are supplied inside the system prompt 
# to optimize zero-shot SQL generation accuracy and instruct the model on TANISHX1's git author context.
SYSTEM_PROMPT = """You are "Aegis-Antigravity SRE", an elite Zero-Warehouse root-cause investigation agent and Principal Systems Architect. 
Your goal is to investigate production incidents, find root causes, and trigger automated remediations.

You are equipped with two tools:
1. `execute_coral_query`: Takes a raw SQL string to run on Coral and returns a JSON payload.
2. `trigger_n8n_workflow`: Takes a JSON payload containing remediation details to execute an n8n workflow (e.g., alert Slack or create Jira tickets).

---
### FEDERATED CORAL DATABASE SCHEMA SPECIFICATION

You do not have a standard database warehouse. Instead, you query live data sources and offline logs directly on-the-fly using Coral SQL. You MUST write complex multi-hop JOINs combining these schemas when analyzing bugs:

1. **Offline Server Logs**
   - Syntax: `local_file.read('/logs/<filename>.parquet')` (e.g., `local_file.read('/logs/server.parquet')`)
   - Schema:
     * `timestamp` (TIMESTAMP): Event log time.
     * `level` (VARCHAR): 'INFO', 'WARN', 'ERROR', 'CRITICAL'.
     * `service` (VARCHAR): Service identifier (e.g., 'api-gateway', 'auth-service', 'payment-v2').
     * `message` (VARCHAR): Log diagnostic string (e.g., 'vulnerability found', 'KeyExpired', 'jwt error').
     * `ip` (VARCHAR): Source IP address.
     * `request_path` (VARCHAR): HTTP endpoint path (e.g., '/auth/login', '/v1/transactions').
     * `response_code` (INTEGER): HTTP status code (e.g., 500, 403, 200).

2. **Google OSV API (Vulnerability Databases)**
   - Namespace Table: `osv.packages`
   - Schema:
     * `package_name` (VARCHAR): Dependency library name (e.g., 'cryptography', 'urllib3', 'django').
     * `installed_version` (VARCHAR): Installed version.
     * `vulnerable_version_range` (VARCHAR): Ranges matching CVEs.
     * `cve` (VARCHAR): Vulnerability identifier (e.g., 'CVE-2023-49083').
     * `severity` (VARCHAR): 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'.
     * `summary` (VARCHAR): Description of vulnerability.

3. **VCS GitHub Commits**
   - Namespace Table: `github.commits`
   - Schema:
     * `commit_hash` (VARCHAR): Commit SHA hash.
     * `author` (VARCHAR): Committer username (specifically look for developer 'TANISHX1').
     * `commit_date` (TIMESTAMP): Date commit was pushed.
     * `message` (VARCHAR): Commit message.
     * `changed_files` (VARCHAR): Comma-separated list of modified files (e.g., 'requirements.txt, auth_service/jwt.py').

---
### MULTI-HOP JOIN INSTRUCTION EXAMPLES

To find if a commit by TANISHX1 introduced a package vulnerability currently triggering 500 errors in offline logs, you MUST construct a query joining all three tables:
```sql
SELECT 
    l.timestamp, l.service, l.message,
    o.package_name, o.installed_version, o.cve, o.severity,
    g.commit_hash, g.author, g.message AS commit_msg
FROM local_file.read('/logs/server.parquet') l
JOIN osv.packages o ON l.message LIKE CONCAT('%', o.package_name, '%')
JOIN github.commits g ON g.changed_files LIKE CONCAT('%', o.package_name, '%')
WHERE g.author = 'TANISHX1' AND l.response_code = 500
ORDER BY l.timestamp DESC
```

---
### AGENTIC RUNNING RULES:
1. Always analyze the user's report. If they upload a file, identify its filename and plan a query against `/logs/<filename>`.
2. Construct queries targeting the root cause. Match vulnerabilities with recent commits (especially focusing on developer TANISHX1).
3. If you identify a critical issue, calculate the blast radius (which nodes/services are affected) and use `trigger_n8n_workflow` to dispatch the remediation automatically.
4. Explain your technical reasoning step-by-step to the operator, including the exact SQL joins you formulated. Keep descriptions deep, professional, and clear.
"""

# Define OpenAI raw tool schemas
# Why? We provide raw JSON schemas for standard API integration to keep tool definitions 
# descriptive and strictly typed, which prevents hallucinations in argument extraction.
OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "execute_coral_query",
            "description": "Executes a federated Coral SQL query across offline logs, Google OSV API, and GitHub commits. Returns a JSON dataset.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The exact SQL query string. Must use local_file.read('/logs/<file>.parquet') for offline logs and join osv.packages or github.commits if needed."
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "trigger_n8n_workflow",
            "description": "Triggers automated SRE remediation workflows (e.g., alerting Slack, creating Jira tickets, or launching kubernetes rollback pods) via local n8n gateway.",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "object",
                        "description": "Structured incident report for n8n.",
                        "properties": {
                            "incident_id": {"type": "string", "description": "Unique incident ID, e.g., INC-2026-001."},
                            "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                            "service": {"type": "string", "description": "Compromised or malfunctioning service name."},
                            "root_cause": {"type": "string", "description": "Summary of identified root cause (e.g., Vulnerable urllib3 version committed by TANISHX1)."},
                            "blast_radius_nodes": {
                                "type": "array", 
                                "items": {"type": "string"},
                                "description": "List of hostnames or services impacted by this incident (Blast Radius)."
                            },
                            "remediation_action": {"type": "string", "description": "Actionable step to recover system (e.g., Upgrade urllib3 to 1.26.18, rollback commit a5d89f3)."}
                        },
                        "required": ["incident_id", "severity", "service", "root_cause", "blast_radius_nodes", "remediation_action"]
                    }
                },
                "required": ["payload"]
            }
        }
    }
]


class SREBrain:
    def __init__(self):
        # 1. CLIENT INITIALIZATION
        # Why? We extract the API key from environment variables. If missing or if the openai
        # library is not installed, we gracefully allow mock initialization so the app doesn't
        # crash on startup.
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not HAS_OPENAI or not self.api_key:
            if not HAS_OPENAI:
                logger.warning("openai library is not installed. Operating SRE Brain in simulated mock mode.")
            else:
                logger.warning("OPENAI_API_KEY environment variable is missing. Operating SRE Brain in simulated mock mode.")
            self.client = None
        else:
            # We initialize a standard client thread-safely.
            self.client = OpenAI(api_key=self.api_key)
            
        # Model parameterization - using gpt-4o for top-tier reasoning capabilities on complex joins
        self.model = os.getenv("SRE_LLM_MODEL", "gpt-4o")

    def run_investigation_loop(self, user_prompt: str, history: List[Dict[str, str]] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Coordinates the multi-turn agentic reasoning loop.
        Streams thoughts, tool execution steps, and final analysis to the caller using a Generator.
        
        Args:
            user_prompt (str): Incident report or manual query.
            history (List[Dict[str, str]]): Chat history structure to preserve context across turns.
            
        Yields:
            Dict[str, Any]: Structured execution state.
        """
        # Load chat history or initialize fresh list
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user_prompt})

        # Check if we are running in simulated mock mode
        if not self.client:
            yield from self._run_mocked_investigation_loop(user_prompt)
            return

        # Maximum agent loop depth to prevent runaway cost or looping recursion
        MAX_TURNS = 5
        current_turn = 0

        while current_turn < MAX_TURNS:
            current_turn += 1
            logger.info(f"Agent Loop - Turn {current_turn} of {MAX_TURNS}")
            
            yield {"type": "status", "content": f"Analyzing incident and querying system state (Turn {current_turn})..."}

            try:
                # 2. CALL CHAT COMPLETIONS WITH TOOLS
                # - tools=OPENAI_TOOLS binds our custom functions.
                # - tool_choice="auto" allows the model to decide whether to output text or trigger a tool.
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=OPENAI_TOOLS,
                    tool_choice="auto",
                    temperature=0.1  # Low temperature guarantees analytical, reproducible SQL syntax and JSON structures.
                )

                response_message = response.choices[0].message
                messages.append(response_message)

                # 3. INTERMEDIATE COGNITION STREAMING
                # If the agent responds with thinking/reasoning before tool calls, stream it immediately.
                if response_message.content:
                    yield {"type": "thought", "content": response_message.content}

                # Check if the model requested function execution
                tool_calls = response_message.tool_calls
                if not tool_calls:
                    # No tool calls means the agent is ready with its final report.
                    yield {"type": "final", "content": response_message.content or "Investigation concluded."}
                    break

                # 4. PARSING & ROUTING TOOL CALLS
                # The model can emit multiple parallel tool calls (e.g. running a query and triggering an alert).
                for tool_call in tool_calls:
                    function_name = tool_call.function.name
                    arguments = json.loads(tool_call.function.arguments)
                    tool_call_id = tool_call.id

                    logger.info(f"LLM requested tool call: {function_name} with arguments: {arguments}")
                    
                    # Yield tool-executing state to keep user engaged (Premium Micro-animation support)
                    yield {
                        "type": "tool_call",
                        "tool_name": function_name,
                        "arguments": arguments
                    }

                    # Route tool executions
                    if function_name == "execute_coral_query":
                        sql_query = arguments.get("query")
                        yield {"type": "status", "content": f"Executing Coral SQL: {sql_query[:60]}..."}
                        
                        tool_result = execute_coral_query(sql_query)
                        
                    elif function_name == "trigger_n8n_workflow":
                        payload_data = arguments.get("payload")
                        yield {"type": "status", "content": f"Dispatching remediation alert for service: {payload_data.get('service')}..."}
                        
                        tool_result = trigger_n8n_workflow(payload_data)
                        
                    else:
                        tool_result = {"status": "error", "message": f"Unknown tool name: {function_name}"}

                    # 5. RETURNING LOGIC FEEDBACK TO LLM CONTEXT
                    # SRE brain needs to inspect the tool returns. We append the result as a 'tool' role message.
                    # This provides the LLM with direct feedback of its database queries or dispatcher status.
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call_id,
                        "name": function_name,
                        "content": json.dumps(tool_result)
                    })
                    
                    yield {
                        "type": "tool_result",
                        "tool_name": function_name,
                        "result": tool_result
                    }

            except Exception as ex:
                logger.exception("Exception in SRE Brain core iteration loop.")
                yield {"type": "error", "content": f"SRE Brain error during reasoning turn: {str(ex)}"}
                break
        else:
            yield {"type": "error", "content": "Maximum agent reasoning iterations reached. Stopping loop to prevent thread exhaustion."}

    def _run_mocked_investigation_loop(self, user_prompt: str) -> Generator[Dict[str, Any], None, None]:
        """
        Fallback simulation loop when OPENAI_API_KEY is not defined.
        Allows the application to run fully, simulating agentic tool calls, database joins, and remediation.
        """
        import asyncio
        logger.info("Engaging mocked SRE brain reasoning generator.")
        
        yield {"type": "status", "content": "Simulating cognitive analysis of incident..."}
        
        # Simulated delay mimicking LLM processing time (increases perceived UI realism)
        yield {"type": "thought", "content": "Analyzing SRE request. Initiating forensic scan of logs, vulnerabilities, and GitHub git history."}
        
        # 1. Simulate Coral SQL execution tool call
        mock_sql = "SELECT * FROM local_file.read('/logs/server.parquet') JOIN osv.packages JOIN github.commits WHERE author = 'TANISHX1'"
        yield {
            "type": "tool_call",
            "tool_name": "execute_coral_query",
            "arguments": {"query": mock_sql}
        }
        
        # Query results simulation
        coral_result = execute_coral_query(mock_sql)
        yield {
            "type": "tool_result",
            "tool_name": "execute_coral_query",
            "result": coral_result
        }

        # 2. Simulate thought synthesis
        yield {
            "type": "thought",
            "content": f"Forensic scan discovered high-severity vulnerability CVE-2023-43804 (urllib3 package) introduced in commit a5d89f3 by TANISHX1. This is currently generating 500 response codes in the api-gateway service.\n\nRecommended mitigation: Roll back commit a5d89f3 and upgrade urllib3 dependency to 1.26.18. Dispatching automated remediation workflow via n8n."
        }

        # 3. Simulate n8n workflow dispatch tool call
        mock_payload = {
            "incident_id": "INC-2026-042",
            "severity": "HIGH",
            "service": "api-gateway",
            "root_cause": "Vulnerable urllib3 library (CVE-2023-43804) committed by TANISHX1",
            "blast_radius_nodes": ["api-gateway", "auth-service"],
            "remediation_action": "Roll back commit a5d89f3 and upgrade urllib3 to 1.26.18"
        }
        yield {
            "type": "tool_call",
            "tool_name": "trigger_n8n_workflow",
            "arguments": {"payload": mock_payload}
        }

        n8n_result = trigger_n8n_workflow(mock_payload)
        yield {
            "type": "tool_result",
            "tool_name": "trigger_n8n_workflow",
            "result": n8n_result
        }

        # 4. Stream final report
        yield {
            "type": "final",
            "content": """### Root Cause Analysis & Forensic Summary: Aegis-Antigravity SRE

1. **Root Cause**: The production crash was triggered by a high-severity cookie-leak vulnerability in **urllib3** (`CVE-2023-43804`). This vulnerability was committed by developer **TANISHX1** in commit `a5d89f3` while refactoring dependencies.
2. **Blast Radius**: The issue has degraded **api-gateway** and **auth-service**, generating `500 Server Error` response codes across 12% of traffic.
3. **Triggered Actions**:
   * An n8n workflow was successfully launched to quarantine the node.
   * Slack alerts and incident tickets have been dispatched to the on-call SRE queue.
   * Scheduled dependency upgrade tasks to force-install `urllib3==1.26.18` have been registered."""
        }
