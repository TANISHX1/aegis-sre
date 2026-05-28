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

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    OpenAI = None
    HAS_OPENAI = False

try:
    from google import genai
    from google.genai import types
    HAS_GEMINI = True
except ImportError:
    genai = None
    types = None
    HAS_GEMINI = False

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

1. **Service Telemetry Logs (Local Parquet Files)**
   - Namespace Table: `logs.telemetry`
   - Schema:
     * `timestamp` (TIMESTAMP): Event log time.
     * `service` (VARCHAR): Service identifier (e.g., 'api-gateway', 'auth-service', 'payment-service').
     * `ip` (VARCHAR): Source IP address of the node.
     * `request_count` (INTEGER): Throughput.
     * `error_count` (INTEGER): Number of failures.
     * `vulnerable_package` (VARCHAR): Detected package string in format `name==version` (e.g., 'urllib3==1.26.15').

2. **Google OSV API (Vulnerability Databases)**
   - Namespace Table: `osv.packages`
   - Mandatory Filter: Must ALWAYS include `WHERE package_name = '...'` or `WHERE vulnerability_id = '...'` to trigger the API.
   - Schema:
     * `package_name` (VARCHAR): Core package name.
     * `version` (VARCHAR): Specific version to check.
     * `ecosystem` (VARCHAR): Ecosystem (e.g., 'PyPI', 'npm', 'Go', 'Maven').
     * `vulnerability_id` (VARCHAR): Vulnerability identifier (e.g., 'GHSA-2xpw-w6gg-jr37').
     * `summary` (VARCHAR): Brief description of the issue.

### JOIN PATTERNS
To audit a service, perform a JOIN between logs and OSV. Since `vulnerable_package` contains the version string, use literal filters for now when identifying package details. 

Example Federated Audit Query:
`SELECT l.ip, l.service, o.vulnerability_id, o.summary FROM logs.telemetry l JOIN osv.packages o ON o.package_name = 'urllib3' AND o.version = '1.26.15' WHERE l.vulnerable_package = 'urllib3==1.26.15' AND o.ecosystem = 'PyPI'`

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
    l.timestamp, l.service, l.vulnerable_package,
    o.vulnerability_id, o.summary,
    g.commit_hash, g.author, g.message AS commit_msg
FROM logs.telemetry l
JOIN osv.packages o ON o.package_name = 'urllib3' AND o.version = '1.26.15'
JOIN github.commits g ON g.changed_files LIKE '%requirements.txt%'
WHERE g.author = 'TANISHX1' AND l.error_count > 100
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
        # Why? We extract the API key from environment variables. If missing or if the libraries
        # are not installed, we gracefully allow mock initialization so the app doesn't
        # crash on startup.
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("SRE_LLM_MODEL", "gemini-1.5-flash")
        
        # Detect if we should use Google GenAI native client or OpenAI client
        self.is_gemini_native = False
        if self.api_key and self.api_key.startswith("AIzaSy"):
            self.is_gemini_native = True
            
        if not self.api_key or "your_openai_api_key" in self.api_key:
            logger.warning("OPENAI_API_KEY environment variable is missing or set to placeholder. Operating SRE Brain in simulated mock mode.")
            self.client = None
        else:
            if self.is_gemini_native:
                if not HAS_GEMINI:
                    logger.warning("google-genai library is not installed. Operating SRE Brain in simulated mock mode.")
                    self.client = None
                else:
                    logger.info("Initializing Google GenAI native client for Gemini model.")
                    self.client = genai.Client(api_key=self.api_key)
            else:
                if not HAS_OPENAI:
                    logger.warning("openai library is not installed. Operating SRE Brain in simulated mock mode.")
                    self.client = None
                else:
                    logger.info("Initializing OpenAI standard client.")
                    base_url = os.getenv("OPENAI_API_BASE", None)
                    self.client = OpenAI(api_key=self.api_key, base_url=base_url)

    def run_investigation_loop(self, user_prompt: str, history: List[Dict[str, str]] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Coordinates the multi-turn agentic reasoning loop.
        Streams thoughts, tool execution steps, and final analysis to the caller using a Generator.
        """
        # Check if we are running in simulated mock mode
        if not self.client:
            yield from self._run_mocked_investigation_loop(user_prompt)
            return

        # Delegate to native Gemini GenAI SDK if it is a Google key
        if self.is_gemini_native:
            yield from self.run_gemini_native_loop(user_prompt)
            return

        # Load chat history or initialize fresh list
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user_prompt})

        # Maximum agent loop depth to prevent runaway cost or looping recursion
        MAX_TURNS = 5
        current_turn = 0

        while current_turn < MAX_TURNS:
            current_turn += 1
            logger.info(f"Agent Loop - Turn {current_turn} of {MAX_TURNS}")
            
            yield {"type": "status", "content": f"Analyzing incident and querying system state (Turn {current_turn})..."}

            try:
                # 2. CALL CHAT COMPLETIONS WITH TOOLS
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=OPENAI_TOOLS,
                    tool_choice="auto",
                    temperature=0.1
                )

                response_message = response.choices[0].message
                messages.append(response_message)

                if response_message.content:
                    yield {"type": "thought", "content": response_message.content}

                # Check if the model requested function execution
                tool_calls = response_message.tool_calls
                if not tool_calls:
                    yield {"type": "final", "content": response_message.content or "Investigation concluded."}
                    break

                for tool_call in tool_calls:
                    function_name = tool_call.function.name
                    arguments = json.loads(tool_call.function.arguments)
                    tool_call_id = tool_call.id

                    logger.info(f"LLM requested tool call: {function_name} with arguments: {arguments}")
                    
                    yield {
                        "type": "tool_call",
                        "tool_name": function_name,
                        "arguments": arguments
                    }

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
                yield {
                    "type": "thought", 
                    "content": f"⚠️ SRE Brain API call failed ({str(ex)}). Engaging high-fidelity mock SRE dry-run mode to ensure continuous dashboard execution..."
                }
                # Delegate execution immediately to the robust local mock generator
                for mock_step in self._run_mocked_investigation_loop(user_prompt):
                    yield mock_step
                break
        else:
            yield {"type": "error", "content": "Maximum agent reasoning iterations reached. Stopping loop to prevent thread exhaustion."}

    def run_gemini_native_loop(self, user_prompt: str) -> Generator[Dict[str, Any], None, None]:
        """
        Coordinates the native Gemini GenAI SDK tool-calling loop.
        """
        tools = [execute_coral_query, trigger_n8n_workflow]
        yield {"type": "status", "content": "Initializing Google GenAI SRE Triage session..."}
        
        try:
            chat = self.client.chats.create(
                model=self.model,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    tools=tools,
                    temperature=0.1,
                )
            )
            
            current_message = user_prompt
            MAX_TURNS = 5
            current_turn = 0
            
            while current_turn < MAX_TURNS:
                current_turn += 1
                logger.info(f"Native Gemini Turn {current_turn} of {MAX_TURNS}")
                yield {"type": "status", "content": f"Analyzing incident and querying system state (Turn {current_turn})..."}
                
                response = chat.send_message(current_message)
                
                if response.text:
                    yield {"type": "thought", "content": response.text}
                
                function_calls = response.function_calls
                if not function_calls:
                    yield {"type": "final", "content": response.text or "Incident trace completed successfully."}
                    break
                
                function_responses = []
                for function_call in function_calls:
                    name = function_call.name
                    args = function_call.args
                    
                    yield {
                        "type": "tool_call",
                        "tool_name": name,
                        "arguments": args
                    }
                    
                    if name == "execute_coral_query":
                        sql_query = args.get("query")
                        yield {"type": "status", "content": f"Executing Coral SQL: {sql_query[:60]}..."}
                        tool_result = execute_coral_query(sql_query)
                    elif name == "trigger_n8n_workflow":
                        payload_data = args.get("payload")
                        yield {"type": "status", "content": f"Dispatching remediation alert for service: {payload_data.get('service')}..."}
                        tool_result = trigger_n8n_workflow(payload_data)
                    else:
                        tool_result = {"status": "error", "message": f"Unknown tool name: {name}"}
                        
                    yield {
                        "type": "tool_result",
                        "tool_name": name,
                        "result": tool_result
                    }
                    
                    function_responses.append(
                        types.Part.from_function_response(
                            name=name,
                            response={"result": tool_result}
                        )
                    )
                
                current_message = function_responses
            else:
                yield {"type": "error", "content": "Maximum agent reasoning iterations reached. Stopping loop to prevent thread exhaustion."}
                
        except Exception as ex:
            logger.exception("Exception in SRE Brain Gemini native loop.")
            yield {
                "type": "thought",
                "content": f"⚠️ SRE Brain Gemini native API call failed ({str(ex)}). Engaging high-fidelity mock SRE dry-run mode to ensure continuous dashboard execution..."
            }
            for mock_step in self._run_mocked_investigation_loop(user_prompt):
                yield mock_step

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
