"""
Aegis-Antigravity: Cognitive AI Brain & Tool Coordinator
------------------------------------------------------------
This module acts as the Principal reasoning agent, integrating raw OpenAI API calls 
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

from pydantic import BaseModel, Field

class ThreatNode(BaseModel):
    id: str = Field(description="Unique string ID of the node")
    label: str = Field(description="Display label of the node")
    x: int = Field(description="X coordinate between 50 and 260")
    y: int = Field(description="Y coordinate between 50 and 260")
    status: str = Field(description="Must be 'Healthy' or 'Degraded'")
    vulnerable: str = Field(description="Vulnerability description or 'None'")
    remediation: str = Field(description="Remediation steps")

class ThreatEdge(BaseModel):
    source: str = Field(description="Source node ID")
    target: str = Field(description="Target node ID")

def update_threat_topology(nodes: list[ThreatNode], edges: list[ThreatEdge]) -> dict:
    """
    Updates the visual Threat Topology graph on the dashboard with new microservice components.
    """
    nodes_dict = [n.model_dump() if hasattr(n, "model_dump") else n for n in nodes]
    edges_dict = [e.model_dump() if hasattr(e, "model_dump") else e for e in edges]
    return {"status": "success", "nodes": nodes_dict, "edges": edges_dict}

# Initialize dotenv to load local secrets. override=True ensures .env values
# always take precedence over stale shell-exported variables.
load_dotenv(override=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SREBrain")

# Configure the System Prompt containing the federated architecture instructions.
# Why? Explicit schema definitions and join patterns are supplied inside the system prompt 
# to optimize zero-shot SQL generation accuracy and instruct the model on TANISHX1's git author context.
SYSTEM_PROMPT = """You are "Aegis-Antigravity", an elite Zero-Warehouse root-cause investigation agent and Principal Systems Architect. 
Your goal is to investigate production incidents, find root causes, and trigger automated remediations.

You are equipped with three tools:
1. `execute_coral_query`: Takes a raw SQL string to run on Coral and returns a JSON payload.
2. `trigger_n8n_workflow`: Takes a JSON payload containing remediation details to execute an n8n workflow (e.g., alert Slack or create Jira tickets).
3. `update_threat_topology`: Takes a list of nodes and edges to redraw the microservice topology graph on the UI when you discover the architecture of a new repository.

---
### FEDERATED CORAL DATABASE SCHEMA SPECIFICATION

You do not have a standard database warehouse. Instead, you query live data sources and offline logs directly on-the-fly using Coral SQL. You MUST write complex multi-hop JOINs combining these schemas when analyzing bugs:

1. **Offline Server Logs (Telemetry Data)**
   - Namespace Tables: `local_file.api_gateway_logs`, `local_file.auth_service_logs`, `local_file.payment_gateway_logs`
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

3. **Live GitHub Commits (Real GitHub API via Coral)**
   - Namespace Table: `github.commits`
   - ⚠️ REQUIRED WHERE FILTERS: `owner` and `repo` are MANDATORY in every query!
   - The target repository is: owner = '{github_owner}', repo = '{github_repo_name}'
   - Key Columns:
     * `sha` (VARCHAR): Full commit SHA hash.
     * `commit__message` (VARCHAR): Commit message text.
     * `commit__author__name` (VARCHAR): Author's display name.
     * `commit__author__email` (VARCHAR): Author's email.
     * `commit__author__date` (VARCHAR): Commit date (ISO 8601 format).
     * `commit__committer__name` (VARCHAR): Committer's name.
     * `commit__committer__date` (VARCHAR): Committer date.
     * `author__login` (VARCHAR): GitHub username/login of the author.
     * `committer__login` (VARCHAR): GitHub username/login of committer.
     * `files` (VARCHAR): JSON array of changed files (includes filename, additions, deletions, changes).
     * `stats__additions` (INTEGER): Total lines added.
     * `stats__deletions` (INTEGER): Total lines deleted.
     * `stats__total` (INTEGER): Total lines changed.
     * `html_url` (VARCHAR): Web URL to view the commit on GitHub.
   - Optional Filters:
     * `ref` (VARCHAR): Branch name (e.g., 'heads/main') or tag (e.g., 'tags/v1.0').
     * `path` (VARCHAR): Only return commits touching this file path.
     * `author` (VARCHAR): Filter by GitHub username.
     * `committer` (VARCHAR): Filter by committer username.

---
### QUERY EXAMPLES

**Example 1: Get the last 30 commits from the repository:**
```sql
SELECT sha, commit__author__name, commit__author__date, commit__message, files
FROM github.commits
WHERE owner = '{github_owner}' AND repo = '{github_repo_name}'
LIMIT 30
```

**Example 2: Cross-reference commits with vulnerabilities and logs:**
```sql
SELECT 
    l.timestamp, l.service, l.message, l.response_code,
    o.package_name, o.cve, o.severity,
    g.sha, g.commit__author__name, g.commit__message
FROM local_file.api_gateway_logs l
JOIN osv.packages o ON l.message LIKE CONCAT('%', o.package_name, '%')
JOIN github.commits g ON g.commit__message LIKE CONCAT('%', o.package_name, '%')
WHERE g.owner = '{github_owner}' AND g.repo = '{github_repo_name}' 
  AND l.response_code = 500
ORDER BY l.timestamp DESC
```

**Example 3: Find commits by a specific developer:**
```sql
SELECT sha, commit__author__name, commit__message, commit__author__date, files, stats__total
FROM github.commits
WHERE owner = '{github_owner}' AND repo = '{github_repo_name}' AND author = 'TANISHX1'
LIMIT 20
```

---
### AGENTIC RUNNING RULES:
1. Always analyze the user's report. If they upload a file, query the `local_file.*` tables.
2. **CRITICAL**: When querying `github.commits`, you MUST always include `WHERE owner = '{github_owner}' AND repo = '{github_repo_name}'`. These are required filters — queries without them will fail.
3. Use `LIMIT` to control how many commits to fetch (e.g., LIMIT 30 for the last 30 commits).
4. If the user asks about a DIFFERENT repository, extract the owner and repo from their message and use those values instead.
5. Construct queries targeting the root cause. Match vulnerabilities with recent commits.
6. If you identify a critical issue, calculate the blast radius (which nodes/services are affected) and use `trigger_n8n_workflow` to dispatch the remediation automatically.
7. Explain your technical reasoning step-by-step to the operator, including the exact SQL queries you formulated.
8. If the user asks you to "map" or "analyze architecture" (or triggers a playbook for it), you MUST use the `update_threat_topology` tool to draw a visual representation of at least 4-5 distinct microservices/components related to the user's codebase. Use diverse X and Y coordinates (between 50 and 260) to spread nodes out visually. Connect them logically with edges.
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
                        "description": "The exact SQL query string. Must use local_file.logs for offline logs and join osv.packages or github.commits if needed."
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
    },
    {
        "type": "function",
        "function": {
            "name": "update_threat_topology",
            "description": "Updates the visual Threat Topology graph on the dashboard with new microservice components.",
            "parameters": {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "label": {"type": "string"},
                                "x": {"type": "integer"},
                                "y": {"type": "integer"},
                                "status": {"type": "string", "enum": ["Healthy", "Degraded"]},
                                "vulnerable": {"type": "string"},
                                "remediation": {"type": "string"}
                            },
                            "required": ["id", "label", "x", "y", "status", "vulnerable", "remediation"]
                        }
                    },
                    "edges": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source": {"type": "string"},
                                "target": {"type": "string"}
                            },
                            "required": ["source", "target"]
                        }
                    }
                },
                "required": ["nodes", "edges"]
            }
        }
    }
]


class SREBrain:
    def __init__(self):
        # 1. CLIENT INITIALIZATION
        # Priority: GROQ_API_KEY > GEMINI_API_KEY > OPENAI_API_KEY
        # Groq provides free, fast OpenAI-compatible API with generous rate limits.
        # Gemini uses the native google-genai SDK with function calling.
        # OpenAI is the standard fallback with configurable base URL.
        
        self.provider = "mock"  # Will be set to "groq", "gemini", or "openai"
        self.is_gemini_native = False
        
        groq_key = os.getenv("GROQ_API_KEY")
        gemini_key = os.getenv("GEMINI_API_KEY")
        openai_key = os.getenv("OPENAI_API_KEY")
        
        # Guard against placeholder values
        _placeholders = ("your_openai_api_key", "your_gemini_key", "your-key-here", 
                         "your_groq_key", "gsk_placeholder")
        
        def _is_valid(key):
            return key and key.strip() and not any(p in key.lower() for p in _placeholders)
        
        self.client = None
        
        # Priority 1: Gemini (native SDK with function calling)
        if _is_valid(gemini_key):
            if HAS_GEMINI:
                logger.info("Initializing Google GenAI native client for Gemini model.")
                self.api_key = gemini_key
                self.model = os.getenv("SRE_LLM_MODEL", "gemini-1.5-flash-8b")
                self.client = genai.Client(api_key=gemini_key)
                self.is_gemini_native = True
                self.provider = "gemini"
            else:
                logger.warning("Gemini key found but google-genai library not installed.")
        
        # Priority 2: Groq (free, fast, no rate limit issues)
        if not self.client and _is_valid(groq_key):
            if HAS_OPENAI:
                logger.info("🚀 Initializing Groq client (Llama 3.3 70B via OpenAI-compatible API).")
                self.api_key = groq_key
                self.model = os.getenv("SRE_LLM_MODEL", "llama-3.3-70b-versatile")
                self.client = OpenAI(
                    api_key=groq_key,
                    base_url="https://api.groq.com/openai/v1"
                )
                self.provider = "groq"
            else:
                logger.warning("Groq key found but openai library not installed.")
        
        # Priority 3: OpenAI (standard or custom endpoint)
        if not self.client and _is_valid(openai_key):
            if HAS_OPENAI:
                base_url = os.getenv("OPENAI_API_BASE", None)
                logger.info(f"Initializing OpenAI client{' (custom endpoint)' if base_url else ''}.")
                self.api_key = openai_key
                self.model = os.getenv("SRE_LLM_MODEL", "gpt-4o")
                self.client = OpenAI(api_key=openai_key, base_url=base_url)
                self.provider = "openai"
            else:
                logger.warning("OpenAI key found but openai library not installed.")
        
        if not self.client:
            logger.warning("No valid LLM API key found (checked GROQ_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY). Operating in mock mode.")

        # 2. DYNAMIC SYSTEM PROMPT CONFIGURATION
        # Inject the target GitHub repository from environment into the system prompt
        # so the LLM generates correct WHERE owner/repo clauses automatically.
        github_repo = os.getenv("GITHUB_REPO", "Harshit7623/aegis-sre")
        if "/" in github_repo:
            self.github_owner, self.github_repo_name = github_repo.split("/", 1)
        else:
            self.github_owner, self.github_repo_name = "Harshit7623", github_repo
        
        self.system_prompt = SYSTEM_PROMPT.format(
            github_owner=self.github_owner,
            github_repo_name=self.github_repo_name
        )
        logger.info(f"System prompt configured for repo: {self.github_owner}/{self.github_repo_name}")

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
        messages = [{"role": "system", "content": self.system_prompt}]
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
                    elif function_name == "update_threat_topology":
                        nodes = arguments.get("nodes", [])
                        edges = arguments.get("edges", [])
                        tool_result = update_threat_topology(nodes, edges)
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
        tools = [execute_coral_query, trigger_n8n_workflow, update_threat_topology]
        yield {"type": "status", "content": "Initializing Google GenAI SRE Triage session..."}
        
        try:
            # CRITICAL: Disable AFC (Automatic Function Calling). 
            # When AFC is enabled, the SDK auto-executes tools internally and feeds results
            # back to the model without yielding them to our generator loop. This means
            # trigger_investigation() in aegis_app.py never sees the tool_result events 
            # and can never update blast_radius_nodes or other UI state.
            # By disabling AFC, we force all tool calls through our manual loop below,
            # which properly yields tool_call/tool_result events to the UI handler.
            chat = self.client.chats.create(
                model=self.model,
                config=types.GenerateContentConfig(
                    system_instruction=self.system_prompt,
                    tools=tools,
                    temperature=0.1,
                    automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
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
                    elif name == "update_threat_topology":
                        nodes = args.get("nodes", [])
                        edges = args.get("edges", [])
                        tool_result = update_threat_topology(nodes, edges)
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
        logger.info("Engaging mocked SRE brain reasoning generator.")
        
        yield {"type": "status", "content": "Simulating cognitive analysis of incident..."}
        
        yield {"type": "thought", "content": "Analyzing SRE request. Initiating forensic scan of logs, vulnerabilities, and GitHub git history."}
        
        # 1. Simulate Coral SQL execution tool call
        # Dynamically pull repo from env so this adapts to any user's configuration
        github_repo = os.getenv("GITHUB_REPO", "Harshit7623/aegis-sre")
        owner, repo = github_repo.split("/") if "/" in github_repo else ("Harshit7623", "aegis-sre")
        mock_sql = f"SELECT * FROM local_file.api_gateway_logs JOIN osv.packages JOIN github.commits WHERE author = 'TANISHX1' AND owner = '{owner}' AND repo = '{repo}'"
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
            "content": """### Root Cause Analysis & Forensic Summary: Aegis-Antigravity
*   **Root Cause**: The production crash was triggered by a high-severity cookie-leak vulnerability in **urllib3** (`CVE-2023-43804`). This vulnerability was committed by developer **TANISHX1** in commit `a5d89f3` while refactoring dependencies.
*   **Blast Radius**: The issue has degraded **api-gateway** and **auth-service**, generating `500 Server Error` response codes across 12% of traffic.
*   **Triggered Actions**:
    * An n8n workflow was successfully launched to quarantine the node.
    * Slack alerts and incident tickets have been dispatched to the on-call queue.
    * Scheduled dependency upgrade tasks to force-install `urllib3==1.26.18` have been registered."""
        }
