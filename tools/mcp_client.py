"""
Aegis-Antigravity: Coral MCP Client
----------------------------------------
A lightweight Model Context Protocol (MCP) client that communicates with Coral's
built-in MCP server (`coral mcp-stdio`) via JSON-RPC 2.0 over stdin/stdout.

CRITICAL ARCHITECTURAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. MCP Over Subprocess:
   Instead of shelling out to `coral sql` and parsing raw JSON output, we maintain
   a persistent MCP session with Coral. This gives us structured responses, typed
   error objects, and access to Coral's full tool suite (catalog browsing, schema
   discovery, SQL execution) through a single connection.

2. Persistent Process with Lazy Initialization:
   The Coral MCP server is started once as a subprocess and reused across all queries.
   This eliminates the ~300ms cold-start overhead per query that subprocess.run() 
   incurred. The process is started lazily on first use and restarted if it dies.

3. Schema Learning at Runtime:
   The `discover_schema()` method queries `coral.columns` and `coral.tables` via MCP
   to auto-discover table structures. This means the system prompt can be dynamically
   built from real schemas instead of hardcoded column definitions.

4. Thread Safety:
   All MCP calls are protected by a threading Lock to prevent interleaved JSON-RPC
   messages when multiple Reflex background tasks run concurrently.
"""

import os
import json
import shutil
import logging
import subprocess
import threading
from typing import Dict, Any, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CoralMCP")


class CoralMCPClient:
    """
    A persistent MCP client that communicates with `coral mcp-stdio`.
    
    Usage:
        client = CoralMCPClient()
        result = client.sql("SELECT * FROM github.commits WHERE owner='X' AND repo='Y' LIMIT 5")
        schema = client.list_columns("github", "commits")
    """
    
    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._request_id = 0
        self._initialized = False
        self._server_info: Dict[str, Any] = {}
        self._instructions: str = ""
    
    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id
    
    def _ensure_process(self):
        """Start the Coral MCP server process if not already running."""
        if self._process is not None and self._process.poll() is None:
            return  # Already running
        
        coral_binary = shutil.which("coral")
        if not coral_binary:
            raise RuntimeError("Coral CLI binary not found in PATH. Install: curl -fsSL https://withcoral.com/install.sh | sh")
        
        # Build environment with GITHUB_TOKEN if available
        env = {**os.environ}
        github_token = os.getenv("GITHUB_TOKEN")
        if github_token:
            env["GITHUB_TOKEN"] = github_token
        
        logger.info(f"Starting Coral MCP server: {coral_binary} mcp-stdio")
        self._process = subprocess.Popen(
            [coral_binary, "mcp-stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            bufsize=1  # Line-buffered for real-time communication
        )
        self._initialized = False
    
    def _send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Send a JSON-RPC 2.0 request to the Coral MCP server and read the response.
        Thread-safe via internal lock.
        """
        with self._lock:
            self._ensure_process()
            
            request_id = self._next_id()
            request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
            }
            if params is not None:
                request["params"] = params
            
            request_line = json.dumps(request) + "\n"
            
            try:
                self._process.stdin.write(request_line)
                self._process.stdin.flush()
                
                # Read exactly one response line
                response_line = self._process.stdout.readline()
                if not response_line:
                    raise RuntimeError("Coral MCP server returned empty response (process may have crashed)")
                
                response = json.loads(response_line.strip())
                
                # Validate response ID matches
                if response.get("id") != request_id:
                    logger.warning(f"Response ID mismatch: expected {request_id}, got {response.get('id')}")
                
                return response
                
            except (BrokenPipeError, OSError) as e:
                logger.error(f"Coral MCP connection broken: {e}. Restarting...")
                self._kill_process()
                raise RuntimeError(f"Coral MCP connection failed: {e}")
    
    def _kill_process(self):
        """Terminate the MCP server process."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                self._process.kill()
            self._process = None
            self._initialized = False
    
    def initialize(self) -> Dict[str, Any]:
        """
        Send the MCP initialize handshake. Must be called before any tool calls.
        Returns the server info including capabilities and instructions.
        """
        if self._initialized:
            return self._server_info
        
        response = self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "aegis-sre",
                "version": "1.0.0"
            }
        })
        
        if "error" in response:
            raise RuntimeError(f"MCP initialization failed: {response['error']}")
        
        result = response.get("result", {})
        self._server_info = result.get("serverInfo", {})
        self._instructions = result.get("instructions", "")
        self._initialized = True
        
        logger.info(f"✅ MCP connected to Coral v{self._server_info.get('version', 'unknown')}")
        return result
    
    def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP tool and return the result."""
        self.initialize()
        
        response = self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })
        
        if "error" in response:
            error = response["error"]
            raise RuntimeError(f"MCP tool '{tool_name}' error ({error.get('code')}): {error.get('message')}")
        
        return response.get("result", {})
    
    # ─── PUBLIC API ───────────────────────────────────────────────
    
    def sql(self, query: str) -> Dict[str, Any]:
        """
        Execute a SQL query via Coral MCP and return structured results.
        
        Returns:
            Dict with 'status', 'data' (list of row dicts), and 'count'.
        """
        try:
            result = self._call_tool("sql", {"sql": query})
            
            # Extract structured content (preferred) or parse text content
            structured = result.get("structuredContent")
            if structured and "rows" in structured:
                rows = structured["rows"]
                return {
                    "status": "success",
                    "data": rows,
                    "count": len(rows)
                }
            
            # Fallback: parse from text content
            content_items = result.get("content", [])
            for item in content_items:
                if item.get("type") == "text":
                    try:
                        parsed = json.loads(item["text"])
                        rows = parsed.get("rows", [])
                        return {
                            "status": "success",
                            "data": rows,
                            "count": len(rows)
                        }
                    except json.JSONDecodeError:
                        return {
                            "status": "success",
                            "data": [{"result": item["text"]}],
                            "count": 1
                        }
            
            return {"status": "success", "data": [], "count": 0}
            
        except Exception as e:
            logger.error(f"MCP SQL execution failed: {e}")
            return {
                "status": "error",
                "message": str(e),
                "data": [],
                "count": 0
            }
    
    def list_catalog(self, schema: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """List available tables/functions in the catalog."""
        args = {"limit": limit}
        if schema:
            args["schema"] = schema
        
        try:
            result = self._call_tool("list_catalog", args)
            structured = result.get("structuredContent", {})
            return structured.get("items", [])
        except Exception as e:
            logger.error(f"MCP list_catalog failed: {e}")
            return []
    
    def search_catalog(self, pattern: str, schema: str = None) -> List[Dict[str, Any]]:
        """Search the catalog using a regex pattern."""
        args = {"pattern": pattern}
        if schema:
            args["schema"] = schema
        
        try:
            result = self._call_tool("search_catalog", args)
            structured = result.get("structuredContent", {})
            return structured.get("items", [])
        except Exception as e:
            logger.error(f"MCP search_catalog failed: {e}")
            return []
    
    def describe_table(self, schema: str, table: str) -> Dict[str, Any]:
        """Get metadata for a specific table."""
        try:
            result = self._call_tool("describe_table", {
                "schema": schema,
                "table": table
            })
            # Extract from content
            content_items = result.get("content", [])
            for item in content_items:
                if item.get("type") == "text":
                    return {"description": item["text"]}
            return result
        except Exception as e:
            logger.error(f"MCP describe_table failed: {e}")
            return {"error": str(e)}
    
    def list_columns(self, schema: str, table: str, required_only: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
        """
        List columns for a specific table. Used for runtime schema learning.
        
        Returns:
            List of column dicts with keys: column_name, data_type, is_required_filter, description
        """
        args = {
            "schema": schema,
            "table": table,
            "limit": limit,
        }
        if required_only:
            args["required_only"] = True
        
        try:
            result = self._call_tool("list_columns", args)
            structured = result.get("structuredContent", {})
            return structured.get("columns", [])
        except Exception as e:
            logger.error(f"MCP list_columns failed: {e}")
            return []
    
    def discover_schema(self, schemas: List[str] = None, 
                         focused_tables: Dict[str, List[str]] = None) -> Dict[str, Dict[str, List[Dict]]]:
        """
        Auto-discover table schemas from Coral at runtime.
        
        Args:
            schemas: List of schema names to discover (e.g., ['local_file', 'osv', 'github']).
            focused_tables: Optional dict mapping schema names to specific tables to introspect.
                           e.g. {'github': ['commits', 'pulls']}. If a schema is not in this dict,
                           all its tables are introspected.
        
        Returns:
            Nested dict: {schema_name: {table_name: [column_defs]}}
        """
        discovered = {}
        
        # Default: only introspect the tables we actually use
        if focused_tables is None:
            focused_tables = {
                "github": ["commits", "pulls", "issues"],  # Don't introspect all 362 GitHub tables
            }
        
        target_schemas = schemas or ["local_file", "osv", "github"]
        
        for schema_name in target_schemas:
            focus_list = focused_tables.get(schema_name)
            
            if focus_list:
                # Directly list columns for focused tables (skip catalog)
                for table_name in focus_list:
                    columns = self.list_columns(schema_name, table_name, limit=50)
                    if columns:
                        if schema_name not in discovered:
                            discovered[schema_name] = {}
                        discovered[schema_name][table_name] = self._filter_columns(columns)
            else:
                # Discover all tables in this schema
                catalog = self.list_catalog(schema=schema_name, limit=50)
                
                for item in catalog:
                    if item.get("kind") != "table":
                        continue
                    
                    table_info = item.get("table", {})
                    table_name = table_info.get("table_name", item.get("name", "").replace(f"{schema_name}.", ""))
                    
                    if schema_name not in discovered:
                        discovered[schema_name] = {}
                    
                    columns = self.list_columns(schema_name, table_name, limit=50)
                    discovered[schema_name][table_name] = self._filter_columns(columns)
        
        return discovered
    
    def _filter_columns(self, columns: List[Dict]) -> List[Dict]:
        """Filter out internal/URL columns to keep the schema concise for LLM prompts."""
        skip_patterns = ("_url", "node_id", "gravatar", "events_url", "followers_url",
                        "following_url", "gists_url", "organizations_url", "repos_url",
                        "subscriptions_url", "received_events", "starred_url", "site_admin",
                        "user_view_type", "starred_at")
        key_columns = []
        for col in columns:
            name = col.get("column_name", "")
            if any(p in name for p in skip_patterns):
                continue
            key_columns.append({
                "column_name": name,
                "data_type": col.get("data_type", ""),
                "is_required_filter": col.get("is_required_filter", False),
                "description": col.get("description", ""),
            })
        return key_columns
    
    def get_mcp_instructions(self) -> str:
        """Get the MCP server's instruction text for system prompts."""
        self.initialize()
        return self._instructions
    
    def close(self):
        """Cleanly shut down the MCP connection."""
        self._kill_process()
    
    def __del__(self):
        self.close()


# Module-level singleton for reuse across the application
_client: Optional[CoralMCPClient] = None
_client_lock = threading.Lock()


def get_mcp_client() -> CoralMCPClient:
    """Get or create the singleton MCP client instance."""
    global _client
    with _client_lock:
        if _client is None:
            _client = CoralMCPClient()
        return _client
