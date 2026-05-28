"""
Aegis SRE: Core Backend & Asynchronous MCP Engine
------------------------------------------------
This module implements the principal execution loop for the Aegis SRE agent.
It leverages Model Context Protocol (MCP) to communicate with Coral and 
integrates with the Reflex frontend state via non-blocking background tasks.
"""

import os
import json
import asyncio
import logging
from typing import Dict, Any, List

# Enforce Sandboxed Runtime
# All Coral configurations and logical caches are stored here.
ABS_SANDBOX_PATH = os.path.abspath("./.aegis_sandbox")
os.environ["CORAL_CONFIG_DIR"] = ABS_SANDBOX_PATH

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AegisCore")

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    logger.error("MCP Client libraries missing. Run 'pip install mcp'")

class AegisCore:
    def __init__(self):
        self.background_tasks = set()

    async def run_forensic_query(self, sql_query: str) -> Dict[str, Any]:
        """
        Executes a SQL query against the Coral MCP Server.
        Connects via stdin/stdout to the 'coral mcp server' process.
        """
        if not HAS_MCP:
            return {"status": "error", "message": "MCP library not installed."}

        server_params = StdioServerParameters(
            command="coral",
            args=["mcp", "server"],
            env=os.environ.copy()
        )

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    
                    # In MCP mode, we call the 'query' tool exposed by the Coral server
                    results = await session.call_tool("query", {"sql": sql_query})
                    return {
                        "status": "success",
                        "data": results
                    }
        except Exception as e:
            logger.error(f"MCP Query Failure: {str(e)}")
            return {"status": "error", "message": str(e)}

    def get_upload_path(self, filename: str) -> str:
        """
        Maps a filename to the Reflex upload directory.
        Used to substitute local log paths in Coral queries.
        """
        # In a real Reflex app, this would use rx.get_upload_dir()
        # For now, we point to our local forensic logs directory.
        return os.path.abspath(f"./uploaded_files/{filename}")

# Note: The @rx.background decorator is applied in the Reflex State class 
# thin-wrapping these calls to prevent event-loop blocks.
