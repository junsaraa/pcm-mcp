"""Standalone github MCP server.  Run:  python -m servers.github.server"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from servers.workload_servers import build_github, BUILDERS

if __name__ == "__main__":
    _, port = BUILDERS["github"]
    mcp = build_github()
    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = port
    mcp.run(transport="streamable-http")
