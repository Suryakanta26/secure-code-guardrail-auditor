import os
from langchain_mcp_adapters.client import MultiServerMCPClient
from app.config import settings

class GithubMCPService:
    def __init__(self):
        self.client = None
        self.session_context = None
        self.session = None

    async def initialize(self):
        env = os.environ.copy()
        # Map existing GITHUB_TOKEN to GITHUB_PERSONAL_ACCESS_TOKEN
        if settings.github_token:
            env["GITHUB_PERSONAL_ACCESS_TOKEN"] = settings.github_token
            
        connections = {
            "github": {
                "command": "npx.cmd" if os.name == "nt" else "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": env,
                "transport": "stdio"
            }
        }
        self.client = MultiServerMCPClient(connections)
        self.session_context = self.client.session("github")
        self.session = await self.session_context.__aenter__()
        print("Github MCP Server Initialized.")

    async def close(self):
        if self.session_context:
            await self.session_context.__aexit__(None, None, None)
            self.session = None
            self.session_context = None
        print("Github MCP Server Closed.")

    async def search_repositories(self, query: str):
        if not self.session:
            raise RuntimeError("MCP Session not initialized.")
        res = await self.session.call_tool("search_repositories", {"query": query})
        return res

    async def list_pull_requests(self, owner: str, repo: str, state: str = "open"):
        if not self.session:
            raise RuntimeError("MCP Session not initialized.")
        res = await self.session.call_tool("list_pull_requests", {"owner": owner, "repo": repo, "state": state})
        return res

    async def get_pull_request_files(self, owner: str, repo: str, pull_number: int):
        if not self.session:
            raise RuntimeError("MCP Session not initialized.")
        res = await self.session.call_tool("get_pull_request_files", {"owner": owner, "repo": repo, "pull_number": pull_number})
        return res

# Singleton instance
github_mcp = GithubMCPService()
