"""Demo CLI: runs one goal through the agent, using the real MCP server.

Usage:
    python scripts/run_demo.py "check which ports are open on my machine"

Requires ANTHROPIC_API_KEY to be set (see .env.example). When the agent
proposes a sensitive tool call, the graph pauses and this script prompts for
approval on the terminal before resuming.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from agent.audit import AuditLogger
from agent.graph import build_graph, initial_state
from agent.llm import get_llm

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_PATH = REPO_ROOT / "mcp_server" / "server.py"


def ask_for_approval(request: dict) -> bool:
    print("\n--- HUMAN APPROVAL REQUIRED ---")
    print(f"tool:      {request['tool']}")
    print(f"arguments: {request['arguments']}")
    print(f"reason:    {request['reason']}")
    answer = input("Approve this action? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


async def main(goal: str) -> None:
    load_dotenv()

    client = MultiServerMCPClient(
        {
            "recon": {
                "transport": "stdio",
                "command": sys.executable,
                "args": [str(SERVER_PATH)],
            }
        }
    )
    tools = await client.get_tools()

    audit_logger = AuditLogger(REPO_ROOT / "audit_log.json")
    graph = build_graph(get_llm(), tools, audit_logger, MemorySaver())
    config = {"configurable": {"thread_id": "demo"}}

    state = initial_state(goal)
    result = await graph.ainvoke(state, config=config)

    while "__interrupt__" in result:
        request = result["__interrupt__"][0].value
        approved = ask_for_approval(request)
        result = await graph.ainvoke(Command(resume={"approved": approved}), config=config)

    print("\n--- FINAL ANSWER ---")
    print(result.get("final_answer"))
    print(f"\nAudit log written to {audit_logger.path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} '<goal>'")
        raise SystemExit(1)
    asyncio.run(main(sys.argv[1]))
