"""End-to-end graph tests using a scripted fake LLM. No API key required.

These exercise the full plan -> policy_check -> act -> review loop, including
the human-in-the-loop interrupt for the sensitive tool, entirely offline.
"""

import json

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from agent.audit import AuditLogger
from agent.graph import build_graph, initial_state


class FakeLLM:
    """Stands in for a real chat model: bind_tools is a no-op, ainvoke pops
    the next scripted AIMessage off a queue."""

    def __init__(self, responses):
        self.responses = list(responses)

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        return self.responses.pop(0)


@tool
def ping_host(host: str = "127.0.0.1", count: int = 4) -> str:
    """Ping a host."""
    return "4 packets transmitted, 4 received"


@tool
def list_open_ports(host: str = "127.0.0.1", start_port: int = 1, end_port: int = 1024) -> str:
    """List open ports."""
    return json.dumps({"host": host, "open_ports": [22, 80]})


TOOLS = [ping_host, list_open_ports]


def _config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


@pytest.mark.asyncio
async def test_non_sensitive_tool_runs_without_interruption(tmp_path):
    responses = [
        AIMessage(
            content="",
            tool_calls=[{"name": "ping_host", "args": {"host": "127.0.0.1", "count": 2}, "id": "call_1"}],
        ),
        AIMessage(content="The host is reachable."),
    ]
    audit = AuditLogger(tmp_path / "audit.json")
    graph = build_graph(FakeLLM(responses), TOOLS, audit, MemorySaver())

    result = await graph.ainvoke(initial_state("is localhost up?"), config=_config("t-ping"))

    assert "__interrupt__" not in result
    assert result["done"] is True
    assert result["final_answer"] == "The host is reachable."

    entries = audit.read_all()
    assert len(entries) == 2  # policy decision + act result
    assert entries[0]["tool"] == "ping_host"
    assert entries[0]["policy_decision"]["allowed"] is True
    assert entries[1]["result"] is not None


@pytest.mark.asyncio
async def test_sensitive_tool_interrupts_and_resumes_on_approval(tmp_path):
    responses = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "list_open_ports",
                    "args": {"host": "127.0.0.1", "start_port": 1, "end_port": 100},
                    "id": "call_1",
                }
            ],
        ),
        AIMessage(content="Ports 22 and 80 are open."),
    ]
    audit = AuditLogger(tmp_path / "audit.json")
    graph = build_graph(FakeLLM(responses), TOOLS, audit, MemorySaver())
    config = _config("t-approve")

    first = await graph.ainvoke(initial_state("scan my open ports"), config=config)
    assert "__interrupt__" in first
    interrupt_payload = first["__interrupt__"][0].value
    assert interrupt_payload["tool"] == "list_open_ports"

    final = await graph.ainvoke(Command(resume={"approved": True}), config=config)

    assert final["done"] is True
    assert final["final_answer"] == "Ports 22 and 80 are open."

    entries = audit.read_all()
    assert entries[0]["policy_decision"] == {"allowed": True, "sensitive": True, "reason": "ok"}
    assert entries[1]["result"] is not None


@pytest.mark.asyncio
async def test_sensitive_tool_stops_when_human_denies(tmp_path):
    responses = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "list_open_ports",
                    "args": {"host": "127.0.0.1", "start_port": 1, "end_port": 100},
                    "id": "call_1",
                }
            ],
        ),
        AIMessage(content="Understood, I will not scan."),
    ]
    audit = AuditLogger(tmp_path / "audit.json")
    graph = build_graph(FakeLLM(responses), TOOLS, audit, MemorySaver())
    config = _config("t-deny")

    first = await graph.ainvoke(initial_state("scan my open ports"), config=config)
    assert "__interrupt__" in first

    final = await graph.ainvoke(Command(resume={"approved": False}), config=config)

    assert final["done"] is True
    assert final["final_answer"] == "Understood, I will not scan."

    entries = audit.read_all()
    assert entries[0]["policy_decision"]["allowed"] is False
    assert entries[0]["policy_decision"]["reason"] == "denied by human reviewer"


@pytest.mark.asyncio
async def test_disallowed_target_is_blocked_without_any_interrupt(tmp_path):
    responses = [
        AIMessage(
            content="",
            tool_calls=[{"name": "ping_host", "args": {"host": "93.184.216.34", "count": 4}, "id": "call_1"}],
        ),
        AIMessage(content="I cannot ping that host."),
    ]
    audit = AuditLogger(tmp_path / "audit.json")
    graph = build_graph(FakeLLM(responses), TOOLS, audit, MemorySaver())

    result = await graph.ainvoke(initial_state("ping 93.184.216.34"), config=_config("t-badhost"))

    assert "__interrupt__" not in result
    assert result["done"] is True
    assert result["final_answer"] == "I cannot ping that host."

    entries = audit.read_all()
    assert len(entries) == 1  # policy denial only; act never runs
    assert entries[0]["policy_decision"]["allowed"] is False


@pytest.mark.asyncio
async def test_plan_can_finish_immediately_without_calling_a_tool(tmp_path):
    responses = [AIMessage(content="I don't need any tools to answer that.")]
    audit = AuditLogger(tmp_path / "audit.json")
    graph = build_graph(FakeLLM(responses), TOOLS, audit, MemorySaver())

    result = await graph.ainvoke(initial_state("what is 2+2?"), config=_config("t-direct"))

    assert result["done"] is True
    assert result["final_answer"] == "I don't need any tools to answer that."
    assert audit.read_all() == []
