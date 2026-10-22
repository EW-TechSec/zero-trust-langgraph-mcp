"""The LangGraph StateGraph: plan -> policy_check -> act -> review.

Every tool call the LLM proposes in `plan` must pass through `policy_check`
before `act` is even reachable. `policy_check` is where the zero-trust
enforcement lives: allowlist, Pydantic argument validation, and a LangGraph
`interrupt()` for tools marked sensitive, which pauses the graph until a
human resumes it with an approval decision. Every decision is written to the
audit log from inside `policy_check` and `act`.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import interrupt

from agent.audit import AuditLogger
from agent.policy import evaluate_policy
from agent.state import AgentState

DEFAULT_MAX_STEPS = 3


def _last_human_text(messages: list[BaseMessage]) -> Optional[str]:
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            return str(message.content)
    return None


def _stringify_tool_result(raw: Any) -> str:
    """MCP tools return a list of content blocks (e.g. {"type": "text", ...});
    plain LangChain tools (used in tests) return a str directly."""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        texts = [block["text"] for block in raw if isinstance(block, dict) and block.get("type") == "text"]
        if texts:
            return "\n".join(texts)
    return str(raw)


def build_graph(
    llm: BaseChatModel,
    tools: list[BaseTool],
    audit_logger: AuditLogger,
    checkpointer: BaseCheckpointSaver,
    max_steps: int = DEFAULT_MAX_STEPS,
) -> CompiledStateGraph:
    tools_by_name = {tool.name: tool for tool in tools}
    llm_with_tools = llm.bind_tools(tools)

    async def plan(state: AgentState) -> dict[str, Any]:
        ai_message = await llm_with_tools.ainvoke(state["messages"])
        tool_calls = getattr(ai_message, "tool_calls", None) or []

        if not tool_calls:
            return {
                "messages": [ai_message],
                "pending_tool_call": None,
                "done": True,
                "final_answer": ai_message.content,
            }

        call = tool_calls[0]
        pending = {"name": call["name"], "args": call.get("args") or {}, "id": call.get("id") or ""}
        return {"messages": [ai_message], "pending_tool_call": pending, "done": False}

    def route_after_plan(state: AgentState) -> str:
        return END if state.get("done") else "policy_check"

    def policy_check(state: AgentState) -> dict[str, Any]:
        pending = state["pending_tool_call"]
        result = evaluate_policy(pending["name"], pending["args"])
        decision = {"allowed": result.allowed, "sensitive": result.sensitive, "reason": result.reason}
        effective_args = result.validated_args or pending["args"]

        if result.allowed and result.sensitive:
            approval = interrupt(
                {
                    "type": "approval_request",
                    "tool": pending["name"],
                    "arguments": effective_args,
                    "reason": result.reason,
                }
            )
            approved = approval.get("approved", False) if isinstance(approval, dict) else bool(approval)
            if not approved:
                decision = {"allowed": False, "sensitive": True, "reason": "denied by human reviewer"}

        audit_logger.log(
            prompt=_last_human_text(state["messages"]),
            tool=pending["name"],
            arguments=effective_args,
            policy_decision=decision,
            result=None,
        )

        return {
            "policy_decision": decision,
            "pending_tool_call": {**pending, "args": effective_args},
        }

    def route_after_policy(state: AgentState) -> str:
        return "act" if state["policy_decision"]["allowed"] else "review"

    async def act(state: AgentState) -> dict[str, Any]:
        pending = state["pending_tool_call"]
        tool = tools_by_name[pending["name"]]
        try:
            raw_result = await tool.ainvoke(pending["args"])
            result_str = _stringify_tool_result(raw_result)
        except Exception as exc:  # noqa: BLE001 - surfaced to the LLM as a tool error, not raised
            result_str = f"ERROR: {exc}"

        tool_message = ToolMessage(content=result_str, tool_call_id=pending["id"] or "unknown")

        audit_logger.log(
            prompt=None,
            tool=pending["name"],
            arguments=pending["args"],
            policy_decision=state["policy_decision"],
            result=result_str,
        )

        return {
            "messages": [tool_message],
            "tool_result": result_str,
            "step_count": state.get("step_count", 0) + 1,
        }

    def review(state: AgentState) -> dict[str, Any]:
        decision = state.get("policy_decision") or {}
        step_count = state.get("step_count", 0)
        limit = state.get("max_steps", max_steps)
        pending = state.get("pending_tool_call") or {}

        if not decision.get("allowed", False):
            reason = decision.get("reason", "denied by policy")
            denial_message = ToolMessage(
                content=f"DENIED by zero-trust policy: {reason}",
                tool_call_id=pending.get("id") or "unknown",
            )
            new_step_count = step_count + 1
            update: dict[str, Any] = {"messages": [denial_message], "step_count": new_step_count}
            if new_step_count >= limit:
                update["done"] = True
                update["final_answer"] = f"Stopped after repeated policy denials. Last reason: {reason}"
            else:
                update["done"] = False
            return update

        if step_count >= limit:
            return {"done": True, "final_answer": state.get("tool_result", "")}
        return {"done": False}

    def route_after_review(state: AgentState) -> str:
        return END if state.get("done") else "plan"

    graph = StateGraph(AgentState)
    graph.add_node("plan", plan)
    graph.add_node("policy_check", policy_check)
    graph.add_node("act", act)
    graph.add_node("review", review)

    graph.add_edge(START, "plan")
    graph.add_conditional_edges("plan", route_after_plan, {"policy_check": "policy_check", END: END})
    graph.add_conditional_edges("policy_check", route_after_policy, {"act": "act", "review": "review"})
    graph.add_edge("act", "review")
    graph.add_conditional_edges("review", route_after_review, {"plan": "plan", END: END})

    return graph.compile(checkpointer=checkpointer)


def initial_state(goal: str, max_steps: int = DEFAULT_MAX_STEPS) -> AgentState:
    return {
        "messages": [HumanMessage(content=goal)],
        "pending_tool_call": None,
        "policy_decision": None,
        "tool_result": None,
        "step_count": 0,
        "max_steps": max_steps,
        "done": False,
        "final_answer": None,
    }
