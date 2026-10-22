"""Shared graph state.

`messages` uses LangGraph's MessagesState so LLM/tool messages accumulate
correctly across nodes. The remaining fields are scratch space written by
exactly one node per step, so they don't need reducers.
"""

from __future__ import annotations

from typing import Any, Optional, TypedDict

from langgraph.graph import MessagesState


class ToolCall(TypedDict):
    name: str
    args: dict[str, Any]
    id: str


class PolicyDecision(TypedDict):
    allowed: bool
    sensitive: bool
    reason: str


class AgentState(MessagesState):
    pending_tool_call: Optional[ToolCall]
    policy_decision: Optional[PolicyDecision]
    tool_result: Optional[str]
    step_count: int
    max_steps: int
    done: bool
    final_answer: Optional[str]
