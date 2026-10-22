"""JSON audit log: one entry per graph step, covering every policy decision."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.exists():
            self.path.write_text("[]")

    def log(
        self,
        *,
        prompt: Optional[str],
        tool: Optional[str],
        arguments: Optional[dict[str, Any]],
        policy_decision: Optional[dict[str, Any]],
        result: Optional[str],
    ) -> None:
        entries = json.loads(self.path.read_text())
        entries.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "prompt": prompt,
                "tool": tool,
                "arguments": arguments,
                "policy_decision": policy_decision,
                "result": result,
            }
        )
        self.path.write_text(json.dumps(entries, indent=2))

    def read_all(self) -> list[dict[str, Any]]:
        return json.loads(self.path.read_text())
