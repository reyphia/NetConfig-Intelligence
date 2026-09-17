"""Safe, presentation-ready unified configuration diffs."""

from __future__ import annotations

from difflib import unified_diff


def configuration_diff(original: str, modified: str) -> dict[str, object]:
    lines = list(unified_diff(original.splitlines(), modified.splitlines(), lineterm=""))
    added = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in lines if line.startswith("-") and not line.startswith("---"))
    return {"unified": "\n".join(lines), "added": added, "removed": removed, "changed_lines": added + removed}
