"""
Tool classification, resolved restrictively from the protocol's own
ToolAnnotations hints (readOnlyHint / destructiveHint / idempotentHint).
Hints are self-reported, so a hint may only TIGHTEN a class, never relax it:
a safety claim (readOnlyHint, destructiveHint=False) is honored only from an
attested server; a danger claim is honored from anyone. A tool with no
authoritative signal defaults to state-changing and irreversible (fail-closed).

Classes: "read" | "write" (state-changing, reversible) | "irreversible".
"""


def resolve_class(annotations: dict | None, attested: bool) -> str:
    ann = annotations or {}
    if ann.get("readOnlyHint") is True:
        return "read" if attested else "irreversible"
    if ann.get("destructiveHint") is False:
        return "write" if attested else "irreversible"
    return "irreversible"


class ToolClasses:
    """Per-session class map, filled at IP-2 as each tool list is validated."""

    def __init__(self):
        self._map: dict[str, str] = {}

    def register(self, server, tool, annotations=None, attested=False):
        self._map[f"{server}.{tool}"] = resolve_class(annotations, attested)

    def classify(self, server, tool) -> str:
        return self._map.get(f"{server}.{tool}", "irreversible")
