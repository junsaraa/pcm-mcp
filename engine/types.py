"""
Core types for the policy engine. No I/O, no framework -- pure data structures
that the hooks operate over. Read this first: everything else refers to these.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


# --------------------------------------------------------------------------
# Slots -- the binding between a plan variable and a tool argument.
# --------------------------------------------------------------------------
class SlotKind(str, Enum):
    LITERAL = "literal"     # value known at plan time, must be a span of prompt
    DERIVED = "derived"     # extracted from an earlier step's output by the Q-LLM
    RESOLVED = "resolved"   # filled by an authorised lookup (clock, contacts)


@dataclass
class Slot:
    name: str
    kind: SlotKind
    type: str | None = None                 # "number" | "text" | "enum"
    value: object = None                     # set for LITERAL
    domain: object = None                    # [lo,hi] for number, list for enum
    max_length: int | None = None
    source_var: str | None = None            # for DERIVED: which earlier var
    required_prov: frozenset[str] = frozenset()


@dataclass
class Step:
    step_id: int
    server: str
    tool: str
    slots: list[Slot] = field(default_factory=list)
    repeat: int = 1                          # amplification: calls in this step
    is_extraction: bool = False              # a Q-LLM extract, not a tool call


@dataclass
class Plan:
    steps: list[Step]
    prompt: str = ""

    def tools_used(self) -> set[tuple[str, str]]:
        return {(s.server, s.tool) for s in self.steps if not s.is_extraction}

    def total_calls(self) -> int:
        return sum(s.repeat for s in self.steps if not s.is_extraction)


# --------------------------------------------------------------------------
# Provenance tags -- one per value the engine tracks.
# --------------------------------------------------------------------------
@dataclass
class Tag:
    sources: frozenset[str]                  # servers/user that produced it
    trust: str                               # "trusted" | "untrusted-content"
    attested: bool
    readers: frozenset[str]                  # servers permitted to receive it

    @staticmethod
    def join(tags: list["Tag"]) -> "Tag":
        """Sound over-approximation: union sources, lower trust, intersect readers."""
        if not tags:
            return Tag(frozenset(), "trusted", True, frozenset())
        sources = frozenset().union(*(t.sources for t in tags))
        trust = ("untrusted-content"
                 if any(t.trust == "untrusted-content" for t in tags)
                 else "trusted")
        attested = all(t.attested for t in tags)
        readers = tags[0].readers
        for t in tags[1:]:
            readers = readers & t.readers
        return Tag(sources, trust, attested, readers)


# --------------------------------------------------------------------------
# Session state -- everything the engine owns for one session.
# --------------------------------------------------------------------------
@dataclass
class Cursor:
    admissible: set[int]                     # step_ids that may execute next

    def advance(self, done: int, plan: Plan):
        self.admissible.discard(done)
        nxt = done + 1
        if nxt < len(plan.steps):
            self.admissible.add(nxt)


@dataclass
class SessionState:
    session_id: str
    prompt: str = ""
    prompt_hash: str = ""
    plan: Plan | None = None
    cursor: Cursor | None = None

    capability_set: set[tuple[str, str]] = field(default_factory=set)
    tool_schemas: dict = field(default_factory=dict)       # "server.tool" -> schema
    known_tool_names: set[str] = field(default_factory=set)

    attestation: dict = field(default_factory=dict)        # server -> digest
    pinned_toollist: dict = field(default_factory=dict)    # server -> digest

    tags: dict = field(default_factory=dict)               # value_id -> Tag
    inflight: dict = field(default_factory=dict)           # invocation_id -> slot
    open_requests: dict = field(default_factory=dict)      # req_id -> answered?

    ledger: dict = field(default_factory=dict)             # tool_class -> count
