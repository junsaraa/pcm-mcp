"""
Verdict algebra. The one idea: advisory components can only SUBTRACT.

  Decision (deterministic): ALLOW | DENY
  Advice   (advisory/model): DENY | ABSTAIN     -- note: no ALLOW

Because Advice has no ALLOW, no model can widen what the deterministic checks
permitted. That absence is why the TCB contains no model. Do not add ALLOW.
"""
from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Advice(str, Enum):
    DENY = "deny"
    ABSTAIN = "abstain"


@dataclass
class CheckResult:
    rule_id: str
    decision: Decision
    detail: str = ""


@dataclass
class AdviceResult:
    rule_id: str
    advice: Advice
    source: str
    score: float | None = None
    detail: str = ""


@dataclass
class Verdict:
    ip: str
    decision: Decision
    deterministic: list = field(default_factory=list)
    advisory: list = field(default_factory=list)

    @property
    def failing_rules(self):
        return ([c.rule_id for c in self.deterministic if c.decision is Decision.DENY]
                + [a.rule_id for a in self.advisory if a.advice is Advice.DENY])

    @property
    def denied_by_model_only(self) -> bool:
        det = any(c.decision is Decision.DENY for c in self.deterministic)
        adv = any(a.advice is Advice.DENY for a in self.advisory)
        return adv and not det


def _ok(rule, detail=""): return CheckResult(rule, Decision.ALLOW, detail)
def _no(rule, detail=""): return CheckResult(rule, Decision.DENY, detail)


def combine(ip, deterministic, advisory=None) -> Verdict:
    advisory = advisory or []
    if not deterministic:
        raise RuntimeError(f"{ip}: no deterministic checks -- refusing to decide "
                           f"on advisory input alone (would put a model in the TCB)")
    if any(c.decision is Decision.DENY for c in deterministic):
        return Verdict(ip, Decision.DENY, deterministic, advisory)
    if any(a.advice is Advice.DENY for a in advisory):
        return Verdict(ip, Decision.DENY, deterministic, advisory)
    return Verdict(ip, Decision.ALLOW, deterministic, advisory)
