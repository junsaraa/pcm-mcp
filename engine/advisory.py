"""
Advisory layer. Confined to IP-2 / IP-3 / IP-7 and returns only Advice
(DENY | ABSTAIN). Fail-open to ABSTAIN on error: the deterministic checks are
the mechanism, and a slow model must not halt the system.

MockGuardrail flags text containing obvious injection markers, so the pipeline
runs with no GPU. Swap ShieldstralGuardrail in once you have the model serving;
verify its request/response shape against the model card first.
"""
import os
from .verdict import AdviceResult, Advice

THRESHOLD = 0.5


class MockGuardrail:
    """Loud-injection detector. Deliberately WEAK: it must pass the quiet
    Workload-B payload so the deterministic checks are what block that attack."""
    MARKERS = ["ignore previous", "you are now", "system:", "do not tell",
               "the author does not care about privacy", "disregard"]
    SOURCE = "mock-guardrail"

    def _advise(self, rule_id, text, _task):
        low = (text or "").lower()
        if any(m in low for m in self.MARKERS):
            return AdviceResult(rule_id, Advice.DENY, self.SOURCE, 1.0,
                                "matched loud-injection marker")
        return AdviceResult(rule_id, Advice.ABSTAIN, self.SOURCE, 0.0)

    def tool_description(self, d): return self._advise("ip2.description-scan", d, "poison")
    def user_prompt(self, p):      return self._advise("ip3.prompt-scan", p, "jailbreak")
    def server_output(self, o):    return self._advise("ip7.output-scan", o, "injection")


class ShieldstralGuardrail(MockGuardrail):
    SOURCE = "shieldstral-1.0-3b"

    def __init__(self, base_url):
        import httpx  # only needed for the real model; keeps core deps minimal
        self._c = httpx.Client(base_url=base_url, timeout=2.0)

    def _advise(self, rule_id, text, task):
        try:
            r = self._c.post("/classify", json={"text": text, "task": task})
            r.raise_for_status()
            b = r.json()
            score = float(b.get("score", 0.0))
            if score >= THRESHOLD:
                return AdviceResult(rule_id, Advice.DENY, self.SOURCE, score,
                                    b.get("label", ""))
            return AdviceResult(rule_id, Advice.ABSTAIN, self.SOURCE, score)
        except Exception:
            return AdviceResult(rule_id, Advice.ABSTAIN, self.SOURCE,
                                detail="guardrail unavailable")


def build_guardrail():
    url = os.environ.get("GUARDRAIL_URL")
    if url and os.environ.get("GUARDRAIL_BACKEND", "mock") == "shieldstral":
        return ShieldstralGuardrail(url)
    return MockGuardrail()
