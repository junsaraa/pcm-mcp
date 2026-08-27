"""
Convert a P-LLM JSON plan into the engine's Plan/Step/Slot objects. This is the
boundary where an untrusted model-generated plan enters the system: after this,
IP-4 validates it and IP-4b freezes it, exactly as for a static plan.

The loader is deliberately strict: unknown fields are ignored, and a slot with a
missing required field raises, so a malformed model plan fails loudly at load
rather than silently mis-validating.
"""
from engine.types import Plan, Step, Slot, SlotKind


def load_plan(plan_json, prompt, domains=None):
    """domains: optional {(step_index, slot_name): [lo,hi]} to attach the
    grounded domain the model is not trusted to set (e.g. 'under 50' -> [0,50]).
    In the full system these come from the prompt-grounding pass; here they may
    be supplied by the caller."""
    domains = domains or {}
    steps = []
    for i, st in enumerate(plan_json["steps"]):
        slots = []
        for sl in st.get("slots", []):
            kind = SlotKind(sl["kind"])
            value = sl.get("value")
            if kind is SlotKind.LITERAL and sl.get("type") == "number" and value is not None:
                try:
                    value = float(value)
                except ValueError:
                    pass
            slots.append(Slot(
                name=sl["name"],
                kind=kind,
                type=sl.get("type"),
                value=value,
                domain=domains.get((i, sl["name"])),
                source_var=sl.get("source_var"), request=sl.get("request"),
                required_prov=frozenset({st["server"]}) if kind is SlotKind.DERIVED
                              else frozenset(),
            ))
        steps.append(Step(
            step_id=i,
            server=st["server"],
            tool=st["tool"],
            slots=slots,
            repeat=st.get("repeat", 1),
            is_extraction=st.get("is_extraction", False),
        ))
    return Plan(steps=steps, prompt=prompt)
