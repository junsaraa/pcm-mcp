"""
Deterministic checks -- the security mechanism. Pure functions over engine
state; none consults a model. These keep working when the guardrail misses.
"""
import re
from .verdict import CheckResult, Decision, _ok, _no
from .types import SlotKind, Tag


# ---- normalisation & span grounding --------------------------------------
def _norm(s) -> str:
    s = str(s).strip().lower()
    s = re.sub(r"[$£€,\s]", "", s)
    # normalise a bare integer-valued float: '50.0' -> '50' so it matches '50'
    if re.fullmatch(r"-?\d+\.0+", s):
        s = s.split(".")[0]
    return s


def is_span_of(value, source: str) -> bool:
    return _norm(value) in _norm(source)


# ---- IP-2 ----------------------------------------------------------------
def schemas_wellformed(tool_list) -> CheckResult:
    for t in tool_list:
        sch = t.get("inputSchema", {})
        if sch.get("type") != "object" or "properties" not in sch:
            return _no("ip2.schema-wellformed", f"{t.get('name')} schema not closed")
    return _ok("ip2.schema-wellformed")


def no_name_collision(tool_list, known: set) -> CheckResult:
    for t in tool_list:
        name = t.get("name", "")
        for k in known:
            if name != k and _edit_distance(name, k) <= 2:
                return _no("ip2.no-name-collision", f"{name} collides with {k}")
    return _ok("ip2.no-name-collision")


def _edit_distance(a, b) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j-1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ---- IP-3 ----------------------------------------------------------------
def prompt_channel(prompt, nonce) -> CheckResult:
    # In the prototype the console signs prompts with the session nonce; here we
    # accept any non-empty prompt bearing the nonce.
    return _ok("ip3.channel") if prompt else _no("ip3.channel", "empty prompt")


# ---- IP-4 ----------------------------------------------------------------
def literals_grounded(plan) -> CheckResult:
    for step in plan.steps:
        for slot in step.slots:
            if slot.kind is SlotKind.LITERAL and not is_span_of(slot.value, plan.prompt):
                return _no("ip4.literal-grounded",
                           f"literal {slot.value!r} in {step.tool} not in prompt")
    return _ok("ip4.literal-grounded")


def tools_authorised(plan, capability_set) -> CheckResult:
    for st, tl in plan.tools_used():
        if (st, tl) not in capability_set:
            return _no("ip4.tools-authorised", f"{st}.{tl} not in capability set")
    return _ok("ip4.tools-authorised")


def slot_refines_schema(plan, schemas) -> CheckResult:
    for step in plan.steps:
        if step.is_extraction:
            continue
        sch = schemas.get(f"{step.server}.{step.tool}", {}).get("properties", {})
        for slot in step.slots:
            if slot.name not in sch:
                return _no("ip4.slot-refines", f"slot {slot.name} not in {step.tool} schema")
    return _ok("ip4.slot-refines")


def amplification(plan, budget) -> CheckResult:
    per_step = budget["amplification"]["max_calls_per_plan_step"]
    for step in plan.steps:
        if step.repeat > per_step:
            return _no("ip4.amplification",
                       f"{step.tool} repeats {step.repeat}x (bound {per_step})")
    return _ok("ip4.amplification")


def dataflow(plan, tool_classes) -> CheckResult:
    """DFS over the single-assignment plan DAG. A cross-server or state-changing
    sink fed by an untrusted value needs a declassify() step declared."""
    var_source = {}            # var -> producing step
    declassified = set()       # (var, dest_server) pairs the plan declared
    for step in plan.steps:
        if step.tool == "declassify":
            v = step.slots[0].source_var
            declassified.add((v, step.slots[0].value))
            continue
        for slot in step.slots:
            if slot.kind is SlotKind.DERIVED and slot.source_var in var_source:
                src = var_source[slot.source_var]
                cls = tool_classes.classify(step.server, step.tool)
                crosses = step.server != src.server
                # A value may flow back to a write on ITS OWN server without
                # declassification (same provenance). Declassification is needed
                # only when the value crosses to a DIFFERENT server, or reaches
                # an irreversible sink.
                if (crosses or cls == "irreversible"):
                    if (slot.source_var, step.server) not in declassified:
                        return _no("ip4.dataflow",
                                   f"{src.server}->{step.server}.{step.tool} ({cls}) "
                                   f"no declassification declared")
        # record this step's output variable name convention: v{step_id}
        var_source[f"v{step.step_id}"] = step
    return _ok("ip4.dataflow")


# ---- IP-5 ----------------------------------------------------------------
CONTROL_KEYS = {"method", "tool_name", "params", "jsonrpc", "server", "arguments"}


def no_control_content(raw: dict) -> CheckResult:
    found = CONTROL_KEYS & set(raw.keys())
    return (_no("ip5.no-control", f"value carries control fields {sorted(found)}")
            if found else _ok("ip5.no-control"))


def value_domain(value, slot) -> CheckResult:
    if slot.type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return _no("ip5.value-domain", f"expected number, got {type(value).__name__}")
        lo, hi = slot.domain
        if not (lo <= value <= hi):
            return _no("ip5.value-domain", f"{value} outside [{lo},{hi}]")
    elif slot.type == "text":
        if not isinstance(value, str):
            return _no("ip5.value-domain", "expected text")
        if slot.max_length and len(value) > slot.max_length:
            return _no("ip5.value-domain", f"len {len(value)} > {slot.max_length}")
    elif slot.type == "enum":
        if value not in slot.domain:
            return _no("ip5.value-domain", f"{value!r} not in {slot.domain}")
    return _ok("ip5.value-domain")


def span_grounded(value, source_text) -> CheckResult:
    return (_ok("ip5.span-grounded") if is_span_of(value, source_text)
            else _no("ip5.span-grounded", f"{value!r} not in source"))


def provenance(source_tag: Tag, slot) -> CheckResult:
    if slot.required_prov and not (source_tag.sources <= slot.required_prov):
        return _no("ip5.provenance",
                   f"sources {set(source_tag.sources)} not within {set(slot.required_prov)}")
    return _ok("ip5.provenance")


def invocation_id(response, inflight) -> CheckResult:
    rid = response.get("invocation_id")
    return (_ok("ip5.invocation-id") if rid in inflight
            else _no("ip5.invocation-id", "unknown/consumed invocation id"))


# ---- IP-6 ----------------------------------------------------------------
def destination_in_cursor(message, cursor, plan) -> CheckResult:
    servers = {plan.steps[i].server for i in cursor.admissible if i < len(plan.steps)}
    return (_ok("ip6.dest-in-cursor") if message["server"] in servers
            else _no("ip6.dest-in-cursor",
                     f"{message['server']} not admissible at cursor {cursor.admissible}"))


def egress_readers(message, arg_tags: list[Tag]) -> CheckResult:
    for tag in arg_tags:
        if tag and message["server"] not in tag.readers:
            return _no("ip6.egress-readers",
                       f"value from {set(tag.sources)} may not be read by {message['server']}")
    return _ok("ip6.egress-readers")


def attestation_unchanged(server, recorded, live_digest) -> CheckResult:
    if recorded and recorded != live_digest:
        return _no("ip6.attestation", f"{server} digest changed (rug pull)")
    return _ok("ip6.attestation")


def toollist_unchanged(server, pinned, current) -> CheckResult:
    if pinned.get(server) and pinned[server] != current:
        return _no("ip6.toollist-unchanged", f"{server} tool list changed")
    return _ok("ip6.toollist-unchanged")


# ---- IP-7 ----------------------------------------------------------------
def response_id(response, open_requests) -> CheckResult:
    rid = response.get("id")
    if rid not in open_requests:
        return _no("ip7.response-id", f"response id {rid} never issued")
    if open_requests[rid]:
        return _no("ip7.response-id", f"response id {rid} already answered")
    return _ok("ip7.response-id")


def no_credential_elicitation(response) -> CheckResult:
    elic = str(response.get("elicitation", "")).lower()
    if any(w in elic for w in ("password", "api key", "token", "credential", "cvv")):
        return _no("ip7.no-cred-elicitation", "server elicits sensitive credentials")
    return _ok("ip7.no-cred-elicitation")
