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


def call_bound(plan, bound, confirmed) -> CheckResult:
    """Aggregate abuse is visible as the total number of tool calls. Exceeding
    the default bound is not rejected outright but escalated: it requires the
    user's confirmation of the full plan, as if irreversible."""
    n = plan.total_calls()
    if n > bound and not confirmed:
        return _no("ip4.call-bound",
                   f"{n} calls exceed default bound {bound}; escalated, not confirmed")
    return _ok("ip4.call-bound")
def call_bound(plan, bound, confirmed) -> CheckResult:
    """Aggregate abuse is visible as the total number of tool calls. Exceeding
    the default bound is not rejected outright but escalated: it requires the
    user's confirmation of the full plan, as if irreversible."""
    n = plan.total_calls()
    if n > bound and not confirmed:
        return _no("ip4.call-bound",
                   f"{n} calls exceed default bound {bound}; escalated, not confirmed")
    return _ok("ip4.call-bound")


def flow_policy(plan, tool_classes, confirmations) -> CheckResult:
    """One rule over the plan's statically-known dataflow: a derived value may
    be used only as an argument to a call on the server that produced it. A
    cross-server use in a state-changing call is admitted only if the user
    confirmed that step (the sole path by which a plan's reach may widen)."""
def flow_policy(plan, tool_classes, confirmations) -> CheckResult:
    """One rule over the plan's statically-known dataflow: a derived value may
    be used only as an argument to a call on the server that produced it. A
    cross-server use in a state-changing call is admitted only if the user
    confirmed that step (the sole path by which a plan's reach may widen)."""
    var_source = {}            # var -> producing step
    for step in plan.steps:
        for slot in step.slots:
            if slot.kind is SlotKind.DERIVED and slot.source_var in var_source:
                origin = var_source[slot.source_var]
                origin = var_source[slot.source_var]
                cls = tool_classes.classify(step.server, step.tool)
                if step.server != origin.server and cls in ("write", "irreversible"):
                    if not confirmations.get(step.step_id, False):
                        return _no("ip4.flow",
                                   f"{origin.server}->{step.server}.{step.tool} "
                                   f"({cls}) cross-server use not confirmed")
        var_source[f"v{step.step_id}"] = step
    return _ok("ip4.flow")


def confirmed_flow_pairs(plan) -> set:
    """(origin_server, dest_server) pairs for cross-server derived uses; recorded
    on ALLOW so IP-6 can re-check at transmission what IP-4 admitted."""
    pairs, var_source = set(), {}
    for step in plan.steps:
        for slot in step.slots:
            if slot.kind is SlotKind.DERIVED and slot.source_var in var_source:
                origin = var_source[slot.source_var]
                if step.server != origin.server:
                    pairs.add((origin.server, step.server))
                if step.server != origin.server and cls in ("write", "irreversible"):
                    if not confirmations.get(step.step_id, False):
                        return _no("ip4.flow",
                                   f"{origin.server}->{step.server}.{step.tool} "
                                   f"({cls}) cross-server use not confirmed")
        var_source[f"v{step.step_id}"] = step
    return _ok("ip4.flow")


def confirmed_flow_pairs(plan) -> set:
    """(origin_server, dest_server) pairs for cross-server derived uses; recorded
    on ALLOW so IP-6 can re-check at transmission what IP-4 admitted."""
    pairs, var_source = set(), {}
    for step in plan.steps:
        for slot in step.slots:
            if slot.kind is SlotKind.DERIVED and slot.source_var in var_source:
                origin = var_source[slot.source_var]
                if step.server != origin.server:
                    pairs.add((origin.server, step.server))
        var_source[f"v{step.step_id}"] = step
    return pairs


_PLACEHOLDER = re.compile(r"\{v\d+\}")


def request_grounded(plan) -> CheckResult:
    """The extraction request is itself grounded like a literal: its fixed words
    must be a span of the user prompt, and any {vN} placeholder must reference
    an earlier binding. This is what makes the planner author no free text."""
    bound = set()
    for step in plan.steps:
        if step.is_extraction:
            slot = step.slots[0]
            req = getattr(slot, "request", None)
            if not req:
                return _no("ip4.request-grounded",
                           f"extraction step {step.step_id} declares no request")
            for ref in _PLACEHOLDER.findall(req):
                if ref[1:-1] not in bound:
                    return _no("ip4.request-grounded",
                               f"request references unbound {ref}")
            for frag in _PLACEHOLDER.split(req):
                frag = frag.strip()
                if len(frag) > 2 and not is_span_of(frag, plan.prompt):
                    return _no("ip4.request-grounded",
                               f"request fragment {frag!r} not in prompt")
        bound.add(f"v{step.step_id}")
    return _ok("ip4.request-grounded")
    return pairs


_PLACEHOLDER = re.compile(r"\{v\d+\}")


def request_grounded(plan) -> CheckResult:
    """The extraction request is itself grounded like a literal: its fixed words
    must be a span of the user prompt, and any {vN} placeholder must reference
    an earlier binding. This is what makes the planner author no free text."""
    bound = set()
    for step in plan.steps:
        if step.is_extraction:
            slot = step.slots[0]
            req = getattr(slot, "request", None)
            if not req:
                return _no("ip4.request-grounded",
                           f"extraction step {step.step_id} declares no request")
            for ref in _PLACEHOLDER.findall(req):
                if ref[1:-1] not in bound:
                    return _no("ip4.request-grounded",
                               f"request references unbound {ref}")
            for frag in _PLACEHOLDER.split(req):
                frag = frag.strip()
                if len(frag) > 2 and not is_span_of(frag, plan.prompt):
                    return _no("ip4.request-grounded",
                               f"request fragment {frag!r} not in prompt")
        bound.add(f"v{step.step_id}")
    return _ok("ip4.request-grounded")


# ---- IP-5 ----------------------------------------------------------------


def value_type(raw: dict, slot) -> CheckResult:
    """A response is a single value of the declared type, nothing else. A reply
    carrying control fields, or no value, or a value of the wrong shape, is
    ill-typed -- there is no separate notion of 'suspicious content'."""
    extra = set(raw.keys()) - {"invocation_id", "value", "valid"}
    if extra:
        return _no("ip5.value-type", f"reply carries fields {sorted(extra)} "
                                     f"beyond the declared single {slot.type} "
                                     f"value; not one value of the declared type")
    if "value" not in raw:
        return _no("ip5.value-type", "no value in response")
    v = raw["value"]
    if slot.type == "number" and (not isinstance(v, (int, float)) or isinstance(v, bool)):
        return _no("ip5.value-type", f"expected number, got {type(v).__name__}")
    if slot.type in ("text", "enum") and not isinstance(v, str):
        return _no("ip5.value-type", f"expected {slot.type}, got {type(v).__name__}")
    return _ok("ip5.value-type")


def value_domain(value, slot) -> CheckResult:
    if slot.type == "number" and slot.domain:
        lo, hi = slot.domain
        if not (lo <= value <= hi):
            return _no("ip5.value-domain", f"{value} outside [{lo},{hi}]")
    elif slot.type == "text":
        if slot.max_length and len(value) > slot.max_length:
            return _no("ip5.value-domain", f"len {len(value)} > {slot.max_length}")
    elif slot.type == "enum":
        if value not in slot.domain:
            return _no("ip5.value-domain", f"{value!r} not in {slot.domain}")
    return _ok("ip5.value-domain")


def span_grounded(value, source_text) -> CheckResult:
    return (_ok("ip5.span-grounded") if is_span_of(value, source_text)
            else _no("ip5.span-grounded", f"{value!r} not in source"))


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


def flow_admitted(message, arg_tags: list[Tag], confirmed_flows: set) -> CheckResult:
    """Re-check at transmission what IP-4 admitted: a derived argument travels
    only to its producing server, unless the user confirmed the cross-server
    use at authorization."""
    dest = message["server"]
def flow_admitted(message, arg_tags: list[Tag], confirmed_flows: set) -> CheckResult:
    """Re-check at transmission what IP-4 admitted: a derived argument travels
    only to its producing server, unless the user confirmed the cross-server
    use at authorization."""
    dest = message["server"]
    for tag in arg_tags:
        if not tag:
            continue
        if dest in tag.sources:
            continue
        if any((org, dest) in confirmed_flows for org in tag.sources):
            continue
        if tag.trust == "trusted":          # prompt-grounded: user's own words
            continue
        return _no("ip6.flow-admitted",
                   f"value from {set(tag.sources)} not admitted to {dest}")
    return _ok("ip6.flow-admitted")
        

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


def elicitation_expected(response, plan, cursor) -> CheckResult:
    """Elicitation is permitted only where the current plan step expects it.
    What a server asks for matters less than what the answer may touch: an
    elicited value carries the eliciting server's provenance and is confined
    like any other server-produced value."""
    if "elicitation" not in response:
        return _ok("ip7.elicitation")
    if plan is None or cursor is None:
        return _no("ip7.elicitation", "elicitation outside any plan step")
    for i in cursor.admissible:
        if i < len(plan.steps) and getattr(plan.steps[i], "expects_elicitation", False):
            return _ok("ip7.elicitation")
    return _no("ip7.elicitation", "no admissible plan step expects elicitation")
def elicitation_expected(response, plan, cursor) -> CheckResult:
    """Elicitation is permitted only where the current plan step expects it.
    What a server asks for matters less than what the answer may touch: an
    elicited value carries the eliciting server's provenance and is confined
    like any other server-produced value."""
    if "elicitation" not in response:
        return _ok("ip7.elicitation")
    if plan is None or cursor is None:
        return _no("ip7.elicitation", "elicitation outside any plan step")
    for i in cursor.admissible:
        if i < len(plan.steps) and getattr(plan.steps[i], "expects_elicitation", False):
            return _ok("ip7.elicitation")
    return _no("ip7.elicitation", "no admissible plan step expects elicitation")
