"""
Hook dispatch. One function per introspection point. Read this to see the whole
design: which checks fire where, and where the model participates (IP-2/3/7 only).
"""
import hashlib, json, uuid
from . import checks
from .verdict import combine, Decision
from .types import Tag, Cursor, SlotKind


def _digest(obj) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(obj, sort_keys=True).encode()).hexdigest()[:32]


# ---- IP-0 (runs once, at session start) ----------------------------------
def ip0_session_admission(config, approved_digest, transports_ok):
    det = []
    from .verdict import _ok, _no
    det.append(_ok("ip0.config-digest") if _digest(config) == approved_digest
               else _no("ip0.config-digest", "config differs from approved"))
    det.append(_ok("ip0.transport") if transports_ok
               else _no("ip0.transport", "disallowed transport"))
    return combine("IP-0", det)


# ---- IP-1 ----------------------------------------------------------------
def ip1_server_identity(state, server, digest, signature_valid, registry_hit):
    from .verdict import _ok, _no
    det = [_ok("ip1.tls")]  # prototype: TLS assumed by transport
    if signature_valid and registry_hit:
        det.append(_ok("ip1.attested"))
        attested = True
    else:
        det.append(_ok("ip1.attested", "unattested: outputs tagged untrusted"))
        attested = False
    v = combine("IP-1", det)
    if v.decision is Decision.ALLOW:
        state.attestation[server] = digest
        state.__dict__.setdefault("_attested", {})[server] = attested
    return v


# ---- IP-2 ----------------------------------------------------------------
def ip2_tool_list(state, server, tool_list, guardrail, tool_classes):
    det = [checks.schemas_wellformed(tool_list),
           checks.no_name_collision(tool_list, state.known_tool_names)]
    adv = [guardrail.tool_description(t.get("description", "")) for t in tool_list]
    v = combine("IP-2", det, adv)
    if v.decision is Decision.ALLOW:
        attested = state.__dict__.get("_attested", {}).get(server, False)
        for t in tool_list:
            key = f"{server}.{t['name']}"
            state.tool_schemas[key] = t.get("inputSchema", {})
            state.known_tool_names.add(t["name"])
            state.capability_set.add((server, t["name"]))
            # class resolved restrictively from the tool's own annotations:
            # a safety hint is honored only from an attested server.
            tool_classes.register(server, t["name"],
                                  t.get("annotations"), attested)
        state.pinned_toollist[server] = _digest(tool_list)
    return v


# ---- IP-3 ----------------------------------------------------------------
def ip3_user_prompt(state, prompt, authorized_servers, guardrail):
    det = [checks.prompt_channel(prompt, state.session_id)]
    adv = [guardrail.user_prompt(prompt)]
    v = combine("IP-3", det, adv)
    if v.decision is Decision.ALLOW:
        state.prompt = prompt
        state.prompt_hash = _digest(prompt)
        vid = "user"
        state.tags[vid] = Tag(frozenset({"user"}), "trusted", True,
                              frozenset(authorized_servers))
    return v


# ---- IP-4 (validation AND authorization: one introspection point) --------
def ip4_plan(state, plan, tool_classes, confirmations=None, call_bound=8):
    """Plan validation and authorization, merged: no new datum crosses a
    boundary between the two, so they are one introspection point. The
    admission policies run first; steps that exceed what policy alone can
    admit (irreversible tools, cross-server derived uses, over-bound call
    counts) require entries in `confirmations`, the user's approvals of the
    fully resolved steps. Authorization is all-or-nothing: a missing
    confirmation denies the whole plan."""
    from .verdict import _ok, _no
    confirmations = confirmations or {}
    plan.prompt = state.prompt
    det = [checks.literals_grounded(plan),
           checks.request_grounded(plan),
           checks.tools_authorised(plan, state.capability_set),
           checks.slot_refines_schema(plan, state.tool_schemas),
           checks.call_bound(plan, call_bound,
                             confirmations.get("call_bound", False)),
           checks.flow_policy(plan, tool_classes, confirmations)]
    for step in plan.steps:
        if step.is_extraction:
            continue
        if tool_classes.classify(step.server, step.tool) == "irreversible":
            ok = confirmations.get(step.step_id, False)
            det.append(_ok(f"ip4.confirm.{step.step_id}") if ok
                       else _no(f"ip4.confirm.{step.step_id}",
                                f"irreversible {step.tool} not confirmed"))
    v = combine("IP-4", det)
    if v.decision is Decision.ALLOW:
        state.plan = plan
        state.capability_set &= plan.tools_used()   # may only narrow hereafter
        state.confirmed_flows = checks.confirmed_flow_pairs(plan)
        state.cursor = Cursor(admissible={0})
        # the authorization token: user approval bound to the hash of this
        # exact plan; IP-6 executes only against the plan this hash names.
        state.plan_hash = _digest([(s.server, s.tool,
                                    [(sl.name, str(sl.value)) for sl in s.slots])
                                   for s in plan.steps])
    return v


# ---- IP-5 ----------------------------------------------------------------
def ip5_value(state, response, slot, source_text, source_tag):
    det = [checks.invocation_id(response, state.inflight),
           checks.value_type(response, slot)]
    if det[-1].decision is Decision.ALLOW:
        det += [checks.value_domain(response.get("value"), slot),
                checks.span_grounded(response.get("value"), source_text)]
    v = combine("IP-5", det)
    if v.decision is Decision.ALLOW:
        state.inflight.pop(response["invocation_id"], None)
        vid = f"val-{uuid.uuid4().hex[:8]}"
        state.tags[vid] = Tag.join([source_tag])
        v.value_id = vid
    return v


# ---- IP-6 ----------------------------------------------------------------
def ip6_transmit(state, message, arg_tags, live_digest):
    det = [checks.destination_in_cursor(message, state.cursor, state.plan),
           checks.flow_admitted(message, arg_tags,
                                getattr(state, "confirmed_flows", set())),
           checks.attestation_unchanged(message["server"],
                                        state.attestation.get(message["server"]),
                                        live_digest)]
    v = combine("IP-6", det)
    if v.decision is Decision.ALLOW:
        rid = message.get("id", uuid.uuid4().hex[:8])
        state.open_requests[rid] = False
        v.request_id = rid
    return v


# ---- IP-7 ----------------------------------------------------------------
def ip7_response(state, server, response, guardrail):
    det = [checks.response_id(response, state.open_requests),
           checks.elicitation_expected(response, state.plan, state.cursor)]
    text = json.dumps(response.get("result", ""))
    adv = [guardrail.server_output(text)]
    v = combine("IP-7", det, adv)
    if v.decision is Decision.ALLOW:
        state.open_requests[response["id"]] = True
        attested = state.__dict__.get("_attested", {}).get(server, False)
        vid = f"out-{uuid.uuid4().hex[:8]}"
        # readers defaults to the SOURCE server only: a value may return to the
        # server it came from, but reaching any OTHER server requires an explicit
        # declassification step (which is what blocks cross-server exfiltration).
        state.tags[vid] = Tag(frozenset({server}), "untrusted-content",
                              attested, frozenset({server}))
        v.value_id = vid
        v.source_text = text
    return v


# ---- IP-N ----------------------------------------------------------------
def ipN_out_of_band(state, notification, current_toollist=None):
    """list_changed, or a re-presented tool list whose digest differs from the
    pin, invalidates the authorization token: the freeze is discarded and
    performed again (IP-2 onward), never widened in place."""
    from .verdict import _ok, _no
    method = notification.get("method", "")
    server = notification.get("server", "")
    if method == "notifications/tools/list_changed":
        det = [_no("ipN.list-changed", "tool list changed: plan invalidated")]
    elif current_toollist is not None and state.pinned_toollist.get(server) \
            and state.pinned_toollist[server] != _digest(current_toollist):
        det = [_no("ipN.toollist-pin", f"{server} tool list differs from pin")]
    else:
        det = [_ok("ipN.event")]
    v = combine("IP-N", det)
    if v.decision is Decision.DENY:
        state.plan_hash = None          # token invalidated
    return v
