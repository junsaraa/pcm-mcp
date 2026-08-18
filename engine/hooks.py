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
def ip2_tool_list(state, server, tool_list, guardrail):
    det = [checks.schemas_wellformed(tool_list),
           checks.no_name_collision(tool_list, state.known_tool_names)]
    adv = [guardrail.tool_description(t.get("description", "")) for t in tool_list]
    v = combine("IP-2", det, adv)
    if v.decision is Decision.ALLOW:
        for t in tool_list:
            key = f"{server}.{t['name']}"
            state.tool_schemas[key] = t.get("inputSchema", {})
            state.known_tool_names.add(t["name"])
            state.capability_set.add((server, t["name"]))
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


# ---- IP-4 ----------------------------------------------------------------
def ip4_plan(state, plan, tool_classes):
    plan.prompt = state.prompt
    det = [checks.literals_grounded(plan),
           checks.tools_authorised(plan, state.capability_set),
           checks.slot_refines_schema(plan, state.tool_schemas),
           checks.amplification(plan, state.budget),
           checks.dataflow(plan, tool_classes)]
    v = combine("IP-4", det)
    if v.decision is Decision.ALLOW:
        state.plan = plan
        used = plan.tools_used()
        state.capability_set &= used            # narrow to what the plan uses
    return v


# ---- IP-4b ---------------------------------------------------------------
def ip4b_authorise(state, plan, tool_classes, confirmations: dict):
    from .verdict import _ok, _no
    det = []
    for step in plan.steps:
        if step.is_extraction:
            continue
        cls = tool_classes.classify(step.server, step.tool)
        if cls == "irreversible":
            ok = confirmations.get(step.step_id, False)
            det.append(_ok(f"ip4b.confirm.{step.step_id}") if ok
                       else _no(f"ip4b.confirm.{step.step_id}",
                                f"irreversible {step.tool} not confirmed"))
    if not det:
        det = [_ok("ip4b.no-irreversible")]
    v = combine("IP-4b", det)
    if v.decision is Decision.ALLOW:
        state.cursor = Cursor(admissible={0})
        state.plan_hash = _digest([(s.server, s.tool) for s in plan.steps])
    return v


# ---- IP-5 ----------------------------------------------------------------
def ip5_value(state, response, slot, source_text, source_tag):
    det = [checks.invocation_id(response, state.inflight),
           checks.no_control_content(response),
           checks.value_domain(response.get("value"), slot),
           checks.span_grounded(response.get("value"), source_text),
           checks.provenance(source_tag, slot)]
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
           checks.egress_readers(message, arg_tags),
           checks.attestation_unchanged(message["server"],
                                        state.attestation.get(message["server"]),
                                        live_digest),
           checks.toollist_unchanged(message["server"], state.pinned_toollist,
                                     state.pinned_toollist.get(message["server"]))]
    v = combine("IP-6", det)
    if v.decision is Decision.ALLOW:
        rid = message.get("id", uuid.uuid4().hex[:8])
        state.open_requests[rid] = False
        v.request_id = rid
    return v


# ---- IP-7 ----------------------------------------------------------------
def ip7_response(state, server, response, guardrail):
    det = [checks.response_id(response, state.open_requests),
           checks.no_credential_elicitation(response)]
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
def ipN_out_of_band(state, notification):
    from .verdict import _ok, _no
    method = notification.get("method", "")
    if method == "notifications/tools/list_changed":
        det = [_no("ipN.list-changed", "tool list changed: plan invalidated")]
    else:
        det = [_ok("ipN.event")]
    return combine("IP-N", det)
