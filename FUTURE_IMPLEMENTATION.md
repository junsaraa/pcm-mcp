# What is missing, stubbed, or hardcoded

An honest inventory of the gap between the prototype and the full design. Each
item lists where it lives and what making it real requires. Use this as the basis
for the paper's limitations section.

## 1. Server attestation (IP-1) — verdict logic present, verification stubbed
- Where: `engine/hooks.py:ip1_server_identity(...)` takes `signature_valid` and
  `registry_hit`; the DENY path exists. But all three callers
  (`policy_service.py:99`, `orchestrator.py:103`, `run_dynamic.py:84`) pass
  `True, True` with a fabricated digest `f"sha256:{name}"`.
- Missing: read `pod.status.containerStatuses[].imageID` via the Kubernetes API
  (the RBAC for this already exists in `k8s/10-rbac.yaml`), and verify it with
  `cosign`. Requires a live cluster and signed images. This is the "digital
  signature of the running binary" referenced in the architecture.

## 2. Five of six component pods are placeholders
- Where: `k8s/30-deployments.yaml` runs `python -m http.server` for orchestrator,
  mcp-client, user-console, p-llm, q-llm. Only policy-engine runs real logic.
- Consequence: the workload executes in-process inside the engine pod (via
  `/run_workload`), not as traffic flowing orchestrator → engine → client →
  server across namespaces. The namespaces and NetworkPolicy are real; the
  data path between components is not yet distributed.
- Missing: give each component its own service image and entrypoint, and have the
  orchestrator drive the plan by calling the engine over HTTP per step, with the
  client making the actual MCP calls. The engine hooks are already the right
  shape for this; it is wiring, not new logic.

## 3. MCP server I/O is mocked by default
- Where: `services/mcp_client.py` — `MCP_MOCK=1` (set in `k8s/30-deployments.yaml`
  and the default) returns deterministic stand-ins instead of calling the real
  servers. The real FastMCP servers exist and are deployed, but the SDK call path
  in `mcp_client.py` (`connect`/`list_tools`/`call`) is stubbed with
  `NotImplementedError` on the non-mock branch.
- Missing: implement the async streamable-http session using the SDK
  (`streamablehttp_client` + `ClientSession`) and remove the mock default.

## 4. The guardrail is a mock
- Where: `engine/advisory.py` — `build_guardrail()` returns `MockGuardrail`
  unless `GUARDRAIL_BACKEND=shieldstral`. The mock flags only overt injection
  markers.
- Missing: serve Shieldstral (e.g. vLLM sidecar in the policy-engine pod) and
  verify the `/classify` request/response shape against the model card; the
  `ShieldstralGuardrail` client in the same file is a placeholder for that shape.

## 5. The Action Plan can be static
- Where: `services/policy_service.py` and `orchestrator.py` use fixed
  per-workload plans (`plan_A/B/C`). `run_dynamic.py` uses the live P-LLM, but the
  in-cluster `/run_workload` path still uses the static ones.
- Missing: route `/run_workload` through `pllm.generate_plan` + `plan_loader`.
  Already implemented in `run_dynamic.py`; needs porting into the service.

## 6. Grammarly document text is synthesised
- Where: `servers/workload_servers.py` — `grammarly.load(path)` builds document
  text from the path string rather than reading a file (there is no filesystem in
  the container).
- Missing: mount a volume and read the actual document. The metering and
  correction-counting are real; only the source text is synthetic.

## 7. Tool classification and cost are operator-declared
- Where: `engine/classes.py` (`DEFAULT_TABLE`) and the budget in
  `policy_service.py`. Neither can be derived from an MCP tool description.
- Missing: nothing to implement — this is a design position (fail-closed to
  irreversible). It becomes derivable only if MCP adds a consequence-declaration
  field. State it as a limitation, not a bug.

## 8. Single engine replica, in-process state
- Where: `k8s/30-deployments.yaml` — `replicas: 1`. `SessionState` lives in
  process memory.
- Missing: multiple replicas would need shared session state (the audit chain
  already writes to a PVC, but live session state does not). Out of scope for the
  prototype.

## 9. P-LLM plan validity on real models
- Where: `services/pllm.py` — grammar-constrained JSON keeps the *shape* valid,
  but an 8B model may still produce a semantically wrong plan (missing extraction
  step, wrong tool).
- Missing: a retry-on-validation-failure loop that re-prompts the P-LLM when IP-4
  rejects its plan. Safe by construction (a bad plan is denied, not executed), but
  needed for a smooth live demo.

## Summary for the paper

Real and evaluated: the eleven introspection points and their deterministic
checks; the verdict algebra; the seven-namespace deployment; the NetworkPolicy
isolation (verified); Q-LLM extraction and P-LLM plan generation (offline).
Stubbed or simplified: cosign attestation (#1), distributed component execution
(#2), live MCP I/O (#3), the guardrail model (#4), and the in-cluster dynamic-plan
path (#5). None of the stubs affects the security property under evaluation —
plan confinement is enforced by checks that are fully implemented — but they bound
what the prototype demonstrates end-to-end versus in-process.
