# Deployment — technical overview

## What to run

```bash
cd mcpmon
bash setup.sh                                   # create + populate the cluster
bash k8s/run-workload-job.sh A A2               # run one workload+attack in-cluster
bash k8s/verify-isolation.sh                    # prove model isolation
```

`setup.sh` performs, in order: (1) `kind create cluster` using `k8s/kind-config.yaml`,
(2) installs Calico (kind's default CNI does not enforce NetworkPolicy),
(3) `docker build` of two images from `docker/Dockerfile.engine` and
`docker/Dockerfile.servers`, (4) `kind load docker-image` of both into the cluster,
(5) `kubectl apply` of the five manifests in `k8s/`, (6) waits for all deployments,
(7) runs `verify-isolation.sh`.

For a no-cluster run of the same logic:

```bash
python -m services.run_dynamic --workload A --pllm mock --qllm mock --attack A2
python -m tests.test_attacks
```

## What runs where

The cluster has **7 namespaces / 9 pods**. One image (`mcpmon/engine:dev`) is
reused for every component; the entrypoint differs per pod.

| Namespace     | Pod           | Port | Command in prototype                     | Real role |
|---------------|---------------|------|------------------------------------------|-----------|
| mcp-policy    | policy-engine | 8090 | `uvicorn services.policy_service:app`    | evaluates every IP hook, holds all state |
| mcp-orch      | orchestrator  | 8080 | `python -m http.server` (placeholder)    | walks the plan, calls the engine |
| mcp-client    | mcp-client    | 8070 | `python -m http.server` (placeholder)    | holds MCP connections |
| mcp-user      | user-console  | 3000 | `python -m http.server` (placeholder)    | prompt + confirmations |
| mcp-planner   | p-llm         | 8000 | `python -m http.server` (placeholder)    | generates the plan |
| mcp-extractor | q-llm         | 8000 | `python -m http.server` (placeholder)    | extracts typed values |
| mcp-servers   | amazon-mcp    | 8443 | `python -m servers.workload_servers amazon` | shopping server |
| mcp-servers   | github-mcp    | 8443 | `... github`                              | repository server |
| mcp-servers   | grammarly-mcp | 8443 | `... grammarly`                           | metered checker |

**Only the policy-engine pod runs real logic in the cluster.** The workload is
driven by `run-workload-job.sh`, which starts a throwaway `curl` pod in
`mcp-orch` that POSTs to the engine's `/run_workload`. The engine then executes
the whole plan (P-LLM logic, Q-LLM extraction, MCP calls, all hooks) in-process
and returns the per-introspection-point trace. The other five component pods
exist to make the namespace/NetworkPolicy graph real and to be the targets of the
isolation test; they do not yet run their own service logic (see "Missing").

## What happens where, for `run-workload-job.sh A A2` (Attack A)

1. A `curl` pod starts in **mcp-orch** and POSTs `{workload:A, attack:A2}` to
   `policy-engine.mcp-policy.svc:8090/run_workload`. NetworkPolicy allows only
   mcp-orch → mcp-policy on 8090; the call from any other namespace would be denied.
2. Inside the engine pod, `run_workload()` (in `services/policy_service.py`) runs:
   IP-1/IP-2 per server, IP-3 on the prompt, IP-4/IP-4b on the plan, then per step
   IP-6 → MCP call → IP-7, and for the extraction step it calls the Q-LLM and runs
   IP-5.
3. For Attack A the Q-LLM returns 500; `checks.value_domain` (via `hooks.ip5_value`)
   denies; the loop returns the trace with `status: blocked at IP-5`.
4. The `curl` pod prints the trace and is deleted (`--rm`).

## Every file, briefly

**engine/ (trusted core, no I/O, no model)**
- `types.py` — `Plan`, `Step`, `Slot`/`SlotKind`, `Tag`, `SessionState`.
- `verdict.py` — `Decision` (allow/deny), `Advice` (deny/abstain only), `combine()`.
- `checks.py` — every deterministic check (domain, span, grounding, dataflow, amplification, …).
- `hooks.py` — one function per introspection point; assembles checks, calls `combine()`, mutates state on allow.
- `advisory.py` — guardrail client (mock or Shieldstral); returns only `Advice`.
- `classes.py` — tool classification (read/write/irreversible/metered), default irreversible.

**services/ (untrusted periphery + wiring)**
- `pllm.py` — P-LLM: prompt + validated tools → JSON plan (Ollama grammar-constrained, or mock).
- `plan_loader.py` — converts P-LLM JSON into engine `Plan` objects.
- `qllm.py` — Q-LLM: one tool output → one typed value (mock / ollama / adversarial).
- `mcp_client.py` — MCP calls; `MCP_MOCK=1` uses deterministic stand-ins, else the SDK path.
- `policy_service.py` — FastAPI app; `/run_workload` drives a full workload through every hook.
- `orchestrator.py` — standalone CLI version of the same loop (static plans).
- `run_dynamic.py` — pipeline with the live P-LLM in front (`--pllm`, `--qllm`, `--attack`).

**servers/**
- `workload_servers.py` — the three real servers (search, issue store, metered checker).
- `amazon/server.py`, `github/server.py`, `grammarly/server.py` — per-server entrypoints.

**k8s/**
- `kind-config.yaml` — 2-node cluster, default CNI disabled.
- `00-namespaces.yaml` … `40-networkpolicies.yaml` — namespaces, RBAC (engine reads pod imageIDs), configmaps, deployments/services, NetworkPolicies.
- `run-workload-job.sh` — drives one workload from inside mcp-orch.
- `verify-isolation.sh` — asserts the q-llm pod cannot reach servers/console/engine.

**docker/** — `Dockerfile.engine` (installs FastAPI, copies engine+services), `Dockerfile.servers` (installs the MCP SDK, copies servers).

**tests/test_attacks.py** — all seven attacks + a benign control, run against the engine directly.
