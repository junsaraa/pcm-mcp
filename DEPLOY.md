# MCP Policy Monitor — deployment

Two ways to run, in order. Path 1 proves the security logic in 60s with no
cluster. Path 2 is the full seven-namespace Kubernetes deployment with the three
attacks driven from inside the cluster.

## Path 1 — local, no cluster, no GPU

```bash
cd mcpmon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m tests.test_attacks                       # 8/8 expectations
python -m services.orchestrator --workload A --attack A2   # live per-IP trace
```

## Path 2 — full cluster, one command

Prereqs: Docker Desktop running, plus `kind` and `kubectl` on PATH.

```bash
cd mcpmon
bash setup.sh
```

`setup.sh` creates the kind cluster with Calico (required — the default CNI does
NOT enforce NetworkPolicy), builds and loads the images, applies all seven
namespaces, waits for pods, and runs the isolation check. No manual steps.

### Run the three attacks inside the cluster

Each command runs the workload from a pod in `mcp-orch`, which calls the Policy
Engine's `/run_workload` across the namespace boundary, and prints the verdict at
every introspection point:

```bash
bash k8s/run-workload-job.sh A A2      # $50->$500 substitution -> blocked IP-5
bash k8s/run-workload-job.sh B B1      # quiet injection        -> blocked IP-5
bash k8s/run-workload-job.sh C C1      # economic DoS           -> blocked IP-4
bash k8s/run-workload-job.sh A null    # benign                 -> completes
```

### Tear down
```bash
kind delete cluster --name mcpmon
```

## The seven namespaces

| Namespace       | Pod            | Trust     | Role                              |
|-----------------|----------------|-----------|-----------------------------------|
| `mcp-policy`    | policy-engine  | TCB       | all IP hooks, all state, runs Q-LLM logic |
| `mcp-orch`      | orchestrator   | TCB       | drives the plan (calls the engine) |
| `mcp-client`    | mcp-client     | TCB       | per-server MCP connections        |
| `mcp-user`      | user-console   | authority | prompt + confirmations            |
| `mcp-planner`   | p-llm          | untrusted | plan generation                   |
| `mcp-extractor` | q-llm          | untrusted | value extraction                  |
| `mcp-servers`   | amazon/github/grammarly | external | the three workload servers |

## Notes / limitations (state in the paper)

- The Action Plan is STATIC per workload (not model-generated). Everything else
  — every introspection point, the Q-LLM extraction, the MCP calls — is live.
- MCP servers are called via a mock in `mcp_client.py` by default; the real
  FastMCP servers in `servers/` are deployed and reachable, and the SDK call
  path is stubbed for you to wire if you want fully live server I/O.
- The guardrail is a mock (flags loud injections only). Set GUARDRAIL_BACKEND=
  shieldstral and provide the model to use the real one.
- Tool classification is operator-declared; cost is declared not measured.
