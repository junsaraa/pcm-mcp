# Policy CheckMate — a plan-confining host architecture for the Model Context Protocol

**pcm-mcp** (Policy CheckMate - MCP) is a research prototype of an MCP host in
which **no language model is trusted** — not the models behind the servers,
and not the host's own backbone model. Prior MCP security work protects the
model from a hostile ecosystem; pcm-mcp additionally treats the model as a
possible adversary: one that emits actions the user did not ask for, whether
through misalignment, injection, or hallucination.

The enforced property is **plan confinement**: every MCP message actually
transmitted must be admitted by a plan that was validated, authorized by the
user, and frozen *before* execution began. The property holds regardless of
whether any model in the system is aligned.

> **Paper:** *Policy CheckMate : MCP Policy Enforcement for
Potentially Misaligned Models* — under review.
> Preprint: `https://PLACEHOLDER-PAPER-URL` (to appear).

## How it works

Two models exist, both untrusted and both denied network egress:

- **P-LLM (planner)** reads the user prompt and the validated tool schemas
  and proposes an *Action Plan*: a straight-line, single-assignment program
  in which every argument is a prompt-grounded literal, a typed slot filled
  later, or a verified lookup. It never reads tool output.
- **Q-LLM (extractor)** reads one tool output and returns one typed value.
  It never sees the plan and never constructs a message.

One trusted component decides. The **Policy Engine** (~750 lines of Python,
no I/O framework, no model) evaluates every rule, owns all session state a
check consults, terminates every transport, and mints every trusted
artefact (the authorization token binding user approval to the hash of one
plan; single-use invocation identifiers). The **Orchestrator** executes the
frozen plan and is the sole constructor of MCP messages. The **MCP Client**
holds per-server session state only — no socket — and is untrusted for
confinement.

Mediation happens at **ten introspection points** (IP-0…IP-8, IP-N), placed
on every data flow between components, following the Linux Security Modules
convention: a policy may deny an operation, never grant one. Deterministic
checks return ALLOW/DENY; advisory checks (scanners, classifiers) return a
distinct type admitting only DENY/ABSTAIN, so — enforced by the type
system — no model-based check can permit what the deterministic checks did
not.

## The three attacks

Each workload pairs a benign variant (must complete) with an attack that
per-message content inspection cannot detect in principle:

| | Attack | Why scanners fail | Blocked |
|---|---|---|---|
| A | extractor substitutes price 500 for 34.99 | well-formed number, right server | IP-5: outside domain [0,50], not a span of the source |
| B | quiet injected issue makes the extractor emit a file-write | issue text reads as routine maintenance; scanner abstains | IP-5: ill-typed (control fields where one text value was required) |
| C | plan calls a metered tool 100× on one document | every message byte-identical to a legitimate call | IP-4: call bound escalates the plan; the user refuses |

## Quick start

### Path 1 — local, no cluster, no GPU (~60 s)

```bash
cd pcm-mcp
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m tests.test_attacks                        # 8/8 expectations
python -m services.orchestrator --workload A --attack A2   # per-IP trace
```

### Path 2 — full seven-namespace Kubernetes deployment

Prereqs: Docker running, `kind` and `kubectl` on PATH.

```bash
cd pcm-mcp
bash setup.sh          # cluster + Calico + images + manifests + isolation check
```

Calico is installed explicitly because kind's default CNI does **not**
enforce NetworkPolicy; without it, every isolation rule silently does
nothing. The central rule is an omission: the two model namespaces have an
ingress rule and no egress rule, so a model can answer a request but cannot
initiate a connection.

Run the attacks from inside the cluster and print the verdict at every
introspection point:

```bash
bash k8s/run-workload-job.sh A A2      # $50 -> $500 substitution  -> blocked IP-5
bash k8s/run-workload-job.sh B B1      # quiet indirect injection  -> blocked IP-5
bash k8s/run-workload-job.sh C C1      # economic denial of service -> blocked IP-4
bash k8s/run-workload-job.sh A null    # benign                    -> completes
bash k8s/verify-isolation.sh           # "PASS: models are isolated"
kind delete cluster --name pcm-mcp     # teardown
```

## Reproducing the paper's numbers

```bash
python -m tests.test_attacks           # Table: attacks x blocking rule (8/8)
python -m tests.measure_matrix --n 20  # Table: benign/blocked rates by config
bash k8s/verify-isolation.sh           # isolation claim, as a network fact
```

Live-model rows require [Ollama](https://ollama.com) serving
`llama3.1:8b` (planner) and `llama3.2:3b` (extractor). The deterministic
(`mock`) backends emit fixed responses, so the security results are
byte-reproducible without any model. On the dynamic path
(`services/run_dynamic.py`) the planner is re-prompted on IP-4 rejection
with the Engine's verdict (budget 3); the extractor is never re-prompted.

## Repository layout

```
engine/       TRUSTED CORE — checks, hooks, verdict algebra, tool classes
services/     wiring — Policy Engine service, orchestrator, P-LLM, Q-LLM,
              plan loader, MCP client, dynamic-planning driver
servers/      three real MCP servers (official SDK): amazon, github, grammarly
k8s/          kind config, 7 namespaces, NetworkPolicy, run/verify scripts
docker/       engine and server images
tests/        attack suite, configuration-matrix and FPR harnesses
```

## Trust map (Kubernetes)

| Namespace       | Pod            | Trust     | Role                              |
|-----------------|----------------|-----------|-----------------------------------|
| `mcp-policy`    | policy-engine  | TCB       | all IP hooks, all state           |
| `mcp-orch`      | orchestrator   | TCB       | executes the frozen plan          |
| `mcp-client`    | mcp-client     | untrusted (availability only) | per-server session state; holds no socket |
| `mcp-user`      | user-console   | authority | prompt + confirmations            |
| `mcp-planner`   | p-llm          | untrusted | plan generation                   |
| `mcp-extractor` | q-llm          | untrusted | value extraction                  |
| `mcp-servers`   | amazon/github/grammarly | external | the three workload servers |

## Limitations (stated in the paper, Section 5)

- The in-cluster path (`/run_workload`) uses static per-workload plans;
  `services/run_dynamic.py` runs the live P-LLM with the IP-4 retry loop.
- MCP server I/O is mocked by default; the real servers in `servers/` are
  deployed and reachable, with the SDK call path left to wire for fully
  live server I/O.
- The guardrail is a mock (flags loud injections only); the advisory layer
  can only deny, so no security result depends on it.
- Tool classes are resolved restrictively from the tools' own
  `ToolAnnotations`; safety hints are honored only from attested servers,
  and a tool with no believable signal defaults to irreversible.
- IP-1's cryptographic verification is stubbed (the denial path exists);
  session state lives in a single engine replica.

## Citation

```bibtex
@inproceedings{pcmmcp2026,
  title     = {Secure Architecture Design for MCP},
  author    = {Anonymous},
  booktitle = {PLACEHOLDER — venue},
  year      = {2026},
  note      = {\url{https://PLACEHOLDER-PAPER-URL}}
}
```

## License

Released under the MIT License (see `LICENSE`). For double-blind review the
copyright holder is anonymized; it will be restored in the camera-ready
release.

### Third-party components and licenses

Runtime dependencies (installed via `requirements.txt`):

| Component | Use | License |
|---|---|---|
| `mcp` (official MCP Python SDK, 1.x, incl. FastMCP server helpers) | MCP protocol, workload servers | MIT |
| `fastapi` | Policy Engine HTTP service | MIT |
| `uvicorn` | ASGI server | BSD-3-Clause |
| `pydantic` | schemas / validation | MIT |
| `httpx` | HTTP client | BSD-3-Clause |
| `pyyaml` | config parsing | MIT |

Models and infrastructure (not vendored; installed by the user):

| Component | Use | License |
|---|---|---|
| Llama 3.1 8B (`llama3.1:8b`) | P-LLM planner | Llama 3.1 Community License (Meta) |
| Llama 3.2 3B (`llama3.2:3b`) | Q-LLM extractor | Llama 3.2 Community License (Meta) |
| Ollama | local model serving | MIT |
| kind | local Kubernetes cluster | Apache-2.0 |
| Calico | NetworkPolicy enforcement | Apache-2.0 |
| Kubernetes / kubectl | orchestration | Apache-2.0 |

The Llama models are used unmodified for inference only, within the terms
of their community licenses; no model weights are redistributed with this
repository.
