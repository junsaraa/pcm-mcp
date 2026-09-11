"""Three quick evaluations beyond the attack suite and configuration matrix:
(1) enforcement overhead; (2) residual admissible set for workload A;
(3) randomized plan-mutation sweep, each class rejected at IP-4."""
import re, statistics, time

from engine import hooks, checks
from engine.types import Slot, SlotKind
from engine.verdict import Decision
from services.policy_service import run_workload, WorkloadReq

# ---- (1) overhead ----------------------------------------------------------
N = 200
times = []
for _ in range(N):
    t0 = time.perf_counter()
    run_workload(WorkloadReq(workload="A", attack=None, qllm="mock"))
    times.append((time.perf_counter() - t0) * 1000)
times.sort()
print(f"[overhead] full workload A: median {statistics.median(times):.2f} ms, "
      f"p95 {times[int(N*0.95)]:.2f} ms over {N} runs (mock backends)")

# ---- (2) residual admissible set ------------------------------------------
src_text = "Best ranked coffee machine: Precision Brew 10-Cup, item B0PRBRW10C, price 43.99"
slot = Slot("price", SlotKind.DERIVED, "number", domain=[0, 50], source_var="v0")
admissible = set()
for cand in set(re.findall(r"\d+\.\d+|\d+", src_text)):
    v = float(cand) if "." in cand else int(cand)
    if (checks.value_domain(v, slot).decision is Decision.ALLOW and
            checks.span_grounded(v, src_text).decision is Decision.ALLOW):
        admissible.add(cand)
print(f"[residual] numeric spans passing domain+span for the price slot: "
      f"{sorted(admissible)} (|set| = {len(admissible)})")

