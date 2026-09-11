"""
Configuration matrix: success rate across backend combinations.

Two different notions of success, and the script reports each correctly:
  BENIGN run  -> success = the plan COMPLETES (a refusal is a false positive)
  ATTACK run  -> success = the attack is BLOCKED (a completion is a miss)

The matrix separates policy behaviour from model behaviour. Comparing the
all-mock row against the rows with a live model isolates how much of any
variation comes from the models rather than the engine; comparing the two
half-live attack rows shows which side of the pipeline the attack exercises.

Run:
    python -m tests.measure_matrix --n 20
    python -m tests.measure_matrix --n 20 --latex
"""
import sys, os, io, argparse, contextlib, collections, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services import run_dynamic as rd

# (label, pllm, qllm, attack)  -- attack None => benign
# Full factorial: {static, ollama} x {static, ollama} x {benign, attack}.
CONFIGS = [
    ("static / static, benign",    "mock",   "mock",   None),
    ("ollama / static, benign",    "ollama", "mock",   None),
    ("static / ollama, benign",    "mock",   "ollama", None),
    ("ollama / ollama, benign",    "ollama", "ollama", None),
    ("static / static, attack",    "mock",   "mock",   "ATK"),
    ("ollama / static, attack",    "ollama", "mock",   "ATK"),
    ("static / ollama, attack",    "mock",   "ollama", "ATK"),
    ("ollama / ollama, attack",    "ollama", "ollama", "ATK"),
]

ATTACK = {"A": "A2", "B": "B1", "C": "C1"}
WORKLOADS = ["A", "B", "C"]


fail_hist = collections.Counter()


def one_run(w, pllm, qllm, attack):
    os.environ["SHOW_PLAN"] = "0"
    buf = io.StringIO()
    t0 = time.time()
    try:
        with contextlib.redirect_stdout(buf):
            rd.main(w, pllm, qllm, attack)
            for _ip, d, rules in rd.LAST_TRACE:
                if d != "allow":
                    fail_hist.update(rules)
    except Exception as e:
        return "error", "ERR", [type(e).__name__], time.time() - t0, False
    dt = time.time() - t0
    enacted = any(ip == "enacted" and rules == ["True"]
                  for ip, _d, rules in rd.LAST_TRACE)
    auth_calls = next((int(r[0]) for ip, _d, r in rd.LAST_TRACE
                       if ip == "authorized-calls"), None)
    # C admitted test: the AUTHORIZED plan must itself be over-bound; a
    # fired-then-repaired plan is a block, not an admission.
    if attack == "C1" and enacted and auth_calls is not None \
            and auth_calls <= rd.CALL_BOUND:
        enacted = False
    out = buf.getvalue()
    if "plan completed" in out:
        return "completed", None, [], dt, enacted
    for line in out.splitlines():
        if "DENY" in line:
            p = line.split()
            return "blocked", p[0], [r.strip(",") for r in p[2:]], dt, enacted
    return "unknown", "?", [], dt, enacted


def main(n, emit_latex, rows="all"):
    print(f"\nConfiguration matrix  (n={n} per workload per config)\n")
    results = []
    for label, pllm, qllm, atk_marker in CONFIGS:
        if rows == "benign" and atk_marker is not None: continue
        if rows == "attack" and atk_marker is None: continue
        is_attack = atk_marker is not None
        good = 0
        total = 0
        errors = 0
        n_enacted = 0
        n_enacted_blocked = 0
        admitted = []
        err_types = collections.Counter()
        ips = collections.Counter()
        times = []
        for w in WORKLOADS:
            attack = ATTACK[w] if is_attack else None
            for i in range(n):
                outcome, ip, rules, dt, enacted = one_run(w, pllm, qllm, attack)
                total += 1
                times.append(dt)
                if outcome == "error":
                    errors += 1
                    err_types.update(rules)
                    continue
                if is_attack:
                    if enacted:
                        n_enacted += 1
                        if outcome == "blocked":
                            n_enacted_blocked += 1
                        else:
                            admitted.append((w, outcome))
                    if outcome == "blocked":
                        good += 1
                        ips[ip] += 1
                else:
                    if outcome == "completed":
                        good += 1
                    elif outcome == "blocked":
                        ips[ip] += 1
                if total % 5 == 0:
                    print(f"\r  {label:<26} {total}", end="", flush=True)
        rate = 100.0 * good / total
        med = sorted(times)[len(times) // 2] * 1000
        metric = "blocked" if is_attack else "completed"
        if err_types:
            print(f"\n      error types: {dict(err_types)}")
        if is_attack:
            cond = (100.0 * n_enacted_blocked / n_enacted) if n_enacted else 0.0
            print(f"\n      [{label}] fired: {n_enacted}/{total - errors}"
                  f"  blocked|fired: {n_enacted_blocked}/{n_enacted}"
                  f" ({cond:.1f}%)  ADMITTED: {len(admitted)}"
                  + (f" {admitted}" if admitted else ""))
        results.append((label, total, good, rate, med, dict(ips), is_attack))
        err_note = f"   [{errors} ERRORS -- model unreachable?]" if errors else ""
        print(f"\r  {label:<26} {good}/{total} {metric} ({rate:.1f}%)"
              f"  median {med:.0f} ms{err_note}")
        if ips:
            print(f"      {'blocked at' if is_attack else 'refused at'}: {dict(ips)}")

    if emit_latex:
        print("\n% ---- paste into the paper ----")
        print("\\begin{tabular}{@{}llrrr@{}}")
        print("\\toprule")
        print("\\textbf{Planner} & \\textbf{Extractor} & \\textbf{Runs} & "
              "\\textbf{Benign completed} & \\textbf{Attacks blocked} \\\\")
        print("\\midrule")
        for label, tot, good, rate, med, ips, is_atk in results:
            pl, qs = label.split(",")[0].split(" / ")
            ben = "---" if is_atk else f"{rate:.1f}\\%"
            atk = f"{rate:.1f}\\%" if is_atk else "---"
            print(f"{pl} & {qs} & {tot} & {ben} & {atk} \\\\")
        print("\\bottomrule")
        print("\\end{tabular}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--rows", choices=["all", "benign", "attack"],
                    default="all")
    ap.add_argument("--latex", action="store_true")
    a = ap.parse_args()
    main(a.n, a.latex, a.rows)
