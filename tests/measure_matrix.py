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
CONFIGS = [
    ("mock / mock, benign",        "mock",   "mock",   None),
    ("ollama / ollama, benign",    "ollama", "ollama", None),
    ("mock / mock, attack",        "mock",   "mock",   "ATK"),
    ("ollama / mock, attack",      "ollama", "mock",   "ATK"),
    ("mock / ollama, attack",      "mock",   "ollama", "ATK"),
]
# per-workload attack id. A2/B1 are extractor-side; C1 is planner-side.
ATTACK = {"A": "A2", "B": "B1", "C": "C1"}
WORKLOADS = ["A", "B", "C"]


def one_run(w, pllm, qllm, attack):
    os.environ["SHOW_PLAN"] = "0"
    buf = io.StringIO()
    t0 = time.time()
    try:
        with contextlib.redirect_stdout(buf):
            rd.main(w, pllm, qllm, attack)
    except Exception as e:
        return "error", "ERR", [type(e).__name__], time.time() - t0
    dt = time.time() - t0
    out = buf.getvalue()
    if "plan completed" in out:
        return "completed", None, [], dt
    for line in out.splitlines():
        if "DENY" in line:
            p = line.split()
            return "blocked", p[0], [r.strip(",") for r in p[2:]], dt
    return "unknown", "?", [], dt


def main(n, emit_latex):
    print(f"\nConfiguration matrix  (n={n} per workload per config)\n")
    results = []
    for label, pllm, qllm, atk_marker in CONFIGS:
        is_attack = atk_marker is not None
        good = 0
        total = 0
        errors = 0
        ips = collections.Counter()
        times = []
        for w in WORKLOADS:
            attack = ATTACK[w] if is_attack else None
            for i in range(n):
                outcome, ip, rules, dt = one_run(w, pllm, qllm, attack)
                total += 1
                times.append(dt)
                if outcome == "error":
                    errors += 1
                    continue
                if is_attack:
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
    ap.add_argument("--latex", action="store_true")
    a = ap.parse_args()
    main(a.n, a.latex)
