"""
Measure the false-positive rate: how often a BENIGN request is refused, and at
which introspection point.

This is the usability counterpart to the attack table. Structural enforcement is
only useful if legitimate work gets through; a defence that blocks every attack
by blocking everything is worthless. We therefore run each benign workload N
times and report the refusal rate, broken down by the check that fired.

Two configurations matter and should both be reported:
  mock   -- deterministic planner/extractor. Isolates the ENGINE: any refusal
            here is an over-strict policy, not a model failure. Expect 0%.
  ollama -- live models. Refusals here are dominated by small-model error
            (hallucinated literals, non-extractive values), not by policy.

Run:
    python -m tests.measure_fpr --n 30 --config mock
    python -m tests.measure_fpr --n 30 --config ollama
    python -m tests.measure_fpr --n 30 --config ollama --latex   # emits the table
"""
import sys, os, io, argparse, collections, contextlib, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import run_dynamic as rd

WORKLOADS = ["A", "B", "C"]


def one_run(workload, pllm, qllm):
    """Run one benign workload. Returns (completed, blocking_ip, rules, seconds)."""
    buf = io.StringIO()
    os.environ["SHOW_PLAN"] = "0"
    t0 = time.time()
    try:
        with contextlib.redirect_stdout(buf):
            rd.main(workload, pllm, qllm, None)      # attack=None => benign
    except Exception as e:
        return False, "ERROR", [str(e)[:60]], time.time() - t0
    dt = time.time() - t0
    out = buf.getvalue()

    if "plan completed" in out:
        return True, None, [], dt
    # find the first DENY line and the rules on it
    for line in out.splitlines():
        if "DENY" in line:
            parts = line.split()
            ip = parts[0]
            rules = [r.strip(",") for r in parts[2:]]
            return False, ip, rules, dt
    return False, "UNKNOWN", [], dt


def main(n, config, emit_latex):
    pllm, qllm = ("mock", "mock") if config == "mock" else ("ollama", "ollama")
    print(f"\nBenign false-positive rate  (n={n} per workload, config={config})\n")

    rows = []
    for w in WORKLOADS:
        ok = 0
        by_ip = collections.Counter()
        by_rule = collections.Counter()
        times = []
        for i in range(n):
            completed, ip, rules, dt = one_run(w, pllm, qllm)
            times.append(dt)
            if completed:
                ok += 1
            else:
                by_ip[ip] += 1
                for r in rules:
                    by_rule[r] += 1
            print(f"\r  workload {w}: {i+1}/{n}", end="", flush=True)
        fpr = 100.0 * (n - ok) / n
        med = sorted(times)[len(times) // 2]
        rows.append((w, n, ok, fpr, med, by_ip, by_rule))
        print(f"\r  workload {w}: {ok}/{n} completed, "
              f"false-positive rate {fpr:.1f}%, median {med*1000:.0f} ms")
        if by_ip:
            print(f"      refused at: {dict(by_ip)}")
            print(f"      rules:      {dict(by_rule)}")

    total_n = sum(r[1] for r in rows)
    total_ok = sum(r[2] for r in rows)
    print(f"\n  overall: {total_ok}/{total_n} benign runs completed "
          f"({100.0*(total_n-total_ok)/total_n:.1f}% refused)\n")

    if emit_latex:
        print("% ---- paste into the paper ----")
        print("\\begin{tabular}{@{}lrrrr@{}}")
        print("\\toprule")
        print("\\textbf{Workload} & \\textbf{Runs} & \\textbf{Completed} & "
              "\\textbf{Refused} & \\textbf{Median} \\\\")
        print("\\midrule")
        for w, nn, ok, fpr, med, _, _ in rows:
            print(f"{w} & {nn} & {ok} & {fpr:.1f}\\% & {med*1000:.0f}\\,ms \\\\")
        print("\\midrule")
        print(f"Total & {total_n} & {total_ok} & "
              f"{100.0*(total_n-total_ok)/total_n:.1f}\\% & --- \\\\")
        print("\\bottomrule")
        print("\\end{tabular}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--config", default="mock", choices=["mock", "ollama"])
    ap.add_argument("--latex", action="store_true")
    a = ap.parse_args()
    main(a.n, a.config, a.latex)
