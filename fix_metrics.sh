#!/usr/bin/env bash
# Idempotent repair: brings run_dynamic.py and measure_matrix.py to the final
# patch-5 state regardless of how much of patch 5 previously applied. Safe to
# run on any state after patches 3 and 4. Run from repo root, delete after.
set -eu
[ -f engine/hooks.py ] || { echo "run from the pcm-mcp repo root"; exit 1; }
python3 - << 'EOF'
import re, sys

# ---------------- run_dynamic.py ----------------
src = open("services/run_dynamic.py").read()
assert "TRUE_PRICE" in src, "patch 3 missing: run apply_changes_3.sh first"
if "authorized-calls" not in src:
    m = re.search(r'( *)if trace\("IP-4", v\):\n( *)break', src)
    assert m, "IP-4 break anchor not found"
    ind = m.group(2)
    src = src.replace(m.group(0),
        f'{m.group(1)}if trace("IP-4", v):\n'
        f'{ind}LAST_TRACE.append(("authorized-calls", "info",\n'
        f'{ind}                   [str(plan.total_calls())]))\n'
        f'{ind}break', 1)
    open("services/run_dynamic.py", "w").write(src)
    print("run_dynamic: authorized-calls marker ADDED")
else:
    print("run_dynamic: ok")

# ---------------- measure_matrix.py ----------------
src = open("tests/measure_matrix.py").read()
assert "enacted" in src, "patch 1 missing from measure_matrix"
changed = False

if "authorized-calls" not in src:
    i = src.index("for ip, _d, rules in rd.LAST_TRACE)")
    j = src.index("\n", i) + 1
    ind = "    "
    src = src[:j] + (
f"""{ind}auth_calls = next((int(r[0]) for ip, _d, r in rd.LAST_TRACE
{ind}                   if ip == "authorized-calls"), None)
{ind}# C admitted test: the AUTHORIZED plan must itself be over-bound; a
{ind}# fired-then-repaired plan is a block, not an admission.
{ind}if attack == "C1" and enacted and auth_calls is not None \\
{ind}        and auth_calls <= rd.CALL_BOUND:
{ind}    enacted = False
""") + src[j:]
    changed = True
    print("measure_matrix: retry-aware admitted ADDED")

if "err_types" not in src:
    m = re.search(r'( *)admitted = \[\]', src)
    assert m, "admitted init anchor not found"
    src = src.replace(m.group(0),
                      m.group(0) + f"\n{m.group(1)}err_types = collections.Counter()", 1)
    m = re.search(r'( *)if outcome == "error":\n( *)errors \+= 1\n( *)continue', src)
    assert m, "error-continue anchor not found"
    src = src.replace(m.group(0),
        f'{m.group(1)}if outcome == "error":\n'
        f'{m.group(2)}errors += 1\n'
        f'{m.group(2)}err_types.update(rules)\n'
        f'{m.group(3)}continue', 1)
    m = re.search(r'( *)metric = "blocked" if is_attack else "completed"', src)
    assert m, "metric anchor not found"
    src = src.replace(m.group(0), m.group(0) +
        f'\n{m.group(1)}if err_types:'
        f'\n{m.group(1)}    print(f"\\n      error types: {{dict(err_types)}}")', 1)
    changed = True
    print("measure_matrix: error-type histogram ADDED")

if "--rows" not in src:
    src = src.replace('ap.add_argument("--n", type=int, default=20)',
        'ap.add_argument("--n", type=int, default=20)\n'
        '    ap.add_argument("--rows", choices=["all", "benign", "attack"],\n'
        '                    default="all")', 1)
    m = re.search(r'def main\(n, emit_latex(?:, rows="all")?\):', src)
    assert m, "main signature not found"
    src = src.replace(m.group(0), 'def main(n, emit_latex, rows="all"):', 1)
    src = src.replace("main(a.n, a.latex)", "main(a.n, a.latex, a.rows)", 1)
    m = re.search(r'( *)for label, pllm, qllm, atk_marker in CONFIGS:', src)
    assert m, "config loop anchor not found"
    ind = m.group(1) + "    "
    src = src.replace(m.group(0), m.group(0) +
        f'\n{ind}if rows == "benign" and atk_marker is not None: continue'
        f'\n{ind}if rows == "attack" and atk_marker is None: continue', 1)
    changed = True
    print("measure_matrix: --rows flag ADDED")

if changed:
    open("tests/measure_matrix.py", "w").write(src)
else:
    print("measure_matrix: ok")
EOF
python3 -m tests.measure_matrix --n 1 --rows attack 2>&1 | tr '\r' '\n' | grep -E "static / static, attack.*%|fired" | head -3
python3 -m tests.test_attacks 2>&1 | tail -1
echo "DONE - delete this script"
