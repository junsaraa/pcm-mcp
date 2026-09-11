#!/usr/bin/env bash
# One-shot patch #4: value_type becomes a pure SHAPE check (whitelist of the
# declared reply form) instead of a control-key blacklist, so the ill-typed
# rejection involves no knowledge of any field's meaning. The fired marker
# is aligned. Run once from repo root, delete after.
set -eu
[ -f engine/hooks.py ] || { echo "run from the pcm-mcp repo root"; exit 1; }
python3 - << 'EOF'
src = open("engine/checks.py").read()
old = '''    found = CONTROL_KEYS & set(raw.keys())
    if found:
        return _no("ip5.value-type", f"carries control fields {sorted(found)}, "
                                     f"expected one {slot.type} value")'''
assert old in src, "value_type anchor not found"
src = src.replace(old,
'''    extra = set(raw.keys()) - {"invocation_id", "value", "valid"}
    if extra:
        return _no("ip5.value-type", f"reply carries fields {sorted(extra)} "
                                     f"beyond the declared single {slot.type} "
                                     f"value; not one value of the declared type")''')
open("engine/checks.py", "w").write(src)

src = open("services/run_dynamic.py").read()
old = '''                    control = bool({"tool_name", "arguments", "method"}
                                   & set(resp))'''
assert old in src, "marker anchor not found"
src = src.replace(old,
'''                    control = bool(set(resp)
                                   - {"invocation_id", "value", "valid"})''')
open("services/run_dynamic.py", "w").write(src)

import re
src = open("engine/checks.py").read()
src = re.sub(r'\nCONTROL_KEYS = \{[^}]*\}\n', '\n', src)
open("engine/checks.py", "w").write(src)
print("patched")
EOF
python3 -m tests.test_attacks
python3 -m tests.attack_families | tail -1
python3 -m tests.measure_matrix --n 1 2>&1 | grep -E "static / static"
echo "DONE - delete this script"
