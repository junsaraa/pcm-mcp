#!/usr/bin/env bash
# Isolation is evaluation evidence: a model pod must reach nothing.
set -uo pipefail
Q=$(kubectl -n mcp-extractor get pod -l app=q-llm -o jsonpath='{.items[0].metadata.name}')
fail=0
check() {  # name  ns/svc:port  expect(block|reach)
  local out; out=$(kubectl -n mcp-extractor exec "$Q" -- timeout 4 \
      python -c "import socket,sys;socket.create_connection(('$2',$3),3);print('reach')" 2>/dev/null || echo block)
  if [ "$out" = "$4" ]; then echo "  OK  $1: $out"; else echo "  XX  $1: $out (wanted $4)"; fail=1; fi
}
echo "Isolation checks (from q-llm pod):"
check "q-llm -> amazon server" amazon-mcp.mcp-servers.svc 8443 block
check "q-llm -> user console"  user-console.mcp-user.svc  3000 block
check "q-llm -> policy engine" policy-engine.mcp-policy.svc 8090 block
[ $fail -eq 0 ] && echo "PASS: models are isolated." || { echo "FAIL: NetworkPolicy not enforced?"; exit 1; }
