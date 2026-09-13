#!/usr/bin/env bash
# Run one workload+attack INSIDE the cluster by calling the engine's
# /run_workload from a throwaway pod in the orchestrator namespace. This
# exercises the real namespaces and NetworkPolicy: only mcp-orch is permitted
# to reach the engine.
#
# usage: bash k8s/run-workload-job.sh A attackID|A|B|C|null
set -euo pipefail
W="${1:?workload A|B|C}"; ATK="${2:-null}"
case "$ATK" in A) ATK=A2;; B) ATK=B1;; C) ATK=C1;; esac   # A/B/C aliases
[ "$ATK" = "null" ] && BODY="{\"workload\":\"$W\",\"qllm\":\"mock\"}" \
                    || BODY="{\"workload\":\"$W\",\"attack\":\"$ATK\",\"qllm\":\"mock\"}"

echo "=== Workload $W  attack=$ATK  (run from inside mcp-orch) ==="
kubectl -n mcp-orch run wl-$RANDOM --rm -i --restart=Never \
  --image=curlimages/curl:8.8.0 --quiet -- \
  -s -X POST http://policy-engine.mcp-policy.svc:8090/run_workload \
  -H 'Content-Type: application/json' -d "$BODY" \
| python3 -c "import sys,json
r=json.load(sys.stdin)
print('status:', r['status'])
for t in r['trace']:
    d=t['decision'].upper(); f=', '.join(t['failing']) or '-'
    mo=' [model-only]' if t.get('model_only') else ''
    print(f\"  {t['ip']:<6}{d:<6}{f}{mo}\")"
