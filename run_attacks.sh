#!/usr/bin/env bash
# Adversarial cells of the security table (tab:attacks-matrix): for each
# model family, all four P-LLM/Q-LLM attack configurations, 60 runs per
# cell (20 per workload, aggregated -- no per-workload split). One
# self-describing file per family in results/.
# Usage:  bash run_attacks.sh [N] [family ...]    (default: n=20, all three)
set -eu
N="${1:-20}"; shift 2>/dev/null || true
FAMILIES="${*:-llama qwen gemma}"
export OLLAMA_TIMEOUT="${OLLAMA_TIMEOUT:-480}"
models_for() { case "$1" in
  llama) echo "llama3.1:8b llama3.2:3b" ;;
  qwen)  echo "qwen2.5:7b qwen2.5:3b" ;;
  gemma) echo "gemma2:9b gemma2:2b" ;;
  *) echo "unknown family: $1" >&2; exit 1 ;; esac; }
mkdir -p results
for fam in $FAMILIES; do
  set -- $(models_for "$fam"); PL="$1"; QL="$2"
  OUT="results/${fam}_attacks.txt"
  { echo "family: $fam"; echo "planner: $PL"; echo "extractor: $QL";
    echo "mode: adversarial (60 runs/cell: 20 x workloads A,B,C)";
    echo "n: $N  date: $(date)"; echo; } > "$OUT"
  PLLM_MODEL="$PL" QLLM_MODEL="$QL" \
    python -u -m tests.measure_matrix --n "$N" --rows attack 2>&1 | tee -a "$OUT"
done
echo "ATTACKS DONE -> results/<family>_attacks.txt"
