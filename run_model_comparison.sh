# #!/usr/bin/env bash
# # Runs the full 7-cell configuration matrix (including the two previously
# # missing benign half-live cells) for three model families, pulling each
# # model through Ollama first. Results land in results/<family>.txt plus a
# # combined summary. Usage:
# #   bash run_model_comparison.sh          # n=20 per cell (paper numbers)
# #   bash run_model_comparison.sh 5        # quicker smoke pass
# set -euo pipefail
# N="${1:-20}"

# # family -> "planner extractor". Llama is the paper default; Qwen2.5 and
# # Gemma2 are the two comparison families, each with a planner-sized and an
# # extractor-sized member (all served through Ollama, all support the
# # `format` parameter used for grammar-constrained plan decoding).
# declare -A FAMILIES=(
#   [llama]="llama3.1:8b llama3.2:3b"
#   [qwen]="qwen2.5:7b qwen2.5:3b"
#   [gemma]="gemma2:9b gemma2:2b"
# )

# command -v ollama >/dev/null || { echo "ERROR: ollama not on PATH"; exit 1; }
# ollama list >/dev/null 2>&1 || { echo "ERROR: ollama server not running (run 'ollama serve')"; exit 1; }

# mkdir -p results
# for fam in llama qwen gemma; do
#   read -r PL QL <<< "${FAMILIES[$fam]}"
#   for m in "$PL" "$QL"; do
#     ollama list | grep -q "^${m%%:*}.*${m#*:}" || { echo ">> pulling $m"; ollama pull "$m"; }
#   done
#   echo ">> family=$fam  planner=$PL  extractor=$QL  n=$N/cell"
#   {
#     echo "family: $fam"; echo "planner: $PL"; echo "extractor: $QL"
#     echo "date: $(date -Iseconds)"; echo "n: $N"; echo
#     PLLM_MODEL="$PL" QLLM_MODEL="$QL" python -m tests.measure_matrix --n "$N"
#   } | tee "results/${fam}.txt"
# done

# echo; echo "===== summary (all families) ====="
# {
#   printf "%-8s %-28s %s\n" "family" "configuration" "rate"
#   for fam in llama qwen gemma; do
#     grep -E "completed|blocked" "results/${fam}.txt" | sed 's/\r.*\r//' | \
#       awk -v f="$fam" '{printf "%-8s %-28s %s %s\n", f, $1" "$2" "$3, $(NF-3), $(NF-2)}'
#   done
# } | tee results/summary.txt
# echo "Per-family failing-rule histograms are at the end of results/<family>.txt."

#!/usr/bin/env bash
# Runs the full 7-cell configuration matrix for three model families,
# pulling each model through Ollama first. Portable to bash 3.2 (macOS).
# Results: results/<family>.txt + combined results/summary.txt
# Usage:  bash run_model_comparison.sh        # n=20 per cell (paper numbers)
#         bash run_model_comparison.sh 5      # quicker smoke pass
set -eu
# Usage: bash run_model_comparison.sh [N] [family ...]
#   bash run_model_comparison.sh                 # n=20, all three families
#   bash run_model_comparison.sh 5 qwen          # n=5, Qwen only
#   bash run_model_comparison.sh 20 llama gemma  # n=20, two families
N="${1:-20}"; shift 2>/dev/null || true
FAMILIES="${*:-llama qwen gemma}"

models_for() {  # family -> "planner extractor"
  case "$1" in
    llama) echo "llama3.1:8b llama3.2:3b" ;;
    qwen)  echo "qwen2.5:7b qwen2.5:3b" ;;
    gemma) echo "gemma2:9b gemma2:2b" ;;
    *) echo "unknown family: $1" >&2; exit 1 ;;
  esac
}

command -v ollama >/dev/null || { echo "ERROR: ollama not on PATH"; exit 1; }
ollama list >/dev/null 2>&1 || { echo "ERROR: ollama server not running (run 'ollama serve')"; exit 1; }

mkdir -p results
for fam in $FAMILIES; do
  set -- $(models_for "$fam"); PL="$1"; QL="$2"
  for m in "$PL" "$QL"; do
    ollama list | awk 'NR>1{print $1}' | grep -qx "$m" || { echo ">> pulling $m"; ollama pull "$m"; }
  done
  echo ">> family=$fam  planner=$PL  extractor=$QL  n=$N/cell"
  {
    echo "family: $fam"; echo "planner: $PL"; echo "extractor: $QL"
    echo "date: $(date)"; echo "n: $N"; echo
    PLLM_MODEL="$PL" QLLM_MODEL="$QL" python -m tests.measure_matrix --n "$N"
  } | tee "results/${fam}.txt"
  [ "${OLLAMA_CLEANUP:-0}" = "1" ] && [ "$fam" != "llama" ] && ollama rm "$PL" "$QL"
done

echo; echo "===== summary (all families) ====="
{
  for fam in $FAMILIES; do
    echo "--- $fam ---"
    grep -E "completed|blocked" "results/${fam}.txt" | sed 's/.*\r//'
  done
} | tee results/summary.txt
echo "Per-family failing-rule histograms are at the end of results/<family>.txt."
EOF
chmod +x run_model_comparison.sh && bash -n run_model_comparison.sh && bash -c '
models_for() { case "$1" in llama) echo "llama3.1:8b llama3.2:3b";; qwen) echo "qwen2.5:7b qwen2.5:3b";; gemma) echo "gemma2:9b gemma2:2b";; esac; }
for f in llama qwen gemma; do echo "$f -> $(models_for $f)"; done' && cd /home/claude && tar --exclude='__pycache__' --exclude='*.pyc' --exclude='.venv' -czf /mnt/user-data/outputs/pcm-mcp.tar.gz pcm-mcp && echo repackaged