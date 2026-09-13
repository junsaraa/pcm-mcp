set -e
export OLLAMA_TIMEOUT=480
runwl() {  # family planner extractor
  for W in A B C; do
    OUT=results/$1_attack_$W.txt
    { echo "family: $1"; echo "planner: $2"; echo "extractor: $3";
      echo "workload: $W  attack: $(python3 -c "import tests.measure_matrix as mm; print(mm.ATTACK['$W'])")";
      echo "n: 20  date: $(date)"; echo; } > "$OUT"
    PLLM_MODEL=$2 QLLM_MODEL=$3 WL=$W python -u -c "
import os, tests.measure_matrix as mm
mm.WORKLOADS = [os.environ['WL']]
mm.CONFIGS = [c for c in mm.CONFIGS if c[3] is not None]
mm.main(20, False)" 2>&1 | tee -a "$OUT"
  done
}
runwl llama llama3.1:8b llama3.2:3b
runwl qwen  qwen2.5:7b  qwen2.5:3b
runwl gemma gemma2:9b   gemma2:2b
echo PER-WORKLOAD ATTACKS DONE
