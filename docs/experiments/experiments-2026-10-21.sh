#!/usr/bin/env bash
# Strix-Opt ablation experiments (2026-10-21): smoke -> B -> C- -> C.
#
# Approved API budget: <= $7.5 total. Every scan is hard-capped by
# --max-budget 0.70; per-scan wall-clock ceiling 90 min (baseline max: 40.5).
# Runs sequentially. Milestones go to experiments-2026-10-21.log (and stdout);
# each scan's full output lands in experiment-run-logs/<label>.out.
#
#   smoke     1 task, shadow   - gates everything: no decisions.jsonl => ABORT
#   B (x3)    budget only      - scheduler off, --max-budget 0.70 (M0 unlock)
#   C- (x3)   shadow           - rules measured, never enforced
#   C  (x3)   enforce          - rules act
set -u
DEMO=/var/tmp/psy/strix-demo
cd "$DEMO" || exit 1
LOG=$DEMO/experiments-2026-10-21.log
RUNLOG=$DEMO/experiment-run-logs
mkdir -p "$RUNLOG"

say() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }

# Sanity: the deployed tree must contain the scheduler commit.
if ! git -C "$DEMO/strix" log --oneline -1 | grep -q "adaptive scheduler"; then
  say "ABORT deployed strix commit lacks the scheduler; deploy first"
  exit 1
fi

run_scan() {
  local label=$1 target=$2 scheduler=$3
  local -a extra=()
  [ "$scheduler" != "off" ] && extra+=(--scheduler "$scheduler")
  say "RUN_START $label target=$target scheduler=$scheduler budget=0.70"
  timeout 5400 ./run-strix.sh -t "$target" -n -m deep --max-turns 50 \
    --max-budget 0.70 "${extra[@]}" >"$RUNLOG/$label.out" 2>&1
  local rc=$?
  local dir
  dir=$(ls -t strix_runs 2>/dev/null | head -1)
  say "RUN_DONE $label exit=$rc run_dir=$dir"
  return 0
}

TARGETS=("005 http://10.88.0.5:80" "055 http://10.88.0.6:80" "010 http://10.88.0.7:5000")

# --- smoke: shadow on 005; artifacts gate the spend ----------------------
run_scan smoke-005 http://10.88.0.5:80 shadow
smoke_dir=$(ls -t strix_runs 2>/dev/null | head -1)
if [ -z "$smoke_dir" ] || [ ! -f "strix_runs/$smoke_dir/decisions.jsonl" ]; then
  say "ABORT smoke failed: no decisions.jsonl in ${smoke_dir:-<none>}"
  exit 1
fi
say "SMOKE_OK dir=$smoke_dir decisions=$(wc -l < "strix_runs/$smoke_dir/decisions.jsonl") lines"

# --- B: vanilla budget stack only ----------------------------------------
for t in "${TARGETS[@]}"; do
  set -- $t
  run_scan "expB-$1" "$2" off
done

# --- C-: shadow ------------------------------------------------------------
for t in "${TARGETS[@]}"; do
  set -- $t
  run_scan "expCminus-$1" "$2" shadow
done

# --- C: enforce ------------------------------------------------------------
for t in "${TARGETS[@]}"; do
  set -- $t
  run_scan "expC-$1" "$2" enforce
done

say "ALL_DONE"
