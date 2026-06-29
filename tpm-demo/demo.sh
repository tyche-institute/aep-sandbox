#!/usr/bin/env bash
# One-command launcher for the AEP output-binding feasibility demo.
#
# Runs the pipeline NATIVELY if swtpm + tpm2_startup are on PATH (fastest, no Docker).
# Otherwise falls back to building/running the container image (needs Docker + network
# for the first build to pull the base image).
#
# Usage:
#   ./demo.sh            # auto: native if possible, else docker
#   ./demo.sh --docker   # force the container path
#   ./demo.sh --native   # force native (errors out if tools are missing)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="tyche-aep-demo"
MODE="${1:-auto}"

have_native(){ command -v swtpm >/dev/null 2>&1 && command -v tpm2_startup >/dev/null 2>&1; }

run_native(){
  echo "==> Running natively (swtpm + tpm2-tools found on PATH)"
  bash "$HERE/run_pipeline.sh" "$HERE"
  echo
  echo "==> Verdicts (from results.json):"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.verdicts | to_entries[] | "  \(.key) = \(.value)"' "$HERE/results.json"
    jq -r '"  output_binding_forged_aep = \(.output_binding_forged_aep)"' "$HERE/results.json"
  else
    grep -Eo '"run_[ABC][^}]*|"output_binding_forged_aep":[[:space:]]*"[^"]*"' "$HERE/results.json"
  fi
}

run_docker(){
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: neither native tools nor docker are available." >&2
    exit 1
  fi
  echo "==> Building container image '$IMAGE' (first run pulls the base image)"
  docker build -t "$IMAGE" "$HERE"
  echo "==> Running the demo in a container; artefacts are written back to $HERE"
  # mount the demo dir so results.json/run.log land on the host; run as caller UID
  docker run --rm -u "$(id -u):$(id -g)" -v "$HERE:/demo" "$IMAGE" /demo
  echo
  echo "==> Verdicts (from results.json):"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.verdicts | to_entries[] | "  \(.key) = \(.value)"' "$HERE/results.json"
    jq -r '"  output_binding_forged_aep = \(.output_binding_forged_aep)"' "$HERE/results.json"
  else
    grep -Eo '"run_[ABC][^}]*|"output_binding_forged_aep":[[:space:]]*"[^"]*"' "$HERE/results.json"
  fi
}

case "$MODE" in
  --native) have_native || { echo "ERROR: swtpm/tpm2_startup not on PATH." >&2; exit 1; }; run_native ;;
  --docker) run_docker ;;
  auto|*)   if have_native; then run_native; else
              echo "==> Native swtpm/tpm2-tools not found; falling back to Docker."
              run_docker
            fi ;;
esac
