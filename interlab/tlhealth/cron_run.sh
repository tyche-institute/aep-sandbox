#!/usr/bin/env bash
# cron_run.sh — one scheduled observation of the trusted-list observatory.
#
# Why this exists. Until 30.08.2026 there was no cron at all: every run in the
# series was started by hand. The series therefore stopped for five days without
# anyone noticing, and the published page kept serving the last thing it had —
# which is how tyche.institute came to show Lithuania's list as failing after
# Lithuania had simply moved it to a new address that answers fine. A stale
# observatory does not go quiet; it goes confidently wrong.
#
# Two repositories, both driven from detached worktrees pinned to origin/main so
# a lane branch in a shared tree can never leak into a scheduled run:
#   * aep-sandbox — the instrument and the append-only run records;
#   * tyche-institute-site — the published data.json the page reads.
#
# The observation always runs. Git trouble is logged and never masks the result:
# a failed push must not turn a healthy run red, nor a failed one green.

set -uo pipefail

AEP="${TLH_AEP_ROOT:-/srv/tyche/cron/aep-sandbox-main}"
SITE="${TLH_SITE_ROOT:-/srv/tyche/cron/site-main}"
LOG_TAG="tlhealth-cron"
STAMP() { date -u +%FT%TZ; }
say() { echo "$(STAMP) [$LOG_TAG] $*"; }

# One lock for the whole job: two overlapping runs would interleave writes into
# the same append-only directories and both push.
LOCK="/tmp/tlhealth-cron.lock"
exec 9>"$LOCK" || { say "cannot open lock"; exit 1; }
flock -n 9 || { say "another run holds the lock; exiting"; exit 0; }

sync_tree() {  # $1 = worktree, $2 = label
  local d="$1" l="$2"
  git -C "$d" fetch --quiet origin main 2>&1 | sed "s/^/$(STAMP) [$LOG_TAG] $l fetch: /" || say "$l fetch failed"
  # Discard anything a previous run left behind, then pin to origin/main.
  git -C "$d" reset --hard --quiet origin/main 2>/dev/null || say "$l reset failed"
  git -C "$d" clean -fdq -e node_modules -e dist 2>/dev/null || true
  say "$l at $(git -C "$d" rev-parse --short HEAD)"
}

publish() {  # $1 = worktree, $2 = label, $3 = commit subject, rest = paths
  local d="$1" l="$2" subject="$3"; shift 3
  git -C "$d" add -- "$@" 2>/dev/null || true
  if git -C "$d" diff --cached --quiet 2>/dev/null; then
    say "$l nothing to commit"; return 0
  fi
  git -C "$d" -c user.name="Athena (Tyche Operations Agent)" \
      -c user.email="ops@tyche.institute" \
      commit -q -m "$subject" -m "Scheduled observation, $(STAMP)." || { say "$l commit failed"; return 0; }
  git -C "$d" push -q origin HEAD:main 2>&1 | sed "s/^/$(STAMP) [$LOG_TAG] $l push: /" \
    || say "$l push failed (commit is local; next run will carry it)"
  say "$l pushed $(git -C "$d" rev-parse --short HEAD)"
}

say "=== run start ==="
sync_tree "$AEP" aep
sync_tree "$SITE" site

TLH="$AEP/interlab/tlhealth"
DATA="$SITE/public/lab/trust-list-graph/data.json"
rc=0

# Order matters: probe (transport, and the second vantage for failures), then
# freshness (declared currency), then the pointer crawl, then the export that
# assembles the page's data from those three run records.
for step in "probe.py" "freshness.py" "graph.py"; do
  say "running $step"
  if ! /usr/bin/python3 "$TLH/$step" >>"$TLH/cron.log" 2>&1; then
    say "$step FAILED (continuing; a partial observation is still a record)"; rc=1
  fi
done

say "exporting web data"
if ! /usr/bin/python3 "$TLH/export_web.py" --out "$DATA" >>"$TLH/cron.log" 2>&1; then
  say "export FAILED"; rc=1
fi

# Refresh the copy that lives beside the instrument too, so the repo's own
# artefact never disagrees with the published one.
/usr/bin/python3 "$TLH/export_web.py" >>"$TLH/cron.log" 2>&1 || true

publish "$AEP" aep "tlhealth: scheduled observation" \
  interlab/tlhealth/runs interlab/tlhealth/runs-freshness \
  interlab/tlhealth/runs-graph interlab/tlhealth/graph-data.json
publish "$SITE" site "Trusted-list observatory: scheduled refresh" \
  public/lab/trust-list-graph/data.json

say "=== run end rc=$rc ==="
exit $rc
