#!/usr/bin/env bash
# AEP output-binding feasibility pipeline — output-binding over a software TPM (swtpm)
# appraised à la RATS/Veraison. Produces three real platform verdicts
# (Attested / Contested / Expired) + an output-binding negative control, with NO hardware.
#
# Appraiser = a minimal stand-in for a RATS Verifier (tpm2_checkquote + reference-PCR compare).
# This is the PORTABLE/PACKAGED copy of a verified attestation-feasibility experiment.
# It is self-contained: it spins up its own swtpm in a temp dir,
# writes all artefacts into $OUT (default = the directory holding this script).
#
# Requirements on PATH: swtpm, tpm2-tools (tpm2_startup/quote/checkquote/pcrextend/
# createek/createak/pcrread/evictcontrol/flushcontext), openssl.
set -euo pipefail
OUT="${1:-$(cd "$(dirname "$0")" && pwd)}"
WORK="$(mktemp -d)"; STATE="$WORK/tpmstate"; mkdir -p "$STATE"
LOG="$OUT/run.log"; : > "$LOG"
exec 3>>"$LOG"
say(){ echo "$@"; echo "$@" >&3; }
h(){ printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

cleanup(){ [ -n "${SWTPM_PID:-}" ] && kill "$SWTPM_PID" 2>/dev/null || true; }
trap cleanup EXIT

say "## AEP output-binding feasibility — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "tools: $(swtpm --version 2>&1 | head -1) ; $(tpm2_startup --version 2>&1)"

# 1) software TPM
swtpm socket --tpmstate dir="$STATE" --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --tpm2 --flags startup-clear >&3 2>&1 &
SWTPM_PID=$!; sleep 1
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
tpm2_startup -c >&3 2>&1 || true
cd "$WORK"

# 2) measured boot — extend the "good" platform state; PCR3 measures the model artefact
tpm2_pcrextend 0:sha256=$(h firmware-v1)        >&3 2>&1
tpm2_pcrextend 1:sha256=$(h bootloader-v1)      >&3 2>&1
tpm2_pcrextend 2:sha256=$(h kernel-v1)          >&3 2>&1
tpm2_pcrextend 3:sha256=$(h model-artefact-A)   >&3 2>&1
tpm2_pcrread sha256:0,1,2,3 > "$OUT/reference-pcrs.txt" 2>&3
say "reference PCRs (good state) written to reference-pcrs.txt"

# 3) attestation keys
tpm2_createek -c ek.ctx -G rsa -u ek.pub >&3 2>&1
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub -n ak.name >&3 2>&1
# persist the AK and free transient object slots (swtpm holds few) so quotes can load the AK
AKH=0x81010002
tpm2_flushcontext -t >&3 2>&1 || true          # free transient slots (EK) BEFORE loading ak.ctx
tpm2_evictcontrol -c ak.ctx "$AKH" >&3 2>&1     # persist the AK
tpm2_flushcontext -t >&3 2>&1 || true

# 4) synthetic AEP and the output-binding qualifying data = H(AEP) folded with a fresh appraiser nonce
cat > "$OUT/aep.json" <<JSON
{"action":"summarise_case_file","authorised_by":"officer:42","scope":"read+summarise","model":"model-artefact-A","outcome_digest":"$(h 'the produced summary text')"}
JSON
AEPH=$(sha256sum "$OUT/aep.json" | cut -d' ' -f1)
NONCE_A=$(openssl rand -hex 16)
QUAL_A=$(h "${AEPH}:${NONCE_A}")
say "AEP digest          = $AEPH"
say "fresh nonce (run A) = $NONCE_A"
say "qualifying data A   = $QUAL_A   (binds AEP outcome + freshness into the quote)"

quote(){ tpm2_quote -c "$AKH" -l sha256:0,1,2,3 -q "$1" -m "$2.msg" -s "$2.sig" -o "$2.pcrs" -g sha256 >&3 2>&1; }
# appraiser: verify signature+freshness via checkquote(-q), then compare PCRs to the golden reference
appraise(){ # $1=tag $2=qual-expected $3=reference-pcrs
  local sigok pcrok
  if tpm2_checkquote -u ak.pub -m "$1.msg" -s "$1.sig" -f "$1.pcrs" -q "$2" -g sha256 >&3 2>&1; then sigok=yes; else sigok=no; fi
  if cmp -s "$1.pcrs" "$3"; then pcrok=match; else pcrok=diverged; fi
  echo "$sigok $pcrok"
}

# ---- RUN A: good state, fresh nonce -> Attested
quote "$QUAL_A" runA
cp runA.pcrs "$OUT/golden.pcrs"
read SIG PCR <<<"$(appraise runA "$QUAL_A" "$OUT/golden.pcrs")"
[ "$SIG" = yes ] && [ "$PCR" = match ] && VA=Attested || VA="(unexpected:$SIG/$PCR)"
say "RUN A  sig=$SIG pcrs=$PCR  -> VERDICT: $VA"

# ---- RUN B: perturb the platform (tamper a measurement) -> Contested
tpm2_pcrextend 3:sha256=$(h model-artefact-B-SWAPPED) >&3 2>&1   # the model was swapped after boot
NONCE_B=$(openssl rand -hex 16); QUAL_B=$(h "${AEPH}:${NONCE_B}")
quote "$QUAL_B" runB
read SIG PCR <<<"$(appraise runB "$QUAL_B" "$OUT/golden.pcrs")"
[ "$SIG" = yes ] && [ "$PCR" = diverged ] && VB=Contested || VB="(unexpected:$SIG/$PCR)"
say "RUN B  sig=$SIG pcrs=$PCR  -> VERDICT: $VB   (PCR3 model-artefact swapped)"

# ---- RUN C: replay run A's quote against a NEW fresh challenge -> Expired (stale/replayed)
NONCE_C=$(openssl rand -hex 16); QUAL_C=$(h "${AEPH}:${NONCE_C}")
read SIG PCR <<<"$(appraise runA "$QUAL_C" "$OUT/golden.pcrs")"   # appraise OLD quote with NEW expected nonce
[ "$SIG" = no ] && VC=Expired || VC="(unexpected:$SIG/$PCR)"
say "RUN C  sig=$SIG (freshness)  -> VERDICT: $VC   (run A quote replayed under a new challenge)"

# ---- output-binding control: forge the AEP outcome, re-appraise run A under the forged digest
AEPH_FORGED=$(h 'a DIFFERENT, fabricated summary')
QUAL_FORGED=$(h "${AEPH_FORGED}:${NONCE_A}")
read SIG PCR <<<"$(appraise runA "$QUAL_FORGED" "$OUT/golden.pcrs")"
[ "$SIG" = no ] && BIND=rejected || BIND="(unexpected:$SIG)"
say "BIND   forged AEP outcome under run-A quote: checkquote=$SIG -> $BIND (cannot swap the outcome without invalidating the quote)"

cat > "$OUT/results.json" <<JSON
{
  "host": "developer workstation",
  "tools": {"swtpm": "$(swtpm --version 2>&1 | head -1)", "tpm2_tools": "$(tpm2_startup --version 2>&1 | sed 's/.*version="\([^"]*\)".*/\1/')"},
  "aep_digest": "$AEPH",
  "verdicts": {"run_A_good_fresh": "$VA", "run_B_perturbed_pcr3": "$VB", "run_C_replayed_quote": "$VC"},
  "output_binding_forged_aep": "$BIND",
  "notes": "Appraiser is a minimal RATS-Verifier stand-in: tpm2_checkquote (signature+qualifying-data/freshness) + reference-PCR compare. PCR3 carries the model-artefact measurement; qualifying data binds H(AEP outcome) + fresh nonce into the AK-signed quote."
}
JSON
say "results.json written. Verdicts: A=$VA  B=$VB  C=$VC  binding=$BIND"
