# Round 0 — how to take part

Track B of the Tyche Labs open interlaboratory comparison measures whether an
**independently written** verifier reaches the same verdicts as the references on a fixed,
versioned corpus of action evidence packages.

## What you do

1. Take `vectors/r0-*.aep.json`, the per-case run parameters in `vectors/cases.json`, and the
   trust anchor list `trusted_issuers.json`.
2. Run **your own** verifier over every vector with the case's `now` and `consumed` inputs.
3. Return one JSON array of `{file, verdict, reason}` — `verdict` is `ALLOW` or `DENY`, and on
   `DENY` the `reason` comes from the fixed vocabulary in `RULES-draft.md`. Nothing else.
4. Send it to the address on tyche.institute, or open a pull request adding it under
   `submissions/` if you would rather be public from the start.

## What we do

Submissions are **coded**: they are separated from submitter identity before scoring, and we
do not learn which return came from whom until scoring is complete. Results are published as
a divergence matrix — which vectors were answered differently, by how many participants, and
what the disagreement was about. **No participant is named without their written agreement,
and no ranking of participants is published, ever.** Agreement with the references is not a
certificate of anything; it is a measurement.

## What counts as participation

Both reference implementations are open source. Running one of them and returning its output
is possible and meaningless — it measures only that our code agrees with itself. Participation
means the verdicts came from an implementation written independently of ours. We cannot
enforce that and do not try; we state it so that an echo is understood as a null result.

You may also participate **without a verifier** by auditing the instrument: regenerate the
vectors and confirm they come out byte-identical, check `MANIFEST.sha256`, and confirm the
sealed commitment in `RULES-draft.md` equals the SHA-256 of the assigned values when they are
released. An independent statement that the instrument was sound is worth more before the
measurements than after.

## Minimum viable round

**Three external participants plus the two references.** Below that the round does not produce
a divergence matrix worth the name.

If we do not reach it, that is itself published: the count we reached, the date we stopped
waiting, and no results dressed up as more than they are. A round that failed to recruit is a
finding about the field, not an embarrassment to hide.

## Deadlines

There is none yet. The round opens when this file is public and closes when either the minimum
is reached and scored, or we publish the shortfall. Both outcomes are published.

## Findings against us are the point

Before any external participant arrived, Round 0 produced a defect in our own reference
implementation — the two references disagree on one vector, and the standard says the one we
call the reference is the wrong side. That is published as Finding 001. If your verifier
disagrees with both of ours, say so; that is the most useful return we can receive.
