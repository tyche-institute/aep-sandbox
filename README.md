# AEP Sandbox

A small, self-contained playground for **attacking** Action Evidence Packages (AEP): the
cryptographic receipts an AI agent leaves so an outside party can later check *what it did,
under whose authority, and whether it stayed inside its mandate* — without taking the
agent's word for it.

It exists to be broken. Clone it, point the verifier at a package, tamper, forge, replay,
overreach, and watch what holds and what gives. It is the hands-on companion to the
[EATF](https://github.com/tyche-institute/eatf) reference implementation and the
[eatf.eu](https://eatf.eu) agent-trust framework, built by [Tyche Institute](https://tyche.institute).

> **Reference implementation of a primitive, not a product.** The point is pedagogical and
> adversarial: to make the guarantees (and the gaps) concrete enough to attack.

## The three layers

The sandbox stacks three layers, weakest first, so you can feel what each one buys:

| Layer | What it is | What it defends | Where it gives |
|---|---|---|---|
| **1. Ledger** (`aep/ledger.py`) | an *unsigned* sha256 hash-chain of action receipts | a single edited field, a deleted/reordered receipt | a full re-chain forge passes — a hash-chain only stops an attacker who can't recompute it |
| **2. Governed AEP** (`aep/package.py`) | a *signed* receipt that folds in a scoped, signed **mandate** | tamper, re-chain forge, forged/swapped mandate, replay, **and overreach beyond the granted scope** | trust rests on the listed issuer key and the agent's private key |
| **3. TPM-bound** (`tpm-demo/`) | the outcome digest folded into a TPM quote (swtpm) | forging the outcome or replaying a quote fails at `tpm2_checkquote` | emulated TPM, not a hardware root of trust |

The trust chain in Layer 2 mirrors how a remote qualified e-signature keeps a human in
*sole control*, transposed to an agent action:

```
issuer  --signs-->  credential   (this principal owns this public key)      [a trusted-list analog]
principal --signs-->  mandate     (this agent may act within THIS scope, until exp)
agent   --signs-->   the AEP      (this is the action I took, and its outcome)
verifier checks all three + the scope + freshness + one-shot replay  ->  ALLOW / DENY
```

## Quickstart

```bash
git clone https://github.com/tyche-institute/aep-sandbox
cd aep-sandbox
python3 -m pip install -r requirements.txt   # one dependency: cryptography (Ed25519); Python 3.8+

# 1. a legitimate, in-scope action verifies clean:
python3 verify.py samples/good.aep.json          # -> ALLOW (exit 0)

# 2. the same agent, same valid mandate, overreaching past its scope:
python3 verify.py samples/exceed-scope.aep.json  # -> DENY:scope_violation (exit 2)
```

That second line is the whole thesis in one command: every signature and hash checks out,
and the verifier *still* refuses, because the principal's grant is enforced against the
agent's own overreach. The agent is not its own judge.

You do **not** need the private trust-anchor keys to attack the sandbox — a fresh clone ships
the public trust store and pre-signed samples. Breaking it without the keys is the game.

## Attack it

Each script in [`attacks/`](attacks/) mutates a real package the way an adversary would and
runs the verifier on the result:

```bash
python3 attacks/tamper_field.py     # edit a field, skip the hash   -> DENY:content_mutated
python3 attacks/forge_rechain.py    # rewrite + recompute all hashes -> ledger PASSES, signed AEP DENY:aep_sig_invalid
python3 attacks/forge_full.py       # mint a whole AEP with your keys -> DENY:issuer_not_listed
python3 attacks/swap_mandate.py     # splice in a broader mandate     -> DENY:aep_sig_invalid
python3 attacks/exceed_scope.py     # valid sig, out-of-scope action  -> DENY:scope_violation
python3 attacks/replay.py           # submit the same AEP twice        -> ALLOW then DENY:replayed
python3 attacks/strip_sig.py        # blank the signature              -> DENY:aep_sig_invalid

# or run the lot + the TPM demo:
make attacks
```

## The CTF

The win condition is precise: **make `verify.py` return ALLOW for an AEP that authorises
something the reference mandate does not** — a refund over the cap, a method outside the
allow-list, a different issuer or agent than the trust anchor. Denial is the defense working;
a wrongful *allow* is a break.

```bash
cp my_forgery.aep.json attacks/out/CHALLENGE.aep.json
python3 did_you_break_it.py
```

If you find a genuine bypass, that is a finding — see [THREAT-MODEL.md](THREAT-MODEL.md) for
scope and how to report it.

## Layout

```
verify.py              the single appraiser you are trying to defeat (ALLOW/DENY + exit code)
mint.py                generate trust anchors + the signed sample packages
did_you_break_it.py    the CTF judge
aep/                   the library: canonical · keys · mandate · ledger · package
attacks/               one readable script per attack lever
samples/               good.aep.json (ALLOW) · exceed-scope.aep.json (DENY) · ledger.jsonl
keys/                  the PUBLIC trust store (private keys are git-ignored — attack without them)
tpm-demo/              the swtpm output-binding demo (Layer 3, needs Docker or swtpm+tpm2-tools)
```

## Authorised use

This is a deliberately vulnerable target for learning and for testing **your own**
attestation systems. Use it against systems you own or are authorised to test. See
[THREAT-MODEL.md](THREAT-MODEL.md).

## Licence

MIT © 2026 Tyche Institute / Anton Sokolov. See [LICENSE](LICENSE).
