#!/usr/bin/env python3
"""mint.py — create keys, two governed AEPs (in-scope + over-scope), and a ledger to attack.

    python3 mint.py init        # generate trust anchors + samples/good.aep.json + ledger
    python3 mint.py governed ... # mint a custom governed AEP (advanced)
    python3 mint.py ledger      # (re)mint the unsigned hash-chain ledger sample

`init` writes PRIVATE keys to keys/private/ (git-ignored) and the PUBLIC trust store to
keys/trusted_issuers.json (committed). An attacker who clones the repo gets the public
trust store and the signed samples, but NOT the private keys — break it without them.
"""

from __future__ import annotations

import argparse
import json
import os

from aep import keys, ledger, mandate, package

ROOT = os.path.dirname(os.path.abspath(__file__))
PRIV = os.path.join(ROOT, "keys", "private")
TRUST_PATH = os.path.join(ROOT, "keys", "trusted_issuers.json")
GOOD_AEP = os.path.join(ROOT, "samples", "good.aep.json")
EXCEED_AEP = os.path.join(ROOT, "samples", "exceed-scope.aep.json")
LEDGER = os.path.join(ROOT, "samples", "ledger.jsonl")

# Fixed demo identities + a fixed logical clock so the committed samples are stable.
ISSUER_ID = "demo-issuer:tyche-sandbox"
PRINCIPAL_ID = "operator:alice"
AGENT_ID = "agent:refund-assistant-1"
IAT = 1_750_000_000
EXP = 2_000_000_000  # ~year 2033; the good sample never "expires" in normal play
NOW_DEFAULT = 1_750_000_100

# The granted scope: this agent may issue refunds up to 1000, or send a receipt. Anything
# else (a bigger refund, a different method) is out of scope -> the verifier must DENY.
SCOPE = {"allowed_methods": ["issue_refund", "send_receipt"], "max_amount": 1000}

GOOD_ACTION = {
    "method": "issue_refund",
    "args": {"order_id": "ORD-4471", "amount": 250, "currency": "EUR"},
    "context": {"channel": "support-queue", "ticket": "T-9012"},
}
GOOD_OUTCOME = {"status": "ok", "refund_id": "RF-22317", "human_signoff": False}

# Same agent, same valid mandate, but the agent overreaches: a 9000 EUR refund, far above
# the granted max_amount of 1000. The agent signs its own AEP correctly, yet the verifier
# must DENY:scope_violation — the principal's grant is enforced against the agent's overreach.
EXCEED_ACTION = {
    "method": "issue_refund",
    "args": {"order_id": "ORD-4471", "amount": 9000, "currency": "EUR"},
    "context": {"channel": "support-queue", "ticket": "T-9012"},
}
EXCEED_OUTCOME = {"status": "ok", "refund_id": "RF-90001", "human_signoff": False}


def _sk_path(name: str) -> str:
    return os.path.join(PRIV, f"{name}.sk")


def _load_or_die(name: str):
    p = _sk_path(name)
    if not os.path.exists(p):
        raise SystemExit(f"missing private key {p} — run: python3 mint.py init")
    return keys.load_private_hex(keys.read_text(p))


def cmd_init(_args: argparse.Namespace) -> None:
    os.makedirs(PRIV, exist_ok=True)
    issuer = keys.generate_private()
    principal = keys.generate_private()
    agent = keys.generate_private()
    for name, sk in (("issuer", issuer), ("principal", principal), ("agent", agent)):
        keys.write_text(_sk_path(name), keys.priv_hex(sk) + "\n")
        keys.write_text(os.path.join(ROOT, "keys", f"{name}.pub"), keys.pub_hex(sk) + "\n")

    trust = mandate.TrustStore(issuers={ISSUER_ID: keys.pub_hex(issuer)})
    keys.write_text(TRUST_PATH, json.dumps(trust.to_dict(), indent=2) + "\n")

    _mint_governed(issuer, principal, agent)
    _mint_ledger()
    print("[init] wrote trust anchors (private -> keys/private/, public -> keys/), "
          "samples/good.aep.json, samples/exceed-scope.aep.json, samples/ledger.jsonl")
    print(f"[init] issuer listed: {ISSUER_ID}")


def _mint_governed(issuer, principal, agent) -> None:
    """Mint the two committed fixtures from one issuer/principal/agent + one valid mandate:
    an in-scope action (ALLOW) and an over-scope action by the same agent (DENY)."""
    credential = mandate.issue_credential(
        issuer, ISSUER_ID, PRINCIPAL_ID, keys.pub_hex(principal)
    )
    mandate_obj = mandate.issue_mandate(
        principal_sk=principal,
        principal_id=PRINCIPAL_ID,
        agent_id=AGENT_ID,
        agent_pub=keys.pub_hex(agent),
        scope=SCOPE,
        iat=IAT,
        exp=EXP,
    )
    good = package.build_aep(
        agent_sk=agent, agent_id=AGENT_ID, action=GOOD_ACTION, outcome=GOOD_OUTCOME,
        credential=credential, mandate_obj=mandate_obj, issued_at=IAT,
        nonce="aep-nonce-0001",
    )
    package.dump(good, GOOD_AEP)

    exceed = package.build_aep(
        agent_sk=agent, agent_id=AGENT_ID, action=EXCEED_ACTION, outcome=EXCEED_OUTCOME,
        credential=credential, mandate_obj=mandate_obj, issued_at=IAT,
        nonce="aep-nonce-0002",
    )
    package.dump(exceed, EXCEED_AEP)


def cmd_governed(_args: argparse.Namespace) -> None:
    issuer, principal, agent = (_load_or_die(n) for n in ("issuer", "principal", "agent"))
    _mint_governed(issuer, principal, agent)
    print(f"[governed] re-minted {GOOD_AEP} and {EXCEED_AEP}")


def _mint_ledger() -> None:
    actions = [
        {"method": "read_file", "args": {"path": "/tmp/report.txt"}},
        {"method": "summarize_document", "args": {"doc_id": "D-1"}},
        {"method": "issue_refund", "args": {"order_id": "ORD-1", "amount": 90}},
        {"method": "send_receipt", "args": {"order_id": "ORD-1"}},
        {"method": "issue_refund", "args": {"order_id": "ORD-2", "amount": 410}},
    ]
    chain = ledger.mint(actions)
    ledger.dump(chain, LEDGER)


def cmd_ledger(_args: argparse.Namespace) -> None:
    _mint_ledger()
    print(f"[ledger] wrote {LEDGER} ({len(ledger.load(LEDGER))} receipts)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="generate keys + samples").set_defaults(fn=cmd_init)
    sub.add_parser("governed", help="re-mint the good governed AEP").set_defaults(fn=cmd_governed)
    sub.add_parser("ledger", help="re-mint the unsigned ledger").set_defaults(fn=cmd_ledger)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
