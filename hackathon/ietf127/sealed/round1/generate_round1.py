#!/usr/bin/env python3
"""generate_round1.py - SEALED generator for the Round 1 blind verdict round.

Withheld until the round closes. It reuses the aep-sandbox machinery (aep/keys.py,
aep/mandate.py, aep/package.py) from a copy of aep-sandbox origin/main, exactly as
interlab/round0/generate_round0.py does, but with FRESH test keys kept in ./keys/.

    # once, to create the test keys and the ordering salt (refuses to overwrite):
    python3 generate_round1.py --sandbox /path/to/aep-sandbox-origin-main --init-keys
    # every build (deterministic, byte-identical on re-run):
    python3 generate_round1.py --sandbox /path/to/aep-sandbox-origin-main

Writes:
  <public>/vectors/r1-NN.aep.json   the corpus (NN = rank of sha256(salt || slug))
  <public>/vectors/cases.json       ONLY {file, now, consumed} per vector
  <public>/trusted_issuers.json     the trust anchor list
  <sealed>/design.json              PRIVATE: slug, class, intended verdict, spec reading,
                                    clause, design note, self-check results

Determinism: Ed25519 signing is deterministic (RFC 8032); every timestamp, nonce, decoy and
file number is derived from the slug and the secret salt; no wall clock, no randomness
outside --init-keys.

Self-check: for every coverage / boundary / ordering vector the generator also builds, in
memory only, the variants with each defect alone and with no defect, and appraises them with
the sandbox's own package.verify_aep. An ordering vector is accepted only if each of its two
defects fires on its own (so both are real) and the clean variant is ALLOW.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(os.path.dirname(HERE))
DEFAULT_PUBLIC = os.path.join(PACK, "public", "round1")
KEYS = os.path.join(HERE, "keys")
KEY_NAMES = ("issuer", "issuer2", "principal", "agent",
             "rogue_issuer", "other_principal", "other_agent")

ISSUER_ID = "test-issuer:r1-anchor-a"
ISSUER2_ID = "test-issuer:r1-anchor-b"
UNLISTED_ISSUER_ID = "test-issuer:r1-anchor-c"
T_BASE = 1_794_000_000


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sandbox", default=os.environ.get("AEP_SANDBOX"),
                    help="path to an extracted copy of aep-sandbox origin/main")
    ap.add_argument("--init-keys", action="store_true")
    ap.add_argument("--public-out", default=DEFAULT_PUBLIC)
    ap.add_argument("--sealed-out", default=HERE)
    return ap.parse_args()


ARGS = parse_args()
if not ARGS.sandbox or not os.path.isdir(os.path.join(ARGS.sandbox, "aep")):
    raise SystemExit("--sandbox must point to an aep-sandbox origin/main copy (with aep/)")
sys.path.insert(0, os.path.abspath(ARGS.sandbox))

from aep import keys, mandate, package          # noqa: E402
from aep.mandate import MANDATE_VERSION          # noqa: E402
from aep.canonical import digest                 # noqa: E402


# --------------------------------------------------------------------------- #
# Keys and salt                                                                #
# --------------------------------------------------------------------------- #
def init_keys() -> None:
    os.makedirs(KEYS, exist_ok=True)
    targets = [os.path.join(KEYS, f"{n}.sk") for n in KEY_NAMES]
    targets.append(os.path.join(KEYS, "order-salt.hex"))
    if any(os.path.exists(t) for t in targets):
        raise SystemExit("keys already exist; refusing to overwrite")
    for n in KEY_NAMES:
        with open(os.path.join(KEYS, f"{n}.sk"), "w", encoding="utf-8") as fh:
            fh.write(keys.priv_hex(keys.generate_private()) + "\n")
    with open(os.path.join(KEYS, "order-salt.hex"), "w", encoding="utf-8") as fh:
        fh.write(os.urandom(32).hex() + "\n")
    print(f"[init] wrote {len(KEY_NAMES)} test keys and the order salt to {KEYS}")


if ARGS.init_keys:
    init_keys()


def _read(name: str) -> str:
    with open(os.path.join(KEYS, name), encoding="utf-8") as fh:
        return fh.read().strip()


SK = {n: keys.load_private_hex(_read(f"{n}.sk")) for n in KEY_NAMES}
PUB = {n: keys.pub_hex(sk) for n, sk in SK.items()}
SALT = bytes.fromhex(_read("order-salt.hex"))

TRUST = {"issuers": {ISSUER_ID: PUB["issuer"], ISSUER2_ID: PUB["issuer2"]}}
TRUST_STORE = mandate.TrustStore.from_dict(TRUST)


def h(tag: str, slug: str) -> str:
    return hashlib.sha256(SALT + f"{tag}:{slug}".encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Scenario parameters                                                          #
# --------------------------------------------------------------------------- #
@dataclass
class P:
    slug: str
    principal_id: str
    agent_id: str
    method: str
    args: dict
    context: dict
    outcome: dict
    scope: dict
    iat: int = 0
    exp: int = 0
    now: int = 0
    nonce: str = ""
    prev: str = ""
    decoys: list = field(default_factory=list)

    def __post_init__(self):
        t = int(h("t", self.slug)[:12], 16)
        self.iat = T_BASE + (t % 2_000_000)
        self.exp = self.iat + 86_400 * (2 + (t >> 8) % 28)
        self.now = self.iat + 1 + (t >> 20) % (self.exp - self.iat - 1)
        self.nonce = "n-" + h("nonce", self.slug)[:20]
        self.prev = h("prev", self.slug)
        k = int(h("dc", self.slug)[:2], 16) % 4          # 0..3 decoys
        self.decoys = ["n-" + h(f"decoy{i}", self.slug)[:20] for i in range(k)]

    def action(self, **over) -> dict:
        a = {"method": self.method, "args": copy.deepcopy(self.args),
             "context": copy.deepcopy(self.context)}
        a.update(over)
        return a


def cred(p: P, issuer_sk=None, issuer_id=ISSUER_ID, principal_id=None) -> dict:
    return mandate.issue_credential(issuer_sk or SK["issuer"], issuer_id,
                                    principal_id or p.principal_id, PUB["principal"])


def mand(p: P, principal_sk=None, principal_id=None, agent_id=None, agent_pub=None,
         scope=None, omit_exp=False) -> dict:
    body = {
        "v": MANDATE_VERSION,
        "principal_id": principal_id or p.principal_id,
        "agent_id": agent_id or p.agent_id,
        "agent_pub": agent_pub or PUB["agent"],
        "scope": scope if scope is not None else copy.deepcopy(p.scope),
        "iat": p.iat,
        "exp": p.exp,
    }
    if omit_exp:
        del body["exp"]
    return {"body": body, "sig": keys.sign(principal_sk or SK["principal"], body)}


def build(p: P, action=None, outcome=None, credential=None, mandate_obj=None) -> dict:
    return package.build_aep(
        agent_sk=SK["agent"], agent_id=p.agent_id,
        action=action if action is not None else p.action(),
        outcome=outcome if outcome is not None else copy.deepcopy(p.outcome),
        credential=credential if credential is not None else cred(p),
        mandate_obj=mandate_obj if mandate_obj is not None else mand(p),
        issued_at=p.iat, nonce=p.nonce, prev_hash=p.prev)


def resign(aep: dict, sk=None) -> dict:
    aep["aep_sig"] = keys.sign(sk or SK["agent"], package._receipt_core(aep))
    aep["receipt_hash"] = package.receipt_hash(aep)
    return aep


def out(aep, now, consumed, raw=None) -> dict:
    return {"aep": aep, "now": now, "consumed": list(consumed), "raw": raw}


# --------------------------------------------------------------------------- #
# The design. Each case: make(defects:set) -> out(...).                       #
# reasons: defect -> the reason it yields ALONE (self-check).                  #
# --------------------------------------------------------------------------- #
CASES: list[dict] = []


def case(slug, klass, scored, verdict, reason, clause, note, defects=(), reasons=None):
    def deco(fn):
        CASES.append(dict(slug=slug, klass=klass, scored=scored, verdict=verdict,
                          reason=reason, clause=clause, note=note, defects=list(defects),
                          reasons=reasons or {}, make=fn))
        return fn
    return deco


# ---- ALLOW --------------------------------------------------------------- #
p01 = P("allow-now-eq-exp", "principal:fleet-ops-12", "agent:freight-booker-3",
        "book_freight",
        {"shipment_ref": "SH-80314", "amount": 4200, "currency": "USD", "lane": "OAK-SEA"},
        {"request": "RQ-5521", "source": "planner"},
        {"status": "booked", "booking_ref": "BK-11902"},
        {"allowed_methods": ["book_freight", "cancel_freight"], "max_amount": 5000})


@case(p01.slug, "boundary", True, "ALLOW", None,
      "s4 step 5g + s5 first note (now == exp is not expired)",
      "now equals mandate exp exactly; strict comparison means not expired")
def m01(d):
    return out(build(p01), p01.exp, p01.decoys)


p02 = P("allow-amount-eq-max", "principal:ap-desk-04", "agent:invoice-runner-9",
        "pay_invoice",
        {"invoice_ref": "INV-2026-0931", "amount": 12500, "currency": "EUR",
         "payee_ref": "V-3307"},
        {"batch": "AP-W46", "approval_ref": "AR-1180"},
        {"status": "paid", "payment_ref": "PM-66104"},
        {"allowed_methods": ["pay_invoice"], "max_amount": 12500})


@case(p02.slug, "boundary", True, "ALLOW", None,
      "s4 step 5f ('not exceed': amount == max_amount is in scope)",
      "args.amount equals scope.max_amount exactly (12500)")
def m02(d):
    return out(build(p02), p02.now, p02.decoys)


p03 = P("allow-no-amount-near-miss-nonces", "principal:care-team-21",
        "agent:notice-sender-2", "send_notice",
        {"recipient_ref": "C-77120", "template": "delay-apology-v2"},
        {"case_ref": "CS-40917", "queue": "tier-2"},
        {"status": "queued", "message_ref": "MS-90022"},
        {"allowed_methods": ["send_notice", "issue_credit"], "max_amount": 800})


@case(p03.slug, "coverage", True, "ALLOW", None,
      "s4 step 5f ('an amount present': no amount, cap does not apply) + step 6 "
      "(consumed values differ from the nonce by value)",
      "amount-less action under a cap; consumed set holds near-miss strings of the nonce "
      "(upper case, one character changed, one character appended) but not the nonce")
def m03(d):
    n = p03.nonce
    near = [n.upper(), n[:-1] + ("0" if n[-1] != "0" else "1"), n + "0"]
    return out(build(p03), p03.now, near)


# ---- boundary DENY -------------------------------------------------------- #
p04 = P("deny-expired-exp-plus-1", "principal:it-licensing-07", "agent:license-renewer-5",
        "renew_license",
        {"license_ref": "LIC-4410", "amount": 960, "currency": "GBP", "seats": 40},
        {"contract_ref": "CN-2207", "term_months": 12},
        {"status": "renewed", "renewal_ref": "RN-5531"},
        {"allowed_methods": ["renew_license"], "max_amount": 1500})


@case(p04.slug, "boundary", True, "DENY", "expired",
      "s4 step 5g ('after' the expiry: now == exp + 1)",
      "now is exactly one second after exp", ["exp_plus_1"], {"exp_plus_1": "expired"})
def m04(d):
    return out(build(p04), p04.exp + 1 if "exp_plus_1" in d else p04.exp, p04.decoys)


p05 = P("deny-amount-max-plus-1", "principal:lab-stores-02", "agent:supply-orderer-8",
        "order_supplies",
        {"catalog_ref": "CAT-2290", "amount": 2001, "currency": "CHF", "qty": 12},
        {"cost_center": "CC-310", "requested_by_ref": "R-118"},
        {"status": "ordered", "order_ref": "OR-70315"},
        {"allowed_methods": ["order_supplies"], "max_amount": 2000})


@case(p05.slug, "boundary", True, "DENY", "scope_violation",
      "s4 step 5f (amount exceeds max_amount by 1)",
      "args.amount = 2001, scope.max_amount = 2000", ["amount_plus_1"],
      {"amount_plus_1": "scope_violation"})
def m05(d):
    a = p05.action()
    if "amount_plus_1" not in d:
        a["args"]["amount"] = 1950
    return out(build(p05, action=a), p05.now, p05.decoys)


p06 = P("deny-replayed", "principal:treasury-03", "agent:sweep-mover-1", "transfer_funds",
        {"from_ref": "ACC-OP-1", "to_ref": "ACC-RES-2", "amount": 30000, "currency": "EUR"},
        {"sweep_ref": "SW-2026-318", "window": "EOD"},
        {"status": "settled", "transfer_ref": "TR-88410"},
        {"allowed_methods": ["transfer_funds"], "max_amount": 50000})


@case(p06.slug, "boundary", True, "DENY", "replayed",
      "s4 step 6 (nonce string is in the consumed set, same value and type)",
      "consumed holds the exact nonce string between two decoys", ["consumed"],
      {"consumed": "replayed"})
def m06(d):
    a, b = ("n-" + h("decoyA", p06.slug)[:20], "n-" + h("decoyB", p06.slug)[:20])
    cons = [a, p06.nonce, b] if "consumed" in d else [a, b]
    return out(build(p06), p06.now, cons)


# ---- coverage DENY ------------------------------------------------------- #
p07 = P("deny-measurements-array", "principal:hr-ops-15", "agent:onboarding-helper-4",
        "provision_account", {"employee_ref": "E-55120", "profile": "standard"},
        {"ticket": "HR-20931", "site": "remote"},
        {"status": "provisioned", "account_ref": "AC-31207"},
        {"allowed_methods": ["provision_account", "revoke_account"]})


@case(p07.slug, "coverage", True, "DENY", "malformed_aep",
      "s4 step 1 ('measurements, if present, must be an object')",
      "measurements is a JSON array holding the two correct digests; core re-signed so "
      "only the structure defect is present", ["meas_array"], {"meas_array": "malformed_aep"})
def m07(d):
    v = build(p07)
    if "meas_array" in d:
        m = v["measurements"]
        v["measurements"] = [m["action_sha256"], m["outcome_sha256"]]
        resign(v)
    return out(v, p07.now, p07.decoys)


p08 = P("deny-issuer-pair-mismatch", "principal:grants-office-06",
        "agent:grant-disburser-2", "disburse_grant",
        {"grant_ref": "G-7781", "amount": 7400, "currency": "EUR"},
        {"programme_ref": "PR-12", "tranche": 2},
        {"status": "disbursed", "disbursement_ref": "DB-40118"},
        {"allowed_methods": ["disburse_grant"], "max_amount": 10000})


@case(p08.slug, "coverage", True, "DENY", "issuer_not_listed",
      "s4 step 5b ('with exactly the public key the credential carries')",
      "credential names listed issuer id anchor-b but carries (and is validly signed by) "
      "the anchor-a key; both ids and both keys are listed, the pair is not",
      ["pair_mismatch"], {"pair_mismatch": "issuer_not_listed"})
def m08(d):
    c = cred(p08, issuer_id=ISSUER2_ID) if "pair_mismatch" in d else cred(p08)
    return out(build(p08, credential=c), p08.now, p08.decoys)


p09 = P("deny-credential-sig-other-body", "principal:events-09", "agent:venue-booker-6",
        "book_venue",
        {"venue_ref": "VN-310", "amount": 3100, "currency": "USD",
         "date_ref": "D-2026-12-04"},
        {"event_ref": "EV-1204", "headcount": 120},
        {"status": "held", "hold_ref": "HD-7716"},
        {"allowed_methods": ["book_venue"], "max_amount": 3500})


@case(p09.slug, "coverage", True, "DENY", "credential_sig_invalid",
      "s4 step 5c",
      "credential.sig is a genuine anchor-a signature, but over a body whose principal_id "
      "differs by two transposed digits", ["sig_other_body"],
      {"sig_other_body": "credential_sig_invalid"})
def m09(d):
    c = cred(p09)
    if "sig_other_body" in d:
        c["sig"] = cred(p09, principal_id="principal:events-90")["sig"]
    return out(build(p09, credential=c), p09.now, p09.decoys)


# ---- ORDERING (two real defects; first failing check wins) --------------- #
p10 = P("ord-content-mutated-over-scope", "principal:claims-11", "agent:claims-payer-7",
        "settle_claim", {"claim_ref": "CL-90021", "amount": 450, "currency": "EUR"},
        {"adjuster_ref": "AJ-88", "line": "property"},
        {"status": "settled", "settlement_ref": "ST-3390"},
        {"allowed_methods": ["settle_claim"], "max_amount": 300})


@case(p10.slug, "ordering", True, "DENY", "content_mutated",
      "s4 step 2 before step 5f",
      "receipt_hash is a well-formed lowercase hex SHA-256 of a different core (aep_sig is "
      "valid over the real core); amount 450 exceeds max_amount 300",
      ["bad_receipt_hash", "over_cap"],
      {"bad_receipt_hash": "content_mutated", "over_cap": "scope_violation"})
def m10(d):
    a = p10.action()
    if "over_cap" not in d:
        a["args"]["amount"] = 280
    v = build(p10, action=a)
    if "bad_receipt_hash" in d:
        other = dict(v, nonce=v["nonce"] + "0")
        v["receipt_hash"] = package.receipt_hash(other)
    return out(v, p10.now, p10.decoys)


p11 = P("ord-aep-sig-over-expired", "principal:travel-desk-05", "agent:trip-planner-3",
        "book_travel", {"itinerary_ref": "IT-6620", "amount": 1280, "currency": "EUR"},
        {"traveller_ref": "TV-209", "class": "economy"},
        {"status": "ticketed", "pnr_ref": "PN-4Q7XZ"},
        {"allowed_methods": ["book_travel", "cancel_travel"], "max_amount": 2500})


@case(p11.slug, "ordering", True, "DENY", "aep_sig_invalid",
      "s4 step 3 before step 5g",
      "aep_sig made by a different key than agent_pub (receipt_hash correct); now is one "
      "hour after exp", ["wrong_signer", "expired"],
      {"wrong_signer": "aep_sig_invalid", "expired": "expired"})
def m11(d):
    v = build(p11)
    if "wrong_signer" in d:
        resign(v, SK["other_agent"])
    now = p11.exp + 3600 if "expired" in d else p11.now
    return out(v, now, p11.decoys)


p12 = P("ord-measurement-over-issuer", "principal:facilities-08",
        "agent:maintenance-dispatch-2", "dispatch_repair",
        {"site_ref": "S-114", "amount": 640, "currency": "EUR", "priority": 2},
        {"fault_ref": "FL-5520", "asset_ref": "HVAC-3"},
        {"status": "dispatched", "job_ref": "JB-22871"},
        {"allowed_methods": ["dispatch_repair"], "max_amount": 1000})


@case(p12.slug, "ordering", True, "DENY", "measurement_mismatch",
      "s4 step 4 before step 5b",
      "measurements.outcome_sha256 is the digest of a different outcome (core re-signed); "
      "credential issued by an unlisted issuer id and key (anchor-c)",
      ["bad_outcome_digest", "unlisted_issuer"],
      {"bad_outcome_digest": "measurement_mismatch", "unlisted_issuer": "issuer_not_listed"})
def m12(d):
    c = (cred(p12, issuer_sk=SK["rogue_issuer"], issuer_id=UNLISTED_ISSUER_ID)
         if "unlisted_issuer" in d else cred(p12))
    v = build(p12, credential=c)
    if "bad_outcome_digest" in d:
        alt = dict(p12.outcome, status="pending")
        v["measurements"]["outcome_sha256"] = digest(alt)
        resign(v)
    return out(v, p12.now, p12.decoys)


p13 = P("ord-malformed-mandate-over-binding", "principal:procurement-14",
        "agent:po-issuer-5", "issue_purchase_order",
        {"po_ref": "PO-33018", "amount": 8800, "currency": "EUR"},
        {"requisition_ref": "RQ-7702", "buyer_ref": "B-14"},
        {"status": "issued", "po_status_ref": "PS-1130"},
        {"allowed_methods": ["issue_purchase_order"], "max_amount": 9000})


@case(p13.slug, "ordering", True, "DENY", "malformed_mandate",
      "s4 step 5a before step 5e",
      "credential.body is a JSON array wrapping the credential body (core re-signed); the "
      "mandate is validly signed but names another agent id and key",
      ["cred_body_array", "other_agent"],
      {"cred_body_array": "malformed_mandate", "other_agent": "agent_binding_mismatch"})
def m13(d):
    c = cred(p13)
    if "cred_body_array" in d:
        c = {"body": [c["body"]], "sig": c["sig"]}
    mo = (mand(p13, agent_id="agent:po-issuer-50", agent_pub=PUB["other_agent"])
          if "other_agent" in d else mand(p13))
    v = build(p13, credential=c, mandate_obj=mo)
    return out(v, p13.now, p13.decoys)


p14 = P("ord-principal-sig-over-binding", "principal:marketing-10", "agent:ad-buyer-1",
        "buy_ad_slot", {"slot_ref": "AD-7781", "amount": 2200, "currency": "USD"},
        {"campaign_ref": "CP-W47", "region": "west"},
        {"status": "reserved", "reservation_ref": "RS-6620"},
        {"allowed_methods": ["buy_ad_slot"], "max_amount": 2500})


@case(p14.slug, "ordering", True, "DENY", "principal_sig_invalid",
      "s4 step 5d before step 5e",
      "mandate signed by a key other than the credential's principal key (principal ids "
      "equal); mandate agent_id differs from the package agent_id (agent_pub equal)",
      ["wrong_principal_key", "agent_id_differs"],
      {"wrong_principal_key": "principal_sig_invalid",
       "agent_id_differs": "agent_binding_mismatch"})
def m14(d):
    mo = mand(p14,
              principal_sk=SK["other_principal"] if "wrong_principal_key" in d else None,
              agent_id="agent:ad-buyer-11" if "agent_id_differs" in d else None)
    return out(build(p14, mandate_obj=mo), p14.now, p14.decoys)


p15 = P("ord-binding-over-scope", "principal:it-ops-19", "agent:patch-runner-6",
        "reboot_host", {"host_ref": "H-2207", "window": "W-14"},
        {"change_ref": "CHG-5108", "env": "staging"},
        {"status": "done", "run_ref": "RN-90311"},
        {"allowed_methods": ["apply_patch", "schedule_patch"]})


@case(p15.slug, "ordering", True, "DENY", "agent_binding_mismatch",
      "s4 step 5e before step 5f",
      "mandate validly signed but its agent_pub is another key (agent_id equal); method "
      "reboot_host is not in allowed_methods", ["other_agent_pub", "method_not_allowed"],
      {"other_agent_pub": "agent_binding_mismatch", "method_not_allowed": "scope_violation"})
def m15(d):
    a = p15.action() if "method_not_allowed" in d else p15.action(method="apply_patch")
    mo = mand(p15, agent_pub=PUB["other_agent"]) if "other_agent_pub" in d else mand(p15)
    return out(build(p15, action=a, mandate_obj=mo), p15.now, p15.decoys)


p16 = P("ord-scope-over-no-exp", "principal:catering-13", "agent:catering-orderer-4",
        "order_catering",
        {"event_ref": "EV-512", "amount": 1750, "currency": "EUR", "covers": 70},
        {"menu_ref": "MN-3", "dietary_ref": "DT-9"},
        {"status": "confirmed", "order_ref": "CT-4419"},
        {"allowed_methods": ["order_catering"], "max_amount": 1500})


@case(p16.slug, "ordering", True, "DENY", "scope_violation",
      "s4 step 5f before step 5g",
      "amount 1750 exceeds max_amount 1500; mandate body carries no exp (validly signed)",
      ["over_cap", "no_exp"], {"over_cap": "scope_violation", "no_exp": "expired"})
def m16(d):
    a = p16.action()
    if "over_cap" not in d:
        a["args"]["amount"] = 1450
    mo = mand(p16, omit_exp="no_exp" in d)
    return out(build(p16, action=a, mandate_obj=mo), p16.now, p16.decoys)


p17 = P("ord-expired-over-replayed", "principal:payroll-16", "agent:payroll-runner-2",
        "run_payroll_batch", {"batch_ref": "PB-2026-46", "amount": 41000, "currency": "EUR"},
        {"period": "2026-11", "entity_ref": "EN-2"},
        {"status": "submitted", "batch_status_ref": "BS-7730"},
        {"allowed_methods": ["run_payroll_batch"], "max_amount": 45000})


@case(p17.slug, "ordering", True, "DENY", "expired",
      "s4 step 5g before step 6",
      "now is one day after exp; the nonce string is in the consumed set",
      ["expired", "consumed"], {"expired": "expired", "consumed": "replayed"})
def m17(d):
    now = p17.exp + 86_400 if "expired" in d else p17.now
    cons = list(p17.decoys) + ([p17.nonce] if "consumed" in d else [])
    return out(build(p17), now, cons)


p18 = P("ord-credential-sig-over-principal", "principal:legal-17", "agent:filing-clerk-3",
        "file_document",
        {"matter_ref": "M-2209", "amount": 150, "currency": "EUR", "court_ref": "CT-9"},
        {"deadline_ref": "DL-1130", "doc_type": "notice"},
        {"status": "filed", "filing_ref": "FI-55028"},
        {"allowed_methods": ["file_document"], "max_amount": 500})


@case(p18.slug, "ordering", True, "DENY", "credential_sig_invalid",
      "s4 step 5c before step 5d",
      "last byte of credential.sig altered; mandate principal_id differs from the "
      "credential principal_id (mandate validly signed by the principal key)",
      ["cred_sig_flip", "principal_id_differs"],
      {"cred_sig_flip": "credential_sig_invalid", "principal_id_differs": "principal_sig_invalid"})
def m18(d):
    c = cred(p18)
    if "cred_sig_flip" in d:
        s = c["sig"]
        c["sig"] = s[:-2] + format(int(s[-2:], 16) ^ 0x01, "02x")
    mo = mand(p18, principal_id="principal:legal-71") if "principal_id_differs" in d \
        else mand(p18)
    return out(build(p18, credential=c, mandate_obj=mo), p18.now, p18.decoys)


# ---- PROBES (unscored) ---------------------------------------------------- #
p19 = P("probe-duplicate-nonce-member", "principal:archive-18", "agent:records-keeper-9",
        "archive_records", {"box_ref": "BX-4410", "count": 36},
        {"retention_ref": "RT-7Y", "site": "vault-2"},
        {"status": "archived", "archive_ref": "AR-30081"},
        {"allowed_methods": ["archive_records"]})


@case(p19.slug, "probe", False, None, None,
      "s1 (a JSON object) and s2: the specification does not say how a duplicate member "
      "name is treated",
      "raw text carries the top-level nonce member twice: first a consumed decoy, then the "
      "signed value. Last-wins parsers: ALLOW; first-wins: content_mutated (hash over the "
      "decoy); a parser that rejects duplicates may say malformed_aep")
def m19(d):
    v = build(p19)
    decoy = "n-" + h("dupdecoy", p19.slug)[:20]
    raw = _dumps(v).replace(f'"nonce": "{p19.nonce}"',
                            f'"nonce": "{decoy}",\n  "nonce": "{p19.nonce}"', 1)
    assert raw.count('"nonce"') == 2
    return out(v, p19.now, [decoy], raw=raw)


p20 = P("probe-int-plus-minus-2p53-minus-1", "principal:ledger-20", "agent:ledger-sync-1",
        "post_ledger_entry",
        {"entry_seq": 9007199254740991, "amount": 5000, "currency": "EUR"},
        {"offset": -9007199254740991, "source": "sync"},
        {"status": "posted", "entry_ref": "LE-90071"},
        {"allowed_methods": ["post_ledger_entry"], "max_amount": 9000})


@case(p20.slug, "probe", False, "ALLOW", None,
      "s2 Numbers ('integers within +-(2^53-1)', read as inclusive)",
      "signed payload carries 9007199254740991 and -9007199254740991; inside the profile if "
      "'within' is inclusive; both references and the spec reading give ALLOW")
def m20(d):
    return out(build(p20), p20.now, p20.decoys)


p21 = P("probe-nonascii-key-order", "principal:intl-desk-22", "agent:translator-4",
        "send_notice", {"recipient_ref": "C-30418", "template": "welcome-intl"},
        {"channel": "portal", "Ｔａｇ": "priorité",
         "\U0001F4CE": "attachment-2"},
        {"status": "queued", "message_ref": "MS-41190"},
        {"allowed_methods": ["send_notice"]})


@case(p21.slug, "probe", False, None, None,
      "s2 ('object keys sorted': the sort order is not defined)",
      "action.context member names U+FF34.. (fullwidth 'Tag') and U+1F4CE: code point / "
      "UTF-8 byte order puts U+FF34 first (Python signer); UTF-16 code unit order (JS sort) "
      "puts the emoji first -> different canonical bytes -> JS content_mutated")
def m21(d):
    return out(build(p21), p21.now, p21.decoys)


p22 = P("probe-float-100-point-0", "principal:fx-desk-23", "agent:fx-converter-7",
        "convert_currency", {"amount": 100.0, "from": "EUR", "to": "USD"},
        {"quote_ref": "QT-55011", "desk": "spot"},
        {"status": "converted", "conversion_ref": "CV-1907"},
        {"allowed_methods": ["convert_currency"], "max_amount": 250})


@case(p22.slug, "probe", False, None, None,
      "s2 Numbers (non-integer number: outside the profile under a lexical reading; the "
      "spec does not define the verdict)",
      "args.amount written as 100.0; Python signs over '100.0', JS re-serialises 100 -> "
      "content_mutated in JS, ALLOW in Python")
def m22(d):
    return out(build(p22), p22.now, p22.decoys)


# --------------------------------------------------------------------------- #
def _dumps(aep: dict) -> str:
    return json.dumps(aep, ensure_ascii=False, indent=2) + "\n"


def appraise(aep, now, consumed):
    try:
        r = package.verify_aep(aep, TRUST_STORE, now=now, consumed=set(consumed))
    except Exception:  # noqa: BLE001  (mirror verify.py's guard)
        return ("DENY", "malformed_aep")
    return (r["verdict"], r["reason"])


def self_check(c) -> dict:
    res = {}
    if c["klass"] == "probe":
        return {"skipped": "probe"}
    full = c["make"](set(c["defects"]))
    res["full"] = appraise(full["aep"], full["now"], full["consumed"])
    clean = c["make"](set())
    res["clean"] = appraise(clean["aep"], clean["now"], clean["consumed"])
    for dname in c["defects"]:
        one = c["make"]({dname})
        res[f"only:{dname}"] = appraise(one["aep"], one["now"], one["consumed"])
    ok = True
    if c["defects"]:
        ok &= res["clean"] == ("ALLOW", None)
        for dname in c["defects"]:
            ok &= res[f"only:{dname}"] == ("DENY", c["reasons"][dname])
    ok &= res["full"] == (c["verdict"], c["reason"])
    res["ok"] = bool(ok)
    return res


def main() -> int:
    vec_dir = os.path.join(ARGS.public_out, "vectors")
    os.makedirs(vec_dir, exist_ok=True)
    os.makedirs(ARGS.sealed_out, exist_ok=True)
    slugs = [c["slug"] for c in CASES]
    assert len(set(slugs)) == len(slugs)
    order = sorted(CASES, key=lambda c: h("order", c["slug"]))
    cases_pub, design = [], []
    failures = 0
    for i, c in enumerate(order, start=1):
        fname = f"r1-{i:02d}.aep.json"
        o = c["make"](set(c["defects"]))
        text = o["raw"] if o["raw"] is not None else _dumps(o["aep"])
        with open(os.path.join(vec_dir, fname), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        cases_pub.append({"file": fname, "now": o["now"], "consumed": o["consumed"]})
        sc = self_check(c)
        if sc.get("ok") is False:
            failures += 1
        design.append({
            "file": fname, "slug": c["slug"], "class": c["klass"], "scored_intent": c["scored"],
            "spec_verdict": c["verdict"] if c["klass"] != "probe" or c["verdict"] else
            "UNDEFINED",
            "spec_reason": c["reason"], "spec_clause": c["clause"], "design_note": c["note"],
            "defects": c["defects"], "defect_reasons": c["reasons"], "self_check": sc,
            "now": o["now"], "consumed": o["consumed"],
        })
    cases_pub.sort(key=lambda r: r["file"])
    design.sort(key=lambda r: r["file"])
    with open(os.path.join(vec_dir, "cases.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(cases_pub, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    with open(os.path.join(ARGS.public_out, "trusted_issuers.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(TRUST, fh, indent=2)
        fh.write("\n")
    with open(os.path.join(ARGS.sealed_out, "design.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(design, fh, ensure_ascii=False, indent=2,
                  default=lambda x: list(x) if isinstance(x, tuple) else str(x))
        fh.write("\n")
    print(f"[round1] wrote {len(design)} vectors to {vec_dir}")
    for r in design:
        sc = r["self_check"]
        flag = "probe" if "skipped" in sc else ("OK" if sc["ok"] else "SELF-CHECK FAILED")
        print(f"  {r['file']}  {r['class']:<9} {flag:<18} {r['slug']}")
    if failures:
        print(f"[round1] {failures} self-check failure(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
