# Make your own 2 records, and we check them

This is the reverse direction. You produce the 2 records for the same payload with your own code and your own test key. You can check them yourself with our verifier, using the 2 commands at the end of this page. If you also send a cell-1 return from your own verifier, send that return first. If you send them to us, we run the same check and add the result to the comparison. Its label follows `../README.md`, section "Labels".

## What to produce

Start from `payload/payload.json`. Do not change the payload.

1. **JSON side.** Apply RFC 8785 (JCS). Your bytes must equal `payload/payload.jcs`. Take SHA-256 of them (call it D1).
2. **CBOR side.** Map the JSON value to CBOR as `declaration.json` says (object to map with text keys, string to text string, integer to major type 0 or 1). Encode under RFC 8949 Section 4.2.1. Your bytes must equal `payload/payload.cbor`. Take SHA-256 (D2).
3. **Generate a fresh Ed25519 test key.** Use it for this test and nothing else.
4. **Sign 2 tagged COSE_Sign1 records** (RFC 9052, tag 18, Sig_structure with context `"Signature1"` and empty external_aad, unprotected header `{}`, payload attached).

JSON-side protected header (CPB -06 Hash Envelope Mode plus `cpb-refs`):

```
{ 1: -8,                         / alg: EdDSA /
  2: [-65537],                   / crit: cpb-refs /
  4: h'<your kid>',
  15: { 1: "https://issuer.example",
        2: "urn:air:example.org:agent:refund-assistant" },
  258: -16,                      / payload-hash-alg: SHA-256 /
  259: "application/json",       / preimage-content-type /
  -65537: [ { 1: "example-action-record",
              3: "SHA-256",
              4: "<D1 as 64 lowercase hex characters>" } ] }
payload = D1 (32 bytes)
```

CBOR-side protected header (CDE -00):

```
{ 1: -8,
  4: h'<your kid>',
  15: { 1: "https://issuer.example",
        2: "urn:air:example.org:agent:refund-assistant" },
  258: -16,
  259: "application/cbor",
  271: 1 }                       / deterministic-encodings: core-deterministic /
payload = D2 (32 bytes)
```

Label 271 is the value CDE -00 suggests, not an assigned value. Label -65537 is a test-only private-use label. Do not list 271 in `crit` (CDE -00 says a producer MUST NOT).

You may encode the protected header in any valid CBOR serialization. We encode ours in core deterministic encoding, which gives the same bytes for everyone.

## What to send

- `json-side.cose` and `cbor-side.cose`;
- your test public key (PEM, or 32 bytes in hex);
- who wrote your implementation, so that we can set the label, and whether we may name it when we publish results. The default is no: results appear under codes.

Send them to the address on tyche.institute, or point to them from the AEP entry on the IETF 127 Hackathon wiki.

## How we check them

```sh
python3 tools/verify_cell1.py --record json-side.cose --held payload/payload.json --pubkey your-key.pub.pem --id yours-json --out yours-json.json
python3 tools/verify_cell1.py --record cbor-side.cose --held payload/payload.json --pubkey your-key.pub.pem --id yours-cbor --out yours-cbor.json
```

You can run the same 2 commands yourself before you send. To see our own records made the same way, run `python3 tools/sign_cell1.py` (`--help` shows the options). A match with our checker is a check by the author of these vectors. It is not a check by a non-author.
