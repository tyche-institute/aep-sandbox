// onebyte.mjs - the JavaScript half of onebyte.py. Node 20 or later.
//
//   node onebyte.mjs VERIFY_MJS TRUST_JSON PACKAGE_JSON NOW
//
// Prints one JSON object: the verdict of the JavaScript sandbox port (verify.mjs, unmodified),
// the canonical bytes that port computes for the receipt core, and what RFC 8785 (JSON
// Canonicalization Scheme) gives for the same receipt core in Node.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const [verifyPath, trustPath, pkgPath, nowArg] = process.argv.slice(2);
const { verifyAep, canonical } = await import(pathToFileURL(resolve(verifyPath)).href);
const trust = JSON.parse(readFileSync(trustPath, "utf8"));
const aep = JSON.parse(readFileSync(pkgPath, "utf8"));

// Receipt core: the package without aep_sig and receipt_hash (VERIFIER-SPEC-v1 section 3).
// verify.mjs keeps its own copy private, so we rebuild it the same way.
function receiptCore(p) {
  const core = {};
  for (const k of Object.keys(p)) if (k !== "aep_sig" && k !== "receipt_hash") core[k] = p[k];
  return core;
}

// RFC 8785: strings and numbers as ECMAScript JSON.stringify renders them (section 3.2.2),
// object members sorted by UTF-16 code units (section 3.2.3), no whitespace.
function jcs(v) {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number" && !Number.isFinite(v)) throw new Error("non-finite number");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const keys = Object.keys(v).sort(); // default sort compares UTF-16 code units
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
}

let res;
try {
  res = await verifyAep(aep, trust, Number(nowArg), new Set());
} catch (e) {
  res = { verdict: "DENY", reason: "malformed_aep", checks: [], error: String(e) };
}
const amount = aep?.action?.args?.amount;
console.log(JSON.stringify({
  node: process.version,
  verdict: res.verdict,
  reason: res.reason ?? null,
  checks: res.checks,
  canonical_core: canonical(receiptCore(aep)),
  rfc8785_core: jcs(receiptCore(aep)),
  amount_sandbox: canonical(amount),
  amount_rfc8785: jcs(amount),
}));
