#!/usr/bin/env node
// run_port.mjs — appraise every Round-0 vector with the JS PORT verifier.
//
// Same call path as the browser CTF: verifyAep(aep, trust, now, consumedSet) from the
// shipped public/lab/aep-ctf/verify.mjs. Per-case now/consumed come from vectors/cases.json.
//
// Writes verdicts-js.json: {file, now, consumed, verdict, reason, canonical_core}, where
// canonical_core is THIS implementation's canonical serialisation of the receipt core (the
// exact bytes it hashes/verifies over), so compare.py can pinpoint any divergence.
//
//   node interlab/round0/run_port.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
// The JS verifier under test is the shipped CTF port — imported unmodified.
const VERIFY_MJS =
  "/srv/tyche/repos/tyche-institute-site/public/lab/aep-ctf/verify.mjs";
const { verifyAep, canonical } = await import(VERIFY_MJS);

const VEC = join(HERE, "vectors");
const TRUST_PATH = join(HERE, "trusted_issuers.json");
const OUT = join(HERE, "verdicts-js.json");

const trust = JSON.parse(readFileSync(TRUST_PATH, "utf8"));
const cases = JSON.parse(readFileSync(join(VEC, "cases.json"), "utf8"));

// Mirror the Python receipt-core (drop the two output fields), so we can serialise the exact
// bytes this port hashes over. verify.mjs keeps receiptCore private, so reconstruct it.
const NONCORE = new Set(["aep_sig", "receipt_hash"]);
function receiptCore(aep) {
  const core = {};
  for (const k of Object.keys(aep)) if (!NONCORE.has(k)) core[k] = aep[k];
  return core;
}
function canonicalCore(aep) {
  try {
    return canonical(receiptCore(aep));
  } catch {
    return null;
  }
}

const results = [];
for (const c of cases) {
  const aep = JSON.parse(readFileSync(join(VEC, c.file), "utf8"));
  const consumed = new Set(c.consumed);
  let res;
  try {
    res = await verifyAep(aep, trust, c.now, consumed);
  } catch {
    // Fail closed the same way verify.py's CLI guard does.
    res = { verdict: "DENY", reason: "malformed_aep" };
  }
  results.push({
    file: c.file,
    now: c.now,
    consumed: [...consumed].sort(),
    verdict: res.verdict,
    reason: res.reason ?? null,
    canonical_core: canonicalCore(aep),
  });
  const tag = res.verdict + (res.reason ? ":" + res.reason : "");
  console.log(`  ${c.file.padEnd(42)} -> ${tag}`);
}

writeFileSync(OUT, JSON.stringify(results, null, 2) + "\n");
console.log(`[run_port] wrote ${OUT} (${results.length} verdicts)`);
