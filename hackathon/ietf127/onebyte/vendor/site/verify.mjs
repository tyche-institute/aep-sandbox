// verify.mjs — a faithful browser/Node port of the aep-sandbox reference verifier
// (github.com/tyche-institute/aep-sandbox, aep/package.py + aep/mandate.py + aep/canonical.py).
//
// It reproduces the SAME ordered checks and the SAME verdict reason strings as
// `python3 verify.py`, and is parity-tested against the Python verifier on every shipped
// sample and attack (see parity-test.mjs). Signatures are checked for real with Ed25519
// (WebCrypto); hashes with SHA-256; the message is the same canonical JSON the Python signer
// used. The private trust-anchor keys are NOT here — forging a wrongful ALLOW without them is
// the whole game.

const te = new TextEncoder();

// ---- canonical JSON: json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False) ----
export function canonical(obj) {
  if (obj === null) return "null";
  const t = typeof obj;
  if (t === "boolean") return obj ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(obj)) throw new Error("non-finite number");
    // Integers serialise identically to Python; the shipped signed data is all-integer.
    return Number.isInteger(obj) ? String(obj) : String(obj);
  }
  if (t === "string") return JSON.stringify(obj); // control/quote/backslash escaping matches
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
}
function canonicalBytes(obj) {
  return te.encode(canonical(obj));
}

// ---- hashing ----
function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(bytes) {
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}
export async function digest(obj) {
  return sha256Hex(canonicalBytes(obj));
}

// ---- Ed25519 verify (raw 32-byte pub hex, 64-byte sig hex, canonical(payload) message) ----
function hexToBytes(h) {
  if (typeof h !== "string" || h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
export async function ed25519Verify(pubHex, payload, sigHex) {
  try {
    const pub = hexToBytes(pubHex);
    const sig = hexToBytes(sigHex);
    if (!pub || pub.length !== 32 || !sig || sig.length !== 64) return false;
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, canonicalBytes(payload));
  } catch {
    return false;
  }
}
export function ed25519Available() {
  return !!(globalThis.crypto && crypto.subtle && crypto.subtle.importKey);
}

// ---- helpers mirroring the Python ----
const NONCORE = new Set(["aep_sig", "receipt_hash"]);
function receiptCore(aep) {
  const core = {};
  for (const k of Object.keys(aep)) if (!NONCORE.has(k)) core[k] = aep[k];
  return core;
}
function isDict(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function scopeOk(action, scope) {
  const methods = scope ? scope.allowed_methods : undefined;
  if (methods != null && !methods.includes(action ? action.method : undefined)) return false;
  const cap = scope ? scope.max_amount : undefined;
  if (cap != null) {
    const args = action ? action.args : undefined;
    if (args != null && !isDict(args)) return false;
    const amount = isDict(args) ? args.amount : null;
    if (amount != null) {
      if (typeof amount === "boolean" || typeof amount !== "number") return false;
      if (amount > cap) return false;
    }
  }
  return true;
}

async function checkMandate(trust, credential, mandate, action, agentPub, agentId, now) {
  const cb = isDict(credential) ? credential.body || {} : {};
  const mb = isDict(mandate) ? mandate.body || {} : {};
  if (!isDict(cb) || !isDict(mb)) return "malformed_mandate";
  if (trust.issuers[cb.issuer_id] !== cb.issuer_pub) return "issuer_not_listed";
  if (!(await ed25519Verify(cb.issuer_pub || "", cb, credential.sig || ""))) return "credential_sig_invalid";
  if (cb.principal_id !== mb.principal_id || !(await ed25519Verify(cb.principal_pub || "", mb, mandate.sig || "")))
    return "principal_sig_invalid";
  if (mb.agent_pub !== agentPub || mb.agent_id !== agentId) return "agent_binding_mismatch";
  if (!scopeOk(action, mb.scope || {})) return "scope_violation";
  if (now > (mb.exp ?? 0)) return "expired";
  return null;
}

// ---- the full ordered verification (mirrors package.verify_aep) ----
export async function verifyAep(aep, trust, now, consumed) {
  const checks = [];
  const fail = (name, reason) => {
    checks.push({ name, ok: false });
    return { verdict: "DENY", reason, checks };
  };
  const pass = (name) => checks.push({ name, ok: true });

  if (!isDict(aep)) return fail("structure", "malformed_aep");
  const required = ["agent_pub", "action", "credential", "mandate", "nonce", "aep_sig", "receipt_hash"];
  if (!required.every((k) => k in aep)) return fail("structure", "malformed_aep");
  if (!["action", "credential", "mandate"].every((k) => isDict(aep[k]))) return fail("structure", "malformed_aep");
  if (!("measurements" in aep ? isDict(aep.measurements) : true)) return fail("structure", "malformed_aep");
  pass("structure");

  if (aep.receipt_hash !== (await digest(receiptCore(aep)))) return fail("chain_integrity", "content_mutated");
  pass("chain_integrity");

  if (!(await ed25519Verify(aep.agent_pub, receiptCore(aep), aep.aep_sig)))
    return fail("aep_signature", "aep_sig_invalid");
  pass("aep_signature");

  const m = isDict(aep.measurements) ? aep.measurements : {};
  if (m.action_sha256 !== (await digest(aep.action)) || m.outcome_sha256 !== (await digest(aep.outcome ?? {})))
    return fail("measurements", "measurement_mismatch");
  pass("measurements");

  const reason = await checkMandate(trust, aep.credential, aep.mandate, aep.action, aep.agent_pub, aep.agent_id, now);
  if (reason !== null) return fail("mandate", reason);
  pass("mandate");

  if (consumed && consumed.has(aep.nonce)) return fail("replay", "replayed");
  pass("replay");

  return { verdict: "ALLOW", reason: null, checks };
}
