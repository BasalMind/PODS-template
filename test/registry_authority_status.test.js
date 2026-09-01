// registry_authority_status.js -- unlike pod-root.test.js/policy.test.js,
// this module is NOT yet wired into any PodRoot route (deliberate --
// see the module's own doc comment on why request-path wiring is left
// as future work), so there is no real Durable Object HTTP surface to
// exercise it through. Tested here as a standalone JS module instead,
// with a minimal in-memory fake standing in for `this.sql` -- the fake
// implements exactly the two query shapes this module issues (a
// single-table upsert and a single-row select by primary key), so it
// stays honest about what it's replicating rather than a black box.
//
// Signature tests use a LOCALLY GENERATED Ed25519 test keypair (via
// @noble/ed25519 itself), passed explicitly as verifyAndParseDocument's
// optional publicKeyMultikey override -- never the real hardcoded
// REGISTRY_AUTHORITY_PUBLIC_KEY_MULTIKEY, since this suite has no access
// to BasalMind's actual KMS private key (nor should it). Multikey
// round-trip against the REAL registered public key IS tested (decode
// only, no signing) to confirm the constant baked into this file matches
// what Forge migration 0063 actually registered.

import { describe, it, expect, beforeEach } from "vitest";
import * as ed from "@noble/ed25519";
import {
  verifyAndParseDocument,
  getStanding,
  getCachedStatus,
  setupStatusCacheTable,
  isBlocked,
  deriveBanScope,
  SCOPE_READ_OWN,
  SCOPE_WRITE_OWN,
  SCOPE_READ_OTHERS,
  SCOPE_WRITE_OTHERS,
  _decodeAuthorityPublicKey,
  InvalidStatusSignature,
  InvalidStatusDocument,
} from "../src/registry_authority_status.js";

function base64UrlEncode(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Same base58btc + multicodec-0xed01 convention the real module uses,
// reimplemented independently here (not imported) so a bug in the
// module's own encoder/decoder can't hide itself from these tests.
const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btcEncode(bytes) {
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = "";
  while (num > 0n) {
    out = BASE58BTC_ALPHABET[Number(num % 58n)] + out;
    num /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}
function encodeEd25519Multikey(rawPubKey) {
  const prefixed = new Uint8Array(2 + rawPubKey.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(rawPubKey, 2);
  return "z" + base58btcEncode(prefixed);
}

async function makeSignedDocument(privKey, doc) {
  const payloadBytes = new TextEncoder().encode(JSON.stringify(doc));
  const signature = await ed.signAsync(payloadBytes, privKey);
  return { payload: base64UrlEncode(payloadBytes), signature: base64UrlEncode(signature) };
}

// Minimal in-memory fake for `this.sql(query, ...bindings)` -- implements
// only the two query shapes registry_authority_status.js issues.
function makeFakeSql() {
  const rows = new Map(); // pod_did -> row object
  return function sql(query, ...bindings) {
    if (query.includes("CREATE TABLE")) {
      return [];
    }
    if (query.includes("INSERT INTO registry_authority_status_cache")) {
      const [pod_did, verdict, restricted_scopes, revoked, issued_at, expires_at, authority_key_id, cached_at] = bindings;
      rows.set(pod_did, { pod_did, verdict, restricted_scopes, revoked, issued_at, expires_at, authority_key_id, cached_at });
      return [];
    }
    if (query.includes("SELECT * FROM registry_authority_status_cache")) {
      const [pod_did] = bindings;
      const row = rows.get(pod_did);
      return row ? [row] : [];
    }
    throw new Error(`fake sql: unexpected query: ${query}`);
  };
}

describe("multikey decode against the REAL registered public key", () => {
  it("REGISTRY_AUTHORITY_PUBLIC_KEY_MULTIKEY decodes to a 32-byte Ed25519 key", () => {
    const raw = _decodeAuthorityPublicKey();
    expect(raw.length).toBe(32);
  });

  it("decodes to the EXACT known-answer bytes from the live KMS spike (Forge migration 0063) -- bounded Fable review, 2026-09-01, finding 4: a length check alone lets a wrong-but-32-byte constant pass silently", () => {
    // base64 of the raw public key bytes returned live by GCP KMS
    // GetPublicKey during the spike this multikey constant was derived
    // from -- see Forge migration 0063's own header comment.
    const expectedB64 = "S8rG52fsOwFZi0kbbs5i9elLMsM/4pKh4l8VGtaIwr4=";
    const expectedBytes = Uint8Array.from(atob(expectedB64), (c) => c.charCodeAt(0));
    const raw = _decodeAuthorityPublicKey();
    expect(Array.from(raw)).toEqual(Array.from(expectedBytes));
  });
});

describe("verifyAndParseDocument", () => {
  let privKey, pubKeyMultikey;

  beforeEach(async () => {
    privKey = ed.utils.randomSecretKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);
    pubKeyMultikey = encodeEd25519Multikey(pubKey);
  });

  it("accepts a genuinely valid signature and returns the parsed document", async () => {
    const doc = { pod_did: "did:webvh:pod:example.com", verdict: "active", revoked: false };
    const signed = await makeSignedDocument(privKey, doc);

    const parsed = await verifyAndParseDocument(signed.payload, signed.signature, pubKeyMultikey);

    expect(parsed).toEqual(doc);
  });

  it("rejects a tampered payload (signature no longer matches)", async () => {
    const doc = { pod_did: "did:webvh:pod:example.com", verdict: "active" };
    const signed = await makeSignedDocument(privKey, doc);
    const tamperedDoc = { pod_did: "did:webvh:pod:example.com", verdict: "banned" };
    const tamperedPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(tamperedDoc)));

    await expect(verifyAndParseDocument(tamperedPayload, signed.signature, pubKeyMultikey))
      .rejects.toThrow(InvalidStatusSignature);
  });

  it("rejects a signature verified against the WRONG public key", async () => {
    const doc = { pod_did: "did:webvh:pod:example.com", verdict: "active" };
    const signed = await makeSignedDocument(privKey, doc);
    const otherPrivKey = ed.utils.randomSecretKey();
    const otherPubKey = await ed.getPublicKeyAsync(otherPrivKey);
    const wrongMultikey = encodeEd25519Multikey(otherPubKey);

    await expect(verifyAndParseDocument(signed.payload, signed.signature, wrongMultikey))
      .rejects.toThrow(InvalidStatusSignature);
  });

  it("rejects malformed base64url input instead of crashing uncaught", async () => {
    await expect(verifyAndParseDocument("not-valid-base64!!!", "also-not-valid!!!", pubKeyMultikey))
      .rejects.toThrow(InvalidStatusSignature);
  });
});

describe("getStanding -- caching and fail-open/fail-closed", () => {
  let privKey, pubKeyMultikeyOverride;

  beforeEach(async () => {
    privKey = ed.utils.randomSecretKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);
    pubKeyMultikeyOverride = encodeEd25519Multikey(pubKey);
  });

  // getStanding() always verifies against the module's real hardcoded
  // key, not a per-call override -- so these tests monkeypatch fetchImpl
  // to return documents signed by the REAL key's... which this suite
  // doesn't have. Instead, these tests exercise getStanding()'s CACHING
  // and FAIL-OPEN/CLOSED branching using pre-seeded cache rows (bypassing
  // verifyAndParseDocument entirely for that part) plus a fetchImpl that
  // simulates network failure -- the signature-verification path itself
  // is already fully covered above.

  function futureIso(seconds) {
    return new Date(Date.now() + seconds * 1000).toISOString();
  }
  function pastIso(seconds) {
    return new Date(Date.now() - seconds * 1000).toISOString();
  }

  it("requires context to be 'new' or 'continuing'", async () => {
    const sql = makeFakeSql();
    await expect(getStanding(sql, "did:webvh:pod:example.com", { context: "bogus" }))
      .rejects.toThrow(/context/);
  });

  it("returns a fresh cache entry without calling fetch", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    sql(
      `INSERT INTO registry_authority_status_cache (pod_did, verdict, restricted_scopes, revoked, issued_at, expires_at, authority_key_id, cached_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      "did:webvh:pod:example.com", "active", "[]", 0, pastIso(10), futureIso(300), "gcp-kms-registry-authority-v1", pastIso(10),
    );
    let fetchCalled = false;
    const fetchImpl = async () => { fetchCalled = true; };

    const result = await getStanding(sql, "did:webvh:pod:example.com", { fetchImpl, context: "new" });

    expect(result.source).toBe("cache");
    expect(result.verdict).toBe("active");
    expect(fetchCalled).toBe(false);
  });

  it("context='new' fails CLOSED (unreachable verdict) when fetch fails and there is no cache", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    const fetchImpl = async () => { throw new Error("network down"); };

    const result = await getStanding(sql, "did:webvh:pod:example.com", { fetchImpl, context: "new" });

    expect(result.source).toBe("unreachable-fail-closed");
    expect(result.verdict).toBe("unreachable");
    expect(isBlocked(result, SCOPE_READ_OTHERS)).toBe(true);
  });

  it("context='continuing' fails OPEN (stale cache) when fetch fails but a prior cache entry exists", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    sql(
      `INSERT INTO registry_authority_status_cache (pod_did, verdict, restricted_scopes, revoked, issued_at, expires_at, authority_key_id, cached_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      "did:webvh:pod:example.com", "active", "[]", 0, pastIso(600), pastIso(300), "gcp-kms-registry-authority-v1", pastIso(600),
    );
    const fetchImpl = async () => { throw new Error("network down"); };

    const result = await getStanding(sql, "did:webvh:pod:example.com", { fetchImpl, context: "continuing" });

    expect(result.source).toBe("stale-cache-fail-open");
    expect(result.verdict).toBe("active");
    expect(isBlocked(result, SCOPE_READ_OTHERS)).toBe(false);
  });

  it("context='continuing' still fails CLOSED when fetch fails AND there is no prior cache at all", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    const fetchImpl = async () => { throw new Error("network down"); };

    const result = await getStanding(sql, "did:webvh:pod:example.com", { fetchImpl, context: "continuing" });

    expect(result.source).toBe("unreachable-fail-closed");
  });

  it("a successful, verified fetch caches and returns the fresh document (publicKeyMultikey override, same pattern verifyAndParseDocument already exposes)", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    const doc = {
      protocol_version: "poc-v0", scope: "person", pod_did: "did:webvh:pod:example.com",
      verdict: "active", restricted_scopes: [SCOPE_WRITE_OTHERS], revoked: false,
      issued_at: pastIso(1), expires_at: futureIso(300), authority_key_id: "test-key",
    };
    const signed = await makeSignedDocument(privKey, doc);
    const fetchImpl = async () => ({ ok: true, json: async () => signed });

    const result = await getStanding(sql, "did:webvh:pod:example.com", {
      fetchImpl, context: "new", publicKeyMultikey: pubKeyMultikeyOverride,
    });

    expect(result.source).toBe("network");
    expect(result.verdict).toBe("active");
    expect(result.restricted_scopes).toEqual([SCOPE_WRITE_OTHERS]);
    // Round-trips correctly through the cache's JSON-encoded column too.
    expect(getCachedStatus(sql, "did:webvh:pod:example.com")).toMatchObject({
      verdict: "active", restricted_scopes: [SCOPE_WRITE_OTHERS],
    });
  });

  it("a document signed by an UNTRUSTED key is never cached or returned as valid, even via the network branch", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    const doc = { pod_did: "did:webvh:pod:example.com", verdict: "active" };
    const signed = await makeSignedDocument(privKey, doc); // signed with a DIFFERENT key than the module trusts
    const fetchImpl = async () => ({ ok: true, json: async () => signed });

    const result = await getStanding(sql, "did:webvh:pod:example.com", {
      fetchImpl, context: "new",
      // No publicKeyMultikey override here -- exercises the REAL hardcoded
      // module key, which this document was NOT signed with.
    });

    expect(result.source).toBe("unreachable-fail-closed");
    expect(getCachedStatus(sql, "did:webvh:pod:example.com")).toBeNull();
  });

  it("a verified document whose pod_did does not match the requested pod_did is rejected, not silently accepted", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    const doc = { pod_did: "did:webvh:SOMEONE-ELSE:example.com", verdict: "active" };
    const signed = await makeSignedDocument(privKey, doc);
    const fetchImpl = async () => ({ ok: true, json: async () => signed });

    const result = await getStanding(sql, "did:webvh:pod:example.com", {
      fetchImpl, context: "new", publicKeyMultikey: pubKeyMultikeyOverride,
    });

    expect(result.source).toBe("unreachable-fail-closed");
    expect(getCachedStatus(sql, "did:webvh:pod:example.com")).toBeNull();
  });

  it("a validly-SIGNED but already-EXPIRED document is rejected, never cached as a fresh network result -- bounded Fable review, 2026-09-01, finding 1: a valid signature proves authenticity, not currency", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    const doc = { pod_did: "did:webvh:pod:example.com", verdict: "active", expires_at: pastIso(60) };
    const signed = await makeSignedDocument(privKey, doc);
    const fetchImpl = async () => ({ ok: true, json: async () => signed });

    const result = await getStanding(sql, "did:webvh:pod:example.com", {
      fetchImpl, context: "new", publicKeyMultikey: pubKeyMultikeyOverride,
    });

    expect(result.source).toBe("unreachable-fail-closed");
    expect(getCachedStatus(sql, "did:webvh:pod:example.com")).toBeNull();
  });

  it("a cached row with an unparseable expires_at is treated as EXPIRED, not fresh forever -- bounded Fable review, 2026-09-01, finding 2: Date.now() >= NaN is false, the wrong fail direction", async () => {
    const sql = makeFakeSql();
    setupStatusCacheTable(sql);
    sql(
      `INSERT INTO registry_authority_status_cache (pod_did, verdict, restricted_scopes, revoked, issued_at, expires_at, authority_key_id, cached_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      "did:webvh:pod:example.com", "active", "[]", 0, pastIso(10), "not-a-real-timestamp", "test-key", pastIso(10),
    );
    let fetchCalled = false;
    const fetchImpl = async () => { fetchCalled = true; throw new Error("network down"); };

    const result = await getStanding(sql, "did:webvh:pod:example.com", { fetchImpl, context: "new" });

    // Malformed expiry must NOT be treated as "still fresh" -- a refetch
    // attempt (which then fails closed here, since context="new") proves
    // the cache entry was correctly judged expired, not silently reused.
    expect(fetchCalled).toBe(true);
    expect(result.source).toBe("unreachable-fail-closed");
  });
});

describe("isBlocked", () => {
  it("'unbound' (no BasalMind record at all) blocks NOTHING -- neutral absence of signal, not a ban", () => {
    const standing = { verdict: "unbound", restricted_scopes: [] };
    expect(isBlocked(standing, SCOPE_READ_OWN)).toBe(false);
    expect(isBlocked(standing, SCOPE_WRITE_OWN)).toBe(false);
    expect(isBlocked(standing, SCOPE_READ_OTHERS)).toBe(false);
    expect(isBlocked(standing, SCOPE_WRITE_OTHERS)).toBe(false);
  });

  it("'unreachable' fails CLOSED for others-scopes (the real security boundary) but OPEN for own-scopes (a BasalMind outage must never lock an owner out of their own pod)", () => {
    const standing = { verdict: "unreachable", restricted_scopes: [] };
    expect(isBlocked(standing, SCOPE_READ_OTHERS)).toBe(true);
    expect(isBlocked(standing, SCOPE_WRITE_OTHERS)).toBe(true);
    expect(isBlocked(standing, SCOPE_READ_OWN)).toBe(false);
    expect(isBlocked(standing, SCOPE_WRITE_OWN)).toBe(false);
  });

  it("revoked=true blocks every scope, even with an otherwise-empty restricted_scopes list", () => {
    const standing = { verdict: "active", restricted_scopes: [], revoked: true };
    expect(isBlocked(standing, SCOPE_READ_OWN)).toBe(true);
    expect(isBlocked(standing, SCOPE_WRITE_OTHERS)).toBe(true);
  });

  it("'active' with an empty restricted_scopes blocks nothing", () => {
    const standing = { verdict: "active", restricted_scopes: [] };
    expect(isBlocked(standing, SCOPE_READ_OWN)).toBe(false);
    expect(isBlocked(standing, SCOPE_WRITE_OWN)).toBe(false);
    expect(isBlocked(standing, SCOPE_READ_OTHERS)).toBe(false);
    expect(isBlocked(standing, SCOPE_WRITE_OTHERS)).toBe(false);
  });

  it("only the SPECIFIC restricted scope is blocked -- others are unaffected", () => {
    const standing = { verdict: "active", restricted_scopes: [SCOPE_WRITE_OTHERS] };
    expect(isBlocked(standing, SCOPE_WRITE_OTHERS)).toBe(true);
    expect(isBlocked(standing, SCOPE_READ_OTHERS)).toBe(false);
    expect(isBlocked(standing, SCOPE_READ_OWN)).toBe(false);
    expect(isBlocked(standing, SCOPE_WRITE_OWN)).toBe(false);
  });

  it("multiple restricted scopes are each independently checked", () => {
    const standing = { verdict: "active", restricted_scopes: [SCOPE_READ_OTHERS, SCOPE_WRITE_OTHERS] };
    expect(isBlocked(standing, SCOPE_READ_OTHERS)).toBe(true);
    expect(isBlocked(standing, SCOPE_WRITE_OTHERS)).toBe(true);
    expect(isBlocked(standing, SCOPE_READ_OWN)).toBe(false);
  });
});

describe("deriveBanScope", () => {
  it("combines the action's .read/.write suffix with isOwner", () => {
    expect(deriveBanScope("facet_directory.read", true)).toBe(SCOPE_READ_OWN);
    expect(deriveBanScope("facet_directory.read", false)).toBe(SCOPE_READ_OTHERS);
    expect(deriveBanScope("policy.write", true)).toBe(SCOPE_WRITE_OWN);
    expect(deriveBanScope("policy.write", false)).toBe(SCOPE_WRITE_OTHERS);
  });

  it("throws on an action with neither a .read nor .write suffix -- a route-wiring bug, not a caller error", () => {
    expect(() => deriveBanScope("policy.delete", true)).toThrow(/route-wiring/);
    expect(() => deriveBanScope("no_suffix_at_all", true)).toThrow();
  });
});
