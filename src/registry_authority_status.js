// Facet-DO-side consumption of BasalMind's signed person-level standing
// status documents (Cloudflare pod-binding security addendum item 2.7's
// sibling mechanism -- core PR #1822, BasalTribe/basaltribe/
// pod_registry_authority.py + GET /pod/status). DO-agnostic by design
// (takes a `sql` function, not a specific DO class), same reuse intent as
// policy.js -- meant to be adopted unchanged by every future facet-type
// DO, not a PodRoot-specific feature.
//
// Verification discipline: the signature is checked against the RAW
// base64url-decoded payload bytes, exactly as received -- never a
// re-serialized JSON.stringify() of the parsed document. This is the
// same canonicalization-mismatch avoidance the Python issuer's own module
// doc comment describes (the bug class BL#14293 already hit once in this
// codebase, Python's default json.dumps separators vs. a JS-side
// recompute of "the same" hash).
//
// Public key: BasalMind's registry-authority Ed25519 public key,
// hardcoded below as a multikey string -- it is public by design (the
// whole point of asymmetric signing), so baking it in is not a secret-
// handling concern. The REAL open gap is fleet-wide key ROTATION: this
// file, like policy.js/schemas.js, is meant to be copied unchanged into
// every facet-type template, and a customer fork that never rebases
// would not pick up a rotated key. Same root cause as BL#14317 (extract
// policy.js + schema primitives + protectedRoute into a versioned
// @basalmind/pod-kernel npm package) -- deliberately not solved here with
// a second, different mechanism (e.g. a wrangler.jsonc var a customer
// must remember to update); converges on that one eventual fix instead.
//
// Wired into requirePolicy() automatically as of index.js's own update,
// 2026-09-01 (Jonah, in conversation) -- every protected route gets this
// check for free, a route author cannot forget it. Ban scoping: NOT a
// single flag. 4 independent scopes -- read_own/write_own (can this
// caller use THEIR OWN pod) and read_others/write_others (can this
// caller read/write on pods they don't own) -- mirrored from
// pod_registry_authority.py's own ALL_BAN_SCOPES. Composed as a PURE
// VETO against evaluatePolicy()'s own default-deny decision, never
// additive: a clean (unrestricted) standing document never grants
// anything on its own, it only means this gate doesn't ALSO deny
// something policy.js already allowed. See isBlocked() below and
// index.js's requirePolicy() for where "own" vs "others" and read vs
// write actually get derived (from the existing isOwner computation and
// the action string's own .read/.write suffix -- no new input needed
// from a route author).

import * as ed from "@noble/ed25519";

const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// z6MkjZ7xczHpvek2TspyHVjbAjoZxZZ7VGqgXH71NpPawN6h -- registered live,
// Forge migration 0063_register_gcp_kms_registry_authority_key.sql,
// key_id='gcp-kms-registry-authority-v1'. Same base58btc('z' prefix) +
// multicodec-0xed01 Ed25519 multikey convention pod_did_verifier.py
// already uses for did:webvh keys elsewhere in this system.
export const REGISTRY_AUTHORITY_PUBLIC_KEY_MULTIKEY = "z6MkjZ7xczHpvek2TspyHVjbAjoZxZZ7VGqgXH71NpPawN6h";

// Corrected 2026-09-01 -- this previously said basaltribe.com, which is
// not a real live domain. BasalTribe's main.py is actually served under
// app.basalmind.com (confirmed live via nginx sites-enabled), the same
// domain the rest of the account/onboarding stepper UI lives on.
const DEFAULT_STATUS_URL = "https://app.basalmind.com/pod/status";

// Bounded Fable review, 2026-09-01, finding 3: an unresponsive registry
// endpoint would otherwise stall a "new"-context check (on the live
// request path by design) for the platform's max subrequest duration.
const _FETCH_TIMEOUT_MS = 5000;
// The response body is a small fixed-shape JSON object (two base64url
// fields); anything past a generous margin is not a legitimate response,
// checked via Content-Length when the server sends one (best-effort --
// chunked responses without it still proceed, same as before this check).
const _MAX_RESPONSE_BYTES = 8192;

export class InvalidStatusSignature extends Error {}
export class InvalidStatusDocument extends Error {}
export class StatusFetchFailed extends Error {}

function base58btcDecode(s) {
  let num = 0n;
  for (const ch of s) {
    const idx = BASE58BTC_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`"${ch}" is not a valid base58btc character`);
    }
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  for (const ch of s) {
    if (ch === "1") bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
}

function decodeEd25519Multikey(multikey) {
  if (!multikey.startsWith("z")) {
    throw new Error(`multikey does not use the expected 'z' (base58btc) multibase prefix: ${multikey}`);
  }
  const decoded = base58btcDecode(multikey.slice(1));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("multikey does not use the expected Ed25519 multicodec prefix (0xed01) or wrong length");
  }
  return decoded.slice(2);
}

function base64UrlToBytes(b64url) {
  const padded = b64url + "===".slice((b64url.length + 3) % 4);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Exported for tests -- production callers always go through
// verifyAndParseDocument(), never construct/skip verification themselves.
export function _decodeAuthorityPublicKey() {
  return decodeEd25519Multikey(REGISTRY_AUTHORITY_PUBLIC_KEY_MULTIKEY);
}

// Verifies `signature` against the EXACT bytes `payload` decodes to --
// never re-serializes. Throws InvalidStatusSignature on any failure
// (bad signature, malformed base64, wrong-length key) rather than
// returning false, so a caller cannot accidentally treat "verification
// crashed" as "verification passed."
export async function verifyAndParseDocument(payloadB64Url, signatureB64Url, publicKeyMultikey = REGISTRY_AUTHORITY_PUBLIC_KEY_MULTIKEY) {
  let payloadBytes, signatureBytes, pubKeyBytes;
  try {
    payloadBytes = base64UrlToBytes(payloadB64Url);
    signatureBytes = base64UrlToBytes(signatureB64Url);
    pubKeyBytes = decodeEd25519Multikey(publicKeyMultikey);
  } catch (err) {
    throw new InvalidStatusSignature(`malformed status document input: ${err.message}`);
  }
  let ok;
  try {
    ok = await ed.verifyAsync(signatureBytes, payloadBytes, pubKeyBytes);
  } catch (err) {
    throw new InvalidStatusSignature(`signature verification threw: ${err.message}`);
  }
  if (!ok) {
    throw new InvalidStatusSignature("signature does not verify against the registry-authority public key");
  }
  let doc;
  try {
    doc = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch (err) {
    throw new InvalidStatusDocument(`verified payload is not valid JSON: ${err.message}`);
  }
  return doc;
}

export function setupStatusCacheTable(sql) {
  sql(`
    CREATE TABLE IF NOT EXISTS registry_authority_status_cache (
      pod_did           TEXT PRIMARY KEY,
      verdict           TEXT NOT NULL,
      restricted_scopes TEXT NOT NULL,
      revoked           INTEGER NOT NULL,
      issued_at         TEXT NOT NULL,
      expires_at        TEXT NOT NULL,
      authority_key_id  TEXT NOT NULL,
      cached_at         TEXT NOT NULL
    );
  `);
}

function _cacheRowToDoc(row) {
  return {
    pod_did: row.pod_did,
    verdict: row.verdict,
    restricted_scopes: JSON.parse(row.restricted_scopes),
    revoked: !!row.revoked,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    authority_key_id: row.authority_key_id,
  };
}

export function getCachedStatus(sql, podDid) {
  const row = [...sql(`SELECT * FROM registry_authority_status_cache WHERE pod_did = ?;`, podDid)][0];
  return row ? _cacheRowToDoc(row) : null;
}

function _cacheStatus(sql, doc) {
  sql(
    `INSERT INTO registry_authority_status_cache
       (pod_did, verdict, restricted_scopes, revoked, issued_at, expires_at, authority_key_id, cached_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (pod_did) DO UPDATE SET
       verdict = excluded.verdict, restricted_scopes = excluded.restricted_scopes,
       revoked = excluded.revoked, issued_at = excluded.issued_at,
       expires_at = excluded.expires_at, authority_key_id = excluded.authority_key_id,
       cached_at = excluded.cached_at;`,
    doc.pod_did, doc.verdict, JSON.stringify(doc.restricted_scopes || []), doc.revoked ? 1 : 0,
    doc.issued_at, doc.expires_at, doc.authority_key_id, new Date().toISOString(),
  );
}

// Bounded Fable review, 2026-09-01, finding 2: Date.parse(undefined/
// malformed) is NaN, and `Date.now() >= NaN` is FALSE -- so a doc with a
// missing or unparseable expires_at was previously treated as fresh
// FOREVER (fails open on malformed input, the wrong direction for an
// expiry check). Unparseable now counts as expired.
function _isExpired(doc) {
  const parsed = Date.parse(doc.expires_at);
  if (Number.isNaN(parsed)) return true;
  return Date.now() >= parsed;
}

async function refreshStatus(sql, podDid, fetchImpl, statusUrl, publicKeyMultikey) {
  const url = `${statusUrl}?pod_did=${encodeURIComponent(podDid)}`;
  let res;
  try {
    res = await fetchImpl(url, { signal: AbortSignal.timeout(_FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new StatusFetchFailed(`network error fetching ${url}: ${err.message}`);
  }
  if (!res.ok) {
    throw new StatusFetchFailed(`status endpoint returned HTTP ${res.status}`);
  }
  const contentLength = res.headers && res.headers.get ? res.headers.get("content-length") : null;
  if (contentLength && Number(contentLength) > _MAX_RESPONSE_BYTES) {
    throw new StatusFetchFailed(`status endpoint response too large (${contentLength} bytes)`);
  }
  const body = await res.json();
  const doc = await verifyAndParseDocument(body.payload, body.signature, publicKeyMultikey);
  if (doc.pod_did !== podDid) {
    throw new InvalidStatusDocument(`document pod_did (${doc.pod_did}) does not match requested pod_did (${podDid})`);
  }
  // Bounded Fable review, 2026-09-01, finding 1: a validly-signed but
  // ALREADY-EXPIRED document (e.g. served by a stale cache somewhere
  // upstream, or replayed) was previously accepted and cached as a fresh
  // network result -- defeating the entire point of a short-TTL signed
  // document. The signature proves authenticity, not currency; both must
  // hold before this is trusted or cached.
  if (_isExpired(doc)) {
    throw new InvalidStatusDocument(`fetched document is already expired (expires_at=${doc.expires_at})`);
  }
  _cacheStatus(sql, doc);
  return doc;
}

// The main entrypoint. `context` distinguishes two DIFFERENT trust
// postures (memory: fail-open/fail-closed split, hybrid-layer design):
//   "new"        -- honoring a NEW inbound grant or accepting a NEW
//                    outbound counterparty. A stale/unreachable status
//                    endpoint fails CLOSED here -- matches this addendum's
//                    existing fail-closed-on-silence grant principle.
//   "continuing" -- an ALREADY-established interaction continuing within
//                    a cache this pod once successfully verified. Fails
//                    OPEN on an unreachable endpoint (falls back to the
//                    stale cached verdict) so a BasalMind outage does not
//                    become a network-wide pod outage.
//
// v1 scope note, named not hidden: "continuing" fail-open uses ANY
// previously-verified cache entry regardless of its own staleness, not
// narrowed further to "within the counterparty's own certificate's
// remaining not_after validity" -- the status document doesn't carry
// not_after today (only its own issued_at/expires_at signing-cadence
// budget). Narrowing that is real follow-up work, not done here.
export async function getStanding(sql, podDid, {
  fetchImpl = fetch, statusUrl = DEFAULT_STATUS_URL, context,
  publicKeyMultikey = REGISTRY_AUTHORITY_PUBLIC_KEY_MULTIKEY,
} = {}) {
  if (context !== "new" && context !== "continuing") {
    throw new Error(`getStanding() requires context: "new" | "continuing", got ${JSON.stringify(context)}`);
  }
  // Opus review, 2026-09-01: setupStatusCacheTable() was previously only
  // ever called from PodRoot.setup() -- a pod that completed /setup
  // BEFORE this module was wired in (e.g. Jonah's own live sovereign-pod
  // PoC) would 500 on its very first protected-route request afterward,
  // instead of the clean 403/pass ownerDid()/status() already defend
  // against for the analogous "table doesn't exist yet" case. CREATE
  // TABLE IF NOT EXISTS is cheap and idempotent -- calling it here makes
  // this module self-healing regardless of caller discipline, matching
  // its own "DO-agnostic, adopt unchanged" design intent.
  setupStatusCacheTable(sql);
  const cached = getCachedStatus(sql, podDid);
  if (cached && !_isExpired(cached)) {
    return { ...cached, source: "cache" };
  }

  try {
    const fresh = await refreshStatus(sql, podDid, fetchImpl, statusUrl, publicKeyMultikey);
    return { ...fresh, source: "network" };
  } catch (err) {
    if (context === "continuing" && cached) {
      return { ...cached, source: "stale-cache-fail-open", staleFetchError: String(err) };
    }
    return {
      pod_did: podDid, verdict: "unreachable", restricted_scopes: [], revoked: null,
      source: "unreachable-fail-closed", fetchError: String(err),
    };
  }
}

// The 4 independent ban scopes -- mirrored from
// pod_registry_authority.py's ALL_BAN_SCOPES. Own vs others is from the
// CALLER's perspective: read_own/write_own gate a caller acting on their
// OWN pod (isOwner === true at the call site), read_others/write_others
// gate a caller acting on someone else's pod.
export const SCOPE_READ_OWN = "read_own";
export const SCOPE_WRITE_OWN = "write_own";
export const SCOPE_READ_OTHERS = "read_others";
export const SCOPE_WRITE_OTHERS = "write_others";

// Is this specific (already-derived) scope blocked for this standing
// result?
//
// Opus architecture review, 2026-09-01, critical finding: an earlier cut
// of this function treated ANY non-"active" verdict -- including
// "unbound" -- as blocking EVERYTHING. Since certificate issuance
// (Phase 6, /pod/bind) doesn't exist yet, EVERY pod today resolves to
// "unbound" for its own owner, which would have silently locked every
// owner out of their own pod from day one -- directly contradicting
// policy.js's own stated invariant that a wiped/absent grant table can
// never lock the owner out (see that module's doc comment). Corrected
// semantics, three-way:
//   "unbound"      -- no BasalMind record exists for this DID at all.
//                      This is a NEUTRAL absence of signal, not a ban --
//                      nothing to enforce, so it does NOT block. A
//                      person must be able to use their own pod, and be
//                      treated by policy's OWN explicit grants for
//                      cross-pod interactions, with zero dependency on
//                      whether they've ever completed BasalMind
//                      onboarding.
//   "unreachable"   -- the registry endpoint could not be reached
//                      (network/outage), NOT a statement about the
//                      person. Fails CLOSED only for read_others/
//                      write_others -- the actual cross-pod security
//                      boundary this whole mechanism exists to protect,
//                      where "we couldn't verify" must mean "don't
//                      trust." Fails OPEN for read_own/write_own -- a
//                      BasalMind outage must never mean "you can't use
//                      your own pod," matching the fail-open reasoning
//                      already established for the "continuing" context
//                      (memory: a BasalMind outage should not become a
//                      network-wide pod outage) but extended here to
//                      cover the FIRST-request case for one's own pod,
//                      not just a subsequent one.
//   "active"        -- the only case where restricted_scopes is
//                      consulted at all; a clean (empty) list here is
//                      the ONLY combination that doesn't block. This
//                      function can only ever say "blocked" more
//                      readily than the caller's own policy grant, never
//                      override one (see the module doc comment's "pure
//                      veto" note) -- verdict=active does not itself
//                      grant anything, it only means this gate has
//                      nothing to add on top of whatever policy already
//                      decided.
// `revoked` (2.7's reserved field, always false today) is checked
// unconditionally alongside restricted_scopes -- when the certificate-
// specific revocation table ships, this function needs no shape change,
// only the value pod_registry_authority.py emits.
export function isBlocked(standing, scope) {
  if (standing.verdict === "unbound") return false;
  if (standing.verdict === "unreachable") {
    return scope === SCOPE_READ_OTHERS || scope === SCOPE_WRITE_OTHERS;
  }
  if (standing.revoked) return true;
  return (standing.restricted_scopes || []).includes(scope);
}

// Derives which of the 4 scopes applies from inputs requirePolicy()
// already has on hand -- no new input needed from a route author. Reuses
// this codebase's existing dot-namespaced action convention (e.g.
// "policy.write", "facet_directory.read") -- the LAST segment must be
// exactly "read" or "write". Throws rather than guessing on any other
// suffix, matching this file's established "route-wiring bugs fail loud"
// discipline (requirePolicy()'s own header-validator check, above).
export function deriveBanScope(action, isOwner) {
  let readOrWrite;
  if (action.endsWith(".read")) readOrWrite = "read";
  else if (action.endsWith(".write")) readOrWrite = "write";
  else {
    throw new Error(
      `deriveBanScope(): action "${action}" must end in ".read" or ".write" so the standing-check ` +
      `veto can classify it -- this is a route-wiring requirement, not a caller error.`
    );
  }
  return `${readOrWrite}_${isOwner ? "own" : "others"}`;
}
