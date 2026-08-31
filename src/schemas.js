// Request-boundary shape validation (Zod), rejecting malformed input at
// the routing perimeter before it ever reaches policy.js's authorization
// logic -- Jonah's 2026-08-31 call, replacing the hand-rolled checks a
// bounded Fable review found gaps in (missing-field validation producing
// raw 500s, an unenforced/lexicographically-fragile expires_at contract).
// policy.js keeps only the checks that are genuinely BUSINESS logic, not
// shape (e.g. "is this caller the owner") -- shape lives here, once.
//
// Not attempting real did:webvh structural validation here (SCID/hash-
// chain/pre-rotation) -- that's BasalTribe/basaltribe/pod_did_verifier.py
// on the server side; a DID string arriving at this Worker is trusted-as-
// asserted regardless of how well-formed it looks, per the same named
// caller-identity gap policy.js's own module doc comment describes. This
// schema only guards against obviously-wrong shapes (empty, absurdly
// long), not cryptographic validity.
import { z } from "zod";

const DidString = z.string().min(1).max(2048);
const NonEmptyString = z.string().min(1).max(512);

export const SetupBodySchema = z
  .object({
    owner_did: DidString.optional(),
  })
  .optional()
  .default({});

export const PolicyGrantSchema = z.object({
  grant_id: NonEmptyString,
  principal_did: DidString,
  action: NonEmptyString,
  resource: NonEmptyString,
  effect: z.enum(["allow", "deny"]),
  // Required key, explicit null for "permanent" -- omitting the key
  // entirely is a validation error, not a silent default. See policy.js's
  // upsertPolicyGrant doc comment for why this was made structural.
  expires_at: z.string().datetime({ precision: 3 }).nullable(),
});

// Header names as Hono's own validator target sees them (lowercased).
export const RequestIdentityHeaderSchema = z.object({
  "x-principal-did": DidString,
  "x-presented-receipt-scope": NonEmptyString.optional(),
});
