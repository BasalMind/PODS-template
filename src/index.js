import { DurableObject } from "cloudflare:workers";
import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { evaluatePolicy, recordPresentedReceipt, setupPolicyTables, upsertPolicyGrant, PolicyEditForbidden } from "./policy.js";
import { SetupBodySchema, PolicyGrantSchema, RequestIdentityHeaderSchema } from "./schemas.js";

const MAX_PRESENTED_RECEIPTS = 200; // storage-management cap, not a shape concern -- stays a plain constant, not a Zod schema

// zValidator defaults every failure to 400. Correct for a malformed JSON
// body (bad request), but a missing/malformed X-Principal-Did is more
// precisely "you didn't identify yourself" -- 401, matching this route's
// pre-Zod behavior. Applied only to the header target, not json bodies.
const identityHeaderHook = (result, c) => {
  if (!result.success) {
    return c.json({ error: "X-Principal-Did header is required" }, 401);
  }
};

// Pod root: the pod's one stable, addressable entry point. Holds routing
// metadata AND the owner-maintained authorization policy every facet DO
// shares (policy.js) -- never facet CONTENTS. Design source:
//   docs/design-briefs/basaltribe-pod-facet-schema.md s0.2 (BasalMind/core)
//     -- what pod root is FOR: "the signed facet index, the cached binding
//     certificate, the protocol version the pod speaks... holds no facet
//     contents, ever."
//   docs/design-briefs/basaltribe-pod-facet-schema-fable-pass.md s5.6
//     -- the facet_directory table shape used here.
//   docs/design-briefs/basaltribe-pod-facet-schema-reconciliation.md s7
//     -- UCAN grants are receipts, not authority; policy.js is the real
//     decision, see that module's own doc comment for the full reasoning.
//
// PROOF-OF-CONCEPT SCOPE, still true of everything except the policy
// layer added this session: this does NOT implement the binding
// certificate, the signed facet index publication, or any real facet --
// those are separate, sequenced work (see the security addendum's own
// prerequisite ordering). The policy layer's OWN scope gap: caller
// identity is asserted (an X-Principal-Did header), not yet
// cryptographically verified -- see policy.js's module doc comment.
//
// Clean Zod rewrite, 2026-08-31 (Jonah's call): request-boundary shape
// validation (schemas.js) now happens once, declaratively, via
// @hono/zod-validator, before a request reaches any handler below --
// replacing the hand-rolled try/catch-JSON-parse and manual field checks
// a bounded Fable review found gaps in. Route handlers and policy.js's
// upsertPolicyGrant now trust shape and only implement BUSINESS logic
// (is this the owner, does the policy table permit this).
export class PodRoot extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.app = this.buildApp();
  }

  sql(query, ...bindings) {
    return this.ctx.storage.sql.exec(query, ...bindings);
  }

  async setup(ownerDid) {
    this.sql(`
      CREATE TABLE IF NOT EXISTS pod_meta (
        singleton         INTEGER PRIMARY KEY CHECK (singleton = 1),
        pod_id            TEXT NOT NULL,
        protocol_version  TEXT NOT NULL,
        owner_did         TEXT NOT NULL,
        created_at        TEXT NOT NULL
      );
    `);
    this.sql(`
      CREATE TABLE IF NOT EXISTS facet_directory (
        facet_id        TEXT PRIMARY KEY,
        facet_profile   TEXT NOT NULL,
        profile_version TEXT NOT NULL,
        label           TEXT NOT NULL,
        service_path    TEXT NOT NULL,
        visibility      TEXT NOT NULL DEFAULT 'private'
                          CHECK (visibility IN ('private', 'listed')),
        created_at      TEXT NOT NULL,
        retired_at      TEXT
      );
    `);
    setupPolicyTables((q, ...b) => this.sql(q, ...b));

    const existing = [...this.sql(`SELECT pod_id FROM pod_meta WHERE singleton = 1;`)][0];
    if (!existing) {
      if (!ownerDid) {
        throw new MissingOwnerDid("first-time setup requires an owner DID -- there is no owner to root policy on otherwise");
      }
      this.sql(
        `INSERT INTO pod_meta (singleton, pod_id, protocol_version, owner_did, created_at) VALUES (1, ?, ?, ?, ?);`,
        crypto.randomUUID(),
        "poc-v0",
        ownerDid,
        new Date().toISOString(),
      );
    }
    // Deliberately NOT this.status() -- see that method's own comment.
    // /setup's response goes only to the caller who just performed setup
    // (or is re-confirming an already-set-up pod), so echoing owner_did
    // back here is a one-time acknowledgment, not the standing,
    // repeatable, unauthenticated disclosure /status was leaking.
    const meta = [...this.sql(`SELECT pod_id, protocol_version, owner_did, created_at FROM pod_meta WHERE singleton = 1;`)][0];
    return { ok: true, pod: meta };
  }

  // Bounded Fable review, 2026-08-31, finding 1: /status is deliberately
  // unauthenticated (a health check any caller, including an owner who
  // hasn't proven anything yet, should be able to hit) -- but it was
  // leaking owner_did (the exact value X-Principal-Did-based ownership
  // hinges on, given the named unauthenticated-caller-identity gap) and
  // every facet regardless of visibility, including 'private' ones. Fixed:
  // owner_did dropped from this response entirely (an authenticated route
  // is the right place for a caller to confirm their own ownership, not a
  // public one); facets filtered to visibility='listed' only.
  async status() {
    const meta = [...this.sql(`SELECT pod_id, protocol_version, created_at FROM pod_meta WHERE singleton = 1;`)][0];
    const facets = [
      ...this.sql(`SELECT facet_id, facet_profile, label, visibility FROM facet_directory WHERE visibility = 'listed';`),
    ];
    return {
      ok: true,
      scope: "proof-of-concept -- launch mechanics + policy-table authorization, no binding certificate, no real facet, no cryptographic caller verification yet",
      pod: meta || null,
      facets,
    };
  }

  ownerDid() {
    // pod_meta doesn't exist at all until /setup has run once -- a bare
    // "table not found" SQL error IS "not set up yet," not a crash.
    let rows;
    try {
      rows = [...this.sql(`SELECT owner_did FROM pod_meta WHERE singleton = 1;`)];
    } catch {
      return null;
    }
    return rows[0] ? rows[0].owner_did : null;
  }

  // Every protected route composes zValidator('header', RequestIdentityHeaderSchema)
  // BEFORE this middleware -- header shape (non-empty, length-bounded) is
  // already guaranteed by the time this runs; this only does the
  // BUSINESS check (does the policy table permit this). Caller identity
  // itself is still UNAUTHENTICATED (see module docstring + policy.js) --
  // this enforces the POLICY decision correctly, it does not and cannot
  // yet enforce that the caller genuinely controls the DID it claims.
  requirePolicy(action, resource) {
    return async (c, next) => {
      const owner = this.ownerDid();
      if (owner === null) {
        return c.json({ error: "pod not set up" }, 409);
      }
      // Round-2 bounded Fable review, 2026-08-31, finding N1: c.req.valid()
      // returns undefined if zValidator("header", ...) was never attached
      // to this route -- previously an unhandled TypeError/500 on the very
      // copy-paste-a-new-route mistake this coupling exists to catch. Fail
      // loud in a way that says exactly what's wrong, not a generic 500.
      const headers = c.req.valid("header");
      if (!headers) {
        throw new Error(
          `requirePolicy("${action}", "${resource}") was reached without zValidator("header", ` +
          `RequestIdentityHeaderSchema) attached to the same route first -- this is a route-wiring ` +
          `bug, not a caller error.`
        );
      }
      const principalDid = headers["x-principal-did"];
      const receiptScope = headers["x-presented-receipt-scope"];
      if (receiptScope) {
        // Provenance only -- see policy.js. This line is the entire
        // extent to which a presented receipt participates in this
        // request; it is never read by evaluatePolicy() below. maxRows
        // prunes unboundedly-growing storage (bounded Fable review,
        // 2026-08-31, finding 3) -- length is already bounded by the
        // header schema above.
        recordPresentedReceipt((q, ...b) => this.sql(q, ...b), principalDid, receiptScope, MAX_PRESENTED_RECEIPTS);
      }
      const result = evaluatePolicy((q, ...b) => this.sql(q, ...b), { ownerDid: owner, principalDid, action, resource });
      if (result.decision !== "allow") {
        return c.json({ error: "forbidden", reason: result.reason }, 403);
      }
      c.set("principalDid", principalDid);
      c.set("isOwner", principalDid === owner);
      await next();
    };
  }

  buildApp() {
    const app = new Hono();

    app.post("/setup", zValidator("json", SetupBodySchema), async (c) => {
      const { owner_did: ownerDid } = c.req.valid("json");
      try {
        return c.json(await this.setup(ownerDid));
      } catch (err) {
        if (err instanceof MissingOwnerDid) {
          return c.json({ error: err.message }, 400);
        }
        throw err;
      }
    });

    app.get("/status", async (c) => c.json(await this.status()));

    // Owner-only: edit the policy table. Rooted in identity (policy.js's
    // upsertPolicyGrant checks editorDid === ownerDid itself, defense in
    // depth alongside this route's own requirePolicy gate) -- resource
    // "policy_grants" is a deliberately reserved action/resource pair a
    // real facet type's own action vocabulary should never reuse.
    app.post(
      "/policy/grants",
      zValidator("header", RequestIdentityHeaderSchema, identityHeaderHook),
      this.requirePolicy("policy.write", "policy_grants"),
      zValidator("json", PolicyGrantSchema),
      async (c) => {
        const body = c.req.valid("json");
        try {
          upsertPolicyGrant((q, ...b) => this.sql(q, ...b), {
            ownerDid: this.ownerDid(),
            editorDid: c.get("principalDid"),
            grantId: body.grant_id,
            principalDid: body.principal_did,
            action: body.action,
            resource: body.resource,
            effect: body.effect,
            expiresAt: body.expires_at,
          });
          return c.json({ ok: true });
        } catch (err) {
          if (err instanceof PolicyEditForbidden) {
            return c.json({ error: err.message }, 403);
          }
          throw err;
        }
      },
    );

    // Reference-implementation protected route, exercising the pattern a
    // real facet type will repeat for its own actions/resources -- not
    // itself a facet, just proof the middleware composes correctly.
    app.get(
      "/facets",
      zValidator("header", RequestIdentityHeaderSchema, identityHeaderHook),
      this.requirePolicy("facet_directory.read", "facet_directory"),
      async (c) => {
        const facets = [...this.sql(`SELECT facet_id, facet_profile, label, visibility FROM facet_directory;`)];
        return c.json({ facets, as: c.get("principalDid"), owner: c.get("isOwner") });
      },
    );

    app.notFound((c) => c.json({ error: "not found" }, 404));
    return app;
  }

  async fetch(request) {
    return this.app.fetch(request);
  }
}

export class MissingOwnerDid extends Error {}

export default {
  async fetch(request, env) {
    const id = env.POD_ROOT.idFromName("pod-root");
    const stub = env.POD_ROOT.get(id);
    return stub.fetch(request);
  },
};
