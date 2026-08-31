import { DurableObject } from "cloudflare:workers";

// Pod root: the pod's one stable, addressable entry point. Holds routing
// metadata only -- never facet contents. Design source:
//   docs/design-briefs/basaltribe-pod-facet-schema.md s0.2 (BasalMind/core)
//     -- what pod root is FOR: "the signed facet index, the cached binding
//     certificate, the protocol version the pod speaks... holds no facet
//     contents, ever."
//   docs/design-briefs/basaltribe-pod-facet-schema-fable-pass.md s5.6
//     -- the facet_directory table shape used here.
//
// PROOF-OF-CONCEPT SCOPE, stated in code as well as the README: this proves
// the launch mechanics (a customer's own GitHub Action, using the customer's
// own Cloudflare credentials, deploying to the customer's own account) work
// end to end. It does NOT implement the binding certificate, the signed
// facet index publication, or any real facet -- those are separate,
// sequenced work (see the security addendum's own prerequisite ordering).
export class PodRoot extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
  }

  sql(query, ...bindings) {
    return this.ctx.storage.sql.exec(query, ...bindings);
  }

  async setup() {
    this.sql(`
      CREATE TABLE IF NOT EXISTS pod_meta (
        singleton         INTEGER PRIMARY KEY CHECK (singleton = 1),
        pod_id            TEXT NOT NULL,
        protocol_version  TEXT NOT NULL,
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

    const existing = [...this.sql(`SELECT pod_id FROM pod_meta WHERE singleton = 1;`)][0];
    if (!existing) {
      this.sql(
        `INSERT INTO pod_meta (singleton, pod_id, protocol_version, created_at) VALUES (1, ?, ?, ?);`,
        crypto.randomUUID(),
        "poc-v0",
        new Date().toISOString(),
      );
    }
    return this.status();
  }

  async status() {
    const meta = [...this.sql(`SELECT pod_id, protocol_version, created_at FROM pod_meta WHERE singleton = 1;`)][0];
    const facets = [...this.sql(`SELECT facet_id, facet_profile, label, visibility FROM facet_directory;`)];
    return {
      ok: true,
      scope: "proof-of-concept -- launch mechanics only, no binding certificate, no real facets",
      pod: meta || null,
      facets,
    };
  }

  async fetch(request) {
    const url = new URL(request.url);
    let result;
    switch (url.pathname) {
      case "/setup":
        result = await this.setup();
        break;
      case "/status":
        result = await this.status();
        break;
      default:
        return new Response("not found", { status: 404 });
    }
    return new Response(JSON.stringify(result, null, 2), {
      headers: { "content-type": "application/json" },
    });
  }
}

export default {
  async fetch(request, env) {
    const id = env.POD_ROOT.idFromName("pod-root");
    const stub = env.POD_ROOT.get(id);
    return stub.fetch(request);
  },
};
