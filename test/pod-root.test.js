import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";

const OWNER = "did:webvh:owner-scid:example.com:persons:alice";

function setupPod(stub, ownerDid = OWNER) {
  return stub.fetch("http://pod/setup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ owner_did: ownerDid }),
  });
}

describe("pod-root facet", () => {
  it("setup creates pod_meta and facet_directory, idempotently", async () => {
    const id = env.POD_ROOT.idFromName("pod-root");
    const stub = env.POD_ROOT.get(id);

    const first = await (await setupPod(stub)).json();
    expect(first.ok).toBe(true);
    expect(first.pod.protocol_version).toBe("poc-v0");
    expect(first.pod.owner_did).toBe(OWNER);
    const podId = first.pod.pod_id;

    // Idempotent: calling /setup again must not mint a second pod_id, and
    // must not require (or accept a change of) owner_did on repeat calls.
    const second = await (await setupPod(stub, "did:webvh:someone-else:example.com")).json();
    expect(second.pod.pod_id).toBe(podId);
    expect(second.pod.owner_did).toBe(OWNER); // unchanged -- setup never re-roots ownership

    const third = await (await stub.fetch("http://pod/setup", { method: "POST" })).json();
    expect(third.pod.pod_id).toBe(podId); // no body at all is fine once already set up
  });

  it("first-time setup with no owner_did is rejected -- there is no owner to root policy on otherwise", async () => {
    const id = env.POD_ROOT.idFromName("no-owner-check");
    const stub = env.POD_ROOT.get(id);
    const res = await stub.fetch("http://pod/setup", { method: "POST" });
    expect(res.status).toBe(400);
  });

  it("status reflects an empty facet directory before any real facet is registered", async () => {
    const id = env.POD_ROOT.idFromName("status-check");
    const stub = env.POD_ROOT.get(id);
    await (await setupPod(stub)).json();

    const status = await (await stub.fetch("http://pod/status")).json();
    expect(status.ok).toBe(true);
    expect(status.facets).toEqual([]);
    expect(status.scope).toMatch(/proof-of-concept/);
  });

  it("/status on a never-set-up pod returns 200 with pod: null, not a raw 500", async () => {
    // Found writing worker-entry.test.js: pod_meta/facet_directory don't
    // exist until /setup has run once -- a fresh deploy's very first
    // /status check (before anyone has run /setup) previously crashed.
    const id = env.POD_ROOT.idFromName("status-before-setup");
    const stub = env.POD_ROOT.get(id);
    const res = await stub.fetch("http://pod/status");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.pod).toBeNull();
    expect(body.facets).toEqual([]);
  });

  it("an unknown path 404s", async () => {
    const id = env.POD_ROOT.idFromName("404-check");
    const stub = env.POD_ROOT.get(id);
    const res = await stub.fetch("http://pod/nope");
    expect(res.status).toBe(404);
  });

  it("/status does not disclose owner_did or private facets -- bounded Fable review, 2026-08-31, finding 1", async () => {
    const id = env.POD_ROOT.idFromName("status-no-disclosure");
    const stub = env.POD_ROOT.get(id);
    await setupPod(stub);
    const status = await (await stub.fetch("http://pod/status")).json();
    expect(status.pod.owner_did).toBeUndefined();
    // Confirm the filter is real, not just "no facets exist": seed one
    // private and one listed facet directly, then check /status only
    // shows the listed one. There's no route to insert a facet yet (no
    // real facet type built), so this reaches into the DO's own storage
    // via a second /setup-adjacent path is not available -- documenting
    // the gap: this test can only assert the filtered query's SHAPE
    // (owner_did absent) until a facet-insertion route exists to seed
    // both visibilities and assert the filter's BEHAVIOR end to end.
  });
});
