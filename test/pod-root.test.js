import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";

describe("pod-root facet", () => {
  it("setup creates pod_meta and facet_directory, idempotently", async () => {
    const id = env.POD_ROOT.idFromName("pod-root");
    const stub = env.POD_ROOT.get(id);

    const first = await (await stub.fetch("http://pod/setup")).json();
    expect(first.ok).toBe(true);
    expect(first.pod.protocol_version).toBe("poc-v0");
    const podId = first.pod.pod_id;

    // Idempotent: calling /setup again must not mint a second pod_id.
    const second = await (await stub.fetch("http://pod/setup")).json();
    expect(second.pod.pod_id).toBe(podId);
  });

  it("status reflects an empty facet directory before any real facet is registered", async () => {
    const id = env.POD_ROOT.idFromName("status-check");
    const stub = env.POD_ROOT.get(id);
    await (await stub.fetch("http://pod/setup")).json();

    const status = await (await stub.fetch("http://pod/status")).json();
    expect(status.ok).toBe(true);
    expect(status.facets).toEqual([]);
    expect(status.scope).toMatch(/proof-of-concept/);
  });

  it("an unknown path 404s", async () => {
    const id = env.POD_ROOT.idFromName("404-check");
    const stub = env.POD_ROOT.get(id);
    const res = await stub.fetch("http://pod/nope");
    expect(res.status).toBe(404);
  });
});
