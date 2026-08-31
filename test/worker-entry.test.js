import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// Exercises the TOP-LEVEL Worker export (SELF.fetch), not the DO stub
// directly -- pod-root.test.js and policy.test.js both call
// env.POD_ROOT.get(id).fetch(...), which bypasses the default export's
// KNOWN_ROUTES cheap-reject entirely. That cheap-reject (Opus
// architecture review, 2026-08-31: garbage requests to an anonymous
// public endpoint were waking the DO and billing the customer's account
// before a 404 ever fired) is only real if something actually calls the
// Worker's own fetch handler, not just the DO underneath it.

describe("top-level Worker entry -- KNOWN_ROUTES cheap-reject", () => {
  it("a known (method, path) pair reaches the DO and gets a real response", async () => {
    const res = await SELF.fetch("http://pod/status");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });

  it("an unknown path 404s from the Worker itself, before any DO hop", async () => {
    const res = await SELF.fetch("http://pod/this-path-does-not-exist");
    expect(res.status).toBe(404);
  });

  it("a known path with the WRONG method 404s -- method is part of the route identity", async () => {
    // /status is only ever registered as GET.
    const res = await SELF.fetch("http://pod/status", { method: "DELETE" });
    expect(res.status).toBe(404);
  });

  it("garbage paths never reach far enough to need identity headers -- confirms this is the cheap-reject, not the policy layer's own 401", async () => {
    // No X-Principal-Did at all. If this fell through to the DO's policy
    // layer for a route that required one, it would be a 401, not a 404.
    const res = await SELF.fetch("http://pod/totally-made-up-endpoint");
    expect(res.status).toBe(404);
  });
});
