# PODS-template

Sovereign pod launch template (proof of concept).

This is BasalMind's published protocol for standing up a sovereign data pod: a Cloudflare
Durable Object, deployed to **your own** Cloudflare account, using **your own** credentials, on
**your own** device or a GitHub Action running under **your own** repo. BasalMind never touches
your Cloudflare account, never holds a credential to it, and has no technical capability to.

## What this proves, and what it doesn't yet

**Current status: proof of concept.** This repo demonstrates the launch *mechanics* -- fork it,
add your own credentials as repo secrets, run one workflow, and a real Durable Object exists in
your own Cloudflare account, all without BasalMind ever seeing your token. It deliberately does
**not** yet include:

- A binding certificate linking this pod to a verified BasalMind identity.
- Any real facet (personal outcomes, relationships, offerings, etc.) -- only the pod-root
  routing facet, which holds no personal data.
- Signed releases or a transparency log for this repo's own code. Until those exist, running
  this workflow means trusting that this specific commit of this specific repo does what it
  says -- read `src/index.js` yourself before running it against a real account, the same way
  you should for any script that runs with your credentials loaded. This is a named, accepted
  gap for a proof-of-concept pass, not an oversight.

None of the above blocks proving the mechanics work. All of it is real, separate, sequenced work
before this becomes the production pod-launch flow.

## How it works

1. Fork this repo to your own GitHub account.
2. In your fork's settings, add two repository secrets:
   - `CLOUDFLARE_API_TOKEN` -- an API token from your own Cloudflare account
     (`dash.cloudflare.com/profile/api-tokens`), scoped at minimum to Workers Scripts: Edit.
   - `CLOUDFLARE_ACCOUNT_ID` -- your own Cloudflare account ID (visible on the Cloudflare
     dashboard's right sidebar for any zone, or via `wrangler whoami`).
3. Go to your fork's **Actions** tab, select **Setup Pod**, and click **Run workflow**.
4. The workflow deploys `src/index.js` to a Worker in your own account. Its `*.workers.dev` URL
   is printed in the deploy step's output.
5. Visit `<your-worker-url>/setup`, then `<your-worker-url>/status` to confirm a real pod-root
   Durable Object is running and answering.

At no point does this repo, this workflow, or BasalMind's own infrastructure receive your
Cloudflare token -- it lives only in your fork's own GitHub Actions secrets, which GitHub
encrypts and exposes only inside your own workflow runs.

## What's inside

- `wrangler.jsonc` -- Worker + Durable Object configuration, SQLite storage backend.
- `src/index.js` -- the pod-root facet: a `PodRoot` Durable Object holding pod identity
  (`pod_meta`) and a directory of registered facets (`facet_directory`). Holds no facet
  contents, ever -- see `docs/design-briefs/basaltribe-pod-facet-schema.md` (BasalMind's
  `core` repo) s0.2 for why pod-root is scoped this narrowly.
- `.github/workflows/setup-pod.yml` -- the deploy action described above.
- `test/pod-root.test.js` -- runs against the real Cloudflare Workers runtime locally
  (`@cloudflare/vitest-pool-workers`), not a mock. `npm install && npm test` to run it yourself
  before trusting any of the above.

## License

Apache License 2.0 -- see `LICENSE`.
