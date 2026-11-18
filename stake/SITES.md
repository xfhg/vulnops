# Private Sites release

Publish only the static browser application. ZIPs, browser stores and assessment captures stay local. Preserve the existing project and origin across releases so saved browser workspaces remain accessible. No push or deployment is performed by the preparation script.

## Prepare app-only source

From `stake/`:

```sh
node scripts/prepare-sites.mjs prepare /absolute/disposable/stake-sites-source
```

The destination must be new and outside the app directory. The [script](scripts/prepare-sites.mjs) copies only TypeScript/TSX/CSS under `src/`, the brand SVG, package and lock files, TypeScript/Vite configuration, `index.html`, this guide, the preparation script and hosting metadata. It generates a small `.gitignore` and prints a sorted size/SHA-256 inventory. Symlinks and unexpected source/assets fail; harness history, server code, reports, tests, credentials and captures are excluded.

Use a new independent repository for the first release; retain its app-only history and remote for later releases. Never push the harness repository or change its remotes. The local `stake/.openai/` binding and `*.tar.provenance.json` are excluded from the public product repository; retain them privately. The separate Sites source repository must include its own binding.

## Bind the existing private site

Inspect root/viewer bindings and the current Sites account before creating anything. Reuse the exact recorded project ID. If no site exists, create one owner-private site and immediately record the returned ID atomically in the local and isolated bindings. Resolve conflicting bindings; do not create another site after an upload or credential failure.

Sites requires this shape:

```json
{
  "project_id": "<exact returned project ID>",
  "static": { "directory": "dist" }
}
```

`static` must be an object and `directory` a supported value. Preparation creates an unbound `{ "static": { "directory": "dist" } }` if metadata is absent; packaging requires the real project ID. Keep credentials out of metadata, committed files and credential-bearing remote URLs. Use Sites' short-lived authentication flow; `work_proxy` authenticates the ordinary remote URL outside the executor.

## Build the pushed commit

Preview with `npm ci` and `npm run build:web` in the isolated checkout, then test `dist-browser` on a static server using synthetic archives. Check graph workers, highlighting and evidence without a report service, `/api/*`, remote assets or `unsafe-eval`.

Commit and push the reviewed source and binding to the Sites source branch. Set its upstream; local HEAD and the live remote tip must match the full SHA from `git rev-parse HEAD`. Then run:

```sh
node scripts/prepare-sites.mjs package /absolute/disposable/stake-sites-source FULL_PUSHED_SHA /absolute/disposable/stake-release.tar
node scripts/prepare-sites.mjs verify /absolute/disposable/stake-release.tar FULL_PUSHED_SHA
```

Packaging requires a clean checkout with allowlisted current/history paths and rejects symlinks, submodules, unpushed/mismatched commits and existing output files. It builds a fresh `git archive` snapshot with `npm ci` and `build:web`, checks that source inputs and the remote tip are unchanged, and removes its temporary checkout/cache.

Local browser output remains `dist-browser`; local CLI output is untouched. Packaging copies fresh browser bytes into artifact-only `dist/`. The deterministic tar contains only `.openai/hosting.json` and those static files, including `dist/index.html`. Adjacent provenance records the commit/tree, project, directory mapping, source/build/artifact inventories and archive hash. `verify` checks the selected SHA, binding, archive and exact `dist-browser/` → `dist/` hash mapping. Preserve both files unchanged until Sites accepts the version. These hashes establish consistency, not publisher authenticity.

## Deploy and verify

Recheck the current Sites contract. Supply the exact `project_id`, full pushed `commit_sha` and absolute tar path. Source changes require a new commit and rebuild; never relabel an older artifact. Preserve the site's audience and use the private operation only for a known owner-private site. No runtime database or connectors are needed. Reconcile an existing publish-on-push deployment rather than duplicating it.

Keep the saved version and deployment IDs. Poll nonterminal deployment status. Deployment success alone does not establish hosted acceptance: test the actual URL with synthetic archives, covering empty state, import, reload/deep links, all views, graphs, repair instructions/examples, evidence, replacement and removal. Inspect request paths, queries, headers and bodies for report-data egress. Never publish real reports or their captures.

Before release, record the previous successfully deployed version if one exists. Roll back by redeploying it on the same project/origin with unchanged private access. Do not clear visitor archives; an unsupported stored format must show recovery controls without destructive migration. Browser storage remains origin/profile-specific and can be cleared or evicted.

Run `npm test -- tests/sites-packaging.test.ts` for inventory, schema, provenance and rejection checks. Local packaging tests do not replace hosted acceptance.
