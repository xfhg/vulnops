# Private Sites release

The hosted viewer is a static browser application. Imported ZIPs and browser databases are visitor data and are never release inputs. The local CLI remains a separate build. Keep the same Sites project and origin across releases so supported saved browser workspaces remain available.

## Source boundary

Run preparation from `stake/`:

```sh
node scripts/prepare-sites.mjs prepare /absolute/disposable/stake-sites-source
```

The destination must not exist and must be outside the app directory. The script copies only:

- `src/**/*.ts`, `src/**/*.tsx` and `src/**/*.css`;
- `public/brand/vulnops-icon.svg`;
- `package.json`, the exact `package-lock.json`, `tsconfig.json`, `vite.config.ts` and `index.html`;
- `.openai/hosting.json`, this guide and the preparation script when present;
- a generated `.gitignore` for local dependencies and browser output.

The printed sorted inventory includes the SHA-256 and size of each copied file. Symlinks and unexpected files inside source/assets fail preparation. Harness directories, Git history, server code, tests, real archives, `.env` files, screenshots and runtime state are outside the allowlist. The destination is not initialized from the harness Git repository. Never add a Sites remote to the harness checkout or push its history.

The local `stake/.openai/` binding and generated `*.tar.provenance.json` files are excluded from the public VulnOps repository. Preserve them privately. The separate private Sites source repository retains its own binding for exact-source deployment; excluding it from the public product does not remove or change that deployment.

An initial preparation can create `.openai/hosting.json` with only `"static": { "directory": "dist" }`. This is an unbound deployment configuration, not a project identity. Sites requires the `static` configuration object, whose `directory` must use a supported value; `dist-browser` is not supported. Before creating a site, inspect the existing root and viewer hosting bindings and the current Sites account. Reuse the exact matching `project_id` when present. Resolve conflicting bindings before proceeding. If no project exists, create one owner-private site, then immediately and atomically record its returned opaque ID in `stake/.openai/hosting.json` and the isolated source's matching file. Preserve other metadata. Do not recreate a site after a failed credential or upload attempt.

Preview the candidate with `npm ci` and `npm run build:web` in the isolated directory. Verify the resulting `dist-browser` on a static server using synthetic ZIPs only. The build must run without the harness, Node/Python report service, `/api/*`, remote dependencies or `unsafe-eval`. Source includes the HTTP adapter for CLI compatibility; the selected browser runtime must not invoke it. Confirm local graph workers and highlighting work and inspect requests for report-data egress.

## Exact source and artifact

Initialize a new independent repository for the first release. For subsequent releases, retain the established app-only history and remote. Stage only the reviewed allowlisted files and remove superseded app files deliberately. Bind the isolated repository to the Sites-returned source repository and branch. Keep short-lived credentials in the supported authentication flow, never in committed metadata, scripts, logs or a credential-bearing remote URL. The `work_proxy` mode uses the ordinary remote URL with authentication supplied outside the executor.

Commit and push the final source and project binding before packaging. The local branch must have an upstream, its working tree must be clean, and both local HEAD and the live upstream branch tip must equal the full selected SHA. Obtain that SHA with `git rev-parse HEAD` in the isolated checkout, then run:

```sh
node scripts/prepare-sites.mjs package /absolute/disposable/stake-sites-source FULL_PUSHED_SHA /absolute/disposable/stake-release.tar
node scripts/prepare-sites.mjs verify /absolute/disposable/stake-release.tar FULL_PUSHED_SHA
```

Packaging rejects source or historical paths outside the allowlist, symlinks, submodules, unpushed or mismatched commits, dirty inputs and existing output files. It builds a fresh `git archive` snapshot of the pushed commit using the exact lockfile, never a prior local `dist-browser`. It checks that the build did not change its source inputs and that the remote tip still matches afterward. npm's temporary cache and build checkout are removed when packaging finishes.

The browser build still writes `dist-browser`; the local CLI's `dist` output is unchanged. Artifact assembly copies the exact fresh browser build bytes into a separate staging directory named `dist/`, as required by the supported Sites static setting. It does not read or overwrite the source checkout's local `dist` or `dist-browser` output.

The deterministic POSIX tar contains only `.openai/hosting.json` with `"static": { "directory": "dist" }` and the staged static files, including `dist/index.html`. A separate `.tar.provenance.json` records the full commit/tree SHA, project ID, build-output and published directory names, sorted source/build/artifact inventories, and archive hash. Build and artifact hashes must match under the exact `dist-browser/` → `dist/` prefix mapping. This file is local release evidence, not a report store or browser asset. The `verify` command rejects a different publication SHA, changed archive, changed binding, mismatched inventory or changed copied build bytes. Hashes prove candidate consistency, not publisher authenticity. Keep the tar and provenance unchanged until Sites has accepted the version.

## Sites contract and private deployment

The live `save_site_version`/private save-and-deploy contract requires:

- the exact opaque `project_id` from the recorded binding;
- `commit_sha` equal to the current HEAD of the configured remote source branch;
- an absolute local `archive` path whose build source is that same commit;
- `.openai/hosting.json` using `{ "project_id": "<exact recorded ID>", "static": { "directory": "dist" } }` and `dist/index.html` in the tar.

Use the locally packaged archive whenever packaging succeeds. Do not label a prebuilt tar with a newer commit. If source changes, push and rebuild it. Recheck the current tool contract during each publication; this guide does not replace a platform compatibility check.

For an existing site, inspect its access configuration first. Preserve its audience; do not add public/workspace access or use a deployment call as an access probe. A newly created site starts private. Use the private save-and-deploy operation only for the known owner-private site; the backend independently enforces that access. The viewer uses no runtime credentials, database or connectors. If an accepted publish-on-push flow already created this deployment, reconcile that version instead of creating a duplicate.

Retain the saved version ID, its user-facing version number and deployment ID. A saved version is not a live deployment. Poll a nonterminal deployment, and report success only after the platform confirms it and the actual production URL passes synthetic acceptance: empty overview; ZIP import; reload and a fragment deep link; all views; graph workers; complete repair instructions, examples and archive evidence; replacement; removal; and no assessment content in outgoing paths, queries, headers or bodies. Do not publish real assessment files or captures from local validation.

## Rollback at the same origin

Before release, record the previous successfully deployed version ID when one exists. If deployment or hosted acceptance fails, retain that known-good target. Re-deploy that saved version on the same project and origin, preserving owner-private access, then verify the actual served URL. Do not create a replacement site or change the slug/domain as a rollback mechanism.

Rollback never removes visitor archives. A prior viewer that cannot read a newer saved representation must preserve its original ZIP and show recovery controls, allowing explicit replacement or removal. Browser storage is scoped to an origin/profile and can still be cleared or evicted; this workflow provides neither cross-device synchronization nor guaranteed retention.

## Verification

```sh
npm test -- tests/sites-packaging.test.ts
```

The synthetic tests check allowlist exclusions, deterministic inventories and tar output, symlink refusal, source/remote commit mismatch, dirty inputs, forbidden Git history, the static configuration object with its supported directory, unchanged project binding, exact browser-build-to-static-asset hashes, publication-SHA mismatch and altered-archive rejection. They do not establish hosted acceptance: run the browser and network checks described above against the actual deployed URL.
