# VulnOps @stake

VulnOps @stake turns completed VulnOps reports into a workspace for prioritizing findings, understanding attack paths and implementing repairs. It reads recorded assessments; it does not run audits, execute examples, inspect the current source checkout, apply patches or modify input reports.

| Runtime | Inputs and storage | Requirements |
| --- | --- | --- |
| Local CLI | Run folders; report snapshots stay in server memory and selected paths can be remembered. | Node.js 22.12+, npm, Python 3.11+ and the complete VulnOps checkout on macOS/Linux. |
| Browser / hosted | One ZIP containing an ordinary/Advantage pair; the original ZIP is saved in this browser's IndexedDB. | A modern browser. No local server, Python or harness checkout. |

The runtime is selected at build time. A failed local-server request never switches to browser mode.

## Launch locally

From the repository root:

```bash
npm --prefix stake ci
npm --prefix stake run build
npm --prefix stake start -- serve
```

The first launch opens **Load your reports**. Enter an ordinary run folder and an Advantage run folder, or select inputs explicitly:

```bash
npm --prefix stake start -- serve \
  --run "/path/to/ordinary-run" \
  --run "/path/to/advantage-run"
```

Repeat `--run` for additional inputs. Relative CLI paths resolve from the invoking directory, including `npm --prefix` launches. Quote paths containing spaces. Add `--port 43179` for a fixed loopback port or `--no-open` to open the printed URL yourself; otherwise an available port is chosen. Ctrl+C stops the server. The equivalent direct entrypoint is `node stake/dist-server/cli.js serve ...`.

Set `STAKE_PYTHON` if the Python executable is not `python3`. The bridge uses this checkout's publication reader and schemas, with no additional pip packages. After preparation, local production use is offline: scripts, fonts, highlighting and graph workers are bundled.

### Local Settings and persistence

**Settings → Report sources** accepts literal absolute paths on the server machine. Do not enter shell quotes, `~`, variables or shell expressions. **Load reports** validates both roles before switching; errors preserve the current workspace and typed paths. A successful load returns to Overview, clears old selections and keeps the theme. Closing Settings does not cancel an accepted load. Reload the same paths to capture changed files; there is no file watcher, and browser refresh alone keeps the server snapshot.

Startup precedence:

1. Explicit `--run` arguments load only those inputs. Valid inputs remain available beside failures; an entirely invalid selection exits nonzero. Repeated canonical roots import once.
2. Without arguments, a valid saved pair is re-admitted.
3. Missing, invalid or unavailable saved sources open setup with diagnostics. No valid subset is silently activated.

Only a complete ordinary/Advantage pair is remembered. A partial CLI selection, extra inputs or failed server startup cannot replace saved paths. If reports load but persistence fails, they remain usable with **Loaded for this session; paths could not be remembered**. This differs from browser import, which requires a successful durable save.

The settings file stores only `{ version: 1, ordinaryPath, advantagePath }`:

| Platform | File |
| --- | --- |
| macOS | `~/Library/Application Support/VulnOps/stake/sources.json` |
| Linux | `$XDG_CONFIG_HOME/vulnops/stake/sources.json`, or `~/.config/vulnops/stake/sources.json` |

`STAKE_CONFIG_DIR` overrides the directory with an absolute path outside the checkout and report inputs. Unsafe locations disable persistence with a diagnostic. Writes replace the complete file atomically; report contents and credentials are never stored there.

Tabs connected to one server share its selection and reconcile changes while visible every five seconds and on focus. A stale Settings draft requires **Use current sources** or reopening the sheet. Separate server processes retain independent active workspaces.

## Required publications

Each run folder needs:

```text
run-folder/
  report/security-report.json
  report/security-report.md
  final-verification/findings.json
  ... referenced canonical support
```

Use compatible schema `2.0` publications with matching execution ownership and agreement between report and final findings. Current embedded publication metadata takes precedence over retired manifests; no runtime context, task ledger, graph cache or source checkout is required. Compatible legacy publications without embedded metadata need exactly one original completed identity manifest: `run-manifest.json` or `advantage-manifest.json`. Inputs are read without migration.

Missing companions, conflicting execution IDs, mismatched dossiers and actions-only Advantage reports are rejected. Distinct folders claiming one execution are not interchangeable. Keep optional canonical support for evidence drilldowns; copying only `report/` is insufficient.

Admission checks structure, identity, companion agreement and publication hygiene. It preserves recorded review conclusions without replaying historical reviewers, validating every evidence receipt, proving publisher authenticity or establishing applicability to today's source. Supported unknown and nullable values remain unknown, including an unestablished service name.

## Import a ZIP in the browser

Open **Settings**, choose one ZIP, then select **Load assessment**. Dropping a ZIP on the empty overview opens the same form. The archive must contain two sibling run folders, optionally beneath one common wrapper:

```text
assessment.zip
  ordinary-folder/     # required publication files above
  advantage-folder/    # required publication files above
```

Folder names are arbitrary; publication metadata determines roles. Exactly one ordinary and one non-actions Advantage execution with distinct IDs is required. The ordinary run may differ from Advantage's recorded baseline, but absent baseline evidence remains unavailable. macOS packaging metadata is ignored after path validation.

Both inputs are validated before saving. **Cancel import** stops preparation; the announced saving transaction cannot be cancelled. Closing Settings lets work continue. Validation, quota or storage-write failure preserves the previous active and saved pair; there is no session-only replacement fallback. A valid zero-finding pair opens the dashboard rather than the empty shell.

| Browser bound | Limit |
| --- | --- |
| Compressed ZIP | 256 MiB |
| Entries | 20,000 |
| Declared aggregate / actually consumed expansion | 1 GiB |
| Consumed JSON/text entry | 128 MiB, subject to tighter publication limits |
| Import or worker read | 120 seconds |
| Publication nesting | 64 levels |

Only stored and DEFLATE ZIP entries are supported. Encryption, unsafe or colliding paths, links, special entries and corrupt consumed content are rejected. Files are never extracted to the host filesystem. Report JSON/Markdown may exceed 16 MiB within the browser bound; final findings and most support retain a 16 MiB publication limit, discovery/other report support 2 MiB, and receipts 64 KiB. Limits reject content rather than truncate it. See [archive limits](src/data/archive/types.ts) and [artifact policy](src/data/archive/hygiene.ts) for exact rules.

Settings shows the saved archive, executions and storage status. **Replace assessment** switches the pair; **Remove local assessment** deletes this site's saved reports while retaining the theme. Reload revalidates the original ZIP and restores valid routes. Corrupt or unsupported saved state opens recovery controls without automatic deletion. If IndexedDB is unavailable, import cannot activate a new pair. Denied persistent-storage permission does not invalidate a successful IndexedDB save.

Storage belongs to this browser profile and site origin; it can be cleared or evicted. Keep the ZIP for re-import. Tabs reconcile replacement/removal every five seconds while visible and on focus. An outdated draft requires **Use current assessment** before resubmission; a slow import cannot overwrite a newer selection.

Browser links use fragments (`/#?view=findings&finding=...`), keeping selections outside HTTP requests. Another browser needs the same ZIP. First import resumes a matching initial deep link; later replacement returns to Overview. Assessment contents are processed locally and are not uploaded. Loading the hosted shell requires connectivity; it is not an offline PWA.

## Use the workspace

| View | Purpose |
| --- | --- |
| Overview | Prioritize confirmed outcomes, environment requirements, repositories and Advantage contributions. |
| Findings | Search and filter by assessment, repository, severity, disposition, kind and classification. |
| Attack explorer | Compare recorded entrypoint associations and compositions; inspect a finding's procedure, source trace and primitives. |
| Code map | Follow findings to scoped source citations and repair locations. |
| Remediation | Read a repair brief, explore its map or inspect all repair records. |
| Assessment | Inspect assessment context, source scopes, open questions and report artifacts. |

For a developer, start with **Findings → finding → Reproduce → Repair → Verify**. Reproduce retains recorded setup, ordered actions, controlled inputs, expected effects and observations. Copying an example never executes it. Repair shows the complete implementation change, rationale, source locations and explicitly linked steps/examples. **Read repair instructions** and graph repair-location links open the owning action or exact location guide; **Open repair map** retains that action. **Show interruption** displays the graph overlay. Verify keeps attack rejection and legitimate-operation expectations separate.

Source examples appear only when explicitly linked to the action and their same-file citation covers the complete repair range. Missing excerpts are identified; citations never fabricate source. Full records, long explanations and every paginated graph/list record remain accessible.

### Interpret outcomes and graphs

- **Confirmed** means accepted in the recorded assessment scope, not necessarily dynamically reproduced. **Source-established** and **observed contained** remain distinct and apply only to their recorded claims.
- **Needs environment**, unconfirmed, non-promoted and rejected records are separate from confirmed totals. Historical records retain their original owner and scope; missing metadata is not filled from another run. Unknown is not zero.
- Advantage added outcomes are recorded new roots, new chains and impact expansions. Revalidations, corrections and historical copies remain separate. Repository totals represent associations and can overlap.
- **Proposed repair/check** does not mean applied or passed. Verification checks belong to the finding unless the report explicitly establishes a narrower relationship.

Graph connections preserve their recorded meaning:

| Projection | What a connection means |
| --- | --- |
| Entry points | A finding names that exact entrypoint within its execution, scope, source view and repository. Sharing an entrypoint does not establish composition. |
| Procedure | Next recorded exploitation step, in original order. |
| Trace | Next assessed source location, not a complete application call graph. |
| Composition | An explicit producer/consumer primitive transition, including unresolved obligations. No cross-finding transitions are invented. |
| Connected records | Explicit component, primitive, example, evidence or repair associations, not execution arrows. |
| Code / Repair map | Recorded citations, repair targets, interrupted steps and separately labeled finding context. Shared files do not imply a shared root cause. |

Repair overlays use exact `breaks_steps` and repair locations; they do not simulate a fix. Missing targets remain unavailable. Dense graphs expose focus, layers/windows and complete lists. Zoom, fit, focus-selection and minimap controls are available; arrow-key panning and Home-to-fit work while navigation controls have focus. Selection and ordering survive route reload/history, and linear views provide a keyboard alternative.

### Evidence and links

The inspector opens only registered references under their owning execution:

- Whole artifacts: `report/security-report.json`.
- Unique declared record IDs: `sast/verified-findings.json:C-001` or `#C-001`.
- JSON pointers: `final-verification/findings.json#/findings/0`.
- Inert source coordinates: `service/src/orders.ts:42-55`.

Typed inherited references require the matching loaded execution; identical filenames in another run are never substituted. `source_id`/`record_id` metadata does not create selector authority. Missing, ambiguous, corrupt or unsupported optional evidence affects that reference, not the admitted finding. Runtime state, drafts, recovery archives, raw execution material and unsafe paths cannot be browsed. Prose, external embeds and examples remain inert.

Core reports are captured at admission; optional artifacts are cached on first read. Local mode keeps these snapshots for the server generation; reload paths through Settings or restart to read folder changes. Browser mode rebuilds from the saved immutable ZIP on reload. Old handles cannot retrieve a replacement workspace's data.

Local deep links require the referenced inputs in that server and are inaccessible to other users through your loopback address. Use a fixed port for a stable local origin. Browser links do not share assessment data. Neither runtime provides shared remediation tracking, patch application, a cloud report database or full source browsing.

## Build and test

From `stake/`:

```bash
npm run typecheck
npm test
npm run build
npm run test:e2e
npm run build:web
npm run test:e2e:web
```

`build` produces CLI assets in `dist` and `dist-server`; `build:web` produces the standalone browser app in `dist-browser`. `dev` starts only Vite UI tooling; use the built CLI for local report loading. `dev:web` supports browser import. Private static publication uses the separate app-only workflow in [SITES.md](SITES.md).

Tests use synthetic reports, isolated settings and temporary servers. Build before each corresponding browser suite. Playwright uses `STAKE_BROWSER`, installed macOS Chrome, or its Chromium; install the latter during preparation with `npm exec -- playwright install chromium`. Test processes need loopback and browser-launch permission. Reserve port `43179` for local-server tests and `43181` for browser-runtime tests.

The UI uses React, Radix/shadcn-style components and Tailwind; React Flow with ELK handles graphs, Recharts handles charts, and Shiki renders inert code examples. Runtime assets are bundled locally.

### Local API contract

The loopback API enforces its Host/Origin boundary. Bootstrap endpoints are `GET /api/workspace`, `/api/workspace/sources` and `/api/workspace/version`. `POST /api/workspace/sources` accepts exactly `ordinaryPath`, `advantagePath` and `expectedGeneration`; it requires same-origin JSON and permits no other mutation.

Data requests carry `X-Stake-Workspace`. Missing generations return `428 reload_required`; stale generations return `409 workspace_changed`. Responses identify the generation used, and clients discard reads/pages crossing a replacement. Overlapping loads return `409 load_in_progress`; field admission errors return `422`. The source request body is capped at 64 KiB and each path at 16 KiB, independently of report size. There is no filesystem-listing or command-execution API. See [server routing](server/server.ts) and [source types](src/domain/sources.ts) for the complete contract.
