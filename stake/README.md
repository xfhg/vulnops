# VulnOps @stake

VulnOps @stake is a React workspace for consuming completed VulnOps reports. Product owners can prioritize assessed outcomes; developers can follow attack procedures, inspect cited code locations, and find the proposed repairs and verification checks.

Choose ordinary and Advantage run folders in Settings, or supply run folders on the command line. @stake reads their existing publications and opens a browser on `127.0.0.1`. It does not start an audit, execute reproduction examples, inspect target source, apply patches, or change the supplied folders.

## Browser ZIP workspace

The hosted build runs entirely in your browser. On a fresh visit it shows a black overview with **Load assessment** and **Settings**. Drop one ZIP onto the page or choose it in Settings, then select **Load assessment**. A valid zero-finding assessment still opens the normal dashboard.

```text
assessment.zip
  ordinary-folder/
    report/security-report.json
    report/security-report.md
    final-verification/findings.json
    ... referenced supporting evidence
  advantage-folder/
    report/security-report.json
    report/security-report.md
    final-verification/findings.json
    ... referenced supporting evidence
```

The folders may have any names and may sit inside one common wrapper. Roles come from publication metadata. Supply exactly one ordinary and one non-actions Advantage execution; their IDs must differ. A different ordinary run from Advantage's recorded baseline is allowed, but missing baseline evidence remains unavailable. macOS packaging metadata is ignored. Current and compatible legacy schema 2.0 publications retain the same structural admission checks as local viewing.

Import reads and validates both reports before saving or switching. **Cancel import** stops preparation; **Saving assessment** finishes its atomic transaction and cannot be cancelled. Closing Settings keeps preparation running with a compact reopen control. A malformed ZIP, missing companion, incompatible publication, exceeded limit or storage-write failure keeps the previous active and saved assessment. Errors remain in Settings; successful imports add no persistent banner.

| Browser import bound | Limit |
| --- | --- |
| Compressed archive | 256 MiB |
| Entries | 20,000 |
| Aggregate declared/actual expansion | 1 GiB |
| Consumed JSON/text entry | 128 MiB, with existing tighter artifact limits |
| Import operation | 120 seconds |

Report JSON and Markdown can exceed the old generic 16 MiB ceiling; canonical final findings and optional support retain their tighter limits. No report is truncated. Password-protected archives, unsupported compression, unsafe paths, duplicate normalized entries, links and corrupt required content are rejected. Optional support is read on demand; an unavailable optional reference does not remove its finding. Nothing is extracted to your filesystem or executed.

The original ZIP and its metadata are saved in **IndexedDB**, rather than localStorage. Reload restores the same report bytes and valid finding/repair links. Settings lists the archive, both executions, import time and storage information; **Replace assessment** changes the pair, and **Remove local assessment** deletes this site's stored reports while retaining your theme. Storage is specific to this browser/profile and site address. The browser may clear or evict it; retain your ZIP for re-import. Denial of persistent-storage permission does not invalidate an otherwise successful save. Unsupported or corrupt saved data remains available for recovery/removal rather than being deleted automatically.

Tabs at the same site reconcile saved changes within five seconds while visible and on focus. A slow import cannot overwrite a later replacement/removal. An open stale draft requires **Use current assessment** before another explicit submission. Old evidence/graph results cannot populate a new generation.

Hosted report links use URL fragments, such as `/#?view=findings&finding=...`, so report selections stay out of HTTP requests. A link in another browser requires the same assessment ZIP. A first import resumes a matching initial finding link; later replacements return to Overview and clear old selections. Restoring on reload preserves the route. Neither ZIP contents nor assessment text are uploaded to Sites.

The same finding panels, attack explorer, code map and repair map remain available. Follow **Read repair instructions** to the complete action, exact file/line context and explicitly linked source examples; reproduction and verification links keep their owning execution. A source citation is recorded evidence, not access to your current checkout. The browser reader resolves canonical artifact selectors and JSON pointers from the appropriate folder and never searches another run for a substitute.

Build the standalone browser application separately:

```bash
npm --prefix stake run build:web
```

Its output is `stake/dist-browser`; it does not replace `dist` or `dist-server` used by the CLI. `npm --prefix stake run dev:web` runs browser-mode development. The build fixes the data source at startup: browser mode uses the archive/IndexedDB adapter, local mode uses the HTTP adapter. A failed server request never switches modes. See [SITES.md](SITES.md) for isolated private publication. The hosted shell needs connectivity to load; it is not an offline PWA.

## Prepare and launch locally

Prerequisites:

- Node.js **22.12 or newer**, with npm.
- Python **3.11 or newer**, available as `python3`, on the harness's supported macOS/Linux platform.
- This complete VulnOps checkout: the bridge uses `scripts/report_bundle.py` and the bundled schemas. The bridge needs no additional pip packages.
- A modern browser. Ordinary use does not require Playwright.

From the repository root, install the pinned dependencies and build during preparation:

```bash
npm --prefix stake ci
npm --prefix stake run build
```

Start the local workspace:

```bash
npm --prefix stake start -- serve
```

On the first launch, **Load your reports** asks for an ordinary run folder and an Advantage run folder. Later launches attempt the last successfully remembered pair. Use **Settings → Report sources** to change the pair while the server is running.

To select completed runs explicitly, replace the following paths:

```bash
npm --prefix stake start -- serve \
  --run "/path/to/ordinary-run" \
  --run "/path/to/advantage-run"
```

Arguments identify run-directory roots. Inside `stake/`, both launch forms are available:

```bash
npm start -- serve
npm start -- serve --run "/path/to/ordinary-run" --run "/path/to/advantage-run"
```

The built CLI can also run directly:

```bash
node stake/dist-server/cli.js serve --run "/path/to/run" --port 43179 --no-open
```

Repeat `--run` for additional inputs. Explicit arguments take precedence over saved sources and never fall back to them after an import failure. CLI relative paths resolve against the directory from which the command was invoked, including `npm --prefix stake` launches. Quote CLI paths containing spaces. Without `--port`, the operating system selects an available loopback port. An occupied explicitly requested port is an error. `--no-open` leaves browser opening to you; if automatic opening fails, the printed URL remains usable. Press Ctrl+C to stop the local process.

If Python has another executable location, set `STAKE_PYTHON` to that executable before starting. @stake reports missing interpreter or checkout prerequisites and does not install anything automatically.

After installation and build, the production viewer operates offline. Its fonts, scripts, syntax highlighting, charts and graph worker are local assets; imported external embeds are not fetched. Launching @stake does not require an LLM endpoint or network access.

## Select and remember report sources

Open **Settings → Report sources** beside the theme control. The sheet lists the current inputs separately from the two editable role fields. Enter literal absolute paths on the machine running the server, then choose **Load reports**. Paths may contain spaces; do not add shell quotes, `~`, environment variables or shell expressions to the fields. Settings does not upload folders or browse the filesystem.

Both folders must pass admission together, identify different canonical roots, and match their ordinary/Advantage roles. A field error keeps the current workspace, saved pair and typed paths intact. A successful load replaces the workspace at the same local URL, returns to Overview, and clears old report filters, findings, graph selections and evidence inspectors while retaining the theme. Closing an unsubmitted sheet discards its draft. Closing during an accepted load does not cancel the operation; progress remains visible in the workspace.

Loading the same paths again deliberately creates a fresh snapshot, including optional evidence. Browser refresh alone retains the server's current snapshot. There is no file watcher. All six workspace views switch together; a source change does not perform new vulnerability verification.

Startup follows this precedence:

| Inputs | Startup behavior |
| --- | --- |
| Any explicit `--run` arguments | Load only those inputs, retaining generic CLI partial admission and repeated-root deduplication. An entirely invalid selection exits with an error. |
| No explicit inputs, valid saved pair | Re-admit both saved folders and open the workspace. |
| No explicit inputs, no saved selection | Open setup with empty fields. |
| No explicit inputs, invalid settings or unavailable saved folders | Open setup with diagnostics and any recoverable paths. No valid subset is silently activated, and the settings file is retained. |

A successful Settings load remembers canonical absolute paths. An explicit CLI selection is remembered only after the server successfully starts and the complete canonical input set contains exactly one ordinary and one Advantage publication without failures. A single input, more than two inputs, a partial CLI import or a failed listener does not replace the saved pair.

If the reports load but saving fails, the workspace remains usable and announces **Loaded for this session; paths could not be remembered.** Previous settings remain intact. A lost browser response is reconciled against server load state; the browser does not automatically submit the load again.

The settings file contains only format metadata and the two paths:

```json
{
  "version": 1,
  "ordinaryPath": "/absolute/path/to/ordinary-run",
  "advantagePath": "/absolute/path/to/advantage-run"
}
```

| Platform | Default settings file |
| --- | --- |
| macOS | `~/Library/Application Support/VulnOps/stake/sources.json` |
| Linux | `$XDG_CONFIG_HOME/vulnops/stake/sources.json`, or `~/.config/vulnops/stake/sources.json` when unset |
| Windows settings resolver | `%APPDATA%/VulnOps/stake/sources.json`, with the user's roaming application-data directory as fallback; the harness runtime remains supported on macOS/Linux. |

Set `STAKE_CONFIG_DIR` to an **absolute directory** to isolate these preferences; its file is `sources.json`. For example:

```bash
STAKE_CONFIG_DIR="/absolute/path/to/private-stake-settings" npm --prefix stake start -- serve --no-open
```

Settings writes use an atomic complete-file replacement and restrictive permissions where supported. They are kept outside the checkout, report inputs and audit state. An unsafe settings location disables persistence with a diagnostic. Reports, evidence, credentials, execution IDs and browser selections are not stored in this file. Separate server processes may remember a different complete pair; their active workspaces remain independent.

## What to supply

Each current ordinary or non-actions Advantage input requires this layout:

```text
run-directory/
  report/
    security-report.json
    security-report.md
  final-verification/
    findings.json
  ... optional referenced canonical evidence
```

The report JSON must contain compatible schema `2.0` publication identity. Its findings and canonical final findings must agree. Current bundles need no `run-manifest.json`, task ledger, runtime context, graph cache, or source checkout. Retired control files do not override embedded publication identity. Keep referenced canonical evidence alongside the report for useful drilldowns; copying only `report/` is insufficient for admission.

A component can record `service.name: null` when its service binding is unknown. This is supported: the component name, repository, entrypoints, locations and exact service limitation remain available. The viewer retains the unknown service name instead of substituting a component or repository label.

Compatible legacy schema `2.0` publications without embedded publication metadata require exactly one original completed identity manifest (`run-manifest.json` for ordinary or `advantage-manifest.json` for Advantage), plus the same publication companions and effective finding agreement. @stake reads those records without migrating them.

Actions-only Advantage reports and unsupported schema shapes produce explicit import failures. A missing required companion, conflicting execution owner, or differing final dossier rejects that input. For explicit CLI selections, other valid inputs remain available; if every explicit input fails, startup exits nonzero. Settings requires its complete two-role pair before replacing any active data. Repeated CLI arguments resolving to the same directory import once; distinct directories claiming one execution are both unavailable until you select one root.

Import performs **structural publication checks**, including companion readability, publication hygiene, identity and final-finding agreement. It preserves the report's recorded independent-review conclusions. It does not repeat strict evidence-closure checks, validate every reviewer receipt or hash, establish publisher authenticity, re-review source, or execute an attack.

## Read the results accurately

| Label | Meaning |
| --- | --- |
| Confirmed | An accepted finding within its recorded assessment scope. Confirmation alone does not mean dynamic reproduction occurred. |
| Source-established | The recorded step is supported by source review; expected effects remain distinct from observations. |
| Observed contained | A recorded contained observation supports this specific claim or step. Other steps do not inherit that status. |
| Needs environment / environment-required | A named external or deployment prerequisite remains unresolved. These records are excluded from confirmed severity totals. |
| Historical | An imported dossier retains its original execution and scope. Its presence does not establish later-source applicability. |
| Unconfirmed, non-promoted, rejected | Separate recorded dispositions, not additional confirmed vulnerabilities. |
| Advantage added outcomes | Recorded new roots, new chains and impact expansions. Revalidations, corrections and historical copies remain separate categories. |
| Proposed repair / proposed check | Guidance recorded in the report. @stake does not claim a patch was applied or a test passed. |
| Unknown | The report does not establish the value. Unknown is not zero. |

Findings use their execution plus finding ID as identity. Identical embedded history can share the loaded baseline's historical record; revalidation and impact expansion remain distinct assessment results. Conflicting representations are disclosed. Matching titles or source filenames do not establish identity or a chain.

Assessment time, publication time, source view and recorded revision remain separate. Missing metadata is not filled from today's checkout or another report. Bounded accounting cohorts retain recorded totals and omitted counts. Coverage cohorts can overlap; cited locations are not a repository coverage percentage.

## Owner and developer workflows

| View | What to do there |
| --- | --- |
| Overview | Drill into confirmed outcomes, critical/high findings, recorded chains or environment-required outcomes. Review the priority table, repository distribution, Advantage contributions and developer handoff. |
| Findings | Combine search with assessment, repository, severity, disposition, kind and classification filters. Filtered counts do not replace assessment-wide totals. |
| Attack explorer | Explore findings grouped by recorded entrypoint, or review all recorded compositions. Open a finding for its procedure, code trace and composition with an evidence inspector or linear list. |
| Code map | Browse cited repositories, components, files and locations; follow related findings and repair points. No source checkout is required. |
| Remediation | Start with a repair brief, then explore its Repair Map or complete record inventory. Follow source locations, interrupted steps, examples and finding-level checks into the evidence, Code Map and finding dossier. |
| Assessment | Switch between an assessment summary, source-scope table, open-question cohorts and evidence artifacts. Expand supporting records only when needed. |

A typical developer path is **Findings → selected finding → Reproduce → Repair → Verify**. Read setup and conditions first. Reproduce provides the recorded ordered actions, controlled inputs, expected effects, actual observations where present, and copyable examples. Copying never executes an example. Repair links concrete changes and locations to the steps they interrupt. Verify separates expected attack rejection from preserved legitimate behavior and shows whether checks remain proposed.

Complete dossier content remains reachable through the finding panels and full-record disclosure. Tables and details load separately; pagination does not remove findings. Canonical reports have no inherited 16 MiB rejection ceiling, and successful imports retain complete dossiers. An actual resource or loading failure is reported instead of silently truncating data.

## Visual organization

The interface uses the VulnOps Doberman identity with a prominent VulnOps wordmark and smaller @stake label. Both themes retain the reference palette—black (`#000000`), deep red (`#830000`), crimson (`#bc0202`) and bright red (`#ff0000`)—with `#ff1d58` as the additional primary highlight. Primary actions, selected navigation and priority emphasis use the new highlight; text shades adapt to each surface for readable contrast. Light mode pairs neutral white surfaces with pink priority accents; dark mode uses charcoal and a subtle pink-tinted priority surface. Small text uses contrast-adjusted shades. Status labels and graph line patterns preserve their meaning independently of color, including gray dashed uncertainty and red repair highlights. Locally owned shadcn-style components use Radix behavior for tabs, accordions, sheets, scroll areas and expandable Trace rows. Assessment separates its summary, source scope, open questions and evidence into focused tabs; detailed records stay available through expandable sections and pagination.

Overview uses independently stacked desktop columns so a tall repository inventory does not leave a blank area beneath shorter sections. Repository rows and handoff facts stay compact; high/critical outcomes receive the strongest primary-color emphasis. Overview counts follow the selected assessment and repository. The priority table orders confirmed outcomes by severity, then natural finding ID; its environment-required tab stays separate. Advantage new roots, new chains and impact expansions are distinguished from revalidations and corrections. Repository rows show finding associations, so a finding spanning two repositories appears in both rows. Repair guidance counts describe recorded actions, with no applied or verified status inferred.

Finding headers separate title, severity and disposition from repository, verification and action counts. Long summaries expand from a three-line preview. The Assessment context disclosure contains complete execution and scope identifiers; historical navigation also identifies the owning execution in a visible banner. Attack-path controls occupy their own compact panel inside the Attack map tab.

Finding details open with the explanation and a direct **Read repair instructions** action. The Summary → Reproduce → Repair → Verify navigation sits immediately below the header; **Attack map** and **Evidence** remain separate destinations. Repair changes are fully visible, with source context and copyable exact citations before secondary associations. Linked steps and technical examples open and focus their written records; returning selects the originating repair action. **Open repair map** binds the exact finding, assessment scope and action, and **Back to repair map** restores that context. Graph overlays remain available through **Show interruption**. Their repair alerts link directly to the selected implementation action or exact change location. Each repair location shows its full path, line, recorded mechanism and explicitly linked source excerpts whose citations cover that coordinate; missing excerpts are identified. Repair Map location controls open the same guide, while citation evidence remains a separate supporting view. Direct panel and record links survive reload and browser history.  Summary uses the shadcn Trace pattern for recorded access, boundary failure, impact and source citations. Short previews expand to the full original explanation; citations remain directly accessible. These are static assessed records, not live execution statuses. Affected components expand into numbered entrypoint inventories, separate service context and source-location tables. Reproduce pairs a compact setup checklist with ordered steps, expected and observed effects, evidence links and copyable examples. Repair leads with the proposed control change, lists its explicit interruption points and source locations, and separates containment, detection, limitations and unresolved decisions. Verify pairs attack rejection with legitimate-operation expectations; Evidence presents assessment facts, revisions and the ordered source trace. Full records are available on demand, with their original content and reference ownership retained.

The dashboard composition follows [shadcn Blocks](https://ui.shadcn.com/blocks); the finding explanation adapts [Radix Trace](https://ui.shadcn.com/docs/components/radix/trace) to the existing Radix primitives and theme. The project’s `components.json` uses the standard registry. For optional development-time registry access, configure the [shadcn MCP server](https://ui.shadcn.com/docs/mcp) with this folder as its working directory. The viewer itself does not use MCP or contact the registry at runtime. The tested development configuration pins the shadcn CLI and points it at this project:

```bash
codex mcp add shadcn -- npx -y shadcn@4.23.0 mcp --cwd /absolute/path/to/stake
```

Restart Codex after adding the server so its registry tools become available.

## Graph semantics

The Attack explorer starts with a workspace map. **Entry points** groups the exact recorded `affected_components.entrypoints` labels within one execution, assessment scope, source view and repository. A dashed association means the finding cites that entrypoint. Shared entrypoints do not establish a composed exploit. Missing scope metadata keeps records separate, and findings without a recorded entrypoint remain explicitly accessible.

**Composed attacks** shows the recorded compositions together, retaining separate finding ownership and only the primitive transitions recorded by each dossier. Choose a finding to inspect its full evidence and the three detailed representations below. No cross-finding capability edge is synthesized from a shared route or file.

Graph ordering is explicit and stable:

- **Entry points** defaults to most shared first, with alternatives for finding priority and repository/route. Connected association groups occupy separate lanes; routes stay on the left and findings on the right. Findings within a group follow disposition, severity and natural finding ID.
- **Composed attacks** uses one labeled lane per finding, ordered by finding priority or natural finding ID. Recorded producer/consumer dependencies determine left-to-right placement; independent branches use recorded order as a tiebreaker. Cycles and disconnected primitives remain present.
- **Finding priority** orders confirmed, environment-required, unconfirmed, non-promoted and rejected records, then severity, then natural finding ID and complete execution/scope identity. Sorting never changes a recorded disposition.

Maps with more than 24 entrypoints initially focus the highest-ranked route. The focus selector explicitly exposes the complete association map, and searching covers all routes when using this automatic focus. Existing selected deep links retain the full map. “Focus selected group” zooms into a lane; “Fit View” includes every displayed lane and its header. Sort choices and selected record identities survive URL reload and browser history.

- **Procedure** uses the original exploitation steps and their IDs in recorded order. Sequence edges mean “next recorded action,” not inferred function calls.
- **Trace** uses the original ordered source locations, symbols and explanations. It represents the assessed flow, not a complete application call graph. A two-step procedure can legitimately have eight trace entries.
- **Composition** uses only recorded primitives and producer/consumer transitions, including their proof obligations and unresolved conditions. Shared files and similar titles never create new attack chains. An empty composition is a valid state.

Selecting a repair highlights its exact `breaks_steps` and recorded repair locations. The overlay is guidance, not a simulation of successful protection. Missing relationship targets remain visible as unavailable instead of selecting a similarly named step elsewhere.

**Connected records** adds the selected action's or transition's explicitly referenced components, primitives, examples, evidence and proposed repairs. Dotted links describe associations; they never become execution arrows. Select one to inspect its metadata and original references. **Selected neighborhood** focuses adjacent recorded steps without inventing shortcuts; turn it off to restore the full projection. Metadata selection survives URL reload, and the linear view exposes the same relationships.

**Code map** connects findings to exact cited source ranges and proposed repair locations within the selected execution, assessment scope and source view. The file is a visual group; finding-to-source citations, explicit repair locations and supporting repair evidence have distinct line patterns. Connections retain their finding ownership and original explanation. Selecting a node highlights its incident links; edge labels appear on hover, focus or selection. Five source ranges are shown per window, with counts and previous/next navigation; the complete location list remains available. Narrow panes initially focus a readable source range, with Fit View available for all displayed connections. Sharing a file or coordinate does not establish a shared root cause or a call relationship.

**Remediation hierarchy** begins with a repair brief: the proposed change, its recorded rationale, a compact source-location preview and links to interruptions and finding-level checks. Scope totals are secondary. The queue orders confirmed findings first and then severity; narrow layouts collapse it behind **Choose a repair**. **Repair map** and **All repair records** are separate reading tabs, and the inspector opens after selecting a record or connection. Assessment context and complete records remain available through disclosures. Explicit graph links still open the map directly; an explicit tab choice takes precedence, survives reload and retains the selected action. Switching away from and back to the map preserves its layers and window.

**Repair map** centers one proposed action and separates its explicit change locations/components from interrupted steps/examples. The optional finding-context layer links verification checks, containment, detection, limitations and unresolved decisions to their owning finding; it never invents action-specific check relationships. A searchable queue orders actions by finding disposition, severity and natural IDs. Reused action IDs remain qualified by their finding, execution and assessed scope. The graph shows three records per layer window with complete counts, paging and a jump-to-record selector; the list view exposes every record. Selected records and connections survive reload and browser history. The inspector retains original status and evidence ownership, exact source ranges and unavailable references, and provides direct handoffs to Code Map, reproduction and verification. Historical-only recommendations are labeled, including when their original run is embedded in an Advantage report.

All canvases provide zoom percentage, fit-all, focus-selection and a pannable/zoomable minimap. Contextual node toolbars open findings or citations; overview lane headings focus their group. Nodes simplify their presentation when zoomed out. Controls support keyboard panning with arrow keys and fit-all with Home; textual labels accompany status colors. The interface supports narrow layouts and reduced-motion preferences. These interactions use React Flow's custom nodes and edges, handles, node toolbars and parent/child grouping.

## Evidence navigation

The evidence inspector resolves only references registered from an admitted publication or subsequently read canonical support. References retain their owning execution, artifact and selector:

- Whole canonical artifacts, such as `report/security-report.json`.
- Declared unique record selectors, such as `sast/verified-findings.json:C-001`.
- JSON pointers, such as `final-verification/findings.json#/findings/0`.
- Source coordinates, such as `service/src/orders.ts:42-55`, shown as inert historical citations.

Typed inherited references can resolve only through an explicitly loaded matching execution. A same-named file in another run is not substituted. Missing optional support is reported at that reference without removing an accepted finding. Ambiguous or unsupported selectors remain unavailable.

Source citations do not open the current checkout or fabricate excerpts. The first release intentionally provides a citation map rather than full source browsing or revision comparison. Runtime state, drafts, recovery archives, raw execution/scanner material, absolute artifact paths, traversal, symlinks and nonregular files are not served through the evidence API. Prose and examples are rendered inertly. The only configuration operation selects report roots and remembers their paths; no reproduction, patch or report-mutation endpoint exists.

Report, Markdown and canonical final authority are captured at import. Optional artifacts are captured on first access, and subsequent selectors use the same captured bytes. Browser reloads keep the process's existing snapshot. To read changed folders, load the same paths again through Settings or restart the CLI. Nothing is written back to imported folders.

## Local state and links

Routes preserve assessment, finding, graph mode, selection and filters, with browser back/forward support. A local-server deep link works only when its referenced inputs are loaded in that @stake process. Another user cannot access your loopback server through that link. The default port can change after restart; use an explicit port if you need a stable local origin.

Theme preference is stored locally in the browser. In local server mode, reports and normalized dossiers remain in server memory; in browser mode, the original ZIP is saved in IndexedDB and reconstructed into memory on restore. Neither mode stores assessments in a cloud database. Panel layout is presentation state; editable remediation tracking, collaboration, shared assessment storage, patch application and full source browsing are outside this release.

Tabs connected to the same server share its current source selection. Visible tabs check for changes every five seconds and refresh on focus. A changed generation invalidates old requests and returns the tab to Overview. An open source draft is marked stale; use **Use current sources** or reopen Settings before submitting it. Its earlier paths are never silently rebased and submitted. Old deep links remain unavailable when their execution or finding is no longer loaded. Paths are not added to URLs. Successful loads return to Overview without a persistent success banner; progress, load errors and a failure to remember paths remain visible when relevant.

Deploy the rebuilt client and server together and restart an older running server once to enable source settings. Subsequent source changes use Settings without restarting. Rolling back the viewer requires no report migration; the earlier CLI can still load explicit paths and ignores the settings file.

## Local API generations

The API is loopback-only and accepts requests for its actual local Host. The browser handles generation headers and reconciliation automatically.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/workspace` | Bootstrap the active summary and opaque `generation`. |
| `GET /api/workspace/sources` | Current source descriptors, recoverable saved pair, origin, loading state, latest load result and persistence outcome. |
| `GET /api/workspace/version` | Lightweight `generation`, `loading` and `lastLoadId` for synchronization. |
| `POST /api/workspace/sources` | Submit exactly `ordinaryPath`, `advantagePath` and `expectedGeneration`; prepare, remember and replace a complete pair. |

Finding, assessment, relationship, reference and evidence requests must send `X-Stake-Workspace` with the expected generation. Workspace data responses carry the generation they actually used in that header. Missing generations receive `428 reload_required`; stale generations receive `409 workspace_changed`. Evidence handles also belong to one generation, so an old handle cannot retrieve newly loaded bytes even when execution and artifact IDs are reused. A pagination sequence that crosses a switch must be discarded and restarted.

The source POST requires an explicit Origin matching the server, matching Host, non-cross-site fetch metadata and `application/json`. Its body is capped at 64 KiB and each path at 16 KiB; these limits do not cap report size. Overlapping loads receive `409 load_in_progress`, stale submissions `409 workspace_changed`, and field admission errors `422`. Configuration syntax, media type and size errors return `400`, `415` and `413` respectively. Other mutations remain denied. No CORS, general filesystem listing or command-execution API is provided.

## Development checks

From `stake/`:

```bash
npm run typecheck
npm test
npm run build
npm run test:e2e
npm run build:web
npm run test:e2e:web
```

`npm test` runs unit and integration tests, including synthetic publication admission, reference boundaries, settings persistence and local loopback serving. Tests use temporary settings directories; every CLI/browser subprocess receives an isolated `STAKE_CONFIG_DIR`, so fixtures cannot replace a user's remembered sources. The browser suite uses synthetic paired bundles, starts its own local servers and exercises the production build. Build before running it. Real report contents are not copied into committed fixtures or screenshot baselines.

Browser tests use `STAKE_BROWSER` when set to a browser executable, otherwise the standard macOS Google Chrome executable when installed. If neither is available, install Playwright Chromium during preparation:

```bash
npm exec -- playwright install chromium
```

That preparation command may download a browser. Tests and normal production use need no runtime CDN or external model service. Sandboxed environments must permit the test process to listen on loopback and launch its browser. The shared browser fixture reserves port `43179`; source-switching cases use separate temporary servers so they cannot replace other tests' data. Stop another process using port `43179` before running the suite.

The supported production entrypoint is the built Node CLI. `npm run dev` starts Vite's UI development server; it is not a replacement for the report-loading CLI.
