# VulnOps offline package guide

Build on a connected host, transfer the package, then install without downloading
dependencies. Model-backed work still needs the configured LLM provider. Offline
packaging does not impose a network sandbox or change runtime permissions.

| Platform | Build and destination host |
|---|---|
| `linux_amd64` | Linux x86-64/AMD64 |
| `darwin_arm64` | macOS Apple silicon/ARM64 |

The build host must match the package platform; cross-platform builds are rejected.

## 1. Build on the connected host

Use Bash, Git, `curl`, Python **3.11+**, a clean VulnOps worktree and enough space
for tools, databases, staging copies, the archive and transport chunks. Run these
commands from the repository root.

First download the snapshot pinned in `config/osv-snapshot.lock.json`:

```bash
bash scripts/fetch-osv-db.sh
```

This preserves the lock. To intentionally create a new reviewed snapshot, run
`bash scripts/fetch-osv-db.sh --refresh-lock <snapshot-id>`, then review and commit
the lock before packaging.

Build for the current host:

```bash
# Linux AMD64
bash scripts/offline-pack.sh --platform linux_amd64

# macOS ARM64
bash scripts/offline-pack.sh --platform darwin_arm64
```

The builder installs checksum-locked tools, OMP native dependencies and WASM
grammars, then copies the verified OSV snapshot. It checks the package inventory,
relocation and extracted `setup.sh verify` before publishing:

```text
vulnops-offline-linux-amd64-<12-character-commit>.tar.gz
# or vulnops-offline-darwin-arm64-<12-character-commit>.tar.gz
offline/<platform>/offline-pack-chunks.json
offline/<platform>/*.part-*
```

Tool versions come from `config/offline-pack.<platform>.lock.json`. The package
includes the required grammars and native runtime; system Node and zstd are not
installation prerequisites.

| Option | Purpose |
|---|---|
| `--output /path/to/archive.tar.gz` | Choose the archive destination, outside `offline/`. |
| `--force` | Replace an existing output. |
| `--allow-dirty` | Include uncommitted source and label the package as a development build. |
| `--include-config` | Include local `config.toml` instead of the template. This may disclose credentials in the archive and every chunk. |

Existing generated archives and platform chunks do not make a release build dirty.
Prefer the template and configure credentials after transfer.

## 2. Transfer the archive or its chunks

### Complete archive

Create a checksum on the build host and transfer both files. On Linux:

```bash
sha256sum vulnops-offline-linux-amd64-<commit>.tar.gz \
  > vulnops-offline-linux-amd64-<commit>.tar.gz.sha256
```

Verify on the destination:

```bash
sha256sum -c vulnops-offline-linux-amd64-<commit>.tar.gz.sha256
```

On macOS, use `shasum -a 256` and `shasum -a 256 -c` with the Darwin archive.
SHA-256 checks integrity against the received checksum; publisher authenticity
requires a separately authenticated channel.

### Transport chunks

Transfer this layout from the same release:

```text
offline-build.sh
scripts/offline_package.py
scripts/osv_snapshot.py
offline/<platform>/offline-pack-chunks.json
offline/<platform>/*.part-*
```

Reconstruct the archive with one of:

```bash
./offline-build.sh --platform linux_amd64
./offline-build.sh --platform darwin_arm64
```

Optional `--output /path/to/archive.tar.gz` changes the destination; `--force`
replaces an existing archive. The command checks chunk names, order, sizes and
hashes, rejects unexpected chunks and verifies the final archive. Do not manually
concatenate parts or edit the manifest.

## 3. Install and configure

The destination needs the matching OS/architecture, Bash, Git, `tar`, Python
**3.11+**, standard command-line utilities and disk space for the installation
and assessment outputs. Tool registries and package managers are not needed.

Extract into an empty directory, using the matching archive name:

```bash
mkdir vulnops-offline
tar -xzf vulnops-offline-linux-amd64-<commit>.tar.gz -C vulnops-offline
cd vulnops-offline
bash setup.sh verify
```

Verification checks immutable inventory, platform, tools/native assets, grammars,
Codegraph relocation, all locked OSV databases and OMP startup without provisioning.
If it fails, obtain or rebuild a valid package; do not repair manifests or replace
individual immutable files.

Edit `config.toml` for your provider, authentication and all twelve `[llm.routing]`
selectors, including optional workflows. Use [config.toml.example](config.toml.example)
for current defaults and supported fields. Legacy `llm.selector`, `llm.roles` and
`llm.verification` settings are unsupported.

For OAuth authentication, use the installation's contained credential store:

```bash
bash setup.sh login openai-codex
```

Omit the provider to use the one in `llm.routing.audit_lead`. Login contacts that
provider's authentication service; it does not install dependencies. Configurations
with credentials already supplied through their supported provider mechanism can
skip login.

Generate the local OMP configuration:

```bash
bash setup.sh configure
```

This rechecks the package, performs **offline** configuration validation and writes
`.harness/offline-install.json`. It does not prove model entitlement or live
readiness. Re-run it after configuration changes. Before an audit, check provider
access explicitly; launchers also run this live gate:

```bash
bash scripts/validate-config.sh
```

An unavailable configured route fails without model substitution. Correct its
selector, provider records or credentials; use `setup.sh login <provider>` to
renew OAuth authentication. Do not refresh the model catalog or install tools to
repair an authentication failure.

## 4. Run an assessment

Place the authorized application under `target/` as one Git repository or multiple
component repositories. Directory prefixes form the source namespace. Keep this
input read-only: do not build, execute or install dependencies inside it.

```bash
./run.sh "audit the target application"

# Optional fresh informed-attacker investigation of a completed ordinary audit:
./advantage.sh <completed-audit-base> --mode deep --depth full
```

These are terminal entrypoints. Inside an existing prepared OMP session, request
Advantage through its controller instead of launching another OMP. The package
already includes its agents, skills and schemas; no plugin download is needed.
Ordinary incomplete work can resume; every explicit Advantage invocation starts
fresh. See [README.md](README.md) for workflow selection, authentication alternatives,
follow-on actions and separate production remediation.

Reports live in `scans/`, runtime state in `.harness/` or `work/`, and linked
remediation bundles in `remediations/`. Transfer completed reports with their
sanitized canonical evidence, excluding target source, runtime state, credentials
and recovery archives.

## Runtime boundaries and updates

The template uses `harness.network.linux_agent_egress = "policy_only"` and
`harness.reproduction.mode = "off"`. It needs no Bubblewrap and does not technically
enforce agent-shell egress. Canonical audit policy permits the configured LLM
connection and does not depend on other online services.

Enforced egress or safe reproduction requires functional Linux Bubblewrap, which
is not bundled. Unavailable containment never permits unsandboxed target execution
or a macOS/Docker fallback. Codegraph failures allow source-only investigation;
package verification still checks its shipped inventory. See
[ARCHITECTURE.md](ARCHITECTURE.md) for evidence and containment contracts.

- Lost only the archive: reconstruct it from unchanged verified chunks.
- Changed source, locks, schemas, runtime assets or OSV snapshot: build a new package.
- Deploy runtime and instructions together after stopping active sessions. Preserve
  completed evidence; runtime rollback does not rewrite assessment records.

Never pair a new archive with an old chunk manifest or edit package manifests by hand.
