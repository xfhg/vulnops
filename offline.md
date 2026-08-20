# VulnOps offline package guide

This guide covers three operations:

1. creating a platform-specific offline package on a connected build host;
2. rebuilding the archive from its verified transport chunks; and
3. installing and configuring the package on the destination host.

Here, “offline” describes installation: the destination can install and start the
harness without downloading tools, libraries, OMP assets, or advisory databases.
It does not describe a network sandbox or a reduced OMP runtime. OMP can connect
normally to the configured LLM provider, including an OpenAI Codex subscription.
The harness does not assume that any other online service is available.

## Supported platforms

| Package platform | Required build and destination host |
|---|---|
| `linux_amd64` | Linux on x86-64/AMD64 |
| `darwin_arm64` | macOS on Apple silicon/ARM64 |

Packages must be built on the same platform on which they will run. Cross-platform
package creation is intentionally rejected.

## 1. Create the offline package

Package creation is an online preparation operation. The build host downloads
only the checksum-locked tool assets. The resulting package contains the tools,
OMP native runtime, reviewed OSV database snapshot, schemas, agents, and harness
source required by the disconnected destination.

Local `context/` data is runtime input and is never included in an offline
package, even for a development build. Transfer it separately only when the
destination audit requires that target-specific background.

### Build-host prerequisites

- Git;
- `curl`;
- Python 3.11 or newer;
- enough space for the tools, OSV databases, staging copies, archive, and chunks;
- a clean VulnOps Git worktree for a release package; and
- network access to the locked tool and OSV asset URLs.

Run all preparation commands from the VulnOps repository root.

### Populate the locked OSV snapshot

Download and verify the snapshot already recorded in
`config/osv-snapshot.lock.json`:

```bash
bash scripts/fetch-osv-db.sh
```

This does not change the lock. Creating a new reviewed snapshot is a separate,
intentional operation:

```bash
bash scripts/fetch-osv-db.sh --refresh-lock <snapshot-id>
```

Review and commit the changed lock before producing a release package.

### Confirm the release worktree

```bash
git status --short
```

A release build requires no source changes. Existing generated archives and
platform chunk outputs are not source inputs and do not make a subsequent build
development-only. To test other uncommitted changes, use `--allow-dirty`; the
package manifest will mark the artifact as a development build.

### Build for Linux AMD64

```bash
bash scripts/offline-pack.sh --platform linux_amd64
```

### Build for macOS ARM64

Run this command on an Apple-silicon Mac:

```bash
bash scripts/offline-pack.sh --platform darwin_arm64
```

The default archive name includes the source commit:

```text
vulnops-offline-<platform>-<commit>.tar.gz
```

The builder also publishes transport chunks beneath:

```text
offline/<platform>/offline-pack-chunks.json
offline/<platform>/*.part-*
```

Package creation succeeds only after locked-asset checks, complete OSV snapshot
verification, relocation checks, archive extraction, and `setup.sh verify` all
pass.

### Useful creation options

Choose an archive path:

```bash
bash scripts/offline-pack.sh \
  --platform linux_amd64 \
  --output /path/to/vulnops-offline-linux-amd64.tar.gz
```

Replace an existing output:

```bash
bash scripts/offline-pack.sh --platform linux_amd64 --force
```

Create a development artifact from a dirty worktree:

```bash
bash scripts/offline-pack.sh --platform linux_amd64 --allow-dirty
```

Include the local `config.toml`:

```bash
bash scripts/offline-pack.sh --platform linux_amd64 --include-config
```

`--include-config` may put live LLM credentials into every archive and chunk.
Prefer the default redacted template and configure the endpoint after transfer.
Package creation validates this file but does not rewrite or restrict its runtime
capabilities.

## 2. Transfer or rebuild the archive

You can transfer either the complete `.tar.gz` archive or its chunks.

### Option A: transfer the complete archive

Create a checksum on the build host and transfer both files:

```bash
sha256sum vulnops-offline-linux-amd64-<commit>.tar.gz \
  > vulnops-offline-linux-amd64-<commit>.tar.gz.sha256
```

Verify it on the Linux destination:

```bash
sha256sum -c vulnops-offline-linux-amd64-<commit>.tar.gz.sha256
```

On macOS, use `shasum -a 256` to create and verify the checksum.

SHA-256 detects corruption or substitution relative to the checksum you
received. It does not establish publisher identity unless the checksum is
delivered through a separately authenticated channel.

### Option B: rebuild from transport chunks

Transfer a VulnOps release tree containing:

```text
offline-build.sh
scripts/offline_package.py
scripts/osv_snapshot.py
offline/<platform>/offline-pack-chunks.json
offline/<platform>/*.part-*
```

From that tree, rebuild the Linux archive:

```bash
./offline-build.sh --platform linux_amd64
```

Or rebuild the macOS archive:

```bash
./offline-build.sh --platform darwin_arm64
```

Choose a different destination:

```bash
./offline-build.sh \
  --platform linux_amd64 \
  --output /path/to/vulnops-offline-linux-amd64.tar.gz
```

Use `--force` only when intentionally replacing an existing rebuilt archive:

```bash
./offline-build.sh --platform linux_amd64 --force
```

The rebuild command validates the platform manifest, exact chunk names and
ordering, every chunk size and SHA-256, absence of unexpected chunks, and the
final archive size and SHA-256. Do not concatenate parts manually or edit the
chunk manifest.

## 3. Install on the destination host

The destination needs:

- the matching supported operating system and architecture;
- Bash, Git, `tar`, and standard command-line utilities;
- Python 3.11 or newer;
- sufficient disk space for extraction, OMP state, scans, and remediation
  bundles; and
- access to the configured LLM endpoint if model-backed audit phases will run.

Bubblewrap, Docker, package managers, and network access to tool registries are
not required for installation or the default runtime configuration. Bubblewrap
is needed only if the operator explicitly configures enforced Linux agent egress
or safe reproduction.

### Extract into an empty directory

```bash
mkdir vulnops-offline
tar -xzf vulnops-offline-linux-amd64-<commit>.tar.gz \
  -C vulnops-offline
cd vulnops-offline
```

Use the corresponding Darwin archive name on macOS.

### Verify before editing configuration

```bash
bash setup.sh verify
```

Verification checks:

- the exact immutable package inventory;
- package platform;
- tool versions, checksums, and OMP native runtime members;
- Codegraph relocation;
- every locked OSV ecosystem database;
- OMP startup without provisioning; and
- a parseable runtime configuration.

Stop if verification fails. Do not repair the extracted manifest or replace
individual package files.

### Configure the LLM endpoint

Edit `config.toml` and set the endpoint, credentials, primary and role selectors,
verifier selector, and custom-provider model records as appropriate for the
environment.

Runtime policy is independent of package format. The default template avoids a
Bubblewrap dependency:

```toml
[harness.network]
linux_agent_egress = "policy_only"

[harness.reproduction]
mode = "off"
```

You may use the full supported configuration surface. Selecting `enforced` egress
or `safe` reproduction requires a functional Bubblewrap installation on the
destination; that executable is intentionally not bundled.

For an OAuth-backed OMP subscription, authenticate it into this installation's
contained credential store. The default selector uses:

```bash
bash setup.sh login openai-codex
```

The login contacts the provider's authentication service, which is part of the
allowed LLM connection. It does not download tools, libraries, extensions, or
databases. API-key and custom-provider configurations do not need this step when
their credentials are already present in `config.toml` or the documented
provider environment variable.

Then generate the contained OMP configuration and run the full readiness gate:

```bash
bash setup.sh configure
```

Neither setup command downloads tools or databases. Successful configuration
writes a local installation receipt to:

```text
.harness/offline-install.json
```

If model resolution fails, correct the configured LLM selector, custom-provider
model records, endpoint credentials, or LLM authentication. For an OAuth-backed
provider, rerun `setup.sh login <provider>`. OMP provider traffic is not blocked
by the package. Do not run `omp models refresh` as an installation repair because
the package already contains the required OMP runtime and bundled model catalog.

### Add the audit target

Place exactly one prepared Git repository beneath `target/`:

```text
target/
└── repository-to-audit/
```

The target is read-only audit input. Do not install dependencies, build it,
execute it, or generate files inside it.

### Start the audit

```bash
./run.sh "audit the target repository"
```

All audit artifacts remain beneath `scans/`, runtime state beneath `.harness/`
or `work/`, and optional post-audit remediation bundles beneath `remediations/`.

## Rebuilding after a change

Use the correct operation for the change:

- If only the `.tar.gz` file was lost, rebuild it from unchanged verified chunks
  with `offline-build.sh`.
- If harness source, tool locks, schemas, OMP assets, or the OSV snapshot
  changed, create a new package with `scripts/offline-pack.sh`.
- Never reuse an old chunk manifest with a new package and never edit package
  manifests by hand.

## Runtime and security boundary

The package guarantees dependency-complete offline installation and integrity
checking. It deliberately does not impose a runtime network policy:

- OMP extensions, LSP support, configured provider authentication, and LLM
  traffic remain available;
- no package-specific guard blocks URL or network-capable operations;
- non-LLM online resources may be absent, so the canonical audit workflow does
  not depend on downloading tools, libraries, or advisory data;
- the default `policy_only` setting does not technically enforce agent-shell
  egress; and
- an operator who selects enforced egress or safe reproduction must provide a
  functionally supported Bubblewrap installation.

The selected runtime policy and any resulting containment limitation are recorded
in audit identity and final reports. They come from configuration and host
capability, not from the offline package format.
