# Fork CI and releases

The fork reuses upstream's Rust toolchain, three native targets and Dockerfile.
All jobs use standard GitHub-hosted runners. It does not require cloud accounts,
paid models, custom runners or repository secrets for PR builds.

## Pull requests and main

`.github/workflows/ci.yml` runs for pull requests targeting `main`, pushes to
`main` and manual dispatches. A PR checks its proposed merge commit. The reusable
`build.yml` checks out the explicit source revision supplied by its caller.

- Rust formatting across the workspace.
- Available Cargo workspace tests and all-target Clippy, with warnings denied,
  on Linux x86-64, Linux ARM64 and macOS ARM64.
- Release binaries on each native target, with a `--version` smoke check.
- Docker builds on Linux amd64 and arm64. The final Dockerfile stage depends
  on its workspace tests and Clippy passing.
- Downloadable binaries and OCI container archives. A failed job prevents
  `CI passed` from succeeding, even if other jobs uploaded their artefacts.

The stable aggregate check is **CI passed**. Select it as a required check in
branch protection if merges must be blocked on CI. Workflow files alone do not
configure repository branch protection.

### Artefacts

Each successful native job uploads `celld-native-<target>` containing:

- `celld-<target>.gz` and its SHA-256 checksum.
- A build record containing the exact source commit, target, Rust version,
  lockfile hash and uncompressed/compressed binary hashes.
- `LICENSE` and `NOTICE`.

Container jobs upload `celld-container-linux-amd64` and
`celld-container-linux-arm64`, each containing an OCI archive and checksums.
These are OCI image archives, not native executables or Docker-save archives.
PR jobs do not push images to a registry. Artefacts are retained for 14 days.

For example, download a successful run's Linux ARM64 binary bundle:

```sh
gh run download RUN_ID --repo raeleighlabs/celld \
  --name celld-native-aarch64-unknown-linux-gnu --dir celld-build
cd celld-build
sha256sum --check celld-aarch64-unknown-linux-gnu.gz.sha256
gzip -dc celld-aarch64-unknown-linux-gnu.gz > celld
chmod +x celld
./celld --version
```

Use `shasum -a 256 --check` on macOS. Check the run conclusion and build record,
not just the presence of an artefact.

## Releases

The existing upstream tags are retained. Fork releases must use
`v<VERSION>-grapefuit.N`, where `VERSION` matches `crates/celld/Cargo.toml` and
`N` is a positive integer. For example, `v0.6.3-grapefuit.1`. Existing tags are
never moved. Use a new revision for another release.

After these workflows are merged to the default branch, create a draft from
the intended source ref:

```sh
gh workflow run release.yml --repo raeleighlabs/celld --ref main \
  -f tag=v0.6.3-grapefuit.1
```

The workflow resolves the source commit, validates the tag and runs the same
complete build/test matrix as CI. Only after all checks succeed does it collect
the three binary bundles, verify checksums, attest the binaries and create a
draft release. The draft retains build records, checksums and licence files.
It does not delete or replace an existing release.

Publishing the draft is a separate action:

```sh
gh release edit v0.6.3-grapefuit.1 --repo raeleighlabs/celld --draft=false
```

Publication runs the checks against the exact tagged commit again. The two
architecture images are then built and pushed to `ghcr.io/raeleighlabs/celld`.
The multi-architecture manifest uses their recorded digests, rather than
resolving mutable architecture tags. Published tags are:

- `sha-<full-source-commit>`
- `v0.6.3-grapefuit.1` and `0.6.3-grapefuit.1`, using the selected fork revision
- `latest`

The workflow retains image provenance and SBOMs and attests the combined image.
The repository token needs permission to write the organisation's GHCR package.
Package visibility is separate from repository visibility. If anonymous image
downloads are wanted, set the resulting package to public in GitHub's package
settings. A release can be visible while its image-publication job is still
running or has failed, so verify the Release run before using its image tags.

## Scope of verification

These jobs run tests present and enabled in this repository. They do not enable
the separate `celld_internal_tests` configuration or claim to run upstream's
external conformance corpus, model-checking specifications or fleet lab.

Grapefuit remains private. Its Go/Pi handoff, WebSocket and native-container
integration fixtures stay in Grapefuit's own checkout and validation pipeline.
Passing fork CI builds does not replace that integration evidence. No private
Grapefuit source, credentials or retained receipts are uploaded by these jobs.
