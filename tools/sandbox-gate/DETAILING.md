# Sandbox launch gate

`gate/main.go` is the static Linux PID-1 helper for native sandbox allocations.
It validates its fixed release path, per-attempt token and command, then waits on
one opened regular release file. It resolves and executes the image command only
after the exact release record is present. A malformed record or five-minute
deadline exits with status 125. The workload inherits PID-1 responsibilities.

The allocator owns the immutable per-attempt copy, read-only binds, release
approval and exact cleanup. Installing this helper does not enable sandbox mode
or change allocations that omit `sandbox`. The fixed shared-memory cap is 8 MiB.

## Build and test

Use Go 1.27.1 and Python 3, with explicit repository-local output and cache paths:

```sh
mkdir -p .tools/sandbox-gate/tmp
GOCACHE="$PWD/.tools/sandbox-gate/cache" GOTMPDIR="$PWD/.tools/sandbox-gate/tmp" \
  GO111MODULE=off GOTOOLCHAIN=local GOMAXPROCS=2 \
  go test -race -p=1 ./tools/sandbox-gate/gate
GOCACHE="$PWD/.tools/sandbox-gate/cache" GOARCH=arm64 \
  bash tools/sandbox-gate/gate-build.sh .tools/sandbox-gate/celld-sandbox-gate
```

`GOARCH` selects `amd64` or `arm64`. The recipe uses the Go standard library,
Linux, disabled cgo, one build job and trimmed paths. The adjacent `.json` receipt
records binary, source and recipe hashes, architecture and compiler identity.
Native Linux CI bundles include the compressed executable, checksum and receipt.
The OCI image includes the executable and receipt and selects the installed path
through `CELLD_SANDBOX_GATE_PATH`. macOS bundles do not include a Linux gate.

Install the matching Linux helper at an administrator-owned, non-workload-writable
path and set `CELLD_SANDBOX_GATE_PATH` on celld. Verify the checksum, build receipt
and source revision before use. ELF and inode checks establish binary identity,
not the trustworthiness of arbitrary installed code. For containerised celld,
Docker must see the helper's copied gate files and allocation journal at the same
absolute host paths as celld. The packaged helper alone does not arrange those
host mounts or prepare XFS, quotas, bridges or runc.

## Source transfer and qualification

The native implementation was transferred from the reviewed sandbox candidate
against `0dccd800affdcad6afe0c7f714e22d8820f44337`. The transferred patch SHA-256 was
`d39916950c151a980f8d5e8d2a02908267f3090c5ff8d28e5f9eb74f207fa427`.
The three helper inputs were transferred unchanged:

| Input | SHA-256 |
| --- | --- |
| `gate/main.go` | `8804101d5d61e448b89bfc0d946cbccb3e8cafe5411f6eedf116cb0c8776847e` |
| `gate/main_test.go` | `ef2c01750f5334641b8c6596e98cc7a2b6bb82d8534826a0208ec7cedcf1677d` |
| `gate-build.sh` | `4dba3ab9309a1d8330765fc7899df974b9826fa9ecd4a3c3ee0784d1242f24ee` |

This branch is now the implementation source of truth. No external patch,
Grapefuit checkout or private receipt is required to build it. The candidate's
Linux ARM64 walkthrough on 31 October 2026 exercised all three quotas, copy-up,
shared-memory exhaustion, generated-file protection, denied ioctl mutations and
checkpoint recovery. That evidence does not qualify freshly packaged binaries.
AMD64 live behaviour, genuine compat-ABI execution, broader gate fault injection
and coding-agent/PTY compatibility remain unqualified. The fixed ioctl policy
denies terminal controls that interactive workloads may need. CI unit tests and
builds are not live Docker/XFS qualification or proof of per-session VM isolation.

## Coordinator fault coverage

`crates/celld/container_sandbox_lifecycle_tests.rs` drives the actual native
allocation coordinator through its queued request API and Unix-socket Docker
adapter. It uses the sealed SQLite journal and private gate files on the host
filesystem. An independent read-only SQLite connection and file-descriptor
metadata checks observe durable records, release bytes and exact ownership.

The test-only `container_sandbox_simulation.rs` registry replaces only the
external Linux/XFS host-verification boundary and installed helper input. It
does not manufacture `/proc`, quota ioctl results or kernel mount evidence.
The Docker adapter is simulated and the ELF-shaped input is never executed.
Configuration, gate identity, journal sealing, release and cleanup code remain
the production implementations. Tests therefore establish coordinator behaviour,
not host enforcement or workload execution. Ordinary tests without a scoped
registration still use the real verifier, including its Linux-only refusal.
No simulation control is compiled into production.

The exhaustive schedules inject errors or abrupt task termination immediately
before and after approval commit, release write, release fsync, final phase
commit, both file unlinks, directory fsync, rmdir, parent fsync and tombstone
commit. Schedule 7 terminates the coordinator task and schedule 42 returns an
I/O error. Every schedule reopens the real journal and retries with faults
removed. This models process interruption and recoverable operation failures,
not loss/reordering of acknowledged writes after a machine power failure.
Explicit socket barriers cover dropped callers and concurrent cleanup. The
release oracle requires committed approval before visible release. The cleanup
oracle requires native absence and retained intent before removing owned files
and requires completed removal before the tombstone. Deadlines only bound hangs,
they do not determine the schedule.

Run the focused schedules with:

```sh
cargo test --locked -p celld --lib container::allocation::tests::sandbox_lifecycle -- --test-threads=1
```

The individual test names select release faults, cleanup faults, cancelled
waiters, approval races, verifier refusal and unconfirmed native deletion.
Fault messages include the schedule, boundary and before/after edge.
