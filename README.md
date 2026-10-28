# yojimbo

This repository holds C#, TypeScript and Rust ports of [yojimbo](https://github.com/mas-bandwidth/yojimbo), a network library for client/server games with dedicated servers, along with the two libraries it is built on: [netcode](https://github.com/mas-bandwidth/netcode) and [reliable](https://github.com/mas-bandwidth/reliable).

The ports track upstream **yojimbo 1.13.5** (netcode 1.4.8, reliable 1.4.5). They speak the same wire protocol (`NETCODE 1.02`), so ported clients and servers interoperate with the C/C++ originals.

To use the library in a game, start with [INTEGRATION.md](INTEGRATION.md). Contributors (and Claude sessions) working on the ports: see [CLAUDE.md](CLAUDE.md).

## Layout

```
cpp/      upstream yojimbo (git submodule) - the reference source every port follows
cs/       C# port (.NET 10)
ts/       TypeScript port (Node 24+ and browsers; WebRTC for browser clients)
rust/     Rust port (std only, no dependencies)
```

Each port mirrors the upstream folder layout file for file, so an upstream change maps directly onto the file that needs it:

| upstream (`cpp/`)                                   | C# (`cs/`), TypeScript (`ts/`) and Rust (`rust/`) |
|-----------------------------------------------------|---------------------------------------------|
| `sodium/sodium.c` (libsodium subset)                | `sodium/sodium.{ts,rs}` (C# uses BouncyCastle) |
| `tlsf/tlsf.c` (allocator)                           | `tlsf/tlsf.rs` (C# and TS emulate it in their allocator) |
| `netcode/netcode.h` + `netcode/netcode.c`           | `netcode/netcode.cs`                        |
| `reliable/reliable.h` + `reliable/reliable.c`       | `reliable/reliable.cs`                      |
| `serialize/serialize.h`                             | `serialize/serialize.cs`                    |
| `include/yojimbo_X.h` + `source/yojimbo_X.cpp`      | `source/yojimbo_X.cs`                       |
| `include/yojimbo_X.h` (header only)                 | `include/yojimbo_X.cs`                      |
| `test.cpp`, `client.cpp`, `server.cpp`, `shared.h`… | `test.cs`, `client.cs`, `server.cs`, `shared.cs`… |
| `fuzz/fuzz_X.c` / `fuzz/fuzz_X.cpp`                 | `fuzz/fuzz_X.cs`                            |

Rules:

- A header and its source collapse into one file, named after the original and placed where the `.cpp`/`.c` lives. A header with no source stays in `include/`.
- Library tests live in the same file as the library, as they do upstream (`netcode_test()` is in `netcode.cs`, `reliable_test()` in `reliable.cs`).
- Names and structure stay close to the C/C++ so upstream diffs can be applied by reading them side by side.

## Building the C# port

Requires the .NET 10 SDK. Check out with submodules (`git clone --recursive`, or `git submodule update --init`): the fuzz corpus and the interop test use `cpp/`.

```bash
dotnet build cs/yojimbo.slnx
```

```bash
dotnet cs/bin/test/Debug/test.dll
```

```bash
dotnet cs/bin/custom_packet_io_test/Debug/custom_packet_io_test.dll
```

```bash
dotnet cs/bin/fuzz/Debug/fuzz.dll
```

Add `-c Release` to the build and use `bin/<project>/Release/` for a release build. `test` takes an optional random seed (`test <seed>`) to reproduce a failure.

`cs/yojimbo.csproj` is the library (yojimbo with netcode, reliable and serialize compiled in). `test`, `custom_packet_io_test`, `client`, `server`, `loopback` and `soak` are executables that reference it, matching the upstream CMake targets. Debug builds turn on the same checks as upstream's debug build: memory and message leak tracking (a leak asserts when its allocator or message factory is disposed) and the packet budget asserts.

### Allocators

Allocation goes through `Allocator` exactly where upstream calls `YOJIMBO_NEW` / `YOJIMBO_ALLOCATE`, so allocation failure and leak tracking behave like upstream. A C# allocator hands out objects built by a factory rather than raw memory, so it can refuse an allocation before anything is built; the GC reclaims what is freed. `TLSF_Allocator` keeps upstream's contract, a fixed size heap per client (`ClientServerConfig.clientMemory` / `serverPerClientMemory`) that fails with `ALLOCATOR_ERROR_OUT_OF_MEMORY` when full, so a client that exhausts its memory is disconnected. It is a byte budget over the GC, not a port of the TLSF algorithm. Left C++ only: the TLSF heap itself, the raw memory blocks behind the client and server allocators (placeholders in C#), and the netcode/reliable allocator callbacks (their buffers stay managed arrays). See the notes at the top of `cs/source/yojimbo_allocator.cs`.

### Fuzzing

`cs/fuzz` holds the upstream fuzz targets (`cpp/fuzz`). With no libFuzzer for C#, `fuzz` runs them as a regression test: it replays every seed in `cpp/fuzz/corpus` and checks the seeds the C code wrote still decode in C#, then runs a seeded mutation pass over the corpus and a batch of pseudo-random inputs. An exception or assert fails the run and saves the input as `crash-<target>-<sha1>`; `fuzz <target> <file>` replays it. `FUZZ_ITERS` (mutations per seed, default 200) and `FUZZ_RANDOM_ITERS` (random inputs per target, default 1000) make longer runs.

### Package

```bash
dotnet pack cs/yojimbo.csproj -c Release
```

builds the `yojimbo` NuGet package with Source Link symbols. The TypeScript port publishes to npm as `yojimbo2` and the Rust port to crates.io as `yojimbo`. All three packages share one version, which mirrors upstream yojimbo and folds the port's own revision into the patch: `1.13.500` is upstream 1.13.5, and `1.13.501` is the first port-only fix on top of it. `node tools/version.mjs` sets and checks it. Pushing a `v<version>` tag runs `.github/workflows/release.yml`, which tests and publishes all three.

### CI

`.github/workflows/cs.yml` builds Debug and Release on Linux, macOS and Windows, runs `test`, `custom_packet_io_test` and `fuzz`, packs the library, and runs `interop/run.sh` (all nine C++/C#/TypeScript pairings) on Linux and macOS. `.github/workflows/ts.yml` typechecks, tests and builds the TypeScript port and runs its WebRTC test on Linux, macOS and Windows. `.github/workflows/upstream.yml` watches upstream for changes to port (see [Tracking upstream](#tracking-upstream)).

## Interop

Unit tests only show that a port agrees with itself. `interop/` runs the ports against each other and against the upstream C++ build:

```bash
interop/run.sh
```

It builds `cpp/` with the system C/C++ compiler (no CMake needed), then runs all sixteen server/client pairings of C++, C#, TypeScript and Rust over UDP. The client sends 1000 reliable-ordered messages (every 8th a block, many multi-fragment) plus unreliable traffic, and verifies every echo. The connect token is generated by the client and decrypted by the server, so mixed pairings also check that the crypto agrees.

## Tracking upstream

The ports follow `cpp/`, which pins one upstream commit. `tools/upstream_diff.mjs` (Node, no dependencies) reports what upstream has done since that pin:

```bash
node tools/upstream_diff.mjs
```

It fetches upstream's default branch into `cpp/` (objects only; the checkout is untouched) and prints a Markdown report: the upstream commits past the pin, a checklist per port of the C#, TypeScript and Rust files to update with the upstream diff stat behind each, upstream files that match no mirroring rule, informational changes (docs, CMake, CI, upstream tooling) and any change to the yojimbo, netcode, reliable or serialize version macros. `--to <ref>` diffs a branch, tag or commit instead, `--from <commit>` replaces the pin, `--no-fetch` uses only what `cpp/` already has and `--out <file>` writes the report to a file. For example, the whole gap the previous port fell behind:

```bash
node tools/upstream_diff.mjs --from 5b563a6 --to v1.13.5
```

The mirroring rules live in one table, `MAP`, at the top of the script. When upstream adds a file the table doesn't cover, the report lists it under "No port counterpart": decide where it goes and add a rule.

`.github/workflows/upstream.yml` runs the report every Monday (and on demand). While upstream is ahead of the pin, it keeps a single open issue labelled `upstream-sync` with the latest report, comments when upstream moves again, and closes the issue once the pin catches up. The checklist is regenerated on each run, so ticks in it don't survive.

To sync:

1. Run `node tools/upstream_diff.mjs` (or read the issue).
2. Port each file on the checklist side by side with its upstream diff (`git -C cpp diff <pin> <upstream> -- <file>`), into every port. Port new upstream tests too. Where a port has to deviate, say so in a comment.
3. Move the pin: `git -C cpp checkout <upstream>`, then `git add cpp`.
4. If upstream's version changed, `node tools/version.mjs set <upstream version>`, and update the in-code version constants and the versions at the top of this README.
5. Run the C# tests, `custom_packet_io_test` and `fuzz`, the same three Rust binaries, the TypeScript tests (`cd ts && npm test`, plus `npm run typecheck` and `npm run test:webrtc`) and `interop/run.sh`.
6. Rerun the report: it should say the pin is at upstream.

## Building the Rust port

Requires a stable Rust toolchain (1.80 or later). See [rust/README.md](rust/README.md) for the port's conventions.

```bash
cargo build --manifest-path rust/Cargo.toml
```

```bash
cargo run --manifest-path rust/Cargo.toml --bin test
```

```bash
cargo run --manifest-path rust/Cargo.toml --bin custom_packet_io_test
```

```bash
cargo run --manifest-path rust/Cargo.toml --bin fuzz
```

Add `--release` for a release build. `test` takes an optional random seed (`test <seed>`), as the C# one does. The crate `yojimbo` is the library (yojimbo with netcode, reliable, serialize, the TLSF allocator and the libsodium subset compiled in); the programs are its binaries, as in C#. Debug builds turn on upstream's debug checks (asserts, memory and message leak tracking, the packet budget). `fuzz` replays `cpp/fuzz/corpus` and runs a seeded mutation pass, like the C# one. `.github/workflows/rust.yml` runs all three on Linux, macOS and Windows in debug and release, packages the crate, and runs the interop test.

## Building the TypeScript port

Requires Node 24+. See [ts/README.md](ts/README.md).

```bash
cd ts && npm install && npm test
```

## Author

yojimbo, netcode and reliable are by [Glenn Fiedler](https://mas-bandwidth.com). See [LICENCE](LICENCE).
