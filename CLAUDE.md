# CLAUDE.md

C#, TypeScript and Rust ports of the yojimbo C++ network library (with netcode, reliable, serialize and the libsodium subset netcode uses). To *use* the library in a game, read [INTEGRATION.md](INTEGRATION.md). This file is for working *on* the ports.

## Layout

- `cpp/`: upstream yojimbo as a git submodule (`mas-bandwidth/yojimbo`, pinned at 1.13.5). The reference every port follows. Never edit it; to move to a new upstream version, bump the pin.
- `cs/`: C# port. The library `cs/yojimbo.csproj` (NuGet id `yojimbo`) targets `net10.0` and `netstandard2.1`, for Unity and other .NET Standard runtimes; the programs run on .NET 10. The executables are `test`, `custom_packet_io_test`, `fuzz`, `client`, `server`, `loopback` and `soak`, all in `cs/yojimbo.slnx`.
- `ts/`: TypeScript port for Node 24+ and browsers (npm package `yojimbo2`; plain `yojimbo` is taken on npm). `ts/webrtc/` adds browser clients over WebRTC, with the server on Node or in a browser page; it is an extension, not an upstream mirror.
- `rust/`: Rust port (crate `yojimbo` on crates.io), std only, no dependencies. The binaries are the same seven as C#, declared in `rust/Cargo.toml`.
- `interop/`: runs C++, C#, TypeScript and Rust against each other in all sixteen server/client pairings. `interop/rust` is the Rust side, its own cargo package.
- `tools/version.mjs`: the package version tool (see Versions and releases). `VERSION` at the root is the source of truth.
- `tools/upstream_diff.mjs`: the upstream change report (see Syncing with upstream).

## Mirroring rules (keep them)

- File for file with `cpp/`: `include/yojimbo_X.h` + `source/yojimbo_X.cpp` collapse into `{cs,ts,rust}/source/yojimbo_X.{cs,ts,rs}`; a header with no source goes to `{cs,ts,rust}/include/`. `netcode/`, `reliable/`, `serialize/`, `fuzz/` and the top-level tests and samples keep their upstream names. `sodium/sodium.c` maps to `ts/sodium/sodium.ts` and `rust/sodium/sodium.rs`; C# uses BouncyCastle. `tlsf/tlsf.c` maps to `rust/tlsf/tlsf.rs`, a real port; C# and TypeScript emulate it inside their allocator file. TypeScript has no fuzz port.
- `MAP` in `tools/upstream_diff.mjs` holds these rules as data. Every rule names every port in `PORTS`, so a new upstream file or a new port means a new rule there.
- Library tests live inside the library file, as upstream (`netcode_test`, `reliable_test`, `serialize_test`).
- Keep upstream names and the order of members within each file, so an upstream diff can be applied by reading it side by side. Where a port must deviate, say so in a comment at the deviation.
- The wire format must stay byte-identical to upstream. `interop/run.sh` is the proof; run it after anything that touches packets, serialization or crypto.

## Commands

```bash
dotnet build cs/yojimbo.slnx                                  # add -c Release for release
dotnet cs/bin/test/Debug/test.dll                             # 147 tests: serialize, netcode, reliable, yojimbo
dotnet cs/bin/custom_packet_io_test/Debug/custom_packet_io_test.dll
dotnet cs/bin/fuzz/Debug/fuzz.dll                             # upstream fuzz corpus replay + seeded mutation
cd ts && npm ci && npm test                                   # 212 tests (node test.ts)
cd ts && npm run typecheck && npm run build && npm run test:webrtc && npm run test:bundle
cd ts && npm run test:declarations                             # packed declarations type-check on TypeScript 5.0 and latest
cd ts && npx playwright-core install --only-shell chromium && npm run test:browser   # server hosted in headless Chromium
cargo build --manifest-path rust/Cargo.toml                   # add --release for release
cargo run --manifest-path rust/Cargo.toml --bin test          # 193 tests: serialize, netcode, reliable, yojimbo (test <seed> reproduces a run)
cargo run --manifest-path rust/Cargo.toml --bin custom_packet_io_test
cargo run --manifest-path rust/Cargo.toml --bin fuzz          # upstream fuzz corpus replay + seeded mutation
interop/run.sh                                                # needs cc/c++, .NET 10, Node 24, cargo
```

- **Tests bind fixed UDP ports** (40000, 30000, ...), so never run two suites at the same time. A "bind failed" or "server_create failed" error often just means another run held the port; rerun before debugging. On Windows with WSL's mirrored networking, a running WSL VM holds UDP 39160 and up: run `wsl --shutdown` before the Windows suites.
- **Linux from Windows:** WSL (Ubuntu 22.04 here) has Rust and gcc but no .NET or Node. Copy the worktree into the Linux filesystem (not `/mnt/f`) and build there. Run scripts as `wsl -e bash /mnt/c/.../script.sh`: inline `wsl -e bash -lc '...'` quoting through PowerShell breaks.
- **CI:** `.github/workflows/cs.yml` runs C# on Linux, macOS and Windows plus interop; `ts.yml` runs TypeScript on all three, plus a `browser` job (headless Chromium, Linux); `rust.yml` runs Rust debug and release on all three plus interop. All must stay green. `upstream.yml` runs weekly and keeps one `upstream-sync` issue open while upstream is past the pin.

## Port conventions

- **.NET Standard 2.1:** `cs/netstandard.cs` fills in the newer APIs the port uses: compiler attributes, `BitOperations`, `ReferenceEqualityComparer`, and C# 14 extension members such as `OperatingSystem.IsWindows` and `Convert.ToHexString`. That lets ported files compile unchanged for both targets.
  - When you use a newer .NET API, either add a polyfill there or guard the code.
  - `Int128`/`UInt128` code is guarded with `#if NET7_0_OR_GREATER` (in tests, `#if !YOJIMBO_NETSTANDARD`).
  - Run the tests against that build with `dotnet build cs/test.csproj -p:YojimboTargetFramework=netstandard2.1 -p:BuildRoot=<other dir>/`. Use a separate output folder so the default build isn't overwritten. CI runs both.
- **Port additions** (not in upstream; keep them through upstream syncs, in every port): `ChannelConfig.allocateBlocksOnDemand` (on-demand block receive buffers in the reliable-ordered channel, tested by `test_connection_reliable_ordered_blocks_on_demand`) and `TLSF_Allocator.GetUsedBytes()`/`GetCapacityBytes()`. Mark any new one with a "port addition" comment where it lives.
- **C#:** C-style names as upstream (`netcode.client_create`, `reliable.endpoint_send_packet`, the `yojimbo` static class for free functions). The stream `serialize_*` extension methods return bool; every call site must propagate a failure. The allocator semantics are real (error level, leak tracking, failure injection in tests).
- **Rust:** see [rust/README.md](rust/README.md), which holds the binding conventions, and [rust/rust.md](rust/rust.md), the port's verification status, open bugs, deviations and gaps. Update `rust.md` when you close a gap or find a new one.
  - Upstream names verbatim (`netcode_client_create`, `Client::Connect`, `m_clientIndex`); the crate allows the casing. Enums are `pub const` `i32`s, and Rust keywords are raw identifiers (`r#type`).
  - The pointer rules are mechanical, so separately ported files fit together:
    - buffers are slices and keep their length parameter, and out-parameters are `&mut T`;
    - netcode/reliable objects are `Option<Box<T>>` from `*_create`;
    - yojimbo's C++ object graph stays raw pointers (`*mut dyn Allocator`, `*mut dyn Message`, ...), created and destroyed through the `Allocator` (`YOJIMBO_NEW!` / `YOJIMBO_DELETE!`), so allocation failure, budgets and leak tracking behave as upstream. Null trait pointers come from `null_<trait>()`.
  - Virtual classes are a trait plus a `<Class>Base` struct. `BaseClient`/`BaseServer` call back into `Client`/`Server` through `BaseClientVirtual`/`BaseServerVirtual`. `Client::new` / `Server::new` return `Box<_>`: netcode and reliable keep a raw context pointer to the object, so it must not move.
  - `serialize_*!` macros keep upstream names and return `false` from the enclosing fn on failure. A stream's allocator `void *` carries a pointer to the `*mut dyn Allocator` (`AllocatorToContext` / `AllocatorFromContext`, `MessageFactory::GetAllocatorContext`).
  - Keep upstream's system calls where their side effect matters: `yojimbo_sleep( 0.0 )` / `netcode_sleep` must yield (`usleep`/`nanosleep` on unix, `Sleep( 0 )` on Windows). `std::thread::sleep` makes no system call for zero, and skipping the yield broke the UDP tests on Linux only. See [rust/rust.md](rust/rust.md).
  - C wraps unsigned arithmetic, so write `wrapping_*`. `overflow-checks` is off in every profile as a safety net.
  - Library tests stay in the library file (`serialize_test`, `netcode_test`, `reliable_test`), and test-local macros are plain `macro_rules!`. Don't `include!` a file whose `#[macro_export]` macros are used through `$crate::`: it fails to compile.
  - The netcode/reliable allocator callbacks stay in the configs, but buffers are `Vec`/`Box`, as in C#. The netcode client/server and network simulator still ask `allocate_function` first, so upstream's allocation-failure tests run.
- **TypeScript:** see [ts/README.md](ts/README.md).
  - The code is ESM, with `erasableSyntaxOnly` (no enums or namespaces).
  - Relative imports use the `.ts` extension.
  - Integers up to 32 bits are `number`; 64-bit values are `bigint`.
  - Serialize calls use the slot API, `serialize_x(stream, obj, 'field', ...)`.
  - Consumers need TypeScript 5.0 or later. Give typed-array class fields an explicit type (`key: Uint8Array = new Uint8Array( 32 )`). Inferred, they emit `Uint8Array<ArrayBuffer>` into the declarations, which needs TypeScript 5.7. `npm run test:declarations` guards this.
  - No `node:` imports outside the platform seams: netcode's dgram socket layer loads through `process.getBuiltinModule`, and `webrtc_server_http.ts` is Node-only. `webrtc_server.ts` must stay browser-bundleable and its declarations DOM-free (`npm run test:bundle` checks the bundle).
- **Node event loop:** sockets deliver only while the event loop runs. Node reads at most 32 datagrams per socket per turn on macOS and Linux, and one on Windows. Loops over real sockets must await between frames, and test pumps yield a fixed number of turns (see `PumpEventLoopTurns` in `ts/test.ts`).

## Versions and releases

- **Packages:** NuGet `yojimbo` (C#), npm `yojimbo2` (TypeScript; plain `yojimbo` on npm is someone else's package), crates.io `yojimbo` (Rust).
- **All three packages share one version** that mirrors upstream yojimbo and folds a port revision (fixes made here between upstream releases) into the patch: MAJOR.MINOR.(PATCH × 100 + REVISION).
  - `1.13.500` is the port of upstream 1.13.5.
  - `1.13.501` is the first port-only fix on top of it.
  - `1.13.600` is the port of upstream 1.13.6.

  `VERSION` holds it, and release tags are `v<VERSION>`. Never publish a plain upstream number such as `1.13.5`: it would sort below the folded ones.
- **Use the tool, never hand-edit:** `node tools/version.mjs set <version>` (takes `1.13.501` or `1.13.5.1`) writes `VERSION`, `cs/yojimbo.csproj`, `ts/package.json` plus its lockfile, and `rust/Cargo.toml` (plus `rust/Cargo.lock` and `interop/rust/Cargo.lock` if present). `node tools/version.mjs check [tag]` verifies them against each other and against `cpp/include/yojimbo_config.h`.
- **In-code version constants** mirror upstream's macros (the upstream version, with no port revision). Don't change them for port fixes.
- **To release:**
  1. Bump with the tool.
  2. Commit and push.
  3. Push the tag `v$(cat VERSION)`.

  `.github/workflows/release.yml` then checks the versions and runs all tests and interop. It packs, publishes to NuGet (secret `NUGET_API_KEY`), npm with provenance (secret `NPM_TOKEN`) and crates.io (secret `CARGO_REGISTRY_TOKEN`; the first publish needs the publish-new scope), and creates the GitHub release. Running the workflow by hand is a dry run unless "publish" is ticked; `targets` picks `all`, `npm`, `nuget` or `crates`.
- **Package contents:**
  - **npm:** only `ts/dist` library files (`files` in `ts/package.json`) and `LICENCE`, which `prepack` copies from the root.
  - **npm entry points:** `.`, `./netcode`, `./reliable`, `./serialize`, `./sodium`, `./webrtc/client`, `./webrtc/server`, `./webrtc/server-http`, `./webrtc/token`. Deep imports are blocked.
  - **NuGet:** `lib/net10.0` and `lib/netstandard2.1`, plus a symbols package.
  - **crates.io:** the library sources only (`include` in `rust/Cargo.toml`), `rust/README.md`, `rust/rust.md` and `rust/LICENCE`, a copy of the root `LICENCE` (keep them identical).
- **Before a release that changes packaging,** prove the packages from the consumer side:
  - `npm pack`, install the tarball into a scratch project, then type-check with full lib checking, run an example and bundle for the browser with esbuild;
  - `dotnet pack` to a local feed, then `dotnet add package yojimbo --source <feed>` and run an example;
  - `cargo package --manifest-path rust/Cargo.toml`, then point a scratch crate at the unpacked `.crate` by path and run an example.

## Syncing with upstream

1. Run `node tools/upstream_diff.mjs` (the weekly `upstream.yml` workflow posts the same report as an `upstream-sync` issue). It lists the commits past the pin and, per port (C#, TypeScript, Rust), the files to update with the upstream diff stat behind each.
2. Port each file on the checklist from its upstream diff (`git -C cpp diff <pin> <new> -- <file>`). Port new upstream tests too. When the report lists a file under "No port counterpart", add a rule to `MAP` in the script.
3. Bump the submodule pin. Set the package version with `node tools/version.mjs set <new upstream version>`, update the in-code version constants and the README.
4. Run every command above, including `interop/run.sh`.

## Working here

- The user wants work committed and pushed straight to `master` when they ask. There are no PRs. The `ssh-agent` may have no keys loaded; pushing over HTTPS with `gh` credentials works: `git -c credential.helper='!gh auth git-credential' push https://github.com/netcode-io/yojimbo.git master`.
- Prefer self-owned code to dependencies. The ChaCha20/Poly1305 port is ours on purpose, and the Rust crate has no dependencies at all.
- Don't add abstraction layers for two fixed implementations. WebRTC is exactly the standard `RTCPeerConnection` API: the browser's own, or `node-datachannel`'s polyfill on Node (passed as a constructor, nothing more). Signaling is one function shape (`connect( token, signal )` / `adapter.accept()`), with HTTP as the built-in transport.
