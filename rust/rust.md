# Rust port: findings and gaps

What is known about `rust/`: how it was verified, where it deviates from upstream, and what is still open. The binding conventions are in [README.md](README.md); this file is the port's status and its list of known gaps. Keep it current: when a gap is closed, move it to the verification table or delete it.

## Verification

| What | Windows (x86_64-pc-windows-msvc) | Linux (WSL2 Ubuntu 22.04, x86_64-unknown-linux-gnu) | macOS |
|---|---|---|---|
| Builds, debug and release, zero warnings | yes | yes | not compiled yet (CI) |
| `test`: 193 tests (serialize 61, netcode 53, reliable 27, yojimbo 52) | pass, debug and release | pass, debug and release, seeds 1–6, twice | not run |
| `custom_packet_io_test` | pass | pass | not run |
| `fuzz` (corpus replay, 200 mutations per seed, 1000 random inputs) | pass; also 3.5M inputs in longer runs | pass | not run |
| `interop/run.sh`, all 16 C++/C#/TypeScript/Rust pairings | pass | the 4 C++/Rust pairings pass (that WSL has no .NET or Node) | not run |
| Samples (`client`/`server` over UDP, `loopback` with Ctrl-C, `soak`) | run | not run | not run |
| `cargo package` | 37 files | not run | not run |
| Rust 1.80 (`rust-version`) | not checked; built with 1.98 | built with 1.99 | |

The C++ side of the Windows interop run was built with clang 17 through wrapper scripts (`-std=c++17 -march=native`), because that machine has no `cc`/`c++`. CI builds it with the system compilers as `interop/build_cpp.sh` says.

How each library was checked beyond its ported tests:

- **sodium**: netcode's AEAD known-answer vectors, the RFC 8439 vectors, HChaCha20/XChaCha vectors, 919 round trips and tamper cases per AEAD, and a byte-for-byte differential against `ts/sodium/sodium.ts` (86 outputs).
- **reliable**: a scenario compiled from `cpp/reliable/reliable.c` with clang and run in Rust gives identical output: 1850 transmits hex-dumped (packets and fragments, with loss), every ack list, all counters and stats. 400k mutated packets through `receive_packet`, no panic.
- **serialize**: the golden wire bytes, the compressed float conformance vectors and a 4.6M-check compressed float differential, all bit-exact.
- **netcode, yojimbo**: the interop run is the wire proof; the AEAD and connect token paths are crossed by every mixed pairing.

## Open bugs

None known.

## Fixed findings

- **Linux: client/server tests over real UDP failed intermittently** (about 8 runs in 12 in WSL; Windows never failed, and upstream's own `test.cpp` built with gcc in the same WSL passed every seed). Clients timed out while connecting, client messages went missing, and once `BaseClient::ReceiveMessage` asserted with no connection.
  - **Cause:** upstream's test pump ends every frame with `yojimbo_sleep( 0.0 )`, which is `usleep( 0 )`: a real system call that yields the CPU. The port used `std::thread::sleep` and skipped zero, and `std::thread::sleep` makes no system call for a zero duration on unix anyway. The pump never yielded. Linux delivers loopback UDP asynchronously (softirq), so without a yield the server's socket received nothing for up to ~200 frames, while simulated time kept advancing 0.1 s per frame. Windows delivers loopback synchronously, so it never showed there.
  - **Fix:** on unix, `yojimbo_sleep` calls `usleep` and `netcode_sleep` calls `nanosleep` through `extern "C"`, exactly as upstream. On Windows `std::thread::sleep` already does `Sleep( 0 )` for zero.
  - **Lesson:** a port must keep upstream's system calls where their side effect matters. A zero sleep is a yield, not a no-op.
- **WSL holds Windows test ports.** With `networkingMode=mirrored` in `.wslconfig`, a running WSL VM keeps Windows from binding UDP ports from about 39160 up, including the tests' 40000. The holder doesn't show in `netstat`. Windows tests then fail with `server_create failed` (`test_runtime_guards`: `check failed: ( server.is_some() )`). Run `wsl --shutdown` (or wait about a minute after the last `wsl` command) before running the Windows suite.

## Design decisions that carry risk

- **Raw-pointer object graph.** yojimbo's C++ objects (allocators, factories, messages, channels, connections, adapters) are raw `*mut dyn Trait` pointers, created and destroyed through the `Allocator` as upstream. That keeps allocation failure, budgets and leak tracking exact, but the public API takes and returns raw pointers (`*mut dyn Message`, `*mut u8` blocks) and user code needs `unsafe` for downcasts (`message_cast`). There is no safe wrapper API yet.
- **Re-entrant callbacks (soundness gap).** netcode and reliable call back into `Client`/`Server` through a `*mut c_void` context while a `&mut self` method of the same object is still on the stack (for example `netcode_server_update` inside `Server::AdvanceTime`). That is upstream's design. Rust's aliasing model (Stacked Borrows) does not allow it, so it is formally undefined behaviour even though it works in debug and release today. Not checked under Miri. A sound fix would route the callbacks through data held outside the object, or make the outer methods take `*mut Self`.
- **`Client::new` / `Server::new` return `Box<_>`** and the contents must never move: netcode and reliable keep the raw context pointer from connect/start until disconnect/stop. Dropping a client or server that is still connected or running asserts, as upstream.
- **Integer overflow.** C relies on unsigned wrap-around (sequence numbers, hashes, PRNGs). The code uses `wrapping_*` where the porting agents saw it, and `rust/Cargo.toml` turns `overflow-checks` off in every profile as a safety net. A dependency is built with the consumer's profiles, so consumers must add `[profile.dev.package.yojimbo] overflow-checks = false` (INTEGRATION.md says so). Closing this means running the suite with overflow checks on and converting every hit.

## Deviations from upstream

Each is marked `// port:` in the code.

### Memory and allocators

- netcode and reliable keep the allocator callbacks in their configs, but hold packets and buffers in `Vec`/`Box`, as the C# port does. netcode's client, server and network simulator still ask `allocate_function` for the bytes (then free them), so upstream's allocation-failure tests run. reliable never calls them, so two reliable tests are reduced (below).
- `TLSF_Allocator` is a real port of TLSF 3.1 over the caller's memory block (C# and TypeScript emulate it as a byte budget). TLSF's own alignment is 8; `TLSF_Allocator` asks for 16 through `tlsf_memalign`. `YOJIMBO_NEW!` refuses types aligned above 16 at compile time.
- `DefaultAllocator` is `std::alloc` with a 16-byte size header.
- A stream's allocator is a `void *`, which can't hold a `*mut dyn Allocator` (a fat pointer). It carries a pointer to the `*mut dyn Allocator` instead: `AllocatorToContext` / `AllocatorFromContext`, `MessageFactory::GetAllocatorContext`.
- Null trait-object pointers are a null pointer of a concrete type cast to the trait (`null_allocator()`, `null_message()`, `null_message_factory()`, `null_channel()`, `null_adapter()`).

### API shape

- C++ overloads get suffixes (`SerializeInternalRead/Write/Measure`, `InsecureConnectAddresses`). Default arguments are explicit at every call.
- Classes with virtuals are a trait plus a `<Class>Base` struct. `BaseClient`/`BaseServer` reach their derived class through `BaseClientVirtual`/`BaseServerVirtual`. The methods that make virtual calls are associated functions taking the derived object (`BaseServer::Start( this, maxClients )`).
- `Message::AsBlockMessage()` replaces the C++ cast after `IsBlockMessage()`. `ChannelPacketData` keeps block messages as `*mut dyn Message` (a `*mut BlockMessage` would lose the derived vtable that `ReleaseMessage` needs).
- `MessageFactory` has no `SetErrorLevel` (upstream has none either; the brief listed one).
- The crate's `yojimbo` module (from `source/yojimbo.cpp`) is private and re-exported, because a public module named `yojimbo` makes `use yojimbo::*;` ambiguous in the bins and in consumers.
- Strings: functions that format into a caller's buffer return `String` (`Address::ToString`, `netcode_address_to_string`). Fixed `char name[N]` config fields stay `[u8; N]` (reliable's endpoint name, so upstream's name-bound tests still apply).

### Platform

- Sockets are `std::net::UdpSocket`, created and bound through a little FFI (`socket`, `setsockopt` for `SO_SNDBUF`/`SO_RCVBUF`/`IPV6_V6ONLY`/TOS, `bind`) because std binds at creation. Windows also uses `WSAIoctl( SIO_UDP_CONNRESET )` and qWAVE packet tagging (left out on windows-gnu, as upstream). Linux, Android, Apple and FreeBSD constants are provided; other platforms hit `compile_error!`.
- netcode's address text uses std's IPv4/IPv6 parsers; its printing uses std's IPv6 formatting, so IPv4-compatible `::a.b.c.d` addresses print in hex. yojimbo's `Address` ports glibc's `inet_pton`/`inet_ntop`, as the C# port does, so it prints the same on every platform (upstream on Windows uses winsock's, which can differ in edge cases).
- Random bytes: libsodium's sysrandom, ported: `RtlGenRandom` on Windows, `getrandom()` with a `/dev/urandom` fallback on Linux and FreeBSD, `/dev/urandom` on macOS (the vendored amalgamation has no `getentropy` path), `arc4random` on OpenBSD.
- `rand()`/`srand()` in tests, soak and samples are `yojimbo_rand`/`yojimbo_srand` (mulberry32, as in the TypeScript port), so a given seed doesn't reproduce C++'s random sequence.
- Time is `std::time::Instant`; sleep is `std::thread::sleep`. A negative sleep returns at once (upstream's Windows `Sleep` would hang).
- Ctrl-C: the samples use `signal` on unix and `SetConsoleCtrlHandler` on Windows (tested on Windows only). `test`'s SOAK mode is compiled out by default, as upstream; its handler is untested.

### Crypto (sodium)

- Only the portable kernels: ChaCha20 "ref", Poly1305 donna64 (on `u128`). No SSSE3/AVX2/SSE2 variants, no guarded heap (`sodium_malloc`, `mlock`), no runtime CPU detection.
- `c` and `m` can't alias, so netcode's in-place encrypt/decrypt copies the input first.

### serialize

- `BitReader` doesn't need upstream's 8 bytes of slack past the data: a read window past the slice end reads zeros, which is wire-identical (as in C# and TypeScript).
- `SERIALIZE_FLOAT_FORCE_ROUND` is a no-op: Rust never contracts floating point. The fp-contract probes report "NOT AVAILABLE".
- `wchar_t` is `u16` on Windows and `u32` elsewhere.
- Tests that check an assert fires use a panicking assert hook plus `catch_unwind` instead of upstream's fork. They now run on Windows debug builds too.

### Logging and asserts

- The 4K printf truncation is not reproduced.
- The default assert handlers print as upstream, then panic (upstream traps). Asserts are active under `cfg(debug_assertions)`.

## Tests not ported or reduced

- `test_public_layout_is_configuration_independent` (yojimbo): not ported. One Rust binary can't hold both a debug and a release layout of a struct. TypeScript skips it too.
- `test_endpoint_create_allocation_failure` (reliable): the allocation-failure injection is skipped because reliable never calls `allocate_function`. Create/destroy with the failing allocator is still checked. C# leaves the test out.
- `test_fragment_reassembly_alloc_failure` (reliable): one check skipped for the same reason; the scenario still runs.
- `test_fragment_cleanup`, `test_endpoint_reset` (reliable): the tracking-allocator leak checks pass trivially; C#'s equivalent checks (no stale reassembly buffers) were added.
- netcode's `test_wire` harness delivers packets on the receiver's next receive, not inside the sender's call, because the C version would hold two `&mut` to one client. Same packets, same order, about one update later.
- netcode's `test_packet_tagging` leaves tagging on for the rest of the process, as upstream (the C# port turns it back off).
- The fuzz mutation pass uses splitmix64, so its mutated inputs differ from C#'s; the mutation kinds are the same. `InitializeYojimbo` runs once per fuzz run, not per target.

## Gaps and next steps

1. Run the samples (`client`/`server`, `loopback`, `soak`) on Linux, and all 16 interop pairings on a Linux with .NET and Node (CI's interop job).
2. Build and test on macOS (first CI run). The Apple socket constants, `/dev/urandom` and the Ctrl-C handler have only been reviewed.
3. Check the minimum Rust version (1.80) in CI, or raise `rust-version`.
4. Run the suite with `overflow-checks = true`, convert every hit to `wrapping_*`, then drop the profile override from the crate and from INTEGRATION.md.
5. Close the re-entrancy soundness gap, and run the non-socket tests under Miri.
6. A safe API layer over the raw-pointer one (message handles, typed create/receive, block slices), kept apart from the line-by-line files.
7. Interop on Linux and macOS with all four implementations (CI's interop jobs do this).
8. Publish: crates.io needs the `CARGO_REGISTRY_TOKEN` secret, and the first publish needs a token allowed to create new crates. `cargo package` warns that the program binaries are left out of the crate, which is intended.
9. Pre-existing, found while writing the Rust docs: a server created at `0.0.0.0` rejects connect tokens that name its real address (netcode checks the token's server list against the server's own address). The C# and TypeScript server examples in INTEGRATION.md create the server at `0.0.0.0:40000` with tokens naming `203.0.113.10:40000`, so they probably hit this. Not verified.
10. Repository: the C# workflow's interop job now builds Rust too, so a Rust breakage turns `cs.yml` red as well.
