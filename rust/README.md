# yojimbo (Rust)

Rust port of yojimbo 1.13.5, with netcode 1.4.8, reliable 1.4.5, serialize, the TLSF allocator and the libsodium subset netcode uses. No dependencies: the crypto, the allocator and the socket layer are ported, not imported.

```bash
cargo build --manifest-path rust/Cargo.toml                  # add --release for release
cargo run --manifest-path rust/Cargo.toml --bin test         # serialize, netcode, reliable, yojimbo tests
cargo run --manifest-path rust/Cargo.toml --bin custom_packet_io_test
cargo run --manifest-path rust/Cargo.toml --bin fuzz         # upstream fuzz corpus replay + seeded mutation
```

## Layout

The port mirrors `cpp/` file for file, like `cs/` and `ts/`:

| upstream (`cpp/`)                              | Rust (`rust/`)                |
|------------------------------------------------|-------------------------------|
| `sodium/sodium.c` (vendored libsodium subset)  | `sodium/sodium.rs`            |
| `tlsf/tlsf.c`                                  | `tlsf/tlsf.rs`                |
| `serialize/serialize.h`                        | `serialize/serialize.rs`      |
| `reliable/reliable.h` + `reliable.c`           | `reliable/reliable.rs`        |
| `netcode/netcode.h` + `netcode.c`              | `netcode/netcode.rs`          |
| `include/yojimbo_X.h` + `source/yojimbo_X.cpp` | `source/yojimbo_X.rs`         |
| `include/yojimbo_X.h` (header only)            | `include/yojimbo_X.rs`        |
| `test.cpp`, `client.cpp`, `shared.h`, …        | `test.rs`, `client.rs`, `shared.rs`, … |
| `fuzz/fuzz_X.c` / `fuzz/fuzz_X.cpp`            | `fuzz/fuzz_X.rs`              |

`lib.rs` is the crate root (the module list, like `cs/yojimbo.csproj`'s compile list). Library tests live in the library file, as upstream (`netcode_test()` is in `netcode/netcode.rs`); `test.rs` runs them all.

## Conventions

The port is line by line: the same functions in the same order, the same names, the same control flow. An upstream diff should apply by reading it side by side. Where Rust forces a deviation, say so in a comment at the deviation (`// port: ...`).

### Names

- Every upstream identifier keeps its spelling: C functions, structs, fields, constants and macros (`netcode_client_create`, `netcode_client_t`, `NETCODE_MAX_CLIENTS`), C++ classes and methods (`Client::Connect`, `m_clientIndex`), enum values. The crate allows the non-Rust casing (`lib.rs`).
- C/C++ enums become `pub const NAME: i32 = value;`, as the C# and TypeScript ports do.
- C++ overloads get a suffix naming the overload (`SerializeInternalRead` / `SerializeInternalWrite` / `SerializeInternalMeasure`).
- Upstream `static` functions are private unless another file (tests, fuzz) needs them; then they are `pub`.

### Modules

- `crate::sodium`, `crate::tlsf`, `crate::serialize`, `crate::netcode`, `crate::reliable` are modules, used by path or `use crate::netcode::*`.
- The yojimbo files are one namespace, as upstream's `namespace yojimbo`: `lib.rs` re-exports every `yojimbo_*` module at the crate root, and each yojimbo file starts with `use crate::*;` (plus `use crate::serialize::*;` etc. as needed).
- C macros become `macro_rules!` with the same name and arguments, `#[macro_export]`ed so they are usable crate-wide as `crate::netcode_printf!(...)` (and by consumers as `yojimbo::serialize_int!(...)`). Test-only macros (`check`) stay local to their file.

### Types

- `uint8_t`..`uint64_t` → `u8`..`u64`, `int8_t`..`int64_t` → `i8`..`i64`, `int` → `i32`, `size_t` → `usize`, `float`/`double` → `f32`/`f64`, `bool` → `bool`, 128-bit → `u128`/`i128`.
- C unsigned arithmetic wraps: use `wrapping_add` / `wrapping_sub` / `wrapping_mul` (sequence numbers, hashes, PRNGs). `Cargo.toml` turns `overflow-checks` off in every profile as a safety net, but write the wrapping form where upstream relies on wrapping.
- Casts use `as`, which truncates like C.

### Pointers and memory

The rules are mechanical so that files ported separately fit together:

- **Every C/C++ parameter stays.** A buffer pointer becomes a slice (`&[u8]` when the function only reads it, `&mut [u8]` when it writes), and its length parameter stays as the upstream integer type.
- **Out-parameters** (`int * bytes`, `uint64_t * sequence`, `struct foo_t * out`) become `&mut T`.
- **C library objects** (netcode, reliable): `*_create` returns `Option<Box<T>>`, `*_destroy` takes `Box<T>`, every other function takes `&mut T` / `&T`. Buffers the library hands out (`netcode_client_receive_packet`, `reliable_endpoint_get_acks`) are `Option<Vec<u8>>` / slices; the matching `*_free_packet` takes the `Vec<u8>`. netcode/reliable keep their allocator callbacks in their configs but hold their buffers in `Vec`/`Box`, as the C# port does (see the notes in `cs/`).
- **Strings**: `const char *` parameters are `&str`. A function that formats into a caller's `char * buffer` and returns it returns `String` instead (the buffer parameter is dropped). Fixed `char name[N]` fields stay `[u8; N]` (NUL-terminated) where they are on the wire, otherwise `String`.
- **`void * context`** is `*mut c_void` (`std::ffi::c_void`). C function pointers are `Option<fn(...)>` with the same parameters under these rules. Code that turns a context back into an object does it in an `unsafe` block.
- **C++ objects are where pointers stay raw.** yojimbo's object graph (allocators, message factories, messages, adapters, channels, connections) is non-owning pointers plus explicit create/destroy through an `Allocator`, and the port keeps it that way so allocation failure, budgets and leak tracking behave exactly as upstream:
  - A pointer or reference to a polymorphic object (`Allocator &`, `MessageFactory *`, `Message *`, `Adapter &`, `Channel *`) is `*mut dyn Trait`. A pointer to a concrete class is `*mut T`. Dereference in small `unsafe` blocks; the owner outlives the pointer, as upstream.
  - A null `*mut dyn Trait` is a null pointer of a concrete implementor cast to the trait (`std::ptr::null_mut::<BlockMessage>() as *mut dyn Message`); each trait's file provides `null_<trait>()` (`null_allocator()`, `null_message()`, `null_message_factory()`, ...). Test with `.is_null()`.
  - `YOJIMBO_NEW!( allocator, T, value )`, `YOJIMBO_DELETE!( allocator, T, p )`, `YOJIMBO_ALLOCATE!( allocator, bytes )` and `YOJIMBO_FREE!( allocator, p )` (in `source/yojimbo_allocator.rs`) take `allocator: *mut dyn Allocator` and work exactly like the C++ macros: `YOJIMBO_NEW!` allocates `size_of::<T>()` bytes from the allocator, moves `value` in and returns `*mut T` (null on failure); `YOJIMBO_DELETE!` drops in place, frees and nulls `p` (also through `*mut dyn Trait`); `YOJIMBO_ALLOCATE!` returns `*mut u8`; `YOJIMBO_FREE!` frees and nulls.
  - Arrays upstream allocates from an `Allocator` (sequence buffer entries, queues, bit arrays, packet and block buffers) are allocated from it in the port too, as raw `*mut T` plus a count.
- **Classes with virtual methods** become a trait with the class's name holding the virtual methods (and its non-virtual methods as provided methods). When the class has data members, they go in a struct `<Class>Base` that implementors embed, and the trait has `fn base( &self ) -> &<Class>Base` and `fn base_mut( &mut self ) -> &mut <Class>Base`. Concrete derived classes are structs that implement the trait. A class that is also extended (`BlockMessage`, `BaseClient`, `BaseServer`) is a struct the derived struct embeds as `base` and delegates to.
- **Serialization**: C++ `template <typename Stream> bool Serialize( Stream & stream )` is `fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool`. `Stream` (in `serialize/serialize.rs`) has `const IsWriting: bool` / `const IsReading: bool` and the stream methods; `ReadStream<'a>`, `WriteStream<'a>`, `MeasureStream` implement it. The `serialize_*` macros return `false` from the enclosing function on failure, as upstream, so every call site propagates a failure.
- **Globals** (log level, printf/assert hooks, init state): atomics or a `Mutex` for hooks; `static mut` only with a comment. Like upstream the libraries are single-threaded by design.

### Logging and asserts

- `netcode_printf!( level, "format", args )`, `reliable_printf!`, `yojimbo_printf!` take Rust format strings; keep upstream's message text. `*_set_printf_function` takes `fn( &str )`.
- `netcode_assert!( condition )`, `reliable_assert!`, `serialize_assert!`, `yojimbo_assert!` are active in debug builds (`cfg(debug_assertions)`, upstream's `!NDEBUG`) and call the assert hook (`*_set_assert_function( fn( condition: &str, function: &str, file: &str, line: i32 ) )`); the default handler prints as upstream and panics.
- `YOJIMBO_DEBUG_MEMORY_LEAKS`, `YOJIMBO_DEBUG_MESSAGE_LEAKS` and `YOJIMBO_DEBUG_MESSAGE_BUDGET` are on in debug builds, as upstream.

### Platform

- Time is `std::time::Instant`, sleep is `std::thread::sleep`, random bytes come from the OS (`sodium/sodium.rs` ports libsodium's `randombytes` sysrandom with a few lines of FFI per platform, as upstream: `RtlGenRandom` on Windows, `getrandom()` with a `/dev/urandom` fallback on Linux and FreeBSD, `/dev/urandom` on macOS, `arc4random` on OpenBSD).
- netcode's sockets are `std::net::UdpSocket` (non-blocking). Options std lacks (`SO_SNDBUF`, `SO_RCVBUF`, `IPV6_V6ONLY` before bind) are set with minimal `extern` FFI on the raw socket. No crates.

## Port additions

Not in upstream; keep them through upstream syncs, as in the C# and TypeScript ports: `ChannelConfig.allocateBlocksOnDemand` and `TLSF_Allocator::GetUsedBytes()` / `GetCapacityBytes()`. Rust-only: `Message::AsBlockMessage()` (the downcast C++ does with a cast after `IsBlockMessage()`) and the `null_<trait>()` helpers.
