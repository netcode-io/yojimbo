/*
 * ISC License
 *
 * Copyright (c) 2013-2026
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Amalgamated libsodium subset for yojimbo/netcode — generated; do not edit by hand. */

/*
    port: Rust port of cpp/sodium/sodium.h + sodium.c (the libsodium 1.0.22 subset netcode uses), one file.

    Layout: the sodium.h sections that carry code or constants come first (constants, the implementation
    structs, sodium_private_common.h's helpers), then every sodium.c section in upstream order.

    What is ported, and what is not:

        - the portable code paths only: ChaCha20 "ref" (chacha-merged), HChaCha20, Poly1305 donna64, the portable
          crypto_verify_n. The SIMD variants (dolbeau ChaCha20 SSSE3/AVX2, Poly1305 SSE2, the SSE2 crypto_verify_n)
          and sodium_runtime.c (CPU feature detection, which only picks among them) have no portable Rust meaning
          and are skipped; every *_pick_best_implementation() selects the portable code. The SIMD variants are
          byte-identical to it, so the wire output is unchanged.
        - Poly1305 uses the donna64 kernel (64 x 64 -> 128 bit multiplies, u128 here): that is what upstream
          compiles on every 64-bit GCC/Clang target (HAVE_TI_MODE from __SIZEOF_INT128__). MSVC builds of upstream
          use donna32 (no __int128); both give the same tags.
        - sodium_utils.c: the guarded heap (sodium_malloc / sodium_free / sodium_mprotect_* / sodium_mlock /
          _sodium_alloc_init) is skipped: Rust owns its memory and nothing here allocates through it.
        - Pointer parameters are slices with the length parameter kept, as the README says. Nullable pointers that
          upstream checks (`ad`, `nsec`, `maclen_p`, the `m` of the detached decrypts, `c` of hchacha20) are
          Option. `c` and `m` cannot alias: callers that encrypt in place copy the input first.
        - sodium_misuse() aborts the process, as upstream.
*/

use std::ptr;
use std::sync::atomic::{compiler_fence, fence, AtomicBool, AtomicI32, AtomicPtr, Ordering};
use std::sync::Mutex;

/* ================= sodium_stream_chacha20.h ================= */

// port: function pointers take slices in place of the C pointers (see the header comment)
pub struct crypto_stream_chacha20_implementation {
    pub stream: fn(c: &mut [u8], clen: u64, n: &[u8], k: &[u8]) -> i32,
    pub stream_ietf_ext: fn(c: &mut [u8], clen: u64, n: &[u8], k: &[u8]) -> i32,
    pub stream_xor_ic: fn(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], ic: u64, k: &[u8]) -> i32,
    pub stream_ietf_ext_xor_ic: fn(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], ic: u32, k: &[u8]) -> i32,
}

/* ================= sodium_export.h ================= */

// port: the macros are const fns / consts
pub const fn SODIUM_MIN(A: u64, B: u64) -> u64 {
    if A < B { A } else { B }
}
pub const SODIUM_SIZE_MAX: u64 = SODIUM_MIN(u64::MAX, usize::MAX as u64);

/* ================= sodium_crypto_stream_chacha20.h ================= */

/*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the crypto_box functions.
 */

// port: byte-count constants are usize (they size arrays); the *_MESSAGEBYTES_MAX bounds are u64, the type of the
// `unsigned long long` lengths they are compared with

pub const crypto_stream_chacha20_KEYBYTES: usize = 32;

pub const crypto_stream_chacha20_NONCEBYTES: usize = 8;

pub const crypto_stream_chacha20_MESSAGEBYTES_MAX: u64 = SODIUM_SIZE_MAX;

/* ChaCha20 with a 64-bit nonce and a 64-bit counter, as originally designed */

/* ChaCha20 with a 96-bit nonce and a 32-bit counter (IETF) */

pub const crypto_stream_chacha20_ietf_KEYBYTES: usize = 32;

pub const crypto_stream_chacha20_ietf_NONCEBYTES: usize = 12;

pub const crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX: u64 = SODIUM_MIN(SODIUM_SIZE_MAX, 64u64 * (1u64 << 32));

/* Aliases */

pub const crypto_stream_chacha20_IETF_KEYBYTES: usize = crypto_stream_chacha20_ietf_KEYBYTES;
pub const crypto_stream_chacha20_IETF_NONCEBYTES: usize = crypto_stream_chacha20_ietf_NONCEBYTES;
pub const crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX: u64 = crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX;

/* ================= sodium_crypto_aead_chacha20poly1305.h ================= */

/* -- IETF ChaCha20-Poly1305 construction with a 96-bit nonce and a 32-bit internal counter -- */

pub const crypto_aead_chacha20poly1305_ietf_KEYBYTES: usize = 32;

pub const crypto_aead_chacha20poly1305_ietf_NSECBYTES: usize = 0;

pub const crypto_aead_chacha20poly1305_ietf_NPUBBYTES: usize = 12;

pub const crypto_aead_chacha20poly1305_ietf_ABYTES: usize = 16;

pub const crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX: u64 = SODIUM_MIN(
    SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ietf_ABYTES as u64,
    64u64 * ((1u64 << 32) - 1u64),
);

/* -- Original ChaCha20-Poly1305 construction with a 64-bit nonce and a 64-bit internal counter -- */

pub const crypto_aead_chacha20poly1305_KEYBYTES: usize = 32;

pub const crypto_aead_chacha20poly1305_NSECBYTES: usize = 0;

pub const crypto_aead_chacha20poly1305_NPUBBYTES: usize = 8;

pub const crypto_aead_chacha20poly1305_ABYTES: usize = 16;

pub const crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX: u64 =
    SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ABYTES as u64;

/* Aliases */

pub const crypto_aead_chacha20poly1305_IETF_KEYBYTES: usize = crypto_aead_chacha20poly1305_ietf_KEYBYTES;
pub const crypto_aead_chacha20poly1305_IETF_NSECBYTES: usize = crypto_aead_chacha20poly1305_ietf_NSECBYTES;
pub const crypto_aead_chacha20poly1305_IETF_NPUBBYTES: usize = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
pub const crypto_aead_chacha20poly1305_IETF_ABYTES: usize = crypto_aead_chacha20poly1305_ietf_ABYTES;
pub const crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX: u64 = crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX;

/* ================= sodium_crypto_aead_xchacha20poly1305.h ================= */

pub const crypto_aead_xchacha20poly1305_ietf_KEYBYTES: usize = 32;

pub const crypto_aead_xchacha20poly1305_ietf_NSECBYTES: usize = 0;

pub const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: usize = 24;

pub const crypto_aead_xchacha20poly1305_ietf_ABYTES: usize = 16;

pub const crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX: u64 =
    SODIUM_SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES as u64;

/* Aliases */

pub const crypto_aead_xchacha20poly1305_IETF_KEYBYTES: usize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
pub const crypto_aead_xchacha20poly1305_IETF_NSECBYTES: usize = crypto_aead_xchacha20poly1305_ietf_NSECBYTES;
pub const crypto_aead_xchacha20poly1305_IETF_NPUBBYTES: usize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
pub const crypto_aead_xchacha20poly1305_IETF_ABYTES: usize = crypto_aead_xchacha20poly1305_ietf_ABYTES;
pub const crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX: u64 = crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX;

/* ================= sodium_crypto_core_hchacha20.h ================= */

pub const crypto_core_hchacha20_OUTPUTBYTES: usize = 32;

pub const crypto_core_hchacha20_INPUTBYTES: usize = 16;

pub const crypto_core_hchacha20_KEYBYTES: usize = 32;

pub const crypto_core_hchacha20_CONSTBYTES: usize = 16;

/* ================= sodium_crypto_onetimeauth_poly1305.h ================= */

// port: upstream's state is `unsigned char opaque[256]` that the implementation casts to its internal state. Here
// it holds the donna64 internal state directly (the only implementation), so no cast is needed.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct crypto_onetimeauth_poly1305_state {
    pub opaque: poly1305_state_internal_t,
}

pub const crypto_onetimeauth_poly1305_BYTES: usize = 16;

pub const crypto_onetimeauth_poly1305_KEYBYTES: usize = 32;

/* ================= sodium_crypto_verify_16.h ================= */

pub const crypto_verify_16_BYTES: usize = 16;

/* ================= sodium_crypto_verify_32.h ================= */

pub const crypto_verify_32_BYTES: usize = 32;

/* ================= sodium_crypto_verify_64.h ================= */

pub const crypto_verify_64_BYTES: usize = 64;

/* ================= sodium_onetimeauth_poly1305.h ================= */

// port: function pointers take slices in place of the C pointers
pub struct crypto_onetimeauth_poly1305_implementation {
    pub onetimeauth: fn(out: &mut [u8], r#in: &[u8], inlen: u64, k: &[u8]) -> i32,
    pub onetimeauth_verify: fn(h: &[u8], r#in: &[u8], inlen: u64, k: &[u8]) -> i32,
    pub onetimeauth_init: fn(state: &mut crypto_onetimeauth_poly1305_state, key: &[u8]) -> i32,
    pub onetimeauth_update: fn(state: &mut crypto_onetimeauth_poly1305_state, r#in: &[u8], inlen: u64) -> i32,
    pub onetimeauth_final: fn(state: &mut crypto_onetimeauth_poly1305_state, out: &mut [u8]) -> i32,
}

/* ================= sodium_private_common.h ================= */

// port: COMPILER_ASSERT is a const assert
macro_rules! COMPILER_ASSERT {
    ($X:expr) => {
        const _: () = assert!($X);
    };
}

/* 128-bit integer support: enables the Poly1305 donna64 and SSE2 code paths.
   Available on 64-bit GCC/Clang targets (x86-64, arm64, ...); not on MSVC. */
// port: Rust has u128 on every target, so the donna64 path is always taken (HAVE_TI_MODE)

/* Optimisation barriers used by the constant-time code and by the AEAD decrypt
   paths (libsodium 1.0.21/1.0.22). Upstream gets these from autoconf; this
   amalgamation derives them from the compiler's own macros, as it already does
   for HAVE_TI_MODE and the SIMD intrinsics above.

   ACQUIRE_FENCE is placed after MAC verification and before the plaintext is
   produced, so a speculative read cannot reach unauthenticated plaintext.
   Falling back to (void) 0 matches upstream's behaviour when autoconf detects
   no fence primitive: correct and interoperable, without the hardening. */
// port: the GCC path (__atomic_thread_fence(__ATOMIC_ACQUIRE)), on every target
macro_rules! ACQUIRE_FENCE {
    () => {
        fence(Ordering::Acquire)
    };
}

// port: ROTL32(X, B) etc. are the functions below, called directly
#[inline(always)]
fn rotl32(x: u32, b: i32) -> u32 {
    (x << b) | (x >> (32 - b))
}

#[inline(always)]
fn rotl64(x: u64, b: i32) -> u64 {
    (x << b) | (x >> (64 - b))
}

#[inline(always)]
fn rotr32(x: u32, b: i32) -> u32 {
    (x >> b) | (x << (32 - b))
}

#[inline(always)]
fn rotr64(x: u64, b: i32) -> u64 {
    (x >> b) | (x << (64 - b))
}

// port: LOAD/STORE take a slice starting at the address upstream passes (`&key[16..]` for `&key[16]`). The
// NATIVE_LITTLE_ENDIAN memcpy path and the byte path compute the same value.
#[inline(always)]
fn load64_le(src: &[u8]) -> u64 {
    let mut w: u64 = src[0] as u64;
    w |= (src[1] as u64) << 8;
    w |= (src[2] as u64) << 16;
    w |= (src[3] as u64) << 24;
    w |= (src[4] as u64) << 32;
    w |= (src[5] as u64) << 40;
    w |= (src[6] as u64) << 48;
    w |= (src[7] as u64) << 56;
    w
}

#[inline(always)]
fn store64_le(dst: &mut [u8], mut w: u64) {
    dst[0] = w as u8; w >>= 8;
    dst[1] = w as u8; w >>= 8;
    dst[2] = w as u8; w >>= 8;
    dst[3] = w as u8; w >>= 8;
    dst[4] = w as u8; w >>= 8;
    dst[5] = w as u8; w >>= 8;
    dst[6] = w as u8; w >>= 8;
    dst[7] = w as u8;
}

#[inline(always)]
fn load32_le(src: &[u8]) -> u32 {
    let mut w: u32 = src[0] as u32;
    w |= (src[1] as u32) << 8;
    w |= (src[2] as u32) << 16;
    w |= (src[3] as u32) << 24;
    w
}

#[inline(always)]
fn store32_le(dst: &mut [u8], mut w: u32) {
    dst[0] = w as u8; w >>= 8;
    dst[1] = w as u8; w >>= 8;
    dst[2] = w as u8; w >>= 8;
    dst[3] = w as u8;
}

/* ----- */

#[inline(always)]
fn load64_be(src: &[u8]) -> u64 {
    let mut w: u64 = src[7] as u64;
    w |= (src[6] as u64) << 8;
    w |= (src[5] as u64) << 16;
    w |= (src[4] as u64) << 24;
    w |= (src[3] as u64) << 32;
    w |= (src[2] as u64) << 40;
    w |= (src[1] as u64) << 48;
    w |= (src[0] as u64) << 56;
    w
}

#[inline(always)]
fn store64_be(dst: &mut [u8], mut w: u64) {
    dst[7] = w as u8; w >>= 8;
    dst[6] = w as u8; w >>= 8;
    dst[5] = w as u8; w >>= 8;
    dst[4] = w as u8; w >>= 8;
    dst[3] = w as u8; w >>= 8;
    dst[2] = w as u8; w >>= 8;
    dst[1] = w as u8; w >>= 8;
    dst[0] = w as u8;
}

#[inline(always)]
fn load32_be(src: &[u8]) -> u32 {
    let mut w: u32 = src[3] as u32;
    w |= (src[2] as u32) << 8;
    w |= (src[1] as u32) << 16;
    w |= (src[0] as u32) << 24;
    w
}

#[inline(always)]
fn store32_be(dst: &mut [u8], mut w: u32) {
    dst[3] = w as u8; w >>= 8;
    dst[2] = w as u8; w >>= 8;
    dst[1] = w as u8; w >>= 8;
    dst[0] = w as u8;
}

#[inline(always)]
fn xor_buf(out: &mut [u8], r#in: &[u8], n: usize) {
    let mut i: usize = 0;
    while i < n {
        out[i] ^= r#in[i];
        i += 1;
    }
}

// port: the SIMD / intrinsics feature selection has no Rust counterpart (see the header comment)

/* ================= sodium_randombytes.h ================= */

// port: function pointers take slices / return &'static str in place of the C pointers
pub struct randombytes_implementation {
    pub implementation_name: fn() -> &'static str, /* required */
    pub random: fn() -> u32,                       /* required */
    pub stir: Option<fn()>,                        /* optional */
    pub uniform: Option<fn(upper_bound: u32) -> u32>, /* optional, a default implementation will be used if NULL */
    pub buf: fn(buf: &mut [u8], size: usize),      /* required */
    pub close: Option<fn() -> i32>,                /* optional */
}

pub const randombytes_BYTES_MAX: u64 = SODIUM_MIN(SODIUM_SIZE_MAX, 0xffffffff);

pub const randombytes_SEEDBYTES: usize = 32;

/* ================= sodium_version.h ================= */

pub const SODIUM_VERSION_STRING: &str = "1.0.22";

pub const SODIUM_LIBRARY_VERSION_MAJOR: i32 = 26;
pub const SODIUM_LIBRARY_VERSION_MINOR: i32 = 2;

/* ================= sodium_version.c ================= */

pub fn sodium_version_string() -> &'static str {
    SODIUM_VERSION_STRING
}

pub fn sodium_library_version_major() -> i32 {
    SODIUM_LIBRARY_VERSION_MAJOR
}

pub fn sodium_library_version_minor() -> i32 {
    SODIUM_LIBRARY_VERSION_MINOR
}

pub fn sodium_library_minimal() -> i32 {
    // port: SODIUM_LIBRARY_MINIMAL is not defined
    0
}

/* ================= sodium_utils.c ================= */

// port: _sodium_dummy_symbol_to_prevent_memzero_lto and friends have no Rust meaning: the volatile writes and the
// compiler fence below are the optimisation barrier

pub fn sodium_memzero(pnt: &mut [u8], len: usize) {
    // port: the portable volatile loop (the #else path), plus a compiler fence; SecureZeroMemory is the same
    let pnt_ = &mut pnt[..len];
    let mut i: usize = 0;

    while i < len {
        unsafe { ptr::write_volatile(&mut pnt_[i], 0u8) };
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
}

// port: sodium_memzero( &struct, sizeof struct ) for the plain-data structs here (chacha_ctx, the Poly1305 state)
// and for callers' structs. The volatile write of T::default() cannot be optimised away.
pub fn sodium_memzero_struct<T: Copy + Default>(pnt: &mut T) {
    unsafe { ptr::write_volatile(pnt as *mut T, T::default()) };
    compiler_fence(Ordering::SeqCst);
}

pub fn sodium_stackzero(len: usize) {
    // port: Rust has neither C variable-length arrays nor alloca, so this is upstream's fallback (no-op) path
    let _ = len;
}

pub fn sodium_memcmp(b1_: &[u8], b2_: &[u8], len: usize) -> i32 {
    // port: volatile pointers become volatile reads; the volatile accumulator is a black_box
    let b1 = &b1_[..len];
    let b2 = &b2_[..len];
    let mut i: usize;
    let mut d: u8 = 0;

    i = 0;
    while i < len {
        d |= unsafe { ptr::read_volatile(&b1[i]) ^ ptr::read_volatile(&b2[i]) };
        d = std::hint::black_box(d);
        i += 1;
    }
    let d = d as i32;
    (1 & ((d - 1) >> 8)) - 1
}

pub fn sodium_compare(b1_: &[u8], b2_: &[u8], len: usize) -> i32 {
    // port: volatile pointers become volatile reads; the volatile locals are black_boxed. The arithmetic is done in
    // i32, the type C promotes the uint16_t / unsigned char operands to.
    let b1 = &b1_[..len];
    let b2 = &b2_[..len];
    let mut i: usize;
    let mut gt: u8 = 0;
    let mut eq: u8 = 1;
    let mut x1: u16;
    let mut x2: u16;

    i = len;
    while i != 0 {
        i -= 1;
        x1 = unsafe { ptr::read_volatile(&b1[i]) } as u16;
        x2 = unsafe { ptr::read_volatile(&b2[i]) } as u16;
        gt |= ((((x2 as i32) - (x1 as i32)) >> 8) & (eq as i32)) as u8;
        eq &= ((((x2 ^ x1) as i32) - 1) >> 8) as u8;
        gt = std::hint::black_box(gt);
        eq = std::hint::black_box(eq);
    }
    ((gt as i32) + (gt as i32) + (eq as i32)) - 1
}

pub fn sodium_is_zero(n: &[u8], nlen: usize) -> i32 {
    let mut i: usize;
    let mut d: u8 = 0;

    i = 0;
    while i < nlen {
        d |= n[i];
        d = std::hint::black_box(d);
        i += 1;
    }
    let d = d as i32;
    1 & ((d - 1) >> 8)
}

pub fn sodium_increment(n: &mut [u8], nlen: usize) {
    let mut i: usize = 0;
    let mut c: u16 = 1;

    // port: the HAVE_AMD64_ASM fast paths are skipped (inline assembly; the loop computes the same)
    while i < nlen {
        c += n[i] as u16;
        n[i] = c as u8;
        c >>= 8;
        i += 1;
    }
}

pub fn sodium_add(a: &mut [u8], b: &[u8], len: usize) {
    let mut i: usize;
    let mut c: u16 = 0;

    // port: the HAVE_AMD64_ASM fast paths are skipped (inline assembly; the loop computes the same)
    i = 0;
    while i < len {
        c += (a[i] as u16) + (b[i] as u16);
        a[i] = c as u8;
        c >>= 8;
        i += 1;
    }
}

pub fn sodium_sub(a: &mut [u8], b: &[u8], len: usize) {
    let mut c: u16 = 0;
    let mut i: usize;

    // port: the HAVE_AMD64_ASM fast path is skipped (inline assembly; the loop computes the same)
    i = 0;
    while i < len {
        c = (a[i] as u16).wrapping_sub(b[i] as u16).wrapping_sub(c);
        a[i] = c as u8;
        c = (c >> 8) & 1;
        i += 1;
    }
}

// port: _sodium_alloc_init, sodium_mlock, sodium_munlock, _mprotect_*, _out_of_bounds, _page_round, _alloc_aligned,
// _free_aligned, _unprotected_ptr_from_user_ptr, _sodium_malloc, sodium_malloc, sodium_allocarray, sodium_free,
// _sodium_mprotect and sodium_mprotect_* (the guarded heap) are not ported: Rust owns its memory, and neither
// netcode nor yojimbo allocates through libsodium

pub fn sodium_pad(padded_buflen_p: Option<&mut usize>, buf: &mut [u8], unpadded_buflen: usize, blocksize: usize, max_buflen: usize) -> i32 {
    let tail: usize; // port: an index into buf in place of the pointer
    let mut i: usize;
    let mut xpadlen: usize;
    let xpadded_len: usize;
    let mut mask: u8;
    let mut barrier_mask: u8;

    if blocksize == 0 {
        return -1;
    }
    xpadlen = blocksize - 1;
    if (blocksize & (blocksize - 1)) == 0 {
        xpadlen -= unpadded_buflen & (blocksize - 1);
    } else {
        xpadlen -= unpadded_buflen % blocksize;
    }
    if usize::MAX - unpadded_buflen <= xpadlen {
        sodium_misuse();
    }
    xpadded_len = unpadded_buflen + xpadlen;
    if xpadded_len >= max_buflen {
        return -1;
    }
    tail = xpadded_len;
    if let Some(padded_buflen_p) = padded_buflen_p {
        *padded_buflen_p = xpadded_len + 1;
    }
    mask = 0;
    i = 0;
    while i < blocksize {
        barrier_mask = ((i ^ xpadlen).wrapping_sub(1) >> ((std::mem::size_of::<usize>() - 1) * 8)) as u8;
        buf[tail - i] = (buf[tail - i] & mask) | (0x80 & barrier_mask);
        mask |= barrier_mask;
        mask = std::hint::black_box(mask);
        i += 1;
    }
    0
}

pub fn sodium_unpad(unpadded_buflen_p: &mut usize, buf: &[u8], padded_buflen: usize, blocksize: usize) -> i32 {
    let tail: usize; // port: an index into buf in place of the pointer
    let mut acc: u8 = 0;
    let mut c: u8;
    let mut valid: u8 = 0;
    let mut pad_len: usize = 0;
    let mut i: usize;
    let mut is_barrier: usize;

    if padded_buflen < blocksize || blocksize == 0 {
        return -1;
    }
    tail = padded_buflen - 1;

    i = 0;
    while i < blocksize {
        c = buf[tail - i];
        is_barrier = (((acc as usize).wrapping_sub(1) & pad_len.wrapping_sub(1) & ((c ^ 0x80) as usize).wrapping_sub(1)) >> 8) & 1;
        acc |= c;
        pad_len |= i & (1usize.wrapping_add(!is_barrier));
        pad_len = std::hint::black_box(pad_len);
        valid |= is_barrier as u8;
        i += 1;
    }
    *unpadded_buflen_p = padded_buflen - 1 - pad_len;

    (valid as u32).wrapping_sub(1) as i32
}

/* ================= sodium_verify.c ================= */

pub fn crypto_verify_16_bytes() -> usize {
    crypto_verify_16_BYTES
}

pub fn crypto_verify_32_bytes() -> usize {
    crypto_verify_32_BYTES
}

pub fn crypto_verify_64_bytes() -> usize {
    crypto_verify_64_BYTES
}

// port: only the portable crypto_verify_n is ported (the SSE2 one returns the same)

// port: a static mut so the compiler cannot assume its value; it is only ever read, volatile, and is always 0
static mut optblocker_u16: u16 = 0;

#[inline]
fn crypto_verify_n(x_: &[u8], y_: &[u8], n: i32) -> i32 {
    // port: volatile pointers become volatile reads; the empty asm barrier is a black_box
    let x = &x_[..n as usize];
    let y = &y_[..n as usize];
    let mut d: u16 = 0;
    let mut i: i32;

    i = 0;
    while i < n {
        d |= unsafe { ptr::read_volatile(&x[i as usize]) ^ ptr::read_volatile(&y[i as usize]) } as u16;
        i += 1;
    }
    d = std::hint::black_box(d);
    d = d.wrapping_sub(1);
    d = ((d >> 13) ^ unsafe { ptr::read_volatile(ptr::addr_of!(optblocker_u16)) }) >> 2;

    (d as i32) - 1
}

pub fn crypto_verify_16(x: &[u8], y: &[u8]) -> i32 {
    crypto_verify_n(x, y, crypto_verify_16_BYTES as i32)
}

pub fn crypto_verify_32(x: &[u8], y: &[u8]) -> i32 {
    crypto_verify_n(x, y, crypto_verify_32_BYTES as i32)
}

pub fn crypto_verify_64(x: &[u8], y: &[u8]) -> i32 {
    crypto_verify_n(x, y, crypto_verify_64_BYTES as i32)
}

/* ================= sodium_runtime.c ================= */

// port: not ported. CPU feature detection only selects among the SIMD implementations, which are not ported.

/* ================= sodium_randombytes_sysrandom.c ================= */

#[cfg(windows)]
mod sysrandom_ffi {
    /* `RtlGenRandom` is used over `CryptGenRandom` on Microsoft Windows based systems:
     *  - `CryptGenRandom` requires pulling in `CryptoAPI` which causes unnecessary
     *     memory overhead if this API is not being used for other purposes
     *  - `RtlGenRandom` is thus called directly instead. A detailed explanation
     *     can be found here: https://blogs.msdn.microsoft.com/michael_howard/2005/01/14/cryptographically-secure-random-number-on-windows-without-using-cryptoapi/
     *
     * In spite of the disclaimer on the `RtlGenRandom` documentation page that was
     * written back in the Windows XP days, this function is here to stay. The CRT
     * function `rand_s()` directly depends on it, so touching it would break many
     * applications released since Windows XP.
     *
     * Also note that Rust, Firefox and BoringSSL (thus, Google Chrome and everything
     * based on Chromium) also depend on it, and that libsodium allows the RNG to be
     * replaced without patching nor recompiling the library.
     */
    #[link(name = "advapi32")]
    extern "system" {
        #[link_name = "SystemFunction036"]
        pub fn RtlGenRandom(RandomBuffer: *mut std::ffi::c_void, RandomBufferLength: u32) -> u8;
    }
}

// port: upstream calls getrandom through syscall(SYS_getrandom, ...) on Linux and through <sys/random.h> on FreeBSD
// 12+; the port calls the libc getrandom() wrapper on both (glibc 2.25+, musl, FreeBSD 12+). Android, where
// bionic only has getrandom() from API 28, takes the /dev/urandom path.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod sysrandom_ffi {
    extern "C" {
        pub fn getrandom(buf: *mut std::ffi::c_void, buflen: usize, flags: u32) -> isize;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod poll_ffi {
    #[repr(C)]
    pub struct pollfd {
        pub fd: std::ffi::c_int,
        pub events: std::ffi::c_short,
        pub revents: std::ffi::c_short,
    }
    pub const POLLIN: std::ffi::c_short = 0x001;
    // nfds_t: unsigned long in glibc / musl, unsigned int in bionic
    #[cfg(target_os = "linux")]
    pub type nfds_t = std::ffi::c_ulong;
    #[cfg(target_os = "android")]
    pub type nfds_t = std::ffi::c_uint;
    extern "C" {
        pub fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: std::ffi::c_int) -> std::ffi::c_int;
    }
}

#[cfg(target_os = "openbsd")]
mod sysrandom_ffi {
    extern "C" {
        pub fn arc4random() -> u32;
        pub fn arc4random_buf(buf: *mut std::ffi::c_void, nbytes: usize);
    }
}

// HAVE_LINUX_COMPATIBLE_GETRANDOM
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const HAVE_LINUX_COMPATIBLE_GETRANDOM: bool = true;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
const HAVE_LINUX_COMPATIBLE_GETRANDOM: bool = false;

// port: HAVE_SAFE_ARC4RANDOM is OpenBSD (CloudABI has no Rust target); __ORBIS__ / __PROSPERO__ have none either

#[cfg(target_os = "openbsd")]
fn randombytes_sysrandom() -> u32 {
    unsafe { sysrandom_ffi::arc4random() }
}

#[cfg(target_os = "openbsd")]
fn randombytes_sysrandom_stir() {}

#[cfg(target_os = "openbsd")]
fn randombytes_sysrandom_buf(buf: &mut [u8], size: usize) {
    let buf = &mut buf[..size];
    unsafe { sysrandom_ffi::arc4random_buf(buf.as_mut_ptr() as *mut std::ffi::c_void, size) };
}

#[cfg(target_os = "openbsd")]
fn randombytes_sysrandom_close() -> i32 {
    0
}

/* __OpenBSD__ */

// port: the file descriptor is a std File (None for -1), and the state sits behind a Mutex
#[cfg(not(target_os = "openbsd"))]
struct SysRandom {
    #[cfg(not(windows))]
    random_data_source_fd: Option<std::fs::File>,
    initialized: i32,
    getrandom_available: i32,
}

#[cfg(not(target_os = "openbsd"))]
static stream: Mutex<SysRandom> = Mutex::new(SysRandom {
    #[cfg(not(windows))]
    random_data_source_fd: None,
    initialized: 0,
    getrandom_available: 0,
});

#[cfg(not(target_os = "openbsd"))]
fn stream_lock() -> std::sync::MutexGuard<'static, SysRandom> {
    stream.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(all(not(windows), not(target_os = "openbsd")))]
fn safe_read(fd: &std::fs::File, buf_: &mut [u8], mut size: usize) -> isize {
    use std::io::Read;
    let mut fd = fd;
    let mut buf: usize = 0; // port: an offset into buf_ in place of the pointer
    let mut readnb: isize;

    debug_assert!(size > 0);
    debug_assert!(size <= isize::MAX as usize);
    loop {
        loop {
            match fd.read(&mut buf_[buf..buf + size]) {
                Ok(n) => {
                    readnb = n as isize;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted || e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => {
                    readnb = -1;
                    break;
                }
            }
        }
        if readnb < 0 {
            return readnb; /* LCOV_EXCL_LINE */
        }
        if readnb == 0 {
            break; /* LCOV_EXCL_LINE */
        }
        size -= readnb as usize;
        buf += readnb as usize;
        if size == 0 {
            break;
        }
    }

    buf as isize
}

// BLOCK_ON_DEV_RANDOM
#[cfg(any(target_os = "linux", target_os = "android"))]
fn randombytes_block_on_dev_random() -> i32 {
    use std::os::unix::io::AsRawFd;
    let mut pfd: poll_ffi::pollfd;
    let fd: std::fs::File;
    let mut pret: i32;

    fd = match std::fs::File::open("/dev/random") {
        Ok(f) => f,
        Err(_) => return 0,
    };
    pfd = poll_ffi::pollfd { fd: fd.as_raw_fd(), events: poll_ffi::POLLIN, revents: 0 };
    loop {
        pret = unsafe { poll_ffi::poll(&mut pfd, 1, -1) };
        let errno = std::io::Error::last_os_error().kind();
        if !(pret < 0 && (errno == std::io::ErrorKind::Interrupted || errno == std::io::ErrorKind::WouldBlock)) {
            break;
        }
    }
    if pret != 1 {
        drop(fd);
        return -1;
    }
    // port: dropping the File closes it (close()'s result is not reported)
    drop(fd);
    0
}

#[cfg(all(not(windows), not(target_os = "openbsd")))]
fn randombytes_sysrandom_random_dev_open() -> Option<std::fs::File> {
    /* LCOV_EXCL_START */
    use std::os::unix::fs::FileTypeExt;
    // port: USE_BLOCKING_RANDOM is not defined, so /dev/urandom comes first
    static devices: [&str; 2] = ["/dev/urandom", "/dev/random"];
    let mut device: usize = 0;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if randombytes_block_on_dev_random() != 0 {
            return None;
        }
    }
    loop {
        match std::fs::File::open(devices[device]) {
            Ok(fd) => {
                if let Ok(st) = fd.metadata() {
                    if st.file_type().is_char_device() {
                        // port: std opens files with O_CLOEXEC already (the F_SETFD / FD_CLOEXEC step)
                        return Some(fd);
                    }
                }
                drop(fd);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                continue;
            }
            Err(_) => {}
        }
        device += 1;
        if device >= devices.len() {
            break;
        }
    }

    None
    /* LCOV_EXCL_STOP */
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn _randombytes_linux_getrandom(buf: &mut [u8], size: usize) -> i32 {
    let mut readnb: i32;

    debug_assert!(size <= 256);
    loop {
        readnb = unsafe { sysrandom_ffi::getrandom(buf.as_mut_ptr() as *mut std::ffi::c_void, size, 0) } as i32;
        let errno = std::io::Error::last_os_error().kind();
        if !(readnb < 0 && (errno == std::io::ErrorKind::Interrupted || errno == std::io::ErrorKind::WouldBlock)) {
            break;
        }
    }

    ((readnb == size as i32) as i32) - 1
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn randombytes_linux_getrandom(buf_: &mut [u8], mut size: usize) -> i32 {
    let mut buf: usize = 0; // port: an offset into buf_ in place of the pointer
    let mut chunk_size: usize = 256;

    loop {
        if size < chunk_size {
            chunk_size = size;
            debug_assert!(chunk_size > 0);
        }
        if _randombytes_linux_getrandom(&mut buf_[buf..buf + chunk_size], chunk_size) != 0 {
            return -1;
        }
        size -= chunk_size;
        buf += chunk_size;
        if size == 0 {
            break;
        }
    }

    0
}

// port: the errno save / restore is dropped (Rust code does not observe errno)
#[cfg(all(not(windows), not(target_os = "openbsd")))]
fn randombytes_sysrandom_init(s: &mut SysRandom) {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        let mut fodder = [0u8; 16];

        if randombytes_linux_getrandom(&mut fodder, 16) == 0 {
            s.getrandom_available = 1;
            return;
        }
        s.getrandom_available = 0;
    }

    s.random_data_source_fd = randombytes_sysrandom_random_dev_open();
    if s.random_data_source_fd.is_none() {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
}

/* _WIN32 */

#[cfg(windows)]
fn randombytes_sysrandom_init(s: &mut SysRandom) {}

#[cfg(not(target_os = "openbsd"))]
fn randombytes_sysrandom_stir() {
    let mut s = stream_lock();
    if s.initialized == 0 {
        randombytes_sysrandom_init(&mut s);
        s.initialized = 1;
    }
}

#[cfg(not(target_os = "openbsd"))]
fn randombytes_sysrandom_stir_if_needed() {
    if stream_lock().initialized == 0 {
        randombytes_sysrandom_stir();
    }
}

#[cfg(not(target_os = "openbsd"))]
fn randombytes_sysrandom_close() -> i32 {
    let mut ret: i32 = -1;
    let mut s = stream_lock();

    #[cfg(not(windows))]
    {
        // port: dropping the File closes it
        if s.random_data_source_fd.is_some() {
            s.random_data_source_fd = None;
            s.initialized = 0;
            ret = 0;
        }
        if HAVE_LINUX_COMPATIBLE_GETRANDOM && s.getrandom_available != 0 {
            ret = 0;
        }
    }
    #[cfg(windows)]
    {
        if s.initialized != 0 {
            s.initialized = 0;
            ret = 0;
        }
    }
    ret
}

#[cfg(not(target_os = "openbsd"))]
fn randombytes_sysrandom_buf(buf: &mut [u8], size: usize) {
    let buf = &mut buf[..size];
    randombytes_sysrandom_stir_if_needed();
    #[cfg(not(windows))]
    {
        let s = stream_lock();
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            if s.getrandom_available != 0 {
                drop(s);
                if randombytes_linux_getrandom(buf, size) != 0 {
                    sodium_misuse(); /* LCOV_EXCL_LINE */
                }
                return;
            }
        }
        let ok = match &s.random_data_source_fd {
            Some(fd) => safe_read(fd, buf, size) == size as isize,
            None => false,
        };
        if !ok {
            sodium_misuse(); /* LCOV_EXCL_LINE */
        }
    }
    #[cfg(windows)]
    {
        COMPILER_ASSERT!(randombytes_BYTES_MAX <= 0xffffffff);
        if size as u64 > 0xffffffffu64 {
            sodium_misuse(); /* LCOV_EXCL_LINE */
        }
        if unsafe { sysrandom_ffi::RtlGenRandom(buf.as_mut_ptr() as *mut std::ffi::c_void, size as u32) } == 0 {
            sodium_misuse(); /* LCOV_EXCL_LINE */
        }
    }
}

#[cfg(not(target_os = "openbsd"))]
fn randombytes_sysrandom() -> u32 {
    let mut r = [0u8; 4];

    randombytes_sysrandom_buf(&mut r, 4);

    // port: the bytes of a uint32_t in native order
    u32::from_ne_bytes(r)
}

/* __OpenBSD__ */

fn randombytes_sysrandom_implementation_name() -> &'static str {
    "sysrandom"
}

pub static randombytes_sysrandom_implementation: randombytes_implementation = randombytes_implementation {
    implementation_name: randombytes_sysrandom_implementation_name,
    random: randombytes_sysrandom,
    stir: Some(randombytes_sysrandom_stir),
    uniform: None,
    buf: randombytes_sysrandom_buf,
    close: Some(randombytes_sysrandom_close),
};

/* ================= sodium_randombytes.c ================= */

// port: the amalgamation renames `implementation` to implementation__rb; null until first use. The pointer only
// ever holds a &'static randombytes_implementation.
static implementation__rb: AtomicPtr<randombytes_implementation> = AtomicPtr::new(ptr::null_mut());

// port: RANDOMBYTES_DEFAULT_IMPLEMENTATION is &randombytes_sysrandom_implementation (no Emscripten / Native Client)
fn RANDOMBYTES_DEFAULT_IMPLEMENTATION() -> *mut randombytes_implementation {
    &randombytes_sysrandom_implementation as *const randombytes_implementation as *mut randombytes_implementation
}

fn implementation_rb() -> &'static randombytes_implementation {
    unsafe { &*implementation__rb.load(Ordering::Acquire) }
}

fn randombytes_init_if_needed() {
    if implementation__rb.load(Ordering::Acquire).is_null() {
        implementation__rb.store(RANDOMBYTES_DEFAULT_IMPLEMENTATION(), Ordering::Release);
        randombytes_stir();
    }
}

pub fn randombytes_set_implementation(r#impl: &'static randombytes_implementation) -> i32 {
    implementation__rb.store(r#impl as *const randombytes_implementation as *mut randombytes_implementation, Ordering::Release);

    0
}

pub fn randombytes_implementation_name() -> &'static str {
    randombytes_init_if_needed();
    (implementation_rb().implementation_name)()
}

pub fn randombytes_random() -> u32 {
    randombytes_init_if_needed();
    (implementation_rb().random)()
}

pub fn randombytes_stir() {
    randombytes_init_if_needed();
    if let Some(stir) = implementation_rb().stir {
        stir();
    }
}

pub fn randombytes_uniform(upper_bound: u32) -> u32 {
    let min: u32;
    let mut r: u32;

    randombytes_init_if_needed();
    if let Some(uniform) = implementation_rb().uniform {
        return uniform(upper_bound);
    }
    if upper_bound < 2 {
        return 0;
    }
    min = (1u32.wrapping_add(!upper_bound)) % upper_bound; /* = 2**32 mod upper_bound */
    loop {
        r = randombytes_random();
        if !(r < min) {
            break;
        }
    }
    /* r is now clamped to a set whose size mod upper_bound == 0
     * the worst case (2**31+1) requires ~ 2 attempts */

    r % upper_bound
}

pub fn randombytes_buf(buf: &mut [u8], size: usize) {
    randombytes_init_if_needed();
    if size > 0 {
        (implementation_rb().buf)(buf, size);
    }
}

pub fn randombytes_buf_deterministic(buf: &mut [u8], size: usize, seed: &[u8]) {
    static nonce: [u8; crypto_stream_chacha20_ietf_NONCEBYTES] = [b'L', b'i', b'b', b's', b'o', b'd', b'i', b'u', b'm', b'D', b'R', b'G'];

    COMPILER_ASSERT!(randombytes_SEEDBYTES == crypto_stream_chacha20_ietf_KEYBYTES);
    // port: #if SIZE_MAX > 0x4000000000ULL is a runtime test of a constant
    if usize::MAX as u64 > 0x4000000000u64 {
        COMPILER_ASSERT!(randombytes_BYTES_MAX <= 0x4000000000u64);
        if size as u64 > 0x4000000000u64 {
            sodium_misuse();
        }
    }
    crypto_stream_chacha20_ietf(buf, size as u64, &nonce, seed);
}

pub fn randombytes_seedbytes() -> usize {
    randombytes_SEEDBYTES
}

pub fn randombytes_close() -> i32 {
    let p = implementation__rb.load(Ordering::Acquire);
    if !p.is_null() {
        if let Some(close) = unsafe { &*p }.close {
            return close();
        }
    }
    0
}

pub fn randombytes(buf: &mut [u8], buf_len: u64) {
    debug_assert!(buf_len <= usize::MAX as u64);
    randombytes_buf(buf, buf_len as usize);
}

/* ================= sodium_core.c ================= */

// port: sodium_init()'s NETCODE_CRYPTO_LOGS printf, kept off as upstream
const NETCODE_CRYPTO_LOGS: bool = false;

static initialized: AtomicI32 = AtomicI32::new(0);

pub fn sodium_init() -> i32 {
    if sodium_crit_enter() != 0 {
        return -1; /* LCOV_EXCL_LINE */
    }
    if initialized.load(Ordering::Acquire) != 0 {
        if sodium_crit_leave() != 0 {
            return -1; /* LCOV_EXCL_LINE */
        }
        return 1;
    }
    // port: _sodium_runtime_get_cpu_features() (sodium_runtime.c) and _sodium_alloc_init() (the guarded heap) are
    // not ported
    randombytes_stir();
    _crypto_onetimeauth_poly1305_pick_best_implementation();
    _crypto_stream_chacha20_pick_best_implementation();
    initialized.store(1, Ordering::Release);
    if sodium_crit_leave() != 0 {
        return -1; /* LCOV_EXCL_LINE */
    }
    if NETCODE_CRYPTO_LOGS {
        println!();
    }
    0
}

// port: the HAVE_ATOMIC_OPS spin lock (__sync_lock_test_and_set / __sync_lock_release) is the portable one, so it
// stands in for the Windows critical section and the pthread mutex

static _sodium_lock: AtomicBool = AtomicBool::new(false);

pub fn sodium_crit_enter() -> i32 {
    while _sodium_lock.swap(true, Ordering::Acquire) {
        std::thread::yield_now();
    }
    0
}

pub fn sodium_crit_leave() -> i32 {
    _sodium_lock.store(false, Ordering::Release);

    0
}

// port: static mut, read and written only inside sodium_crit_enter / sodium_crit_leave, as upstream
static mut _misuse_handler: Option<fn()> = None;

pub fn sodium_misuse() -> ! {
    let handler: Option<fn()>;

    let _ = sodium_crit_leave();
    if sodium_crit_enter() == 0 {
        handler = unsafe { _misuse_handler };
        if let Some(handler) = handler {
            handler();
        }
    }
    /* LCOV_EXCL_START */
    std::process::abort();
}
/* LCOV_EXCL_STOP */

pub fn sodium_set_misuse_handler(handler: Option<fn()>) -> i32 {
    if sodium_crit_enter() != 0 {
        return -1; /* LCOV_EXCL_LINE */
    }
    unsafe { _misuse_handler = handler };
    if sodium_crit_leave() != 0 {
        return -1; /* LCOV_EXCL_LINE */
    }
    0
}

/* ================= sodium_chacha20-ref.c ================= */

/*
 chacha-merged.c version 20080118
 D. J. Bernstein
 Public domain.
 */

#[derive(Clone, Copy, Default)]
struct chacha_ctx {
    input: [u32; 16],
}

macro_rules! U32C {
    ($v:expr) => {
        ($v as u32)
    };
}

macro_rules! U32V {
    ($v:expr) => {
        (($v) as u32 & U32C!(0xFFFFFFFFu32))
    };
}

macro_rules! ROTATE {
    ($v:expr, $c:expr) => {
        rotl32($v, $c)
    };
}
macro_rules! XOR {
    ($v:expr, $w:expr) => {
        (($v) ^ ($w))
    };
}
macro_rules! PLUS {
    ($v:expr, $w:expr) => {
        U32V!(($v).wrapping_add($w))
    };
}
macro_rules! PLUSONE {
    ($v:expr) => {
        PLUS!($v, 1)
    };
}

macro_rules! QUARTERROUND {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
        $a = PLUS!($a, $b);
        $d = ROTATE!(XOR!($d, $a), 16);
        $c = PLUS!($c, $d);
        $b = ROTATE!(XOR!($b, $c), 12);
        $a = PLUS!($a, $b);
        $d = ROTATE!(XOR!($d, $a), 8);
        $c = PLUS!($c, $d);
        $b = ROTATE!(XOR!($b, $c), 7);
    };
}

fn chacha_keysetup(ctx: &mut chacha_ctx, k: &[u8]) {
    ctx.input[0] = U32C!(0x61707865u32);
    ctx.input[1] = U32C!(0x3320646eu32);
    ctx.input[2] = U32C!(0x79622d32u32);
    ctx.input[3] = U32C!(0x6b206574u32);
    ctx.input[4] = load32_le(&k[0..]);
    ctx.input[5] = load32_le(&k[4..]);
    ctx.input[6] = load32_le(&k[8..]);
    ctx.input[7] = load32_le(&k[12..]);
    ctx.input[8] = load32_le(&k[16..]);
    ctx.input[9] = load32_le(&k[20..]);
    ctx.input[10] = load32_le(&k[24..]);
    ctx.input[11] = load32_le(&k[28..]);
}

fn chacha_ivsetup(ctx: &mut chacha_ctx, iv: &[u8], counter: Option<&[u8]>) {
    ctx.input[12] = match counter { None => 0, Some(counter) => load32_le(&counter[0..]) };
    ctx.input[13] = match counter { None => 0, Some(counter) => load32_le(&counter[4..]) };
    ctx.input[14] = load32_le(&iv[0..]);
    ctx.input[15] = load32_le(&iv[4..]);
}

fn chacha_ietf_ivsetup(ctx: &mut chacha_ctx, iv: &[u8], counter: Option<&[u8]>) {
    ctx.input[12] = match counter { None => 0, Some(counter) => load32_le(counter) };
    ctx.input[13] = load32_le(&iv[0..]);
    ctx.input[14] = load32_le(&iv[4..]);
    ctx.input[15] = load32_le(&iv[8..]);
}

// port: the kernel walks m and c as raw pointers, as upstream does, because stream_ref encrypts c in place (m == c)
// and the final partial block points both at tmp. Every caller bounds-checks its slices before the call.
#[inline(always)]
unsafe fn LOAD32_LE_P(src: *const u8) -> u32 {
    u32::from_le_bytes(ptr::read_unaligned(src as *const [u8; 4]))
}

#[inline(always)]
unsafe fn STORE32_LE_P(dst: *mut u8, w: u32) {
    ptr::write_unaligned(dst as *mut [u8; 4], w.to_le_bytes());
}

unsafe fn chacha20_encrypt_bytes(ctx: &mut chacha_ctx, mut m: *const u8, mut c: *mut u8, mut bytes: u64) {
    let mut x0: u32; let mut x1: u32; let mut x2: u32; let mut x3: u32; let mut x4: u32; let mut x5: u32;
    let mut x6: u32; let mut x7: u32; let mut x8: u32; let mut x9: u32; let mut x10: u32; let mut x11: u32;
    let mut x12: u32; let mut x13: u32; let mut x14: u32; let mut x15: u32;
    let j0: u32; let j1: u32; let j2: u32; let j3: u32; let j4: u32; let j5: u32; let j6: u32; let j7: u32;
    let j8: u32; let j9: u32; let j10: u32; let j11: u32; let mut j12: u32; let mut j13: u32; let j14: u32;
    let j15: u32;
    let mut ctarget: *mut u8 = ptr::null_mut();
    let mut tmp = [0u8; 64];
    let mut i: u32;

    if bytes == 0 {
        return; /* LCOV_EXCL_LINE */
    }
    j0 = ctx.input[0];
    j1 = ctx.input[1];
    j2 = ctx.input[2];
    j3 = ctx.input[3];
    j4 = ctx.input[4];
    j5 = ctx.input[5];
    j6 = ctx.input[6];
    j7 = ctx.input[7];
    j8 = ctx.input[8];
    j9 = ctx.input[9];
    j10 = ctx.input[10];
    j11 = ctx.input[11];
    j12 = ctx.input[12];
    j13 = ctx.input[13];
    j14 = ctx.input[14];
    j15 = ctx.input[15];

    loop {
        if bytes < 64 {
            tmp = [0u8; 64];
            i = 0;
            while (i as u64) < bytes {
                tmp[i as usize] = *m.add(i as usize);
                i += 1;
            }
            // port: one pointer for both, so reads through m and writes through c stay valid for the same buffer
            let t = tmp.as_mut_ptr();
            m = t;
            ctarget = c;
            c = t;
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        i = 20;
        while i > 0 {
            QUARTERROUND!(x0, x4, x8, x12);
            QUARTERROUND!(x1, x5, x9, x13);
            QUARTERROUND!(x2, x6, x10, x14);
            QUARTERROUND!(x3, x7, x11, x15);
            QUARTERROUND!(x0, x5, x10, x15);
            QUARTERROUND!(x1, x6, x11, x12);
            QUARTERROUND!(x2, x7, x8, x13);
            QUARTERROUND!(x3, x4, x9, x14);
            i -= 2;
        }
        x0 = PLUS!(x0, j0);
        x1 = PLUS!(x1, j1);
        x2 = PLUS!(x2, j2);
        x3 = PLUS!(x3, j3);
        x4 = PLUS!(x4, j4);
        x5 = PLUS!(x5, j5);
        x6 = PLUS!(x6, j6);
        x7 = PLUS!(x7, j7);
        x8 = PLUS!(x8, j8);
        x9 = PLUS!(x9, j9);
        x10 = PLUS!(x10, j10);
        x11 = PLUS!(x11, j11);
        x12 = PLUS!(x12, j12);
        x13 = PLUS!(x13, j13);
        x14 = PLUS!(x14, j14);
        x15 = PLUS!(x15, j15);

        x0 = XOR!(x0, LOAD32_LE_P(m.add(0)));
        x1 = XOR!(x1, LOAD32_LE_P(m.add(4)));
        x2 = XOR!(x2, LOAD32_LE_P(m.add(8)));
        x3 = XOR!(x3, LOAD32_LE_P(m.add(12)));
        x4 = XOR!(x4, LOAD32_LE_P(m.add(16)));
        x5 = XOR!(x5, LOAD32_LE_P(m.add(20)));
        x6 = XOR!(x6, LOAD32_LE_P(m.add(24)));
        x7 = XOR!(x7, LOAD32_LE_P(m.add(28)));
        x8 = XOR!(x8, LOAD32_LE_P(m.add(32)));
        x9 = XOR!(x9, LOAD32_LE_P(m.add(36)));
        x10 = XOR!(x10, LOAD32_LE_P(m.add(40)));
        x11 = XOR!(x11, LOAD32_LE_P(m.add(44)));
        x12 = XOR!(x12, LOAD32_LE_P(m.add(48)));
        x13 = XOR!(x13, LOAD32_LE_P(m.add(52)));
        x14 = XOR!(x14, LOAD32_LE_P(m.add(56)));
        x15 = XOR!(x15, LOAD32_LE_P(m.add(60)));

        j12 = PLUSONE!(j12);
        /* LCOV_EXCL_START */
        if j12 == 0 {
            j13 = PLUSONE!(j13);
        }
        /* LCOV_EXCL_STOP */

        STORE32_LE_P(c.add(0), x0);
        STORE32_LE_P(c.add(4), x1);
        STORE32_LE_P(c.add(8), x2);
        STORE32_LE_P(c.add(12), x3);
        STORE32_LE_P(c.add(16), x4);
        STORE32_LE_P(c.add(20), x5);
        STORE32_LE_P(c.add(24), x6);
        STORE32_LE_P(c.add(28), x7);
        STORE32_LE_P(c.add(32), x8);
        STORE32_LE_P(c.add(36), x9);
        STORE32_LE_P(c.add(40), x10);
        STORE32_LE_P(c.add(44), x11);
        STORE32_LE_P(c.add(48), x12);
        STORE32_LE_P(c.add(52), x13);
        STORE32_LE_P(c.add(56), x14);
        STORE32_LE_P(c.add(60), x15);

        if bytes <= 64 {
            if bytes < 64 {
                i = 0;
                while i < bytes as u32 {
                    *ctarget.add(i as usize) = *c.add(i as usize); /* ctarget cannot be NULL */
                    i += 1;
                }
            }
            ctx.input[12] = j12;
            ctx.input[13] = j13;

            // port: tmp held keystream bytes; upstream leaves them on the stack
            return;
        }
        bytes -= 64;
        c = c.add(64);
        m = m.add(64);
    }
}

fn stream_ref(c: &mut [u8], clen: u64, n: &[u8], k: &[u8]) -> i32 {
    let mut ctx = chacha_ctx::default();

    if clen == 0 {
        return 0;
    }
    COMPILER_ASSERT!(crypto_stream_chacha20_KEYBYTES == 256 / 8);
    chacha_keysetup(&mut ctx, k);
    chacha_ivsetup(&mut ctx, n, None);
    let c = &mut c[..clen as usize];
    c.fill(0);
    let p = c.as_mut_ptr();
    unsafe { chacha20_encrypt_bytes(&mut ctx, p, p, clen) };
    sodium_memzero_struct(&mut ctx);

    0
}

fn stream_ietf_ext_ref(c: &mut [u8], clen: u64, n: &[u8], k: &[u8]) -> i32 {
    let mut ctx = chacha_ctx::default();

    if clen == 0 {
        return 0;
    }
    COMPILER_ASSERT!(crypto_stream_chacha20_KEYBYTES == 256 / 8);
    chacha_keysetup(&mut ctx, k);
    chacha_ietf_ivsetup(&mut ctx, n, None);
    let c = &mut c[..clen as usize];
    c.fill(0);
    let p = c.as_mut_ptr();
    unsafe { chacha20_encrypt_bytes(&mut ctx, p, p, clen) };
    sodium_memzero_struct(&mut ctx);

    0
}

fn stream_ref_xor_ic(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], ic: u64, k: &[u8]) -> i32 {
    let mut ctx = chacha_ctx::default();
    let mut ic_bytes = [0u8; 8];
    let ic_high: u32;
    let ic_low: u32;

    if mlen == 0 {
        return 0;
    }
    ic_high = U32V!(ic >> 32);
    ic_low = U32V!(ic);
    store32_le(&mut ic_bytes[0..], ic_low);
    store32_le(&mut ic_bytes[4..], ic_high);
    chacha_keysetup(&mut ctx, k);
    chacha_ivsetup(&mut ctx, n, Some(&ic_bytes));
    let c = &mut c[..mlen as usize];
    let m = &m[..mlen as usize];
    unsafe { chacha20_encrypt_bytes(&mut ctx, m.as_ptr(), c.as_mut_ptr(), mlen) };
    sodium_memzero_struct(&mut ctx);

    0
}

fn stream_ietf_ext_ref_xor_ic(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], ic: u32, k: &[u8]) -> i32 {
    let mut ctx = chacha_ctx::default();
    let mut ic_bytes = [0u8; 4];

    if mlen == 0 {
        return 0;
    }
    store32_le(&mut ic_bytes, ic);
    chacha_keysetup(&mut ctx, k);
    chacha_ietf_ivsetup(&mut ctx, n, Some(&ic_bytes));
    let c = &mut c[..mlen as usize];
    let m = &m[..mlen as usize];
    unsafe { chacha20_encrypt_bytes(&mut ctx, m.as_ptr(), c.as_mut_ptr(), mlen) };
    sodium_memzero_struct(&mut ctx);

    0
}

pub static crypto_stream_chacha20_ref_implementation: crypto_stream_chacha20_implementation = crypto_stream_chacha20_implementation {
    stream: stream_ref,
    stream_ietf_ext: stream_ietf_ext_ref,
    stream_xor_ic: stream_ref_xor_ic,
    stream_ietf_ext_xor_ic: stream_ietf_ext_ref_xor_ic,
};
// #undef U32C U32V ROTATE XOR PLUS PLUSONE QUARTERROUND (port: QUARTERROUND is redefined below)

/* ================= sodium_dolbeau_chacha20-ssse3.c ================= */

// port: not ported (SSSE3 intrinsics; byte-identical to the ref implementation)

/* ================= sodium_dolbeau_chacha20-avx2.c ================= */

// port: not ported (AVX2 intrinsics; byte-identical to the ref implementation)

/* ================= sodium_stream_chacha20.c ================= */

// port: the amalgamation renames `implementation` to implementation__cc20. It only ever points at the ref
// implementation here (the SIMD ones are not ported), so it is a constant.
static implementation__cc20: &crypto_stream_chacha20_implementation = &crypto_stream_chacha20_ref_implementation;

pub fn crypto_stream_chacha20_keybytes() -> usize {
    crypto_stream_chacha20_KEYBYTES
}

pub fn crypto_stream_chacha20_noncebytes() -> usize {
    crypto_stream_chacha20_NONCEBYTES
}

pub fn crypto_stream_chacha20_messagebytes_max() -> usize {
    crypto_stream_chacha20_MESSAGEBYTES_MAX as usize
}

pub fn crypto_stream_chacha20_ietf_keybytes() -> usize {
    crypto_stream_chacha20_ietf_KEYBYTES
}

pub fn crypto_stream_chacha20_ietf_noncebytes() -> usize {
    crypto_stream_chacha20_ietf_NONCEBYTES
}

pub fn crypto_stream_chacha20_ietf_messagebytes_max() -> usize {
    crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX as usize
}

pub fn crypto_stream_chacha20(c: &mut [u8], clen: u64, n: &[u8], k: &[u8]) -> i32 {
    if clen > crypto_stream_chacha20_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    (implementation__cc20.stream)(c, clen, n, k)
}

pub fn crypto_stream_chacha20_xor_ic(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], ic: u64, k: &[u8]) -> i32 {
    if mlen > crypto_stream_chacha20_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    (implementation__cc20.stream_xor_ic)(c, m, mlen, n, ic, k)
}

pub fn crypto_stream_chacha20_xor(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], k: &[u8]) -> i32 {
    if mlen > crypto_stream_chacha20_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    (implementation__cc20.stream_xor_ic)(c, m, mlen, n, 0, k)
}

pub fn crypto_stream_chacha20_ietf_ext(c: &mut [u8], clen: u64, n: &[u8], k: &[u8]) -> i32 {
    if clen > crypto_stream_chacha20_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    (implementation__cc20.stream_ietf_ext)(c, clen, n, k)
}

pub fn crypto_stream_chacha20_ietf_ext_xor_ic(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], ic: u32, k: &[u8]) -> i32 {
    if mlen > crypto_stream_chacha20_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    (implementation__cc20.stream_ietf_ext_xor_ic)(c, m, mlen, n, ic, k)
}

fn crypto_stream_chacha20_ietf_ext_xor(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], k: &[u8]) -> i32 {
    if mlen > crypto_stream_chacha20_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    (implementation__cc20.stream_ietf_ext_xor_ic)(c, m, mlen, n, 0, k)
}

pub fn crypto_stream_chacha20_ietf(c: &mut [u8], clen: u64, n: &[u8], k: &[u8]) -> i32 {
    if clen > crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    crypto_stream_chacha20_ietf_ext(c, clen, n, k)
}

pub fn crypto_stream_chacha20_ietf_xor_ic(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], ic: u32, k: &[u8]) -> i32 {
    // port: wrapping arithmetic, as the unsigned long long expression upstream
    if (ic as u64) > ((64u64 * (1u64 << 32)) / 64u64).wrapping_sub(mlen.wrapping_add(63) / 64u64) {
        sodium_misuse();
    }
    crypto_stream_chacha20_ietf_ext_xor_ic(c, m, mlen, n, ic, k)
}

pub fn crypto_stream_chacha20_ietf_xor(c: &mut [u8], m: &[u8], mlen: u64, n: &[u8], k: &[u8]) -> i32 {
    if mlen > crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    crypto_stream_chacha20_ietf_ext_xor(c, m, mlen, n, k)
}

pub fn crypto_stream_chacha20_ietf_keygen(k: &mut [u8]) {
    randombytes_buf(k, crypto_stream_chacha20_ietf_KEYBYTES);
}

pub fn crypto_stream_chacha20_keygen(k: &mut [u8]) {
    randombytes_buf(k, crypto_stream_chacha20_KEYBYTES);
}

pub fn _crypto_stream_chacha20_pick_best_implementation() -> i32 {
    // port: implementation__cc20 is always &crypto_stream_chacha20_ref_implementation (the AVX2 and SSSE3 branches
    // are not ported)
    if NETCODE_CRYPTO_LOGS {
        println!("chacha20 -> ref");
    }
    0
}

/* ================= sodium_core_hchacha20.c ================= */

macro_rules! QUARTERROUND {
    ($A:ident, $B:ident, $C:ident, $D:ident) => {
        $A = $A.wrapping_add($B); $D = rotl32($D ^ $A, 16);
        $C = $C.wrapping_add($D); $B = rotl32($B ^ $C, 12);
        $A = $A.wrapping_add($B); $D = rotl32($D ^ $A, 8);
        $C = $C.wrapping_add($D); $B = rotl32($B ^ $C, 7);
    };
}

pub fn crypto_core_hchacha20(out: &mut [u8], r#in: &[u8], k: &[u8], c: Option<&[u8]>) -> i32 {
    let mut i: i32;
    let mut x0: u32; let mut x1: u32; let mut x2: u32; let mut x3: u32; let mut x4: u32; let mut x5: u32;
    let mut x6: u32; let mut x7: u32;
    let mut x8: u32; let mut x9: u32; let mut x10: u32; let mut x11: u32; let mut x12: u32; let mut x13: u32;
    let mut x14: u32; let mut x15: u32;

    match c {
        None => {
            x0 = 0x61707865;
            x1 = 0x3320646e;
            x2 = 0x79622d32;
            x3 = 0x6b206574;
        }
        Some(c) => {
            x0 = load32_le(&c[0..]);
            x1 = load32_le(&c[4..]);
            x2 = load32_le(&c[8..]);
            x3 = load32_le(&c[12..]);
        }
    }
    x4 = load32_le(&k[0..]);
    x5 = load32_le(&k[4..]);
    x6 = load32_le(&k[8..]);
    x7 = load32_le(&k[12..]);
    x8 = load32_le(&k[16..]);
    x9 = load32_le(&k[20..]);
    x10 = load32_le(&k[24..]);
    x11 = load32_le(&k[28..]);
    x12 = load32_le(&r#in[0..]);
    x13 = load32_le(&r#in[4..]);
    x14 = load32_le(&r#in[8..]);
    x15 = load32_le(&r#in[12..]);

    i = 0;
    while i < 10 {
        QUARTERROUND!(x0, x4, x8, x12);
        QUARTERROUND!(x1, x5, x9, x13);
        QUARTERROUND!(x2, x6, x10, x14);
        QUARTERROUND!(x3, x7, x11, x15);
        QUARTERROUND!(x0, x5, x10, x15);
        QUARTERROUND!(x1, x6, x11, x12);
        QUARTERROUND!(x2, x7, x8, x13);
        QUARTERROUND!(x3, x4, x9, x14);
        i += 1;
    }

    store32_le(&mut out[0..], x0);
    store32_le(&mut out[4..], x1);
    store32_le(&mut out[8..], x2);
    store32_le(&mut out[12..], x3);
    store32_le(&mut out[16..], x12);
    store32_le(&mut out[20..], x13);
    store32_le(&mut out[24..], x14);
    store32_le(&mut out[28..], x15);

    0
}

pub fn crypto_core_hchacha20_outputbytes() -> usize {
    crypto_core_hchacha20_OUTPUTBYTES
}

pub fn crypto_core_hchacha20_inputbytes() -> usize {
    crypto_core_hchacha20_INPUTBYTES
}

pub fn crypto_core_hchacha20_keybytes() -> usize {
    crypto_core_hchacha20_KEYBYTES
}

pub fn crypto_core_hchacha20_constbytes() -> usize {
    crypto_core_hchacha20_CONSTBYTES
}
// #undef QUARTERROUND

/* ================= sodium_poly1305_donna.c ================= */

/* inlined sodium_poly1305_donna64.h */
/*
   poly1305 implementation using 64 bit * 64 bit = 128 bit multiplication
   and 128 bit addition
*/

// port: HAVE_TI_MODE is always true (u128), so this is the donna64 branch; the donna32 #else branch is not ported

macro_rules! MUL {
    ($out:ident, $x:expr, $y:expr) => {
        $out = ($x as u128) * ($y as u128)
    };
}
macro_rules! ADD {
    ($out:ident, $in:expr) => {
        $out = $out.wrapping_add($in)
    };
}
macro_rules! ADDLO {
    ($out:ident, $in:expr) => {
        $out = $out.wrapping_add($in as u128)
    };
}
macro_rules! SHR {
    ($in:expr, $shift:expr) => {
        (($in >> ($shift)) as u64)
    };
}
macro_rules! LO {
    ($in:expr) => {
        ($in as u64)
    };
}

// port: POLY1305_NOINLINE is #[inline(never)]

const poly1305_block_size: u64 = 16;

/* 17 + sizeof(unsigned long long) + 8*sizeof(unsigned long long) */
#[derive(Clone, Copy, Default)]
pub struct poly1305_state_internal_t {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u64; 2],
    leftover: u64,
    buffer: [u8; poly1305_block_size as usize],
    r#final: u8,
}

fn poly1305_init(st: &mut poly1305_state_internal_t, key: &[u8]) {
    let t0: u64;
    let t1: u64;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    t0 = load64_le(&key[0..]);
    t1 = load64_le(&key[8..]);

    /* wiped after finalization */
    st.r[0] = (t0) & 0xffc0fffffff;
    st.r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
    st.r[2] = (t1 >> 24) & 0x00ffffffc0f;

    /* h = 0 */
    st.h[0] = 0;
    st.h[1] = 0;
    st.h[2] = 0;

    /* save pad for later */
    st.pad[0] = load64_le(&key[16..]);
    st.pad[1] = load64_le(&key[24..]);

    st.leftover = 0;
    st.r#final = 0;
}

fn poly1305_blocks(st: &mut poly1305_state_internal_t, m_: &[u8], mut bytes: u64) {
    let hibit: u64 = if st.r#final != 0 { 0 } else { 1u64 << 40 }; /* 1 << 128 */
    let r0: u64; let r1: u64; let r2: u64;
    let s1: u64; let s2: u64;
    let mut h0: u64; let mut h1: u64; let mut h2: u64;
    let mut c: u64;
    let mut d0: u128; let mut d1: u128; let mut d2: u128; let mut d: u128;
    let mut m: usize = 0; // port: an offset into m_ in place of the pointer

    r0 = st.r[0];
    r1 = st.r[1];
    r2 = st.r[2];

    h0 = st.h[0];
    h1 = st.h[1];
    h2 = st.h[2];

    s1 = r1 * (5 << 2);
    s2 = r2 * (5 << 2);

    while bytes >= poly1305_block_size {
        let t0: u64;
        let t1: u64;

        /* h += m[i] */
        t0 = load64_le(&m_[m..]);
        t1 = load64_le(&m_[m + 8..]);

        h0 += (t0) & 0xfffffffffff;
        h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffff;
        h2 += ((t1 >> 24) & 0x3ffffffffff) | hibit;

        /* h *= r */
        MUL!(d0, h0, r0);
        MUL!(d, h1, s2);
        ADD!(d0, d);
        MUL!(d, h2, s1);
        ADD!(d0, d);
        MUL!(d1, h0, r1);
        MUL!(d, h1, r0);
        ADD!(d1, d);
        MUL!(d, h2, s2);
        ADD!(d1, d);
        MUL!(d2, h0, r2);
        MUL!(d, h1, r1);
        ADD!(d2, d);
        MUL!(d, h2, r0);
        ADD!(d2, d);

        /* (partial) h %= p */
        c = SHR!(d0, 44);
        h0 = LO!(d0) & 0xfffffffffff;
        ADDLO!(d1, c);
        c = SHR!(d1, 44);
        h1 = LO!(d1) & 0xfffffffffff;
        ADDLO!(d2, c);
        c = SHR!(d2, 42);
        h2 = LO!(d2) & 0x3ffffffffff;
        h0 += c * 5;
        c = h0 >> 44;
        h0 = h0 & 0xfffffffffff;
        h1 += c;

        m += poly1305_block_size as usize;
        bytes -= poly1305_block_size;
    }

    st.h[0] = h0;
    st.h[1] = h1;
    st.h[2] = h2;
}

#[inline(never)]
fn poly1305_finish(st: &mut poly1305_state_internal_t, mac: &mut [u8]) {
    let mut h0: u64; let mut h1: u64; let mut h2: u64; let mut c: u64;
    let mut g0: u64; let mut g1: u64; let mut g2: u64;
    let t0: u64; let t1: u64;

    /* process the remaining block */
    if st.leftover != 0 {
        let mut i: u64 = st.leftover;

        st.buffer[i as usize] = 1;

        i = i + 1;
        while i < poly1305_block_size {
            st.buffer[i as usize] = 0;
            i += 1;
        }
        st.r#final = 1;
        // port: st.buffer is copied out because st is borrowed mutably by the call
        let buffer = st.buffer;
        poly1305_blocks(st, &buffer, poly1305_block_size);
    }

    /* fully carry h */
    h0 = st.h[0];
    h1 = st.h[1];
    h2 = st.h[2];

    c = h1 >> 44;
    h1 &= 0xfffffffffff;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x3ffffffffff;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= 0xfffffffffff;
    h1 += c;
    c = h1 >> 44;
    h1 &= 0xfffffffffff;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x3ffffffffff;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= 0xfffffffffff;
    h1 += c;

    /* compute h + -p */
    g0 = h0 + 5;
    c = g0 >> 44;
    g0 &= 0xfffffffffff;
    g1 = h1 + c;
    c = g1 >> 44;
    g1 &= 0xfffffffffff;
    g2 = (h2 + c).wrapping_sub(1u64 << 42);

    /* select h if h < p, or h + -p if h >= p */
    c = (g2 >> ((std::mem::size_of::<u64>() * 8) - 1)).wrapping_sub(1);
    g0 &= c;
    g1 &= c;
    g2 &= c;
    c = !c;
    h0 = (h0 & c) | g0;
    h1 = (h1 & c) | g1;
    h2 = (h2 & c) | g2;

    /* h = (h + pad) */
    t0 = st.pad[0];
    t1 = st.pad[1];

    h0 += (t0) & 0xfffffffffff;
    c = h0 >> 44;
    h0 &= 0xfffffffffff;
    h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
    c = h1 >> 44;
    h1 &= 0xfffffffffff;
    h2 += ((t1 >> 24) & 0x3ffffffffff) + c;
    h2 &= 0x3ffffffffff;

    /* mac = h % (2^128) */
    h0 = (h0) | (h1 << 44);
    h1 = (h1 >> 20) | (h2 << 24);

    store64_le(&mut mac[0..], h0);
    store64_le(&mut mac[8..], h1);

    /* zero out the state */
    sodium_memzero_struct(st);
}

fn poly1305_update(st: &mut poly1305_state_internal_t, m_: &[u8], mut bytes: u64) {
    let mut i: u64;
    let mut m: usize = 0; // port: an offset into m_ in place of the pointer

    /* handle leftover */
    if st.leftover != 0 {
        let mut want: u64 = poly1305_block_size - st.leftover;

        if want > bytes {
            want = bytes;
        }
        i = 0;
        while i < want {
            st.buffer[(st.leftover + i) as usize] = m_[m + i as usize];
            i += 1;
        }
        bytes -= want;
        m += want as usize;
        st.leftover += want;
        if st.leftover < poly1305_block_size {
            return;
        }
        // port: st.buffer is copied out because st is borrowed mutably by the call
        let buffer = st.buffer;
        poly1305_blocks(st, &buffer, poly1305_block_size);
        st.leftover = 0;
    }

    /* process full blocks */
    if bytes >= poly1305_block_size {
        let want: u64 = bytes & !(poly1305_block_size - 1);

        poly1305_blocks(st, &m_[m..], want);
        m += want as usize;
        bytes -= want;
    }

    /* store leftover */
    if bytes != 0 {
        i = 0;
        while i < bytes {
            st.buffer[(st.leftover + i) as usize] = m_[m + i as usize];
            i += 1;
        }
        st.leftover += bytes;
    }
}

fn crypto_onetimeauth_poly1305_donna(out: &mut [u8], m: &[u8], inlen: u64, key: &[u8]) -> i32 {
    let mut state = poly1305_state_internal_t::default();

    poly1305_init(&mut state, key);
    poly1305_update(&mut state, m, inlen);
    poly1305_finish(&mut state, out);

    0
}

fn crypto_onetimeauth_poly1305_donna_init(state: &mut crypto_onetimeauth_poly1305_state, key: &[u8]) -> i32 {
    poly1305_init(&mut state.opaque, key);

    0
}

fn crypto_onetimeauth_poly1305_donna_update(state: &mut crypto_onetimeauth_poly1305_state, r#in: &[u8], inlen: u64) -> i32 {
    poly1305_update(&mut state.opaque, r#in, inlen);

    0
}

fn crypto_onetimeauth_poly1305_donna_final(state: &mut crypto_onetimeauth_poly1305_state, out: &mut [u8]) -> i32 {
    poly1305_finish(&mut state.opaque, out);

    0
}

fn crypto_onetimeauth_poly1305_donna_verify(h: &[u8], r#in: &[u8], inlen: u64, k: &[u8]) -> i32 {
    let mut correct = [0u8; 16];

    crypto_onetimeauth_poly1305_donna(&mut correct, r#in, inlen, k);

    crypto_verify_16(h, &correct)
}

pub static crypto_onetimeauth_poly1305_donna_implementation: crypto_onetimeauth_poly1305_implementation = crypto_onetimeauth_poly1305_implementation {
    onetimeauth: crypto_onetimeauth_poly1305_donna,
    onetimeauth_verify: crypto_onetimeauth_poly1305_donna_verify,
    onetimeauth_init: crypto_onetimeauth_poly1305_donna_init,
    onetimeauth_update: crypto_onetimeauth_poly1305_donna_update,
    onetimeauth_final: crypto_onetimeauth_poly1305_donna_final,
};
// #undef MUL ADD ADDLO SHR LO POLY1305_NOINLINE poly1305_block_size

/* ================= sodium_poly1305-sse2.c ================= */

// port: not ported (SSE2 intrinsics; byte-identical to donna)

/* ================= sodium_onetimeauth_poly1305.c ================= */

// port: the amalgamation renames `implementation` to implementation__poly. It only ever points at donna here (the
// SSE2 implementation is not ported), so it is a constant.
static implementation__poly: &crypto_onetimeauth_poly1305_implementation = &crypto_onetimeauth_poly1305_donna_implementation;

pub fn crypto_onetimeauth_poly1305(out: &mut [u8], r#in: &[u8], inlen: u64, k: &[u8]) -> i32 {
    (implementation__poly.onetimeauth)(out, r#in, inlen, k)
}

pub fn crypto_onetimeauth_poly1305_verify(h: &[u8], r#in: &[u8], inlen: u64, k: &[u8]) -> i32 {
    (implementation__poly.onetimeauth_verify)(h, r#in, inlen, k)
}

pub fn crypto_onetimeauth_poly1305_init(state: &mut crypto_onetimeauth_poly1305_state, key: &[u8]) -> i32 {
    (implementation__poly.onetimeauth_init)(state, key)
}

pub fn crypto_onetimeauth_poly1305_update(state: &mut crypto_onetimeauth_poly1305_state, r#in: &[u8], inlen: u64) -> i32 {
    (implementation__poly.onetimeauth_update)(state, r#in, inlen)
}

pub fn crypto_onetimeauth_poly1305_final(state: &mut crypto_onetimeauth_poly1305_state, out: &mut [u8]) -> i32 {
    (implementation__poly.onetimeauth_final)(state, out)
}

pub fn crypto_onetimeauth_poly1305_bytes() -> usize {
    crypto_onetimeauth_poly1305_BYTES
}

pub fn crypto_onetimeauth_poly1305_keybytes() -> usize {
    crypto_onetimeauth_poly1305_KEYBYTES
}

pub fn crypto_onetimeauth_poly1305_statebytes() -> usize {
    // port: the size of this port's state (upstream's opaque state is 256 bytes)
    std::mem::size_of::<crypto_onetimeauth_poly1305_state>()
}

pub fn crypto_onetimeauth_poly1305_keygen(k: &mut [u8]) {
    randombytes_buf(k, crypto_onetimeauth_poly1305_KEYBYTES);
}

pub fn _crypto_onetimeauth_poly1305_pick_best_implementation() -> i32 {
    // port: implementation__poly is always &crypto_onetimeauth_poly1305_donna_implementation (the SSE2 branch is
    // not ported)
    if NETCODE_CRYPTO_LOGS {
        println!("poly1305 -> ref");
    }
    0
}

/* ================= sodium_aead_chacha20poly1305.c ================= */

static _pad0: [u8; 16] = [0u8; 16];

// port: a NULL `ad` (adlen 0) is a valid call upstream; None is passed to the Poly1305 update as an empty slice
#[inline(always)]
fn ad_or_empty(ad: Option<&[u8]>) -> &[u8] {
    match ad {
        Some(ad) => ad,
        None => &[],
    }
}

pub fn crypto_aead_chacha20poly1305_encrypt_detached(c: &mut [u8], mac: &mut [u8], maclen_p: Option<&mut u64>, m: &[u8], mlen: u64, ad: Option<&[u8]>, adlen: u64, nsec: Option<&[u8]>, npub: &[u8], k: &[u8]) -> i32 {
    let mut state = crypto_onetimeauth_poly1305_state::default();
    let mut block0 = [0u8; 64];
    let mut slen = [0u8; 8];

    let _ = nsec;
    crypto_stream_chacha20(&mut block0, 64, npub, k);
    crypto_onetimeauth_poly1305_init(&mut state, &block0);
    sodium_memzero(&mut block0, 64);

    crypto_onetimeauth_poly1305_update(&mut state, ad_or_empty(ad), adlen);
    store64_le(&mut slen, adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    crypto_stream_chacha20_xor_ic(c, m, mlen, npub, 1, k);

    crypto_onetimeauth_poly1305_update(&mut state, c, mlen);
    store64_le(&mut slen, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    crypto_onetimeauth_poly1305_final(&mut state, mac);
    sodium_memzero_struct(&mut state);

    if let Some(maclen_p) = maclen_p {
        *maclen_p = crypto_aead_chacha20poly1305_ABYTES as u64;
    }
    0
}

pub fn crypto_aead_chacha20poly1305_encrypt(c: &mut [u8], clen_p: Option<&mut u64>, m: &[u8], mlen: u64, ad: Option<&[u8]>, adlen: u64, nsec: Option<&[u8]>, npub: &[u8], k: &[u8]) -> i32 {
    let mut clen: u64 = 0;
    let ret: i32;

    if mlen > crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    // port: c + mlen is the second half of split_at_mut
    let (c, mac) = c.split_at_mut(mlen as usize);
    ret = crypto_aead_chacha20poly1305_encrypt_detached(c, mac, None, m, mlen, ad, adlen, nsec, npub, k);
    if let Some(clen_p) = clen_p {
        if ret == 0 {
            clen = mlen + crypto_aead_chacha20poly1305_ABYTES as u64;
        }
        *clen_p = clen;
    }
    ret
}

pub fn crypto_aead_chacha20poly1305_ietf_encrypt_detached(c: &mut [u8], mac: &mut [u8], maclen_p: Option<&mut u64>, m: &[u8], mlen: u64, ad: Option<&[u8]>, adlen: u64, nsec: Option<&[u8]>, npub: &[u8], k: &[u8]) -> i32 {
    let mut state = crypto_onetimeauth_poly1305_state::default();
    let mut block0 = [0u8; 64];
    let mut slen = [0u8; 8];

    let _ = nsec;
    crypto_stream_chacha20_ietf(&mut block0, 64, npub, k);
    crypto_onetimeauth_poly1305_init(&mut state, &block0);
    sodium_memzero(&mut block0, 64);

    crypto_onetimeauth_poly1305_update(&mut state, ad_or_empty(ad), adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &_pad0, (0x10u64.wrapping_sub(adlen)) & 0xf);

    crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, npub, 1, k);

    crypto_onetimeauth_poly1305_update(&mut state, c, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &_pad0, (0x10u64.wrapping_sub(mlen)) & 0xf);

    store64_le(&mut slen, adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    store64_le(&mut slen, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    crypto_onetimeauth_poly1305_final(&mut state, mac);
    sodium_memzero_struct(&mut state);

    if let Some(maclen_p) = maclen_p {
        *maclen_p = crypto_aead_chacha20poly1305_ietf_ABYTES as u64;
    }
    0
}

pub fn crypto_aead_chacha20poly1305_ietf_encrypt(c: &mut [u8], clen_p: Option<&mut u64>, m: &[u8], mlen: u64, ad: Option<&[u8]>, adlen: u64, nsec: Option<&[u8]>, npub: &[u8], k: &[u8]) -> i32 {
    let mut clen: u64 = 0;
    let ret: i32;

    if mlen > crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    // port: c + mlen is the second half of split_at_mut
    let (c, mac) = c.split_at_mut(mlen as usize);
    ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, None, m, mlen, ad, adlen, nsec, npub, k);
    if let Some(clen_p) = clen_p {
        if ret == 0 {
            clen = mlen + crypto_aead_chacha20poly1305_ietf_ABYTES as u64;
        }
        *clen_p = clen;
    }
    ret
}

pub fn crypto_aead_chacha20poly1305_decrypt_detached(m: Option<&mut [u8]>, nsec: Option<&mut [u8]>, c: &[u8], clen: u64, mac: &[u8], ad: Option<&[u8]>, adlen: u64, npub: &[u8], k: &[u8]) -> i32 {
    let mut state = crypto_onetimeauth_poly1305_state::default();
    let mut block0 = [0u8; 64];
    let mut slen = [0u8; 8];
    let mut computed_mac = [0u8; crypto_aead_chacha20poly1305_ABYTES];
    let mlen: u64;
    let ret: i32;

    let _ = nsec;
    crypto_stream_chacha20(&mut block0, 64, npub, k);
    crypto_onetimeauth_poly1305_init(&mut state, &block0);
    sodium_memzero(&mut block0, 64);

    crypto_onetimeauth_poly1305_update(&mut state, ad_or_empty(ad), adlen);
    store64_le(&mut slen, adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    mlen = clen;
    crypto_onetimeauth_poly1305_update(&mut state, c, mlen);
    store64_le(&mut slen, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    crypto_onetimeauth_poly1305_final(&mut state, &mut computed_mac);
    sodium_memzero_struct(&mut state);

    COMPILER_ASSERT!(crypto_aead_chacha20poly1305_ABYTES == 16);
    ret = crypto_verify_16(&computed_mac, mac);
    sodium_memzero(&mut computed_mac, 16);
    let m = match m {
        None => return ret,
        Some(m) => m,
    };
    if ret != 0 {
        m[..mlen as usize].fill(0);
        return -1;
    }
    ACQUIRE_FENCE!();
    crypto_stream_chacha20_xor_ic(m, c, mlen, npub, 1, k);

    0
}

pub fn crypto_aead_chacha20poly1305_decrypt(m: &mut [u8], mlen_p: Option<&mut u64>, nsec: Option<&mut [u8]>, c: &[u8], clen: u64, ad: Option<&[u8]>, adlen: u64, npub: &[u8], k: &[u8]) -> i32 {
    let mut mlen: u64 = 0;
    let mut ret: i32 = -1;

    if clen >= crypto_aead_chacha20poly1305_ABYTES as u64 {
        ret = crypto_aead_chacha20poly1305_decrypt_detached(
            Some(m), nsec,
            c, clen - crypto_aead_chacha20poly1305_ABYTES as u64,
            &c[(clen - crypto_aead_chacha20poly1305_ABYTES as u64) as usize..],
            ad, adlen, npub, k);
    }
    if let Some(mlen_p) = mlen_p {
        if ret == 0 {
            mlen = clen - crypto_aead_chacha20poly1305_ABYTES as u64;
        }
        *mlen_p = mlen;
    }
    ret
}

pub fn crypto_aead_chacha20poly1305_ietf_decrypt_detached(m: Option<&mut [u8]>, nsec: Option<&mut [u8]>, c: &[u8], clen: u64, mac: &[u8], ad: Option<&[u8]>, adlen: u64, npub: &[u8], k: &[u8]) -> i32 {
    let mut state = crypto_onetimeauth_poly1305_state::default();
    let mut block0 = [0u8; 64];
    let mut slen = [0u8; 8];
    let mut computed_mac = [0u8; crypto_aead_chacha20poly1305_ietf_ABYTES];
    let mlen: u64;
    let ret: i32;

    let _ = nsec;
    crypto_stream_chacha20_ietf(&mut block0, 64, npub, k);
    crypto_onetimeauth_poly1305_init(&mut state, &block0);
    sodium_memzero(&mut block0, 64);

    crypto_onetimeauth_poly1305_update(&mut state, ad_or_empty(ad), adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &_pad0, (0x10u64.wrapping_sub(adlen)) & 0xf);

    mlen = clen;
    crypto_onetimeauth_poly1305_update(&mut state, c, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &_pad0, (0x10u64.wrapping_sub(mlen)) & 0xf);

    store64_le(&mut slen, adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    store64_le(&mut slen, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    crypto_onetimeauth_poly1305_final(&mut state, &mut computed_mac);
    sodium_memzero_struct(&mut state);

    COMPILER_ASSERT!(crypto_aead_chacha20poly1305_ietf_ABYTES == 16);
    ret = crypto_verify_16(&computed_mac, mac);
    sodium_memzero(&mut computed_mac, 16);
    let m = match m {
        None => return ret,
        Some(m) => m,
    };
    if ret != 0 {
        m[..mlen as usize].fill(0);
        return -1;
    }
    ACQUIRE_FENCE!();
    crypto_stream_chacha20_ietf_xor_ic(m, c, mlen, npub, 1, k);

    0
}

pub fn crypto_aead_chacha20poly1305_ietf_decrypt(m: &mut [u8], mlen_p: Option<&mut u64>, nsec: Option<&mut [u8]>, c: &[u8], clen: u64, ad: Option<&[u8]>, adlen: u64, npub: &[u8], k: &[u8]) -> i32 {
    let mut mlen: u64 = 0;
    let mut ret: i32 = -1;

    if clen >= crypto_aead_chacha20poly1305_ietf_ABYTES as u64 {
        ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            Some(m), nsec,
            c, clen - crypto_aead_chacha20poly1305_ietf_ABYTES as u64,
            &c[(clen - crypto_aead_chacha20poly1305_ietf_ABYTES as u64) as usize..],
            ad, adlen, npub, k);
    }
    if let Some(mlen_p) = mlen_p {
        if ret == 0 {
            mlen = clen - crypto_aead_chacha20poly1305_ietf_ABYTES as u64;
        }
        *mlen_p = mlen;
    }
    ret
}

pub fn crypto_aead_chacha20poly1305_ietf_keybytes() -> usize {
    crypto_aead_chacha20poly1305_ietf_KEYBYTES
}

pub fn crypto_aead_chacha20poly1305_ietf_npubbytes() -> usize {
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES
}

pub fn crypto_aead_chacha20poly1305_ietf_nsecbytes() -> usize {
    crypto_aead_chacha20poly1305_ietf_NSECBYTES
}

pub fn crypto_aead_chacha20poly1305_ietf_abytes() -> usize {
    crypto_aead_chacha20poly1305_ietf_ABYTES
}

pub fn crypto_aead_chacha20poly1305_ietf_messagebytes_max() -> usize {
    crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX as usize
}

pub fn crypto_aead_chacha20poly1305_ietf_keygen(k: &mut [u8]) {
    randombytes_buf(k, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
}

pub fn crypto_aead_chacha20poly1305_keybytes() -> usize {
    crypto_aead_chacha20poly1305_KEYBYTES
}

pub fn crypto_aead_chacha20poly1305_npubbytes() -> usize {
    crypto_aead_chacha20poly1305_NPUBBYTES
}

pub fn crypto_aead_chacha20poly1305_nsecbytes() -> usize {
    crypto_aead_chacha20poly1305_NSECBYTES
}

pub fn crypto_aead_chacha20poly1305_abytes() -> usize {
    crypto_aead_chacha20poly1305_ABYTES
}

pub fn crypto_aead_chacha20poly1305_messagebytes_max() -> usize {
    crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX as usize
}

pub fn crypto_aead_chacha20poly1305_keygen(k: &mut [u8]) {
    randombytes_buf(k, crypto_aead_chacha20poly1305_KEYBYTES);
}

/* ================= sodium_aead_xchacha20poly1305.c ================= */

// port: the amalgamation renames this file's _pad0 to _pad0__x
static _pad0__x: [u8; 16] = [0u8; 16];

fn _encrypt_detached(c: &mut [u8], mac: &mut [u8], maclen_p: Option<&mut u64>, m: &[u8], mlen: u64, ad: Option<&[u8]>, adlen: u64, nsec: Option<&[u8]>, npub: &[u8], k: &[u8]) -> i32 {
    let mut state = crypto_onetimeauth_poly1305_state::default();
    let mut block0 = [0u8; 64];
    let mut slen = [0u8; 8];

    let _ = nsec;
    crypto_stream_chacha20_ietf_ext(&mut block0, 64, npub, k);
    crypto_onetimeauth_poly1305_init(&mut state, &block0);
    sodium_memzero(&mut block0, 64);

    crypto_onetimeauth_poly1305_update(&mut state, ad_or_empty(ad), adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &_pad0__x, (0x10u64.wrapping_sub(adlen)) & 0xf);

    crypto_stream_chacha20_ietf_ext_xor_ic(c, m, mlen, npub, 1, k);

    crypto_onetimeauth_poly1305_update(&mut state, c, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &_pad0__x, (0x10u64.wrapping_sub(mlen)) & 0xf);

    store64_le(&mut slen, adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    store64_le(&mut slen, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    crypto_onetimeauth_poly1305_final(&mut state, mac);
    sodium_memzero_struct(&mut state);

    if let Some(maclen_p) = maclen_p {
        *maclen_p = crypto_aead_chacha20poly1305_ietf_ABYTES as u64;
    }
    0
}

fn _decrypt_detached(m: Option<&mut [u8]>, nsec: Option<&mut [u8]>, c: &[u8], clen: u64, mac: &[u8], ad: Option<&[u8]>, adlen: u64, npub: &[u8], k: &[u8]) -> i32 {
    let mut state = crypto_onetimeauth_poly1305_state::default();
    let mut block0 = [0u8; 64];
    let mut slen = [0u8; 8];
    let mut computed_mac = [0u8; crypto_aead_chacha20poly1305_ietf_ABYTES];
    let mlen: u64;
    let ret: i32;

    let _ = nsec;
    crypto_stream_chacha20_ietf_ext(&mut block0, 64, npub, k);
    crypto_onetimeauth_poly1305_init(&mut state, &block0);
    sodium_memzero(&mut block0, 64);

    crypto_onetimeauth_poly1305_update(&mut state, ad_or_empty(ad), adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &_pad0__x, (0x10u64.wrapping_sub(adlen)) & 0xf);

    mlen = clen;
    crypto_onetimeauth_poly1305_update(&mut state, c, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &_pad0__x, (0x10u64.wrapping_sub(mlen)) & 0xf);

    store64_le(&mut slen, adlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    store64_le(&mut slen, mlen);
    crypto_onetimeauth_poly1305_update(&mut state, &slen, 8);

    crypto_onetimeauth_poly1305_final(&mut state, &mut computed_mac);
    sodium_memzero_struct(&mut state);

    COMPILER_ASSERT!(crypto_aead_chacha20poly1305_ietf_ABYTES == 16);
    ret = crypto_verify_16(&computed_mac, mac);
    sodium_memzero(&mut computed_mac, 16);
    let m = match m {
        None => return ret,
        Some(m) => m,
    };
    if ret != 0 {
        m[..mlen as usize].fill(0);
        return -1;
    }
    ACQUIRE_FENCE!();
    crypto_stream_chacha20_ietf_ext_xor_ic(m, c, mlen, npub, 1, k);

    0
}

pub fn crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c: &mut [u8], mac: &mut [u8], maclen_p: Option<&mut u64>, m: &[u8], mlen: u64, ad: Option<&[u8]>, adlen: u64, nsec: Option<&[u8]>, npub: &[u8], k: &[u8]) -> i32 {
    let mut k2 = [0u8; crypto_core_hchacha20_OUTPUTBYTES];
    let mut npub2 = [0u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    let ret: i32;

    crypto_core_hchacha20(&mut k2, npub, k, None);
    npub2[4..crypto_aead_chacha20poly1305_ietf_NPUBBYTES].copy_from_slice(
        &npub[crypto_core_hchacha20_INPUTBYTES..crypto_core_hchacha20_INPUTBYTES + crypto_aead_chacha20poly1305_ietf_NPUBBYTES - 4]);
    ret = _encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, &npub2, &k2);
    sodium_memzero(&mut k2, crypto_core_hchacha20_OUTPUTBYTES);

    ret
}

pub fn crypto_aead_xchacha20poly1305_ietf_encrypt(c: &mut [u8], clen_p: Option<&mut u64>, m: &[u8], mlen: u64, ad: Option<&[u8]>, adlen: u64, nsec: Option<&[u8]>, npub: &[u8], k: &[u8]) -> i32 {
    let mut clen: u64 = 0;
    let ret: i32;

    if mlen > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX {
        sodium_misuse();
    }
    // port: c + mlen is the second half of split_at_mut
    let (c, mac) = c.split_at_mut(mlen as usize);
    ret = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, None, m, mlen, ad, adlen, nsec, npub, k);
    if let Some(clen_p) = clen_p {
        if ret == 0 {
            clen = mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES as u64;
        }
        *clen_p = clen;
    }
    ret
}

pub fn crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m: Option<&mut [u8]>, nsec: Option<&mut [u8]>, c: &[u8], clen: u64, mac: &[u8], ad: Option<&[u8]>, adlen: u64, npub: &[u8], k: &[u8]) -> i32 {
    let mut k2 = [0u8; crypto_core_hchacha20_OUTPUTBYTES];
    let mut npub2 = [0u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    let ret: i32;

    crypto_core_hchacha20(&mut k2, npub, k, None);
    npub2[4..crypto_aead_chacha20poly1305_ietf_NPUBBYTES].copy_from_slice(
        &npub[crypto_core_hchacha20_INPUTBYTES..crypto_core_hchacha20_INPUTBYTES + crypto_aead_chacha20poly1305_ietf_NPUBBYTES - 4]);
    ret = _decrypt_detached(m, nsec, c, clen, mac, ad, adlen, &npub2, &k2);
    sodium_memzero(&mut k2, crypto_core_hchacha20_OUTPUTBYTES);

    ret
}

pub fn crypto_aead_xchacha20poly1305_ietf_decrypt(m: &mut [u8], mlen_p: Option<&mut u64>, nsec: Option<&mut [u8]>, c: &[u8], clen: u64, ad: Option<&[u8]>, adlen: u64, npub: &[u8], k: &[u8]) -> i32 {
    let mut mlen: u64 = 0;
    let mut ret: i32 = -1;

    if clen >= crypto_aead_xchacha20poly1305_ietf_ABYTES as u64 {
        ret = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            Some(m), nsec,
            c, clen - crypto_aead_xchacha20poly1305_ietf_ABYTES as u64,
            &c[(clen - crypto_aead_xchacha20poly1305_ietf_ABYTES as u64) as usize..],
            ad, adlen, npub, k);
    }
    if let Some(mlen_p) = mlen_p {
        if ret == 0 {
            mlen = clen - crypto_aead_xchacha20poly1305_ietf_ABYTES as u64;
        }
        *mlen_p = mlen;
    }
    ret
}

pub fn crypto_aead_xchacha20poly1305_ietf_keybytes() -> usize {
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES
}

pub fn crypto_aead_xchacha20poly1305_ietf_npubbytes() -> usize {
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
}

pub fn crypto_aead_xchacha20poly1305_ietf_nsecbytes() -> usize {
    crypto_aead_xchacha20poly1305_ietf_NSECBYTES
}

pub fn crypto_aead_xchacha20poly1305_ietf_abytes() -> usize {
    crypto_aead_xchacha20poly1305_ietf_ABYTES
}

pub fn crypto_aead_xchacha20poly1305_ietf_messagebytes_max() -> usize {
    crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX as usize
}

pub fn crypto_aead_xchacha20poly1305_ietf_keygen(k: &mut [u8]) {
    randombytes_buf(k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}
// #undef _pad0
