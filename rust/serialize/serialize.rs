/*
    serialize

    Copyright © 2016 - 2026, Más Bandwidth LLC.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
    If you use this library in a product, please credit
    "serialize - Glenn Fiedler and Rowan Claude" in your product credits. The
    license doesn't require this credit. It's an official request, and honoring
    it is appreciated.
*/

/*
    port: how the C++ header maps onto Rust (see rust/README.md for the crate-wide rules)

    - Streams: C++ `template <typename Stream>` serialize functions are `fn f<S: Stream>( ..., stream: &mut S ) -> bool`.
      `Stream::IsWriting` / `Stream::IsReading` are the associated consts `S::IsWriting` / `S::IsReading`.
      The write and measure streams take `value` by value upstream; the trait takes `&mut` for all three.
    - Macros: every serialize_* / read_* / write_* macro is a `#[macro_export] macro_rules!` with the upstream name and
      arguments. `stream` is a `&mut S` expression (the `stream` parameter of a serialize function); `value` is a place
      of any integer type, converted with `as` exactly where upstream converts implicitly. Each macro returns `false`
      from the enclosing function on failure, as upstream.
    - Byte buffers are slices. `data` / `string` arguments of the macros are anything that indexes to `[u8]` (an array,
      a slice, a `&mut [u8]`, a `Vec<u8>`): the macros take `&mut ( data )[..]`.
    - 128 bit integers: Rust has native u128 / i128 on every target, so serialize::uint128_t / int128_t are those (the
      `__SIZEOF_INT128__` branch). The emulated serialize_uint128_t / serialize_int128_t pair is still ported, because
      upstream defines it whenever tests are enabled: the tests hold it to native operator by operator, and wide fixed
      point works with emulated storage too.
    - serialize_restrict, SERIALIZE_ALWAYS_INLINE, SERIALIZE_BULK_COPY, the MSVC warning pragmas and _CRT_SECURE_NO_WARNINGS
      are compiler spellings with no Rust meaning beyond `#[inline(always)]` / `copy_from_slice`; Rust's borrow rules give
      the no-overlap promise restrict makes.
*/

use std::ffi::c_void;
use std::ops::{ Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign, Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign };
use std::cmp::Ordering;
use std::sync::Mutex;

pub const SERIALIZE_VERSION_MAJOR: i32 = 1;
pub const SERIALIZE_VERSION_MINOR: i32 = 16;
pub const SERIALIZE_VERSION_PATCH: i32 = 2;
pub const SERIALIZE_VERSION: &str = "1.16.2";

// port: serialize_restrict has no Rust spelling: a `&mut` borrow already promises the compiler that nothing else aliases it

/*
    SERIALIZE_ALWAYS_INLINE — how the per-field serialize spine is spelled, both directions.

    A serialize function is a chain of fallible calls — if ( !stream.SerializeX( ... ) )
    return false; — and LLVM's static branch heuristics treat each success/failure split as
    roughly even odds, so block frequency decays geometrically down the chain. A few fields in,
    every remaining callsite is judged cold and held to the cold-callsite inline threshold, which
    the write helpers do not fit. With the demand in place the write spine inlines end to end.

    The read spine makes the same demand — BitReader::ReadBits/ReadAlign and ReadStream's six
    per-field methods, the exact mirror of the write set.
    The compressed-float and string bodies stay undemanded deliberately: their cost is the
    work, not the call.
*/

// port: SERIALIZE_ALWAYS_INLINE is #[inline(always)] on the same functions

/*
    SERIALIZE_BULK_COPY — how WriteBytes moves memory, spelled so the fortify capture
    can never touch it.
*/

// port: SERIALIZE_BULK_COPY is slice::copy_from_slice (there is no fortify capture in Rust)

/*
    SERIALIZE_FLOAT_FORCE_ROUND( x ) — pins a float intermediate to its rounded float32
    value, so no floating point contraction setting can fuse it into a neighboring
    operation. The compressed float quantization requires TWO distinct roundings on write
    and on read (STANDARD.md): the product must round to float32 before the following add.
    This macro is what makes the wire bits identical under every contraction mode, so they
    no longer depend on the consumer's compiler flags.
*/

// port: Rust never contracts a * b + c into a fused multiply-add (there is no fp-contract mode: every f32 operation
// rounds to f32), so the barrier has nothing to pin. It stays as an inline no-op at the same call sites, so the two
// roundings are still visibly separate statements
#[inline(always)]
pub fn SERIALIZE_FLOAT_FORCE_ROUND( x: &mut f32 )
{
    let _ = x;
}

// port: serialize_assert is active in debug builds (cfg(debug_assertions), upstream's !NDEBUG) and calls the assert
// hook, as netcode_assert / reliable_assert / yojimbo_assert do (rust/README.md, "Logging and asserts"). Upstream it
// is the C assert; the hook is a port addition so tests can observe a failed contract instead of aborting

/// The default serialize assert handler: prints the failed condition like the C assert, then panics.
pub fn serialize_default_assert_handler( condition: &str, function: &str, file: &str, line: i32 )
{
    println!( "{}:{}: {}: Assertion `{}' failed.", file, line, function, condition );
    panic!( "serialize_assert failed: {}", condition );
}

static serialize_assert_function_ptr: Mutex<fn( &str, &str, &str, i32 )> = Mutex::new( serialize_default_assert_handler as fn( &str, &str, &str, i32 ) );

/// Set the function called when a serialize_assert fails. port addition
pub fn serialize_set_assert_function( function: fn( condition: &str, function: &str, file: &str, line: i32 ) )
{
    *serialize_assert_function_ptr.lock().unwrap_or_else( |e| e.into_inner() ) = function;
}

/// Called by serialize_assert! when its condition is false. port addition
#[cold]
#[inline(never)]
pub fn serialize_assert_failed( condition: &str, function: &str, file: &str, line: i32 )
{
    let function_ptr = *serialize_assert_function_ptr.lock().unwrap_or_else( |e| e.into_inner() );
    function_ptr( condition, function, file, line );
}

#[macro_export]
macro_rules! serialize_assert {
    ( $condition:expr ) => {
        if cfg!( debug_assertions ) && !( $condition )
        {
            $crate::serialize::serialize_assert_failed( stringify!( $condition ), module_path!(), file!(), line!() as i32 );
        }
    };
}

// static_assert is C++11, and consumers vendor this header into pre-C++11 builds, so compile
// time invariants go through this macro.
// port: an inline const block, so it can name the generic parameters of the function it sits in and fails at
// monomorphization like the C++ static_assert does at instantiation
#[macro_export]
macro_rules! serialize_static_assert {
    ( $condition:expr, $message:expr ) => {
        const { assert!( $condition, $message ) }
    };
}

// port: SERIALIZE_DEBUG / SERIALIZE_RELEASE follow debug_assertions, as upstream follows NDEBUG
pub const SERIALIZE_DEBUG: bool = cfg!( debug_assertions );
pub const SERIALIZE_RELEASE: bool = !cfg!( debug_assertions );

// port: the endianness detection is the target's endianness
pub const SERIALIZE_LITTLE_ENDIAN: i32 = if cfg!( target_endian = "little" ) { 1 } else { 0 };
pub const SERIALIZE_BIG_ENDIAN: i32 = if cfg!( target_endian = "big" ) { 1 } else { 0 };

// port: the MSVC warning push/pop pragmas and the includes have no Rust meaning

// 128 bit integer support.
//
// serialize::uint128_t and serialize::int128_t exist on every platform. Where the compiler
// provides native __int128 (gcc, clang, clang-cl) they are unsigned __int128 and __int128: the
// fastest representation. On compilers without it (pure MSVC), serialize defines the emulated
// pair below — serialize_uint128_t and serialize_int128_t, full 128 bit integer types with standard
// semantics — and announces them with the SERIALIZE_UINT128_DEFINED handshake macro. The two structs
// are one facility: one announce macro covers the pair, and copies are carried whole, never
// just one half.
//
// THE SHARING CONVENTION: single header libraries cannot include each other, so this definition
// block is carried, verbatim, by sibling projects under the same handshake (the fixed point
// library, and games built on these libraries). Whichever header is included first defines the
// pair; everyone after sees SERIALIZE_UINT128_DEFINED and aliases them, so the types are defined
// exactly once per translation unit instead of two or three times. The copies exist by design;
// the handshake makes them mutually exclusive per translation unit, and the differential tests
// against native __int128 in each C++ home are what keep every copy honest — drift fails loudly.
//
// Semantics match native __int128 exactly, with documented choices where native has none:
// shift counts outside [0,127] yield zero (all sign bits for the signed arithmetic right
// shift; native shifts by 128 or more are undefined behavior), and signed INT128_MIN over -1
// wraps to INT128_MIN, the bit pattern native hardware produces.
//
// DIVISION OR MODULO BY ZERO IS UNDEFINED. Do not do it. It is undefined for native
// __int128 too — C++ says so, and the hardware disagrees with itself: measured, arm64
// returns zero for x / 0 but returns the DIVIDEND for x % 0, while x86-64 IDIV/DIV raises a
// hardware exception and terminates. There is therefore no portable behavior available to
// match, and any value this block returned would be a divergence from somewhere.
// What the block guarantees is only that it is TOTAL — it returns zero quotient and zero
// remainder rather than trapping, so a caller's mistake cannot crash a process and the block
// keeps its no-assert-dependency design. That is an implementation detail, not a contract:
// callers may not rely on it, and the differential test against native deliberately excludes
// zero divisors, because agreement there is not a property either side can promise.
//
// When tests are enabled the pair is defined even where native __int128 exists, so the test
// suite can prove the emulation agrees with native operator by operator and produces byte
// identical wire.

// port: always defined (Rust always has native u128, and upstream defines the pair whenever tests are enabled).
// The C++ constructors per standard integer type are From impls (i32 / i64 sign extend, u32 / u64 zero extend);
// the explicit conversion operators are From impls on u64 / i64; the operators are the std::ops traits, with
// wrapping arithmetic where C++ unsigned arithmetic wraps. ++ / -- are PreIncrement / PostIncrement /
// PreDecrement / PostDecrement; unary + is the identity and is not ported.

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct serialize_uint128_t
{
    pub lo: u64,            // the low 64 bits. first, matching the little endian layout and the wire order
    pub hi: u64,            // the high 64 bits
}

// construction mirrors native conversion to unsigned __int128 exactly: unsigned sources zero
// extend, signed sources sign extend (a negative value wraps modulo 2^128, so the high lane
// fills with ones). one constructor per standard integer type keeps every call an exact match
// after integer promotion — a lone uint64_t constructor would zero extend negative int64
// values where native sign extends, silently diverging the wire between representations.

impl From<i32> for serialize_uint128_t { fn from( value: i32 ) -> Self { serialize_uint128_t { lo: value as i64 as u64, hi: if value < 0 { 0xFFFFFFFFFFFFFFFF } else { 0 } } } }
impl From<i64> for serialize_uint128_t { fn from( value: i64 ) -> Self { serialize_uint128_t { lo: value as u64, hi: if value < 0 { 0xFFFFFFFFFFFFFFFF } else { 0 } } } }
impl From<u32> for serialize_uint128_t { fn from( value: u32 ) -> Self { serialize_uint128_t { lo: value as u64, hi: 0 } } }
impl From<u64> for serialize_uint128_t { fn from( value: u64 ) -> Self { serialize_uint128_t { lo: value, hi: 0 } } }

// bit preserving conversion from the signed type (the explicit converting constructor upstream)
impl From<serialize_int128_t> for serialize_uint128_t { fn from( value: serialize_int128_t ) -> Self { serialize_uint128_t { lo: value.lo, hi: value.hi } } }

// explicit operator uint64_t: the low lane
impl From<serialize_uint128_t> for u64 { fn from( value: serialize_uint128_t ) -> u64 { value.lo } }

impl Ord for serialize_uint128_t
{
    fn cmp( &self, other: &Self ) -> Ordering
    {
        if self.hi != other.hi { self.hi.cmp( &other.hi ) } else { self.lo.cmp( &other.lo ) }
    }
}

impl PartialOrd for serialize_uint128_t
{
    fn partial_cmp( &self, other: &Self ) -> Option<Ordering> { Some( self.cmp( other ) ) }
}

impl Not for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn not( self ) -> serialize_uint128_t
    {
        let mut result = serialize_uint128_t::from( 0 );
        result.lo = !self.lo;
        result.hi = !self.hi;
        result
    }
}

impl BitAnd for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn bitand( self, other: serialize_uint128_t ) -> serialize_uint128_t
    {
        let mut result = serialize_uint128_t::from( 0 );
        result.lo = self.lo & other.lo;
        result.hi = self.hi & other.hi;
        result
    }
}

impl BitOr for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn bitor( self, other: serialize_uint128_t ) -> serialize_uint128_t
    {
        let mut result = serialize_uint128_t::from( 0 );
        result.lo = self.lo | other.lo;
        result.hi = self.hi | other.hi;
        result
    }
}

impl BitXor for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn bitxor( self, other: serialize_uint128_t ) -> serialize_uint128_t
    {
        let mut result = serialize_uint128_t::from( 0 );
        result.lo = self.lo ^ other.lo;
        result.hi = self.hi ^ other.hi;
        result
    }
}

impl Shl<i32> for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn shl( self, shift: i32 ) -> serialize_uint128_t
    {
        // shifting a uint64 lane by 64 is undefined behavior, so the half boundary is an explicit
        // branch. shift counts outside [0,127] yield zero, documented above.
        let mut result = serialize_uint128_t::from( 0 );
        if shift == 0
        {
            result = self;
        }
        else if shift > 0 && shift < 64
        {
            result.hi = ( self.hi << shift ) | ( self.lo >> ( 64 - shift ) );
            result.lo = self.lo << shift;
        }
        else if shift >= 64 && shift < 128
        {
            result.hi = self.lo << ( shift - 64 );
            result.lo = 0;
        }
        result
    }
}

impl Shr<i32> for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn shr( self, shift: i32 ) -> serialize_uint128_t
    {
        // shifting a uint64 lane by 64 is undefined behavior, so the half boundary is an explicit
        // branch. shift counts outside [0,127] yield zero, documented above.
        let mut result = serialize_uint128_t::from( 0 );
        if shift == 0
        {
            result = self;
        }
        else if shift > 0 && shift < 64
        {
            result.lo = ( self.lo >> shift ) | ( self.hi << ( 64 - shift ) );
            result.hi = self.hi >> shift;
        }
        else if shift >= 64 && shift < 128
        {
            result.lo = self.hi >> ( shift - 64 );
            result.hi = 0;
        }
        result
    }
}

impl Add for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn add( self, other: serialize_uint128_t ) -> serialize_uint128_t
    {
        let mut result = serialize_uint128_t::from( 0 );
        result.lo = self.lo.wrapping_add( other.lo );
        result.hi = self.hi.wrapping_add( other.hi ).wrapping_add( if result.lo < self.lo { 1 } else { 0 } );         // carry out of the low lane
        result
    }
}

impl Sub for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn sub( self, other: serialize_uint128_t ) -> serialize_uint128_t
    {
        let mut result = serialize_uint128_t::from( 0 );
        result.lo = self.lo.wrapping_sub( other.lo );
        result.hi = self.hi.wrapping_sub( other.hi ).wrapping_sub( if self.lo < other.lo { 1 } else { 0 } );          // borrow out of the low lane
        result
    }
}

impl Mul for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn mul( self, other: serialize_uint128_t ) -> serialize_uint128_t
    {
        // schoolbook multiplication in 32 bit limbs over the uint64 lanes: the low 64 x 64 product
        // is computed exactly, then the cross products fold into the high lane modulo 2^64
        let a_low: u64 = self.lo & 0xFFFFFFFF;
        let a_high: u64 = self.lo >> 32;
        let b_low: u64 = other.lo & 0xFFFFFFFF;
        let b_high: u64 = other.lo >> 32;

        let product_ll: u64 = a_low.wrapping_mul( b_low );
        let product_lh: u64 = a_low.wrapping_mul( b_high );
        let product_hl: u64 = a_high.wrapping_mul( b_low );
        let product_hh: u64 = a_high.wrapping_mul( b_high );

        let carry: u64 = ( ( product_ll >> 32 ).wrapping_add( product_lh & 0xFFFFFFFF ).wrapping_add( product_hl & 0xFFFFFFFF ) ) >> 32;

        let mut result = serialize_uint128_t::from( 0 );
        result.lo = product_ll.wrapping_add( product_lh << 32 ).wrapping_add( product_hl << 32 );
        result.hi = product_hh.wrapping_add( product_lh >> 32 ).wrapping_add( product_hl >> 32 ).wrapping_add( carry );
        result.hi = result.hi.wrapping_add( self.lo.wrapping_mul( other.hi ).wrapping_add( self.hi.wrapping_mul( other.lo ) ) );
        result
    }
}

impl serialize_uint128_t
{
    pub fn DivMod( dividend: serialize_uint128_t, divisor: serialize_uint128_t, quotient: &mut serialize_uint128_t, remainder: &mut serialize_uint128_t )
    {
        // shift subtract long division. division by zero is UNDEFINED (documented above) — this
        // returns zero quotient and zero remainder only to stay TOTAL, since the block has no
        // assert dependency by design. Not a contract; callers may not rely on the value.
        *quotient = serialize_uint128_t::from( 0 );
        *remainder = serialize_uint128_t::from( 0 );
        if divisor == serialize_uint128_t::from( 0 )
        {
            return;
        }
        if dividend.hi == 0 && divisor.hi == 0
        {
            *quotient = serialize_uint128_t::from( dividend.lo / divisor.lo );
            *remainder = serialize_uint128_t::from( dividend.lo % divisor.lo );
            return;
        }
        let mut i: i32 = 127;
        while i >= 0
        {
            *remainder = *remainder << 1;
            remainder.lo |= ( dividend >> i ).lo & 1;
            if *remainder >= divisor
            {
                *remainder = *remainder - divisor;
                *quotient = *quotient | ( serialize_uint128_t::from( 1 ) << i );
            }
            i -= 1;
        }
    }

    pub fn PreIncrement( &mut self ) -> &mut serialize_uint128_t
    {
        *self = *self + serialize_uint128_t::from( 1 );
        self
    }

    pub fn PostIncrement( &mut self ) -> serialize_uint128_t
    {
        let before = *self;
        self.PreIncrement();
        before
    }

    pub fn PreDecrement( &mut self ) -> &mut serialize_uint128_t
    {
        *self = *self - serialize_uint128_t::from( 1 );
        self
    }

    pub fn PostDecrement( &mut self ) -> serialize_uint128_t
    {
        let before = *self;
        self.PreDecrement();
        before
    }
}

impl Div for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn div( self, other: serialize_uint128_t ) -> serialize_uint128_t
    {
        let mut quotient = serialize_uint128_t::from( 0 );
        let mut remainder = serialize_uint128_t::from( 0 );
        serialize_uint128_t::DivMod( self, other, &mut quotient, &mut remainder );
        quotient
    }
}

impl Rem for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn rem( self, other: serialize_uint128_t ) -> serialize_uint128_t
    {
        let mut quotient = serialize_uint128_t::from( 0 );
        let mut remainder = serialize_uint128_t::from( 0 );
        serialize_uint128_t::DivMod( self, other, &mut quotient, &mut remainder );
        remainder
    }
}

impl Neg for serialize_uint128_t
{
    type Output = serialize_uint128_t;
    fn neg( self ) -> serialize_uint128_t
    {
        serialize_uint128_t::from( 0 ) - self
    }
}

// the compound assignment operators: *this = *this op other
macro_rules! serialize_impl_assign_ops {
    ( $t:ty ) => {
        impl AddAssign for $t { fn add_assign( &mut self, other: $t ) { *self = *self + other; } }
        impl SubAssign for $t { fn sub_assign( &mut self, other: $t ) { *self = *self - other; } }
        impl MulAssign for $t { fn mul_assign( &mut self, other: $t ) { *self = *self * other; } }
        impl DivAssign for $t { fn div_assign( &mut self, other: $t ) { *self = *self / other; } }
        impl RemAssign for $t { fn rem_assign( &mut self, other: $t ) { *self = *self % other; } }
        impl BitAndAssign for $t { fn bitand_assign( &mut self, other: $t ) { *self = *self & other; } }
        impl BitOrAssign for $t { fn bitor_assign( &mut self, other: $t ) { *self = *self | other; } }
        impl BitXorAssign for $t { fn bitxor_assign( &mut self, other: $t ) { *self = *self ^ other; } }
        impl ShlAssign<i32> for $t { fn shl_assign( &mut self, shift: i32 ) { *self = *self << shift; } }
        impl ShrAssign<i32> for $t { fn shr_assign( &mut self, shift: i32 ) { *self = *self >> shift; } }
    };
}

serialize_impl_assign_ops!( serialize_uint128_t );

/**
    The emulated signed 128 bit integer: a thin two's complement layer over the unsigned lanes.
    Addition, subtraction, multiplication and the bitwise operators produce the same bit patterns
    as the unsigned type (two's complement), so they delegate to it instead of duplicating the
    arithmetic. The signed specific pieces are the comparisons (the high lane compares signed),
    operator>> (ARITHMETIC shift: vacated bits fill with the sign), division and modulo (sign
    extraction, unsigned divmod on the magnitudes, sign application — C++ truncation toward zero
    with the remainder sign following the dividend), unary minus, the sign extending int64_t
    constructor, and the bit preserving conversions to and from the unsigned type.
    Documented choices where native has none: shift counts outside [0,127] yield zero for <<
    and all sign bits for >> (the limit of shifting further); and the one overflowing division,
    INT128_MIN over -1, wraps to INT128_MIN quotient and zero remainder — the same bit pattern
    native two's complement hardware produces.
    Division or modulo by zero is UNDEFINED, as it is for native __int128 — see the block comment
    on serialize_uint128_t. This type stays total and returns zero rather than trapping, which is
    an implementation detail and not a contract.
 */

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct serialize_int128_t
{
    pub lo: u64,            // the low 64 bits. first, matching the little endian layout and the wire order
    pub hi: u64,            // the high 64 bits. the top bit is the sign
}

// construction mirrors native conversion to __int128 exactly: signed sources sign extend,
// unsigned sources zero extend (any uint64 is below 2^127, so the conversion is value
// preserving with a zero high lane).

impl From<i32> for serialize_int128_t { fn from( value: i32 ) -> Self { serialize_int128_t { lo: value as i64 as u64, hi: if value < 0 { 0xFFFFFFFFFFFFFFFF } else { 0 } } } }
impl From<i64> for serialize_int128_t { fn from( value: i64 ) -> Self { serialize_int128_t { lo: value as u64, hi: if value < 0 { 0xFFFFFFFFFFFFFFFF } else { 0 } } } }
impl From<u32> for serialize_int128_t { fn from( value: u32 ) -> Self { serialize_int128_t { lo: value as u64, hi: 0 } } }
impl From<u64> for serialize_int128_t { fn from( value: u64 ) -> Self { serialize_int128_t { lo: value, hi: 0 } } }

impl From<serialize_uint128_t> for serialize_int128_t { fn from( value: serialize_uint128_t ) -> Self { serialize_int128_t { lo: value.lo, hi: value.hi } } }        // bit preserving

// explicit operator int64_t: the low lane, wrapping two's complement like a native narrowing conversion
impl From<serialize_int128_t> for i64 { fn from( value: serialize_int128_t ) -> i64 { value.lo as i64 } }

impl serialize_int128_t
{
    pub fn IsNegative( &self ) -> bool
    {
        ( self.hi >> 63 ) != 0
    }
}

impl Ord for serialize_int128_t
{
    fn cmp( &self, other: &Self ) -> Ordering
    {
        // signed ordering: the high lanes compare signed, the low lanes break ties unsigned
        if self.hi != other.hi
        {
            return ( self.hi as i64 ).cmp( &( other.hi as i64 ) );
        }
        self.lo.cmp( &other.lo )
    }
}

impl PartialOrd for serialize_int128_t
{
    fn partial_cmp( &self, other: &Self ) -> Option<Ordering> { Some( self.cmp( other ) ) }
}

// two's complement: addition, subtraction, multiplication and the bitwise operators are the
// same bit patterns as unsigned, so they delegate to the unsigned type. signed overflow wraps
// by construction, exactly like the underlying hardware.

impl Add for serialize_int128_t { type Output = serialize_int128_t; fn add( self, other: serialize_int128_t ) -> serialize_int128_t { serialize_int128_t::from( serialize_uint128_t::from( self ) + serialize_uint128_t::from( other ) ) } }
impl Sub for serialize_int128_t { type Output = serialize_int128_t; fn sub( self, other: serialize_int128_t ) -> serialize_int128_t { serialize_int128_t::from( serialize_uint128_t::from( self ) - serialize_uint128_t::from( other ) ) } }
impl Mul for serialize_int128_t { type Output = serialize_int128_t; fn mul( self, other: serialize_int128_t ) -> serialize_int128_t { serialize_int128_t::from( serialize_uint128_t::from( self ) * serialize_uint128_t::from( other ) ) } }

impl Not for serialize_int128_t { type Output = serialize_int128_t; fn not( self ) -> serialize_int128_t { serialize_int128_t::from( !serialize_uint128_t::from( self ) ) } }
impl BitAnd for serialize_int128_t { type Output = serialize_int128_t; fn bitand( self, other: serialize_int128_t ) -> serialize_int128_t { serialize_int128_t::from( serialize_uint128_t::from( self ) & serialize_uint128_t::from( other ) ) } }
impl BitOr for serialize_int128_t { type Output = serialize_int128_t; fn bitor( self, other: serialize_int128_t ) -> serialize_int128_t { serialize_int128_t::from( serialize_uint128_t::from( self ) | serialize_uint128_t::from( other ) ) } }
impl BitXor for serialize_int128_t { type Output = serialize_int128_t; fn bitxor( self, other: serialize_int128_t ) -> serialize_int128_t { serialize_int128_t::from( serialize_uint128_t::from( self ) ^ serialize_uint128_t::from( other ) ) } }

impl Shl<i32> for serialize_int128_t
{
    type Output = serialize_int128_t;
    fn shl( self, shift: i32 ) -> serialize_int128_t
    {
        // a logical shift of the bit pattern, matching what native two's complement hardware does.
        // shift counts outside [0,127] yield zero, matching the unsigned type
        serialize_int128_t::from( serialize_uint128_t::from( self ) << shift )
    }
}

impl Shr<i32> for serialize_int128_t
{
    type Output = serialize_int128_t;
    fn shr( self, shift: i32 ) -> serialize_int128_t
    {
        // ARITHMETIC shift right: the vacated high bits fill with the sign. shift counts outside
        // [0,127] yield all sign bits — 0 for non negative values, -1 for negative ones — which is
        // the limit of shifting further, documented above
        if shift < 0 || shift >= 128
        {
            return if self.IsNegative() { serialize_int128_t::from( -1 ) } else { serialize_int128_t::from( 0 ) };
        }
        let mut result = serialize_uint128_t::from( self ) >> shift;
        if self.IsNegative() && shift > 0
        {
            result = result | ( !serialize_uint128_t::from( 0 ) << ( 128 - shift ) );
        }
        serialize_int128_t::from( result )
    }
}

impl Neg for serialize_int128_t
{
    type Output = serialize_int128_t;
    fn neg( self ) -> serialize_int128_t
    {
        serialize_int128_t::from( -serialize_uint128_t::from( self ) )                 // two's complement negation. -INT128_MIN wraps to itself, like native
    }
}

impl serialize_int128_t
{
    pub fn DivMod( dividend: serialize_int128_t, divisor: serialize_int128_t, quotient: &mut serialize_int128_t, remainder: &mut serialize_int128_t )
    {
        // sign extraction, unsigned shift subtract division on the magnitudes, then sign
        // application: C++ semantics, truncation toward zero with the remainder sign following
        // the dividend. the documented edge choices live in the comment block above.
        let dividend_negative = dividend.IsNegative();
        let divisor_negative = divisor.IsNegative();
        let dividend_magnitude = if dividend_negative { -serialize_uint128_t::from( dividend ) } else { serialize_uint128_t::from( dividend ) };
        let divisor_magnitude = if divisor_negative { -serialize_uint128_t::from( divisor ) } else { serialize_uint128_t::from( divisor ) };
        let mut unsigned_quotient = serialize_uint128_t::from( 0 );
        let mut unsigned_remainder = serialize_uint128_t::from( 0 );
        serialize_uint128_t::DivMod( dividend_magnitude, divisor_magnitude, &mut unsigned_quotient, &mut unsigned_remainder );
        *quotient = serialize_int128_t::from( if dividend_negative != divisor_negative { -unsigned_quotient } else { unsigned_quotient } );
        *remainder = serialize_int128_t::from( if dividend_negative { -unsigned_remainder } else { unsigned_remainder } );
    }

    pub fn PreIncrement( &mut self ) -> &mut serialize_int128_t
    {
        *self = *self + serialize_int128_t::from( 1 );
        self
    }

    pub fn PostIncrement( &mut self ) -> serialize_int128_t
    {
        let before = *self;
        self.PreIncrement();
        before
    }

    pub fn PreDecrement( &mut self ) -> &mut serialize_int128_t
    {
        *self = *self - serialize_int128_t::from( 1 );
        self
    }

    pub fn PostDecrement( &mut self ) -> serialize_int128_t
    {
        let before = *self;
        self.PreDecrement();
        before
    }
}

impl Div for serialize_int128_t
{
    type Output = serialize_int128_t;
    fn div( self, other: serialize_int128_t ) -> serialize_int128_t
    {
        let mut quotient = serialize_int128_t::from( 0 );
        let mut remainder = serialize_int128_t::from( 0 );
        serialize_int128_t::DivMod( self, other, &mut quotient, &mut remainder );
        quotient
    }
}

impl Rem for serialize_int128_t
{
    type Output = serialize_int128_t;
    fn rem( self, other: serialize_int128_t ) -> serialize_int128_t
    {
        let mut quotient = serialize_int128_t::from( 0 );
        let mut remainder = serialize_int128_t::from( 0 );
        serialize_int128_t::DivMod( self, other, &mut quotient, &mut remainder );
        remainder
    }
}

serialize_impl_assign_ops!( serialize_int128_t );

pub const SERIALIZE_UINT128_DEFINED: i32 = 1;

// namespace serialize
// port: the namespace is this module (crate::serialize)

/**
    Native 128 bit integer types, where the compiler provides them (gcc, clang, clang-cl).
    int128_t is the storage type for wide fixed point (Q112.16 and friends). uint128_t is the 128 bit wire interchange type.
 */

// port: Rust has native 128 bit integers on every target, so this is always the native branch
pub type int128_t = i128;
pub type uint128_t = u128;

/**
    Calculates the population count of an unsigned 32 bit integer at compile time.
    Population count is the number of bits in the integer that set to 1.
    See "Hacker's Delight" and http://www.hackersdelight.org/hdcodetxt/popArrayHS.c.txt
    @see serialize::Log2
    @see serialize::BitsRequired
 */

// port: the compile time templates are structs with const generic parameters and an associated const `result`
// (`PopCount::<0x55>::result`, `BitsRequired::<0, 255>::result`). Stable Rust cannot pass an associated const of one
// as the const argument of another, so the enum members are computed in place

pub struct PopCount<const x: u32>;

impl<const x: u32> PopCount<x>
{
    pub const a: u32 = x - ( ( x >> 1 )       & 0x55555555 );
    pub const b: u32 =   ( ( ( Self::a >> 2 )       & 0x33333333 ) + ( Self::a & 0x33333333 ) );
    pub const c: u32 =   ( ( ( Self::b >> 4 ) + Self::b ) & 0x0f0f0f0f );
    pub const d: u32 =   Self::c + ( Self::c >> 8 );
    pub const e: u32 =   Self::d + ( Self::d >> 16 );

    pub const result: u32 = Self::e & 0x0000003f;
}

/**
    Calculates the log 2 of an unsigned 32 bit integer at compile time.
    @see serialize::Log2
    @see serialize::BitsRequired
 */

pub struct Log2<const x: u32>;

impl<const x: u32> Log2<x>
{
    pub const a: u32 = x | ( x >> 1 );
    pub const b: u32 = Self::a | ( Self::a >> 2 );
    pub const c: u32 = Self::b | ( Self::b >> 4 );
    pub const d: u32 = Self::c | ( Self::c >> 8 );
    pub const e: u32 = Self::d | ( Self::d >> 16 );
    pub const f: u32 = Self::e >> 1;

    pub const result: u32 = popcount( Self::f );          // PopCount<f>::result
}

/**
    Calculates the number of bits required to serialize an integer value in [min,max] at compile time.
    @see Log2
    @see PopCount
 */

pub struct BitsRequired<const min: i64, const max: i64>;

impl<const min: i64, const max: i64> BitsRequired<min, max>
{
    pub const result: u32 = if min == max { 0 } else { log2( max.wrapping_sub( min ) as u32 ) + 1 };    // Log2<uint32_t(max-min)>::result + 1
}

/**
    Calculates the number of bits needed to represent an unsigned 64 bit integer at compile time.
    This is floor( log2( x ) ) + 1, and zero for an input of zero.
    @see serialize::BitsRequired64
 */

// port: the template recursion BitCount64<x> = 1 + BitCount64<x >> 1>, BitCount64<0> = 0 is a const loop
pub struct BitCount64<const x: u64>;

impl<const x: u64> BitCount64<x>
{
    pub const result: i32 = bits_required64_constexpr( 0, x );
}

/**
    Calculates the number of bits required to serialize a 64 bit integer value in [min,max] at compile time.
    The subtraction is performed in the unsigned domain, so ranges wider than 2^63 work.
    @see serialize::BitsRequired
    @see serialize::bits_required64
 */

pub struct BitsRequired64<const min: u64, const max: u64>;

impl<const min: u64, const max: u64> BitsRequired64<min, max>
{
    pub const result: i32 = bits_required64_constexpr( min, max );     // BitCount64< max - min >::result
}

/**
    Calculates the number of bits needed to represent an unsigned 128 bit integer at compile time.
    This is floor( log2( x ) ) + 1, and zero for an input of zero.
    @see serialize::BitsRequired128
 */

pub struct BitCount128<const x: u128>;

impl<const x: u128> BitCount128<x>
{
    pub const result: i32 = bit_count128_constexpr( x );
}

/**
    Calculates the number of bits required to serialize a 128 bit integer value in [min,max] at compile time.
    The subtraction is performed in the unsigned domain, so ranges wider than 2^127 work.
    @see serialize::BitsRequired64
 */

pub struct BitsRequired128<const min: u128, const max: u128>;

impl<const min: u128, const max: u128> BitsRequired128<min, max>
{
    pub const result: i32 = bit_count128_constexpr( max.wrapping_sub( min ) );     // BitCount128< max - min >::result
}

// port: the recursion of BitCount128, as a const fn
const fn bit_count128_constexpr( x: u128 ) -> i32
{
    let mut bits = 0;
    let mut value = x;
    while value != 0
    {
        bits += 1;
        value >>= 1;
    }
    bits
}

/**
    Calculates the population count of an unsigned 32 bit integer.
    The population count is the number of bits in the integer set to 1.
    @param x The input integer value.
    @returns The number of bits set to 1 in the input value.
 */

// port: count_ones is __builtin_popcount (the __GNUC__ branch); const so the compile time structs can use it
#[inline(always)]
pub const fn popcount( x: u32 ) -> u32
{
    x.count_ones()
}

/**
    Calculates the log base 2 of an unsigned 32 bit integer.
    @param x The input integer value.
    @returns The log base 2 of the input.
 */

#[inline(always)]
pub const fn log2( x: u32 ) -> u32
{
    let a: u32 = x | ( x >> 1 );
    let b: u32 = a | ( a >> 2 );
    let c: u32 = b | ( b >> 4 );
    let d: u32 = c | ( c >> 8 );
    let e: u32 = d | ( d >> 16 );
    let f: u32 = e >> 1;
    popcount( f )
}

/**
    Calculates the number of bits required to serialize an integer in range [min,max].
    @param min The minimum value.
    @param max The maximum value.
    @returns The number of bits required to serialize the integer.
 */

// port: leading_zeros is __builtin_clz (the __GNUC__ branch)
#[inline(always)]
pub fn bits_required( min: u32, max: u32 ) -> i32
{
    if min == max { 0 } else { 32 - max.wrapping_sub( min ).leading_zeros() as i32 }
}

/**
    Calculates the number of bits required to serialize a 64 bit integer in range [min,max].
    @param min The minimum value.
    @param max The maximum value.
    @returns The number of bits required to serialize the integer in [0,64].
 */

#[inline(always)]
pub fn bits_required64( min: u64, max: u64 ) -> i32
{
    if min == max
    {
        return 0;
    }
    // subtract in the unsigned domain: max - min overflows signed arithmetic when the range is wider than 2^63
    let diff: u64 = max.wrapping_sub( min );
    64 - diff.leading_zeros() as i32
}

/**
    Calculates the number of bits required to serialize a 128 bit integer in range [min,max].
    The subtraction is performed in the unsigned domain, so ranges wider than 2^127 work.
    @param min The minimum value.
    @param max The maximum value.
    @returns The number of bits required to serialize the integer in [0,128].
 */

#[inline(always)]
pub fn bits_required128( min: uint128_t, max: uint128_t ) -> i32
{
    if min == max
    {
        return 0;
    }
    // subtract in the unsigned domain: max - min overflows signed arithmetic when the range is wider than 2^127
    let diff: uint128_t = max.wrapping_sub( min );
    let high: u64 = ( diff >> 64 ) as u64;
    if high != 0 { 64 + bits_required64( 0, high ) } else { bits_required64( 0, diff as u64 ) }
}

/**
    Does a value fit in a raw bit field of this width?
    This is the write side range check for serialize_bits and write_bits, and it runs on the caller's value before the macro narrows it to the group width. An assertion placed after the narrowing sees a value already truncated to the field, so it cannot report the out of range input it exists to diagnose: writing a 40 bit value in 8 bits arrives at BitWriter::WriteBits as the low 8 bits, in range by construction.
    The value is widened rather than narrowed, so a negative signed input arrives as a very large unsigned one and fails: a raw bit field is unsigned, and a signed value belongs in serialize_int over a range that includes it.
    @param value The caller's value.
    @param bits The field width in [1,64].
    @returns True if the value fits in that many bits.
 */

#[inline(always)]
pub fn value_fits_in_bits<T: FixedPointInteger>( value: T, bits: i32 ) -> bool
{
    let widened: u64 = value.to_u64();
    bits >= 64 || widened <= ( ( 1u64 << bits ) - 1 )
}

/**
    Reverse the order of bytes in an integer.
    @param value The input value.
    @returns The input value with the byte order reversed.
 */

// port: the three bswap overloads (uint64_t, uint32_t, uint16_t) are one generic over this trait. swap_bytes is
// __builtin_bswap64 / __builtin_bswap32 (the __GNUC__ branch)
pub trait SerializeByteSwap: Copy
{
    fn bswap( self ) -> Self;
}

impl SerializeByteSwap for u64 { #[inline(always)] fn bswap( self ) -> u64 { self.swap_bytes() } }
impl SerializeByteSwap for u32 { #[inline(always)] fn bswap( self ) -> u32 { self.swap_bytes() } }
impl SerializeByteSwap for u16 { #[inline(always)] fn bswap( self ) -> u16 { ( self & 0x00ff ) << 8 | ( self & 0xff00 ) >> 8 } }

#[inline(always)]
pub fn bswap<T: SerializeByteSwap>( value: T ) -> T
{
    value.bswap()
}

/**
    Template to convert an integer value from local byte order to network byte order.
    IMPORTANT: Because most machines are little endian, serialize defines network byte order to be little endian.
    @param value The input value in local byte order. Supported integer types: uint64_t, uint32_t, uint16_t.
    @returns The input value converted to network byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
    @see serialize::bswap
 */

#[inline(always)]
pub fn host_to_network<T: SerializeByteSwap>( value: T ) -> T
{
    if cfg!( target_endian = "big" )
    {
        bswap( value )
    }
    else
    {
        value
    }
}

/**
    Template to convert an integer value from network byte order to local byte order.
    IMPORTANT: Because most machines are little endian, serialize defines network byte order to be little endian.
    @param value The input value in network byte order. Supported integer types: uint64_t, uint32_t, uint16_t.
    @returns The input value converted to local byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
    @see serialize::bswap
 */

#[inline(always)]
pub fn network_to_host<T: SerializeByteSwap>( value: T ) -> T
{
    if cfg!( target_endian = "big" )
    {
        bswap( value )
    }
    else
    {
        value
    }
}

/**
    Convert a signed integer to an unsigned integer with zig-zag encoding.
    0,-1,+1,-2,+2... becomes 0,1,2,3,4 ...
    @param n The input value.
    @returns The input value converted from signed to unsigned with zig-zag encoding.
 */

#[inline(always)]
pub fn signed_to_unsigned( n: i32 ) -> u32
{
    // shift in the unsigned domain: left shift of a negative signed value is undefined behavior pre C++20
    ( ( n as u32 ) << 1 ) ^ ( 0u32.wrapping_sub( ( n as u32 ) >> 31 ) )
}

/**
    Convert an unsigned integer to as signed integer with zig-zag encoding.
    0,1,2,3,4... becomes 0,-1,+1,-2,+2...
    @param n The input value.
    @returns The input value converted from unsigned to signed with zig-zag encoding.
 */

#[inline(always)]
pub fn unsigned_to_signed( n: u32 ) -> i32
{
    ( ( n >> 1 ) ^ ( 0u32.wrapping_sub( n & 1 ) ) ) as i32
}

/**
    Bitpacks unsigned integer values to a buffer.
    Integer bit values are written to a 64 bit scratch value from right to left.
    Once the scratch fills to 64 bits it is flushed to memory as a qword; the handful of bits that spilled past 64 carry over into the next scratch. Flushing half as often as a dword design makes writes ~30% faster.
    The bit stream is written to memory in little endian order, which is considered network byte order for this library.
    IMPORTANT: The buffer size must be a multiple of 8 bytes, because words are stored to memory 8 bytes at a time. Bytes past the end of the written data are only ever written as zeros.
    @see BitReader
 */

// port: the buffer is a borrowed slice. Upstream's "buffer must not overlap the writer" assert is what the borrow
// checker guarantees, so it is not ported. A default constructed writer holds an empty slice where upstream holds
// NULL: the "used before Initialize" asserts check for it
pub struct BitWriter<'a>
{
    m_data: &'a mut [u8],           // The buffer we are writing to. The buffer size is a multiple of 8, so qword stores always stay in bounds.
    m_scratch: u64,                 // The scratch value where we write bits to (right to left). When it fills to 64 bits it is stored to memory as a qword and the bits that spilled past 64 carry over.
    m_numBits: i64,                 // The number of bits in the buffer. This is equivalent to the size of the buffer in bytes multiplied by 8.
    m_bitsWritten: i64,             // The number of bits written so far.
    m_wordIndex: i64,               // The current word index. The next word flushed to memory will be at this index in m_data.
    m_scratchBits: i32,             // The number of valid bits in scratch, in [0,63].
}

impl<'a> Default for BitWriter<'a>
{
    fn default() -> Self
    {
        BitWriter { m_data: &mut [], m_scratch: 0, m_numBits: 0, m_bitsWritten: 0, m_wordIndex: 0, m_scratchBits: 0 }
    }
}

impl<'a> BitWriter<'a>
{
    pub fn Initialize( &mut self, data: &'a mut [u8], bytes: i64 )
    {
        serialize_assert!( !data.is_empty() );
        serialize_assert!( ( bytes % 8 ) == 0 );
        serialize_assert!( bytes as usize <= data.len() );          // port: the slice must hold the buffer
        self.m_data = data;
        self.m_numBits = bytes * 8;
        self.m_bitsWritten = 0;
        self.m_wordIndex = 0;
        self.m_scratch = 0;
        self.m_scratchBits = 0;
    }

    /**
        Bit writer constructor.
        Creates a bit writer object to write to the specified buffer.
        @param data The buffer to fill with bitpacked data.
        @param bytes The size of the buffer in bytes. Must be a multiple of 8, because the bit writer stores qwords to memory. Buffer sizes are effectively unlimited, because bit counts are stored in 64 bit signed integers.
     */

    pub fn new( data: &'a mut [u8], bytes: i64 ) -> BitWriter<'a>
    {
        serialize_assert!( !data.is_empty() );
        serialize_assert!( ( bytes % 8 ) == 0 );
        serialize_assert!( bytes as usize <= data.len() );          // port: the slice must hold the buffer
        BitWriter
        {
            m_data: data,
            m_numBits: bytes * 8,
            m_bitsWritten: 0,
            m_wordIndex: 0,
            m_scratch: 0,
            m_scratchBits: 0,
        }
    }

    /**
        Write bits to the buffer.
        Bits are written to the buffer as-is, without padding to nearest byte. Will assert if you try to write past the end of the buffer.
        A boolean value writes just 1 bit to the buffer, a value in range [0,31] can be written with just 5 bits and so on.
        IMPORTANT: When you have finished writing to your buffer, take care to call BitWrite::FlushBits, otherwise the last word of data will not get flushed to memory!
        @param value The integer value to write to the buffer. Must be in [0,(1<<bits)-1].
        @param bits The number of bits to encode in [1,32].
        @see BitReader::ReadBits
     */

    #[inline(always)]
    pub fn WriteBits( &mut self, value: u32, bits: i32 )
    {
        serialize_assert!( !self.m_data.is_empty() );                // if this fires, the writer was used before Initialize
        serialize_assert!( bits > 0 );
        serialize_assert!( bits <= 32 );
        serialize_assert!( self.m_bitsWritten + bits as i64 <= self.m_numBits );
        serialize_assert!( ( value as u64 ) <= ( ( 1u64 << bits ) - 1 ) );

        self.m_scratch |= ( value as u64 ) << self.m_scratchBits;

        let newScratchBits: i32 = self.m_scratchBits + bits;

        if newScratchBits >= 64
        {
            let word: u64 = host_to_network( self.m_scratch );
            let index = self.m_wordIndex as usize * 8;
            self.m_data[index..index + 8].copy_from_slice( &word.to_ne_bytes() );
            self.m_wordIndex += 1;
            // recover the bits that spilled past 64. newScratchBits >= 64 with bits <= 32 implies the shift is in [1,32]
            self.m_scratch = ( value as u64 ) >> ( 64 - self.m_scratchBits );
            self.m_scratchBits = newScratchBits - 64;
        }
        else
        {
            self.m_scratchBits = newScratchBits;
        }

        self.m_bitsWritten += bits as i64;
    }

    /**
        Write an alignment to the bit stream, padding zeros so the bit index becomes is a multiple of 8.
        This is useful if you want to write some data to a packet that should be byte aligned. For example, an array of bytes, or a string.
        IMPORTANT: If the current bit index is already a multiple of 8, nothing is written.
        @see BitReader::ReadAlign
     */

    #[inline(always)]
    pub fn WriteAlign( &mut self )
    {
        let remainderBits: i32 = ( self.m_bitsWritten % 8 ) as i32;

        if remainderBits != 0
        {
            let zero: u32 = 0;
            self.WriteBits( zero, 8 - remainderBits );
            serialize_assert!( ( self.m_bitsWritten % 8 ) == 0 );
        }
    }

    /**
        Write an array of bytes to the bit stream.
        Use this when you have to copy a large block of data into your bitstream.
        Faster than just writing each byte to the bit stream via BitWriter::WriteBits( value, 8 ), because it aligns to byte index and copies into the buffer without bitpacking.
        The body is fused: one qword store flushes the partial scratch word (its high bytes are zero and the payload overwrites them), one bulk copy lands the whole payload at the byte cursor, and one qword load reloads the trailing partial word into the scratch — masked to its tail bits — so later writes pack into it exactly as if its bytes had gone through the packer.
        The tail load reads only the word the final flush is already obliged to store, and the byte-swapped scratch is what makes the edge words single moves on either endianness.
        @param data The byte array data to write to the bit stream.
        @param bytes The number of bytes to write.
        @see BitReader::ReadBytes
     */

    pub fn WriteBytes( &mut self, data: &[u8], bytes: i64 )
    {
        serialize_assert!( !self.m_data.is_empty() );                // if this fires, the writer was used before Initialize
        serialize_assert!( ( self.m_bitsWritten as u64 ) + ( bytes as u64 ) * 8 <= ( self.m_numBits as u64 ) );
        serialize_assert!( ( self.m_bitsWritten % 8 ) == 0 );                         // byte aligned
        serialize_assert!( self.m_scratchBits as i64 == self.m_bitsWritten % 64 );    // mid-stream the scratch tracks the cursor (writing after FlushBits mid-stream was never supported)

        // the head: one word store, not a byte loop. the partial scratch word goes to the
        // buffer whole — its low scratchBits are the bytes already written, its high bytes
        // are zero, and the payload copy below overwrites exactly those zero bytes. the
        // buffer size is a multiple of 8, so the qword store stays in bounds (see FlushBits).
        if self.m_scratchBits != 0
        {
            let word: u64 = host_to_network( self.m_scratch );
            let index = self.m_wordIndex as usize * 8;
            self.m_data[index..index + 8].copy_from_slice( &word.to_ne_bytes() );
        }

        // the body: the whole payload, straight in at the byte cursor
        let start = ( self.m_bitsWritten >> 3 ) as usize;
        self.m_data[start..start + bytes as usize].copy_from_slice( &data[..bytes as usize] );

        self.m_bitsWritten += bytes * 8;
        self.m_wordIndex = self.m_bitsWritten / 64;

        // the tail: reload the trailing partial word into the scratch, masked to its tail
        // bits, so later writes pack into it exactly as if its bytes had gone through the
        // packer. the load reads the word the final flush is already obliged to store
        // (tailBits != 0 keeps m_scratchBits != 0, so FlushBits WILL store it), so it
        // touches no memory the stream does not already own; the bits above the tail are
        // whatever the buffer held, and the mask discards them.
        let tailBits: i32 = ( self.m_bitsWritten % 64 ) as i32;
        if tailBits != 0
        {
            let index = self.m_wordIndex as usize * 8;
            let mut word = [0u8; 8];
            word.copy_from_slice( &self.m_data[index..index + 8] );
            self.m_scratch = network_to_host( u64::from_ne_bytes( word ) ) & ( ( 1u64 << tailBits ) - 1 );
        }
        else
        {
            self.m_scratch = 0;
        }
        self.m_scratchBits = tailBits;
    }

    /**
        Flush any remaining bits to memory.
        Call this once after you've finished writing bits to flush the last word of scratch to memory!
        @see BitWriter::WriteBits
     */

    pub fn FlushBits( &mut self )
    {
        if self.m_scratchBits != 0
        {
            serialize_assert!( !self.m_data.is_empty() );            // if this fires, the writer was used before Initialize
            serialize_assert!( self.m_scratchBits < 64 );
            let word: u64 = host_to_network( self.m_scratch );
            let index = self.m_wordIndex as usize * 8;
            self.m_data[index..index + 8].copy_from_slice( &word.to_ne_bytes() );     // stores a full qword: the buffer size is a multiple of 8 so this stays in bounds, and bytes past the written data are zeros
            self.m_scratch = 0;
            self.m_scratchBits = 0;
            self.m_wordIndex += 1;
        }
    }

    /**
        How many align bits would be written, if we were to write an align right now?
        @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
     */

    pub fn GetAlignBits( &self ) -> i32
    {
        ( ( 8 - ( self.m_bitsWritten % 8 ) ) % 8 ) as i32
    }

    /**
        How many bits have we written so far?
        @returns The number of bits written to the bit buffer.
     */

    pub fn GetBitsWritten( &self ) -> i64
    {
        self.m_bitsWritten
    }

    /**
        How many bits are still available to write?
        For example, if the buffer size is 4, we have 32 bits available to write, if we have already written 10 bytes then 22 are still available to write.
        @returns The number of bits available to write.
     */

    pub fn GetBitsAvailable( &self ) -> i64
    {
        self.m_numBits - self.m_bitsWritten
    }

    /**
        Get a pointer to the data written by the bit writer.
        Corresponds to the data block passed in to the constructor.
        @returns Pointer to the data written by the bit writer.
     */

    // port: the whole buffer slice passed to the constructor
    pub fn GetData( &self ) -> &[u8]
    {
        &self.m_data[..]
    }

    /**
        The number of bytes flushed to memory.
        This is effectively the size of the packet that you should send after you have finished bitpacking values with this class.
        The returned value is not always a multiple of 8, even though we flush qwords to memory. You won't miss any data in this case because the order of bits written is designed to work with the little endian memory layout.
        IMPORTANT: Make sure you call BitWriter::FlushBits before calling this method, otherwise you risk missing the last word of data.
     */

    pub fn GetBytesWritten( &self ) -> i64
    {
        ( self.m_bitsWritten + 7 ) / 8
    }
}

/**
    Reads bit packed integer values from a buffer.
    Relies on the user reconstructing the exact same set of bit reads as bit writes when the buffer was written. This is an unattributed bitpacked binary stream!
    Implementation: branchless. Each read loads a 64 bit window from the current byte position with memcpy and shifts by the bit remainder.
    There is no scratch state and no refill branch, so reads carry no dependency between calls other than advancing the bit index. This makes the reader significantly faster than a word-at-a-time design.
    IMPORTANT: The buffer allocation must extend at least 8 bytes past the end of the packet data, because the reader loads 8 byte windows at byte granularity. The bytes past the end are loaded but never interpreted.
 */

// port: the buffer is a borrowed slice and does NOT need upstream's 8 bytes of allocation past the data (as in the
// C# and TypeScript ports): a window that would run past the end of the slice loads the bytes that exist and zeros
// for the rest. Those bytes are never interpreted, so the values read are the same
pub struct BitReader<'a>
{
    m_data: &'a [u8],               // The bitpacked data we're reading.
    m_numBits: i64,                 // Number of bits to read in the buffer. Of course, we can't *really* know this so it's actually m_numBytes * 8.
    m_numBytes: i64,                // Number of bytes to read in the buffer. We know this, and this is the non-rounded up version.
    m_bitsRead: i64,                // Number of bits read from the buffer so far. This is the only state the reader carries between reads.
}

impl<'a> Default for BitReader<'a>
{
    fn default() -> Self
    {
        BitReader { m_data: &[], m_numBytes: 0, m_numBits: 0, m_bitsRead: 0 }
    }
}

impl<'a> BitReader<'a>
{
    pub fn Initialize( &mut self, data: &'a [u8], bytes: i64 )
    {
        serialize_assert!( bytes >= 0 && bytes as usize <= data.len() );      // port: the slice must hold the data (upstream asserts data != NULL)
        self.m_data = data;
        self.m_numBytes = bytes;
        self.m_numBits = self.m_numBytes * 8;
        self.m_bitsRead = 0;
    }

    /**
        Bit reader constructor.
        Any buffer size is supported, as non-multiples of four naturally occur when packets are read from the network.
        @param data The bitpacked data to read.
        @param bytes The number of bytes of bitpacked data to read. Buffer sizes are effectively unlimited, because bit counts are stored in 64 bit signed integers.
        @see BitWriter
     */

    pub fn new( data: &'a [u8], bytes: i64 ) -> BitReader<'a>
    {
        serialize_assert!( bytes >= 0 && bytes as usize <= data.len() );      // port: the slice must hold the data (upstream asserts data != NULL)
        BitReader
        {
            m_data: data,
            m_numBytes: bytes,
            m_numBits: bytes * 8,
            m_bitsRead: 0,
        }
    }

    /**
        Would the bit reader would read past the end of the buffer if it read this many bits?
        A reader whose position has been poisoned (see BitReader::PoisonPosition) answers true for every bit count, zero included, which is what makes the failure latch total.
        @param bits The number of bits that would be read.
        @returns True if reading the number of bits would read past the end of the buffer.
     */

    #[inline(always)]
    pub fn WouldReadPastEnd( &self, bits: i32 ) -> bool
    {
        self.m_bitsRead + bits as i64 > self.m_numBits
    }

    /**
        Latch the reader into the failed state.
        Failure is terminal: nothing after a failing read has a defined position, so nothing after it is interpretable. The position is poisoned one bit past the end of the buffer, so the past-end check every read already performs refuses every later read and the latch costs the read path nothing. Cleared only by Initialize, which points the reader at a new buffer.
        @see BitReader::WouldReadPastEnd
     */

    #[inline(always)]
    pub fn PoisonPosition( &mut self )
    {
        self.m_bitsRead = self.m_numBits + 1;
    }

    /**
        Read bits from the bit buffer.
        This function will assert in debug builds if this read would read past the end of the buffer.
        In production situations, the higher level ReadStream takes care of checking all packet data and never calling this function if it would read past the end of the buffer.
        @param bits The number of bits to read in [1,32].
        @returns The integer value read in range [0,(1<<bits)-1].
        @see BitReader::WouldReadPastEnd
        @see BitWriter::WriteBits
     */

    #[inline(always)]
    pub fn ReadBits( &mut self, bits: i32 ) -> u32
    {
        serialize_assert!( !self.m_data.is_empty() );                // if this fires, the reader was used before Initialize
        serialize_assert!( bits > 0 );
        serialize_assert!( bits <= 32 );
        serialize_assert!( self.m_bitsRead + bits as i64 <= self.m_numBits );

        // loads up to 7 bytes past the last data byte
        // port: a window past the end of the slice loads zeros for the missing bytes (see the struct comment)
        let index = ( self.m_bitsRead >> 3 ) as usize;
        let mut bytes = [0u8; 8];
        if index + 8 <= self.m_data.len()
        {
            bytes.copy_from_slice( &self.m_data[index..index + 8] );
        }
        else
        {
            let available = self.m_data.len() - index;
            bytes[..available].copy_from_slice( &self.m_data[index..] );
        }
        let mut window: u64 = u64::from_ne_bytes( bytes );
        window = network_to_host( window );

        let output: u32 = ( ( window >> ( self.m_bitsRead & 7 ) ) as u32 ) & ( ( ( 1u64 << bits ) - 1 ) as u32 );

        self.m_bitsRead += bits as i64;

        output
    }

    /**
        Read an align.
        Call this on read to correspond to a WriteAlign call when the bitpacked buffer was written.
        This makes sure we skip ahead to the next aligned byte index. As a safety check, we verify that the padding to next byte is zero bits and return false if that's not the case.
        This will typically abort packet read. Just another safety measure...
        @returns True if we successfully read an align and skipped ahead past zero pad, false otherwise (probably means, no align was written to the stream).
        @see BitWriter::WriteAlign
     */

    #[inline(always)]
    pub fn ReadAlign( &mut self ) -> bool
    {
        let remainderBits: i32 = ( self.m_bitsRead % 8 ) as i32;
        if remainderBits != 0
        {
            let value: u32 = self.ReadBits( 8 - remainderBits );
            serialize_assert!( self.m_bitsRead % 8 == 0 );
            if value != 0
            {
                return false;
            }
        }
        true
    }

    /**
        Read bytes from the bitpacked data.
        @see BitWriter::WriteBytes
     */

    pub fn ReadBytes( &mut self, data: &mut [u8], bytes: i64 )
    {
        serialize_assert!( !self.m_data.is_empty() );                // if this fires, the reader was used before Initialize
        serialize_assert!( self.GetAlignBits() == 0 );
        serialize_assert!( ( self.m_bitsRead as u64 ) + ( bytes as u64 ) * 8 <= ( self.m_numBits as u64 ) );

        // the bit index is byte aligned here (see the align assert), so this is a straight copy
        let start = ( self.m_bitsRead >> 3 ) as usize;
        data[..bytes as usize].copy_from_slice( &self.m_data[start..start + bytes as usize] );

        self.m_bitsRead += bytes * 8;
    }

    /**
        How many align bits would be read, if we were to read an align right now?
        @returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
     */

    pub fn GetAlignBits( &self ) -> i32
    {
        ( ( 8 - self.m_bitsRead % 8 ) % 8 ) as i32
    }

    /**
        How many bits have we read so far?
        @returns The number of bits read from the bit buffer so far.
     */

    pub fn GetBitsRead( &self ) -> i64
    {
        self.m_bitsRead
    }

    /**
        How many bits are still available to read?
        For example, if the buffer size is 4, we have 32 bits available to read, if we have already written 10 bytes then 22 are still available.
        @returns The number of bits available to read.
     */

    pub fn GetBitsRemaining( &self ) -> i64
    {
        self.m_numBits - self.m_bitsRead
    }
}

/**
    Functionality common to all stream classes.
 */

// port: the data members; the methods are also provided methods of the Stream trait, which reaches them through
// Stream::base / Stream::base_mut (rust/README.md, "Classes with virtual methods")
pub struct BaseStream
{
    m_context: *mut c_void,                     // The context pointer set on the stream. May be NULL.
    m_allocator: *mut c_void,                   // The allocator pointer set on the stream. May be NULL.
}

impl Default for BaseStream
{
    fn default() -> Self
    {
        BaseStream::new()
    }
}

impl BaseStream
{
    /**
        Base stream constructor.
     */

    pub fn new() -> BaseStream
    {
        BaseStream { m_context: std::ptr::null_mut(), m_allocator: std::ptr::null_mut() }
    }

    /**
        Set a context on the stream.
        The context lets you pass data through to your serialize functions, for example lookup tables or min/max ranges needed to read and write values.
        Call BaseStream::GetContext inside your serialize method to retrieve it.
     */

    pub fn SetContext( &mut self, context: *mut c_void )
    {
        self.m_context = context;
    }

    /**
        Get the context pointer set on the stream.

        @returns The context pointer. May be NULL.
     */

    pub fn GetContext( &self ) -> *mut c_void
    {
        self.m_context
    }

    /**
        Set an allocator pointer on the stream.
        This can be helpful if you want to perform allocations within serialize functions.
     */

    pub fn SetAllocator( &mut self, allocator: *mut c_void )
    {
        self.m_allocator = allocator;
    }

    /**
        Get the allocator pointer set on the stream.

        @returns The allocator pointer. May be NULL.
     */

    pub fn GetAllocator( &self ) -> *mut c_void
    {
        self.m_allocator
    }
}

/**
    The interface the three stream classes share.
    port: C++ serialize functions are templated over the stream type and call these members by name; in Rust that
    shared surface is this trait (`fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool`). IsWriting and
    IsReading are the streams' enum constants.
 */

pub trait Stream
{
    const IsWriting: bool;
    const IsReading: bool;

    fn base( &self ) -> &BaseStream;
    fn base_mut( &mut self ) -> &mut BaseStream;

    fn SerializeInteger( &mut self, value: &mut i32, min: i32, max: i32 ) -> bool;
    fn SerializeInteger64( &mut self, value: &mut i64, min: i64, max: i64 ) -> bool;
    fn SerializeInteger128( &mut self, value: &mut int128_t, min: int128_t, max: int128_t ) -> bool;
    fn SerializeBits( &mut self, value: &mut u32, bits: i32 ) -> bool;
    fn SerializeBytes( &mut self, data: &mut [u8], bytes: i64 ) -> bool;

    // port: the write and measure streams' SerializeBytes takes const data upstream (the overload write_bytes calls);
    // the read stream cannot read into const data, so on it this asserts and refuses
    fn SerializeBytesConst( &mut self, data: &[u8], bytes: i64 ) -> bool;

    fn SerializeAlign( &mut self ) -> bool;
    fn GetAlignBits( &self ) -> i32;
    fn GetBitsProcessed( &self ) -> i64;
    fn GetBytesProcessed( &self ) -> i64;

    // port: StreamRefusal<Stream>::Fail. The primary template (write, measure, custom streams) is this default: a
    // no-op returning false. The ReadStream specialization overrides it with ReadStream::Fail
    #[inline(always)]
    fn StreamRefusalFail( &mut self ) -> bool
    {
        false
    }

    // BaseStream

    fn SetContext( &mut self, context: *mut c_void ) { self.base_mut().SetContext( context ); }
    fn GetContext( &self ) -> *mut c_void { self.base().GetContext() }
    fn SetAllocator( &mut self, allocator: *mut c_void ) { self.base_mut().SetAllocator( allocator ); }
    fn GetAllocator( &self ) -> *mut c_void { self.base().GetAllocator() }
}

/// port: `Stream::IsWriting` for the stream an expression refers to, for the macros (which cannot name `S`)
#[inline(always)]
pub fn serialize_stream_is_writing<S: Stream>( _stream: &S ) -> bool
{
    S::IsWriting
}

/// port: `Stream::IsReading` for the stream an expression refers to, for the macros (which cannot name `S`)
#[inline(always)]
pub fn serialize_stream_is_reading<S: Stream>( _stream: &S ) -> bool
{
    S::IsReading
}

/**
    Stream class for writing bitpacked data.
    This class is a wrapper around the bit writer class. Its purpose is to provide unified interface for reading and writing.
    You can determine if you are writing to a stream by calling Stream::IsWriting inside your templated serialize method.
    This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
    IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead.
    @see BitWriter
 */

pub struct WriteStream<'a>
{
    pub base: BaseStream,
    m_writer: BitWriter<'a>,            // The bit writer used for all bitpacked write operations.
}

impl<'a> Default for WriteStream<'a>
{
    fn default() -> Self
    {
        WriteStream { base: BaseStream::new(), m_writer: BitWriter::default() }
    }
}

impl<'a> WriteStream<'a>
{
    pub fn Initialize( &mut self, buffer: &'a mut [u8], bytes: i64 )
    {
        self.m_writer.Initialize( buffer, bytes );
    }

    /**
        Write stream constructor.
        @param buffer The buffer to write to. Does not need to be aligned.
        @param bytes The number of bytes in the buffer. Must be a multiple of 8, because the bit writer stores qwords to memory.
     */

    pub fn new( buffer: &'a mut [u8], bytes: i64 ) -> WriteStream<'a>
    {
        WriteStream { base: BaseStream::new(), m_writer: BitWriter::new( buffer, bytes ) }
    }

    /**
        Flush the stream to memory after you finish writing.
        Always call this after you finish writing and before you call WriteStream::GetData, or you'll potentially truncate the last word of data you wrote.
        @see BitWriter::FlushBits
     */

    pub fn Flush( &mut self )
    {
        self.m_writer.FlushBits();
    }

    /**
        Get a pointer to the data written by the stream.
        IMPORTANT: Call WriteStream::Flush before you call this function!
        @returns A pointer to the data written by the stream
     */

    pub fn GetData( &self ) -> &[u8]
    {
        self.m_writer.GetData()
    }

    // port: the body of the const data SerializeBytes, shared by the trait's two SerializeBytes members
    #[inline(always)]
    fn SerializeBytesInternal( &mut self, data: &[u8], bytes: i64 ) -> bool
    {
        serialize_assert!( bytes >= 0 );
        self.SerializeAlign();
        self.m_writer.WriteBytes( data, bytes );
        true
    }
}

impl<'a> Stream for WriteStream<'a>
{
    const IsWriting: bool = true;
    const IsReading: bool = false;

    fn base( &self ) -> &BaseStream { &self.base }
    fn base_mut( &mut self ) -> &mut BaseStream { &mut self.base }

    /**
        Serialize an integer (write).
        @param value The integer value in [min,max].
        @param min The minimum value.
        @param max The maximum value.
        @returns Always returns true. All checking is performed by debug asserts only on write.
     */

    #[inline(always)]
    fn SerializeInteger( &mut self, value: &mut i32, min: i32, max: i32 ) -> bool
    {
        let value: i32 = *value;
        serialize_assert!( min <= max );
        serialize_assert!( value >= min );
        serialize_assert!( value <= max );
        let bits: i32 = bits_required( min as u32, max as u32 );
        if bits == 0
        {
            return true;                // degenerate range: the value IS the range, nothing to send
        }
        // subtract in the unsigned domain: value - min overflows signed arithmetic when the range is wider than 2^31
        let unsigned_value: u32 = ( value as u32 ).wrapping_sub( min as u32 );
        self.m_writer.WriteBits( unsigned_value, bits );
        true
    }

    /**
        Serialize a 64 bit integer (write).
        @param value The integer value in [min,max].
        @param min The minimum value.
        @param max The maximum value.
        @returns Always returns true. All checking is performed by debug asserts only on write.
     */

    #[inline(always)]
    fn SerializeInteger64( &mut self, value: &mut i64, min: i64, max: i64 ) -> bool
    {
        let value: i64 = *value;
        serialize_assert!( min <= max );
        serialize_assert!( value >= min );
        serialize_assert!( value <= max );
        let bits: i32 = bits_required64( min as u64, max as u64 );
        if bits == 0
        {
            return true;                // degenerate range: the value IS the range, nothing to send
        }
        // subtract in the unsigned domain: value - min overflows signed arithmetic when the range is wider than 2^63
        let unsigned_value: u64 = ( value as u64 ).wrapping_sub( min as u64 );
        if bits <= 32
        {
            self.m_writer.WriteBits( unsigned_value as u32, bits );
        }
        else
        {
            // low dword first, then the high remainder: same convention as serialize_bits and serialize_uint64
            self.m_writer.WriteBits( ( unsigned_value & 0xFFFFFFFF ) as u32, 32 );
            self.m_writer.WriteBits( ( unsigned_value >> 32 ) as u32, bits - 32 );
        }
        true
    }

    /**
        Serialize a 128 bit integer (write).
        @param value The integer value in [min,max].
        @param min The minimum value.
        @param max The maximum value.
        @returns Always returns true. All checking is performed by debug asserts only on write.
     */

    #[inline(always)]
    fn SerializeInteger128( &mut self, value: &mut int128_t, min: int128_t, max: int128_t ) -> bool
    {
        let value: int128_t = *value;
        serialize_assert!( min <= max );
        serialize_assert!( value >= min );
        serialize_assert!( value <= max );
        let bits: i32 = bits_required128( min as uint128_t, max as uint128_t );
        if bits == 0
        {
            return true;                // degenerate range: the value IS the range, nothing to send
        }
        // subtract in the unsigned domain: value - min overflows signed arithmetic when the range is wider than 2^127
        let unsigned_value: uint128_t = ( value as uint128_t ).wrapping_sub( min as uint128_t );
        // 32 bit groups, least significant first: the same convention as serialize_bits, serialize_uint64 and the wide fixed point path
        let group0: u32 = ( ( unsigned_value       ) as u64 & 0xFFFFFFFF ) as u32;
        let group1: u32 = ( ( unsigned_value >> 32 ) as u64 & 0xFFFFFFFF ) as u32;
        let group2: u32 = ( ( unsigned_value >> 64 ) as u64 & 0xFFFFFFFF ) as u32;
        let group3: u32 = ( ( unsigned_value >> 96 ) as u64 & 0xFFFFFFFF ) as u32;
        if bits <= 32
        {
            self.m_writer.WriteBits( group0, bits );
        }
        else if bits <= 64
        {
            self.m_writer.WriteBits( group0, 32 );
            self.m_writer.WriteBits( group1, bits - 32 );
        }
        else if bits <= 96
        {
            self.m_writer.WriteBits( group0, 32 );
            self.m_writer.WriteBits( group1, 32 );
            self.m_writer.WriteBits( group2, bits - 64 );
        }
        else
        {
            self.m_writer.WriteBits( group0, 32 );
            self.m_writer.WriteBits( group1, 32 );
            self.m_writer.WriteBits( group2, 32 );
            self.m_writer.WriteBits( group3, bits - 96 );
        }
        true
    }

    /**
        Serialize a number of bits (write).
        @param value The unsigned integer value to serialize. Must be in range [0,(1<<bits)-1].
        @param bits The number of bits to write in [1,32].
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    #[inline(always)]
    fn SerializeBits( &mut self, value: &mut u32, bits: i32 ) -> bool
    {
        serialize_assert!( bits > 0 );
        serialize_assert!( bits <= 32 );
        self.m_writer.WriteBits( *value, bits );
        true
    }

    /**
        Serialize an array of bytes (write).
        @param data Array of bytes to be written.
        @param bytes The number of bytes to write.
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    #[inline(always)]
    fn SerializeBytes( &mut self, data: &mut [u8], bytes: i64 ) -> bool
    {
        self.SerializeBytesInternal( data, bytes )
    }

    #[inline(always)]
    fn SerializeBytesConst( &mut self, data: &[u8], bytes: i64 ) -> bool
    {
        self.SerializeBytesInternal( data, bytes )
    }

    /**
        Serialize an align (write).
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    #[inline(always)]
    fn SerializeAlign( &mut self ) -> bool
    {
        self.m_writer.WriteAlign();
        true
    }

    /**
        If we were to write an align right now, how many bits would be required?
        @returns The number of zero pad bits required to achieve byte alignment in [0,7].
     */

    fn GetAlignBits( &self ) -> i32
    {
        self.m_writer.GetAlignBits()
    }

    /**
        How many bytes have been written so far?
        @returns Number of bytes written. This is effectively the packet size.
     */

    fn GetBytesProcessed( &self ) -> i64
    {
        self.m_writer.GetBytesWritten()
    }

    /**
        Get number of bits written so far.
        @returns Number of bits written.
     */

    fn GetBitsProcessed( &self ) -> i64
    {
        self.m_writer.GetBitsWritten()
    }
}

/**
    Stream class for reading bitpacked data.
    This class is a wrapper around the bit reader class. Its purpose is to provide unified interface for reading and writing.
    You can determine if you are reading from a stream by calling Stream::IsReading inside your templated serialize method.
    This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
    IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead.
    @see BitReader
 */

pub struct ReadStream<'a>
{
    pub base: BaseStream,
    m_reader: BitReader<'a>,            // The bit reader used for all bitpacked read operations.
}

impl<'a> Default for ReadStream<'a>
{
    fn default() -> Self
    {
        ReadStream { base: BaseStream::new(), m_reader: BitReader::default() }
    }
}

impl<'a> ReadStream<'a>
{
    /**
        Point the stream at a new buffer.
        This is the re-initialization that clears a failed stream: a stream that has refused a read refuses every later read until it is re-initialized or discarded.
        @see ReadStream::Fail
     */

    pub fn Initialize( &mut self, buffer: &'a [u8], bytes: i64 )
    {
        self.m_reader.Initialize( buffer, bytes );
    }

    /**
        Read stream constructor.
        @param buffer The buffer to read from.
        @param bytes The number of bytes of packet data to read.
        port: the buffer does not need to extend 8 bytes past the data (see BitReader)
     */

    pub fn new( buffer: &'a [u8], bytes: i64 ) -> ReadStream<'a>
    {
        ReadStream { base: BaseStream::new(), m_reader: BitReader::new( buffer, bytes ) }
    }

    /**
        Refuse the read in progress and latch the stream into the failed state.
        Failure is terminal: the first refused read poisons the reader's position, and every later read on this stream fails, consuming no bits and writing no destination. The failure persists until the stream is re-initialized onto a new buffer, or discarded. Every refusal on this stream goes through here, including refusals decided outside the stream — a malformed string payload, an int_relative reconstruction outside the domain — which reach it through serialize::serialize_fail.
        @returns Always false, so a refusing read reads `return Fail();`.
        @see BitReader::PoisonPosition
        @see serialize::serialize_fail
     */

    #[inline(always)]
    pub fn Fail( &mut self ) -> bool
    {
        self.m_reader.PoisonPosition();
        false
    }
}

impl<'a> Stream for ReadStream<'a>
{
    const IsWriting: bool = false;
    const IsReading: bool = true;

    fn base( &self ) -> &BaseStream { &self.base }
    fn base_mut( &mut self ) -> &mut BaseStream { &mut self.base }

    /**
        Serialize an integer (read).
        @param value The integer value read is stored here. It is guaranteed to be in [min,max] if this function succeeds.
        @param min The minimum allowed value.
        @param max The maximum allowed value.
        @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
     */

    #[inline(always)]
    fn SerializeInteger( &mut self, value: &mut i32, min: i32, max: i32 ) -> bool
    {
        serialize_assert!( min <= max );
        let bits: i32 = bits_required( min as u32, max as u32 );
        // the past-end check comes before the degenerate case so a failed stream refuses a zero bit read too: poisoning the position is what makes WouldReadPastEnd answer true for every bit count
        if self.m_reader.WouldReadPastEnd( bits )
        {
            return self.Fail();
        }
        if bits == 0
        {
            *value = min;               // degenerate range: the value IS the range
            return true;
        }
        let unsigned_value: u32 = self.m_reader.ReadBits( bits );
        // the read side range rule, and the ONLY place it lives at this width: the offset is compared against the span in the unsigned domain, which cannot overflow on hostile input, and the value formed from an accepted offset is in [min,max] by construction. A second check on the decoded value behind this one is unreachable, and a rule guarded twice is a rule no negative control can measure
        if unsigned_value > ( max as u32 ).wrapping_sub( min as u32 )
        {
            return self.Fail();
        }
        // add in the unsigned domain: unsigned_value + min overflows signed arithmetic when the range is wider than 2^31
        *value = unsigned_value.wrapping_add( min as u32 ) as i32;
        true
    }

    /**
        Serialize a 64 bit integer (read).
        @param value The integer value read is stored here. It is guaranteed to be in [min,max] if this function succeeds.
        @param min The minimum allowed value.
        @param max The maximum allowed value.
        @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
     */

    #[inline(always)]
    fn SerializeInteger64( &mut self, value: &mut i64, min: i64, max: i64 ) -> bool
    {
        serialize_assert!( min <= max );
        let bits: i32 = bits_required64( min as u64, max as u64 );
        // the past-end check comes before the degenerate case so a failed stream refuses a zero bit read too
        if self.m_reader.WouldReadPastEnd( bits )
        {
            return self.Fail();
        }
        if bits == 0
        {
            *value = min;               // degenerate range: the value IS the range
            return true;
        }
        let unsigned_value: u64;
        if bits <= 32
        {
            unsigned_value = self.m_reader.ReadBits( bits ) as u64;
        }
        else
        {
            // low dword first, then the high remainder: same convention as serialize_bits and serialize_uint64
            let lo: u32 = self.m_reader.ReadBits( 32 );
            let hi: u32 = self.m_reader.ReadBits( bits - 32 );
            unsigned_value = ( ( hi as u64 ) << 32 ) | lo as u64;
        }
        // the read side range rule at this width, and the only place it lives. See SerializeInteger
        if unsigned_value > ( max as u64 ).wrapping_sub( min as u64 )
        {
            return self.Fail();
        }
        // add in the unsigned domain: unsigned_value + min overflows signed arithmetic when the range is wider than 2^63
        *value = unsigned_value.wrapping_add( min as u64 ) as i64;
        true
    }

    /**
        Serialize a 128 bit integer (read).
        @param value The integer value read is stored here. It is guaranteed to be in [min,max] if this function succeeds.
        @param min The minimum allowed value.
        @param max The maximum allowed value.
        @returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
     */

    #[inline(always)]
    fn SerializeInteger128( &mut self, value: &mut int128_t, min: int128_t, max: int128_t ) -> bool
    {
        serialize_assert!( min <= max );
        let bits: i32 = bits_required128( min as uint128_t, max as uint128_t );
        // the past-end check comes before the degenerate case so a failed stream refuses a zero bit read too
        if self.m_reader.WouldReadPastEnd( bits )
        {
            return self.Fail();
        }
        if bits == 0
        {
            *value = min;               // degenerate range: the value IS the range, on the 128 bit width exactly as on the narrower ones
            return true;
        }
        // 32 bit groups, least significant first: the same convention as the write path
        let mut group0: u32 = 0;
        let mut group1: u32 = 0;
        let mut group2: u32 = 0;
        let mut group3: u32 = 0;
        if bits <= 32
        {
            group0 = self.m_reader.ReadBits( bits );
        }
        else if bits <= 64
        {
            group0 = self.m_reader.ReadBits( 32 );
            group1 = self.m_reader.ReadBits( bits - 32 );
        }
        else if bits <= 96
        {
            group0 = self.m_reader.ReadBits( 32 );
            group1 = self.m_reader.ReadBits( 32 );
            group2 = self.m_reader.ReadBits( bits - 64 );
        }
        else
        {
            group0 = self.m_reader.ReadBits( 32 );
            group1 = self.m_reader.ReadBits( 32 );
            group2 = self.m_reader.ReadBits( 32 );
            group3 = self.m_reader.ReadBits( bits - 96 );
        }
        let unsigned_value: uint128_t = ( ( group3 as uint128_t ) << 96 ) | ( ( group2 as uint128_t ) << 64 ) | ( ( group1 as uint128_t ) << 32 ) | ( group0 as uint128_t );
        // the read side range rule at this width, and the only place it lives. See SerializeInteger
        if unsigned_value > ( max as uint128_t ).wrapping_sub( min as uint128_t )
        {
            return self.Fail();
        }
        // add in the unsigned domain: unsigned_value + min overflows signed arithmetic when the range is wider than 2^127
        *value = unsigned_value.wrapping_add( min as uint128_t ) as int128_t;
        true
    }

    /**
        Serialize a number of bits (read).
        @param value The integer value read is stored here. Will be in range [0,(1<<bits)-1].
        @param bits The number of bits to read in [1,32].
        @returns Returns true if the serialize read succeeded, false otherwise.
     */

    #[inline(always)]
    fn SerializeBits( &mut self, value: &mut u32, bits: i32 ) -> bool
    {
        serialize_assert!( bits > 0 );
        serialize_assert!( bits <= 32 );
        if self.m_reader.WouldReadPastEnd( bits )
        {
            return self.Fail();
        }
        let read_value: u32 = self.m_reader.ReadBits( bits );
        *value = read_value;
        true
    }

    /**
        Serialize an array of bytes (read).
        IMPORTANT: on a refused read the caller's buffer contents are unspecified. The unwritten-destination rule covers scalar reads; a read into a caller-owned buffer is excluded, and this copy path is not restructured for it.
        @param data Array of bytes to read.
        @param bytes The number of bytes to read.
        @returns Returns true if the serialize read succeeded. False otherwise.
     */

    #[inline(always)]
    fn SerializeBytes( &mut self, data: &mut [u8], bytes: i64 ) -> bool
    {
        if bytes < 0
        {
            return self.Fail();
        }
        // the align is what refuses on a failed stream: a poisoned position reads past the end at every align width
        if !self.SerializeAlign()
        {
            return false;
        }
        // compare in bytes rather than bits, consistent with the 64 bit bookkeeping
        if bytes > self.m_reader.GetBitsRemaining() / 8
        {
            return self.Fail();
        }
        self.m_reader.ReadBytes( data, bytes );
        true
    }

    fn SerializeBytesConst( &mut self, data: &[u8], bytes: i64 ) -> bool
    {
        serialize_assert!( false );         // port: a read stream cannot read into const data (write_bytes on a read stream)
        self.Fail()
    }

    /**
        Serialize an align (read).
        @returns Returns true if the serialize read succeeded. False otherwise.
     */

    #[inline(always)]
    fn SerializeAlign( &mut self ) -> bool
    {
        let alignBits: i32 = self.m_reader.GetAlignBits();
        if self.m_reader.WouldReadPastEnd( alignBits )
        {
            return self.Fail();
        }
        if !self.m_reader.ReadAlign()
        {
            return self.Fail();
        }
        true
    }

    /**
        If we were to read an align right now, how many bits would we need to read?
        @returns The number of zero pad bits required to achieve byte alignment in [0,7].
     */

    fn GetAlignBits( &self ) -> i32
    {
        self.m_reader.GetAlignBits()
    }

    /**
        Get number of bits read so far.
        @returns Number of bits read.
     */

    fn GetBitsProcessed( &self ) -> i64
    {
        self.m_reader.GetBitsRead()
    }

    /**
        How many bytes have been read so far?
        @returns Number of bytes read. Effectively this is the number of bits read, rounded up to the next byte where necessary.
     */

    fn GetBytesProcessed( &self ) -> i64
    {
        ( self.m_reader.GetBitsRead() + 7 ) / 8
    }

    // StreamRefusal<ReadStream>
    #[inline(always)]
    fn StreamRefusalFail( &mut self ) -> bool
    {
        self.Fail()
    }
}

/**
    Stream class for estimating how many bits it would take to serialize something.
    This class acts like a bit writer (IsWriting is 1, IsReading is 0), but instead of writing data, it counts how many bits would be written.
    Note that when the serialization includes alignment to byte (see MeasureStream::SerializeAlign), this is an estimate and not an exact measurement. The estimate is guaranteed to be conservative.
    @see BitWriter
    @see BitReader
 */

pub struct MeasureStream
{
    pub base: BaseStream,
    m_bitsWritten: i64,             // Counts the number of bits written.
}

impl Default for MeasureStream
{
    fn default() -> Self
    {
        MeasureStream::new()
    }
}

impl MeasureStream
{
    /**
        Measure stream constructor.
     */

    pub fn new() -> MeasureStream
    {
        MeasureStream { base: BaseStream::new(), m_bitsWritten: 0 }
    }
}

impl Stream for MeasureStream
{
    const IsWriting: bool = true;
    const IsReading: bool = false;

    fn base( &self ) -> &BaseStream { &self.base }
    fn base_mut( &mut self ) -> &mut BaseStream { &mut self.base }

    /**
        Serialize an integer (measure).
        @param value The integer value to write. Not actually used or checked.
        @param min The minimum value.
        @param max The maximum value.
        @returns Always returns true. All checking is performed by debug asserts only on measure.
     */

    fn SerializeInteger( &mut self, value: &mut i32, min: i32, max: i32 ) -> bool
    {
        let value: i32 = *value;
        serialize_assert!( min <= max );
        serialize_assert!( value >= min );
        serialize_assert!( value <= max );
        let bits: i32 = bits_required( min as u32, max as u32 );
        self.m_bitsWritten += bits as i64;
        true
    }

    /**
        Serialize a 64 bit integer (measure).
        @param value The integer value to write. Not actually used or checked.
        @param min The minimum value.
        @param max The maximum value.
        @returns Always returns true. All checking is performed by debug asserts only on measure.
     */

    fn SerializeInteger64( &mut self, value: &mut i64, min: i64, max: i64 ) -> bool
    {
        let value: i64 = *value;
        serialize_assert!( min <= max );
        serialize_assert!( value >= min );
        serialize_assert!( value <= max );
        let bits: i32 = bits_required64( min as u64, max as u64 );
        self.m_bitsWritten += bits as i64;
        true
    }

    /**
        Serialize a 128 bit integer (measure).
        @param value The integer value to measure. Not actually used or checked beyond the debug asserts.
        @param min The minimum value.
        @param max The maximum value.
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    fn SerializeInteger128( &mut self, value: &mut int128_t, min: int128_t, max: int128_t ) -> bool
    {
        let value: int128_t = *value;
        serialize_assert!( min <= max );
        serialize_assert!( value >= min );
        serialize_assert!( value <= max );
        let bits: i32 = bits_required128( min as uint128_t, max as uint128_t );
        self.m_bitsWritten += bits as i64;
        true
    }

    /**
        Serialize a number of bits (write).
        @param value The unsigned integer value to serialize. Not actually used or checked.
        @param bits The number of bits to write in [1,32].
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    fn SerializeBits( &mut self, value: &mut u32, bits: i32 ) -> bool
    {
        serialize_assert!( bits > 0 );
        serialize_assert!( bits <= 32 );
        self.m_bitsWritten += bits as i64;
        true
    }

    /**
        Serialize an array of bytes (measure).
        @param data Array of bytes to 'write'. Not actually used.
        @param bytes The number of bytes to 'write'.
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    fn SerializeBytes( &mut self, data: &mut [u8], bytes: i64 ) -> bool
    {
        self.SerializeBytesConst( data, bytes )
    }

    fn SerializeBytesConst( &mut self, data: &[u8], bytes: i64 ) -> bool
    {
        serialize_assert!( bytes >= 0 );
        self.SerializeAlign();
        self.m_bitsWritten += bytes * 8;
        true
    }

    /**
        Serialize an align (measure).
        @returns Always returns true. All checking is performed by debug asserts on write.
     */

    fn SerializeAlign( &mut self ) -> bool
    {
        let alignBits: i32 = self.GetAlignBits();
        self.m_bitsWritten += alignBits as i64;
        true
    }

    /**
        If we were to write an align right now, how many bits would be required?
        IMPORTANT: Since the number of bits required for alignment depends on where an object is written in the final bit stream, this measurement is conservative.
        @returns Always returns worst case 7 bits.
     */

    fn GetAlignBits( &self ) -> i32
    {
        7
    }

    /**
        Get number of bits written so far.
        @returns Number of bits written.
     */

    fn GetBitsProcessed( &self ) -> i64
    {
        self.m_bitsWritten
    }

    /**
        How many bytes have been written so far?
        @returns Number of bytes written.
     */

    fn GetBytesProcessed( &self ) -> i64
    {
        ( self.m_bitsWritten + 7 ) / 8
    }
}

/**
    Routes a refusal to the stream it happened on.
    Some refusals are decided outside the stream: a value out of range after the caller's own narrowing, a malformed string payload, an int_relative reconstruction outside the domain. Those still have to latch the stream, because failure is terminal. Serialize functions are templated over the stream and compile for all three, and only a read stream has a failure state, so the primary template is the no-op a write or measure needs — neither of which ever refuses.
    A custom stream type gets the primary template and no latch, which is correct for a stream that cannot fail and is the caller's business otherwise.
 */

// port: StreamRefusal is the Stream::StreamRefusalFail member (default: the primary template; ReadStream overrides it)

/**
    Refuse the read in progress on this stream.
    @param stream The stream the refusal happened on.
    @returns Always false, so a refusing read reads `return serialize::serialize_fail( stream );`.
    @see ReadStream::Fail
 */

#[inline(always)]
pub fn serialize_fail<S: Stream>( stream: &mut S ) -> bool
{
    stream.StreamRefusalFail()
}

/**
    Serialize integer value (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    min <= max is the legal relation. A degenerate range where min == max costs zero bits: the writer emits nothing, the reader consumes nothing and takes the value from min, and a measure adds zero.
    On read, a refused read leaves value exactly as the caller left it, and fails the stream: every later read on that stream fails too, until the stream is re-initialized.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The integer value to serialize in [min,max]. The destination must be wide enough to hold the range; a narrower one is caller error, debug asserted.
    @param min The minimum value.
    @param max The maximum value.
 */

#[macro_export]
macro_rules! serialize_int {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( $min ) as i64 <= ( $max ) as i64 );
            let mut int32_value: i32 = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                $crate::serialize_assert!( ( $value ) as i64 >= ( $min ) as i64 );
                $crate::serialize_assert!( ( $value ) as i64 <= ( $max ) as i64 );
                int32_value = ( $value ) as i32;
            }
            if !$crate::serialize::Stream::SerializeInteger( &mut *$stream, &mut int32_value, ( $min ) as i32, ( $max ) as i32 )
            {
                return false;
            }
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = int32_value as _;
                $crate::serialize_assert!( ( $value ) as i64 == int32_value as i64 );
            }
        }
    };
}

/**
    Serialize a 64 bit integer value (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    The full 64 bit range is supported, and the minimal number of bits for [min,max] is used on the wire.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The 64 bit integer value to serialize in [min,max].
    @param min The minimum value.
    @param max The maximum value.
 */

#[macro_export]
macro_rules! serialize_int64 {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( $min ) as i64 <= ( $max ) as i64 );
            let mut int64_value: i64 = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                $crate::serialize_assert!( ( $value ) as i64 >= ( $min ) as i64 );
                $crate::serialize_assert!( ( $value ) as i64 <= ( $max ) as i64 );
                int64_value = ( $value ) as i64;
            }
            if !$crate::serialize::Stream::SerializeInteger64( &mut *$stream, &mut int64_value, ( $min ) as i64, ( $max ) as i64 )
            {
                return false;
            }
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = int64_value as _;
                $crate::serialize_assert!( ( $value ) as i64 == int64_value );
            }
        }
    };
}

/**
    Serialize a ranged 128 bit integer to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    The value is serialized as an offset from min in the minimal number of bits for the range, exactly as serialize_int and serialize_int64 do at their widths, and the bounds are runtime values. Where the range fits 64 bits or fewer the bytes are identical to serialize_int64 over the same bounds.
    min <= max is the legal relation here exactly as on the narrower widths, in every build mode. A degenerate range where min == max costs zero bits: the writer emits nothing, the reader consumes nothing and takes the value from min, and a measure adds zero.
    **Do not confuse this with serialize_uint128**, which is not ranged — it is a raw 128 bit field and always costs 128 bits.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The 128 bit integer value to serialize, in [min,max].
    @param min The minimum value.
    @param max The maximum value.
 */

// port: value, min and max are native integers of any width (converted with `as` to i128)
#[macro_export]
macro_rules! serialize_int128 {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( ( $min ) as $crate::serialize::int128_t ) <= ( ( $max ) as $crate::serialize::int128_t ) );
            let mut int128_value: $crate::serialize::int128_t = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                $crate::serialize_assert!( ( ( $value ) as $crate::serialize::int128_t ) >= ( ( $min ) as $crate::serialize::int128_t ) );
                $crate::serialize_assert!( ( ( $value ) as $crate::serialize::int128_t ) <= ( ( $max ) as $crate::serialize::int128_t ) );
                int128_value = ( $value ) as $crate::serialize::int128_t;
            }
            if !$crate::serialize::Stream::SerializeInteger128( &mut *$stream, &mut int128_value, ( $min ) as $crate::serialize::int128_t, ( $max ) as $crate::serialize::int128_t )
            {
                return false;
            }
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = int128_value as _;
                $crate::serialize_assert!( ( ( $value ) as $crate::serialize::int128_t ) == int128_value );
            }
        }
    };
}

/**
    Serialize bits to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned integer value to serialize. Must be in [0,(1\<\<bits)-1]; a wider value is caller error, debug asserted before the macro narrows it to the group width.
    @param bits The number of bits to serialize in [1,64].
 */

#[macro_export]
macro_rules! serialize_bits {
    ( $stream:expr, $value:expr, $bits:expr ) => {
        {
            $crate::serialize_assert!( ( $bits ) > 0 );
            $crate::serialize_assert!( ( $bits ) <= 64 );
            $crate::serialize_assert!( !$crate::serialize::serialize_stream_is_writing( &*$stream ) ||
                $crate::serialize::value_fits_in_bits( $value, ( $bits ) as i32 ) );
            if ( $bits ) <= 32
            {
                let mut uint32_value: u32 = 0;
                if $crate::serialize::serialize_stream_is_writing( &*$stream )
                {
                    uint32_value = ( $value ) as u32;
                }
                if !$crate::serialize::Stream::SerializeBits( &mut *$stream, &mut uint32_value, ( $bits ) as i32 )
                {
                    return false;
                }
                if $crate::serialize::serialize_stream_is_reading( &*$stream )
                {
                    $value = uint32_value as _;
                }
            }
            else
            {
                let mut hi: u32 = 0;
                let mut lo: u32 = 0;
                if $crate::serialize::serialize_stream_is_writing( &*$stream )
                {
                    lo = ( ( ( $value ) as u64 ) & 0xFFFFFFFF ) as u32;
                    hi = ( ( ( $value ) as u64 ) >> 32 ) as u32;
                }
                if !$crate::serialize::Stream::SerializeBits( &mut *$stream, &mut lo, 32 )
                {
                    return false;
                }
                if !$crate::serialize::Stream::SerializeBits( &mut *$stream, &mut hi, ( ( $bits ) - 32 ) as i32 )
                {
                    return false;
                }
                if $crate::serialize::serialize_stream_is_reading( &*$stream )
                {
                    $value = ( ( ( hi as u64 ) << 32 ) | lo as u64 ) as _;
                }
            }
        }
    };
}

/**
    Serialize a boolean value to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The boolean value to serialize.
 */

#[macro_export]
macro_rules! serialize_bool {
    ( $stream:expr, $value:expr ) => {
        {
            let mut uint32_bool_value: u32 = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                uint32_bool_value = if $value { 1 } else { 0 };
            }
            $crate::serialize_bits!( $stream, uint32_bool_value, 1 );
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = if uint32_bool_value != 0 { true } else { false };
            }
        }
    };
}

#[inline(always)]
pub fn serialize_float_internal<S: Stream>( stream: &mut S, value: &mut f32 ) -> bool
{
    let mut int_value: u32 = 0;
    if S::IsWriting
    {
        int_value = value.to_bits();            // port: memcpy of the float's bits
    }
    if !stream.SerializeBits( &mut int_value, 32 )
    {
        return false;                   // a refused read leaves value exactly as the caller left it
    }
    if S::IsReading
    {
        *value = f32::from_bits( int_value );
    }
    true
}

/**
    Serialize floating point value (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The float value to serialize.
 */

#[macro_export]
macro_rules! serialize_float {
    ( $stream:expr, $value:expr ) => {
        {
            if !$crate::serialize::serialize_float_internal( &mut *$stream, &mut $value )
            {
                return false;
            }
        }
    };
}

/**
    Derive the compressed float wire constants from a (min,max,res) declaration.
    This is the derivation serialize_compressed_float performs on every call, exposed so it can be paid once instead: the constants depend only on the declaration, never on the value, so a schema compiler runs the same derivation at code generation time and passes the results to serialize_compressed_float_precomputed at every call site.
    serialize_compressed_float itself derives with exactly this function and forwards to exactly that entry point, so the two entry points are wire identical by construction.
    A declaration whose delta = max - min, or whose delta / res, is not finite in float32 is non-conforming (STANDARD.md, adopted 2026-08-15) and asserts in debug builds.
    @param min The minimum float value. Must be less than max.
    @param max The maximum float value.
    @param res The resolution the float value is quantized to.
    @param max_integer_value The quantization step count: ceil( ( max - min ) / res ), clamped to [1,4294967040]. Values quantize to integers in [0,max_integer_value].
    @param bits The wire width: bits_required( 0, max_integer_value ), the number of bits a quantized value occupies on the wire, in [1,32].
    @param delta The range width max - min, computed in float32. The quantization arithmetic is pinned to float32, so the wire depends on this exact value, not on the real-number difference.
 */

pub fn serialize_compressed_float_params( min: f32, max: f32, res: f32, max_integer_value: &mut u32, bits: &mut i32, delta: &mut f32 )
{
    serialize_assert!( min < max && res > 0.0 );

    *delta = max - min;

    let mut values: f32 = *delta / res;

    // a declaration whose delta or values is not finite in float32 is non-conforming
    // (STANDARD.md, adopted 2026-08-15) -- assert in debug, per the writer-trusted model.
    // finiteness is spelled x - x == 0 (NaN and both infinities fail it: Inf - Inf is NaN)
    // so the header needs no isfinite and no new include.
    serialize_assert!( *delta - *delta == 0.0 );
    serialize_assert!( values - values == 0.0 );

    // clamp so the uint32_t cast below is defined even for pathological delta / res (the !>= form also catches NaN)
    if !( values >= 1.0 )
    {
        values = 1.0;
    }
    else if values > 4294967040.0      // largest float below 2^32
    {
        values = 4294967040.0;
    }

    *max_integer_value = values.ceil() as u32;

    *bits = bits_required( 0, *max_integer_value );
}

/**
    Serialize compressed floating point value from precomputed wire constants (read/write/measure).
    The audited home of the compressed float quantization arithmetic. serialize_compressed_float derives its constants per call and forwards here; generated code passes constants a schema compiler derived at generation time with the same arithmetic as serialize::serialize_compressed_float_params, skipping the per-field divide, clamp, ceil and bits_required. The two entry points are wire identical by construction.
    On write, the value is clamped into the declared range and quantized; writing a non-finite value is non-conforming and asserts in debug (STANDARD.md). On read, an integer above max_integer_value smuggled into the bit headroom is rejected and the function returns false.
    The constants must be exactly what serialize_compressed_float_params derives for a conforming declaration — anything else is a caller bug, debug asserted per the writer-trusted model.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The float value to serialize. Written on write/measure, filled in on read.
    @param max_integer_value The quantization step count, in [1,4294967040].
    @param bits The wire width in bits. Must equal serialize::bits_required( 0, max_integer_value ).
    @param delta The range width max - min, in float32.
    @param min The minimum float value of the range.
    @returns True if the serialize succeeded, false if the read data is truncated or encodes an integer above max_integer_value.
 */

pub fn serialize_compressed_float_precomputed_internal<S: Stream>( stream: &mut S, value: &mut f32, max_integer_value: u32, bits: i32, delta: f32, min: f32 ) -> bool
{
    serialize_assert!( max_integer_value >= 1 );
    serialize_assert!( bits == bits_required( 0, max_integer_value ) );
    serialize_assert!( delta > 0.0 );
    serialize_assert!( delta - delta == 0.0 );          // finite in float32 (Inf - Inf is NaN)

    let mut integerValue: u32 = 0;

    if S::IsWriting
    {
        // writing a non-finite value (NaN, +/-Inf) through compressed_float is
        // non-conforming (STANDARD.md, adopted 2026-08-15) -- assert in debug. in release
        // the clamp below remains the backstop that keeps the uint32 cast defined.
        serialize_assert!( *value - *value == 0.0 );

        // clamp with the !>= / !<= form so a NaN value is forced into range instead of reaching the uint32 cast below
        let mut normalizedValue: f32 = ( *value - min ) / delta;
        if !( normalizedValue >= 0.0 )
        {
            normalizedValue = 0.0;
        }
        else if !( normalizedValue <= 1.0 )
        {
            normalizedValue = 1.0;
        }
        // STANDARD.md pins this to float32 with TWO roundings: the product
        // rounds before 0.5 is added. The local plus the barrier are what
        // force that, and neither is optional. Written as one expression, a
        // compiler permitted to contract emits a single FMA and rounds ONCE --
        // and that changes the wire. Do not fold this back into one expression.
        // port: max_integer_value converts to float32 (round to nearest) before the multiply, as in C
        let mut scaled: f32 = normalizedValue * max_integer_value as f32;
        SERIALIZE_FLOAT_FORCE_ROUND( &mut scaled );
        integerValue = ( scaled + 0.5 ).floor() as u32;
        // STANDARD.md: the integer clamp is normative (2026-08-23). Once
        // max_integer_value >= 2^23 the float32 ulp at the top of the range
        // reaches 1, so the rounded sum can exceed max_integer_value itself:
        // the writer emits a code its own reader rejects, or one bit wider
        // than the field. Clamping after the floor closes both; no byte
        // changes for any declaration outside [2^23, 2^24).
        if integerValue > max_integer_value
        {
            integerValue = max_integer_value;
        }
    }

    if !stream.SerializeBits( &mut integerValue, bits )
    {
        return false;
    }

    if S::IsReading
    {
        if integerValue > max_integer_value
        {
            return serialize_fail( stream );
        }
        let normalizedValue: f32 = integerValue as f32 / max_integer_value as f32;
        // The reader rounds twice for the same reason the writer above does:
        // the product must round to float32 BEFORE min is added, and the
        // local plus the barrier are what force that. Written as one
        // expression, a compiler permitted to contract fuses the multiply
        // and add into a single FMA on arm64 and rounds ONCE. That decodes a
        // float one ulp away from every conformant runtime whenever min is
        // non-zero, so a value read on arm64 and re-encoded produces
        // different wire. The conformance vector with min = -100 pins them
        // exactly.
        let mut scaledValue: f32 = normalizedValue * delta;
        SERIALIZE_FLOAT_FORCE_ROUND( &mut scaledValue );
        *value = scaledValue + min;
    }

    true
}

pub fn serialize_compressed_float_internal<S: Stream>( stream: &mut S, value: &mut f32, min: f32, max: f32, res: f32 ) -> bool
{
    // derive the wire constants, then run the one audited home of the quantization
    // arithmetic. this body IS the pre-#82 function, split at the line schema issue
    // mas-bandwidth/schema#82 names: everything that depends only on the declaration
    // lives in serialize_compressed_float_params, everything that touches the value or
    // the wire lives in serialize_compressed_float_precomputed_internal, statement for
    // statement.
    let mut max_integer_value: u32 = 0;
    let mut bits: i32 = 0;
    let mut delta: f32 = 0.0;
    serialize_compressed_float_params( min, max, res, &mut max_integer_value, &mut bits, &mut delta );
    serialize_compressed_float_precomputed_internal( stream, value, max_integer_value, bits, delta, min )
}

/**
    Serialize compressed floating point value (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The float value to serialize.
 */

#[macro_export]
macro_rules! serialize_compressed_float {
    ( $stream:expr, $value:expr, $min:expr, $max:expr, $res:expr ) => {
        {
            if !$crate::serialize::serialize_compressed_float_internal( &mut *$stream, &mut $value, ( $min ) as f32, ( $max ) as f32, ( $res ) as f32 )
            {
                return false;
            }
        }
    };
}

/**
    Serialize compressed floating point value from precomputed wire constants (read/write/measure).
    The precomputed companion to serialize_compressed_float, designed for generated code: a schema compiler derives max_integer_value, bits and delta from the declaration at code generation time with the same arithmetic as serialize::serialize_compressed_float_params and passes them as literals, so the per-field derivation (a divide, a clamp, a ceil and a bits_required) is never paid at runtime. Wire bytes are identical to serialize_compressed_float by construction.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The float value to serialize.
    @param max_integer_value The quantization step count, exactly as serialize::serialize_compressed_float_params derives it from the declaration.
    @param bits The wire width in bits: serialize::bits_required( 0, max_integer_value ).
    @param delta The range width max - min, in float32.
    @param min The minimum float value of the range.
 */

#[macro_export]
macro_rules! serialize_compressed_float_precomputed {
    ( $stream:expr, $value:expr, $max_integer_value:expr, $bits:expr, $delta:expr, $min:expr ) => {
        {
            if !$crate::serialize::serialize_compressed_float_precomputed_internal( &mut *$stream, &mut $value, ( $max_integer_value ) as u32, ( $bits ) as i32, ( $delta ) as f32, ( $min ) as f32 )
            {
                return false;
            }
        }
    };
}

#[inline(always)]
pub fn serialize_double_internal<S: Stream>( stream: &mut S, value: &mut f64 ) -> bool
{
    // port: the DoubleInt union is to_bits / from_bits
    let mut int_value: u64 = 0;
    if S::IsWriting
    {
        int_value = value.to_bits();
    }
    serialize_bits!( stream, int_value, 64 );
    if S::IsReading
    {
        *value = f64::from_bits( int_value );
    }
    true
}

/**
    Serialize double precision floating point value to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The double precision floating point value to serialize.
 */

#[macro_export]
macro_rules! serialize_double {
    ( $stream:expr, $value:expr ) => {
        {
            if !$crate::serialize::serialize_double_internal( &mut *$stream, &mut $value )
            {
                return false;
            }
        }
    };
}

#[inline(always)]
pub fn serialize_bytes_internal<S: Stream>( stream: &mut S, data: &mut [u8], bytes: i64 ) -> bool
{
    stream.SerializeBytes( data, bytes )
}

/**
    Serialize unsigned 8 bit integer (read/write/measure).
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned 16 bit integer value.
 */

#[macro_export]
macro_rules! serialize_uint8 {
    ( $stream:expr, $value:expr ) => { $crate::serialize_bits!( $stream, $value, 8 ) };
}

/**
    Serialize unsigned 16 bit integer (read/write/measure).
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned 16 bit integer value.
 */

#[macro_export]
macro_rules! serialize_uint16 {
    ( $stream:expr, $value:expr ) => { $crate::serialize_bits!( $stream, $value, 16 ) };
}

/**
    Serialize unsigned 32 bit integer (read/write/measure).
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned 32 bit integer value.
 */

#[macro_export]
macro_rules! serialize_uint32 {
    ( $stream:expr, $value:expr ) => { $crate::serialize_bits!( $stream, $value, 32 ) };
}

/**
    Serialize unsigned 64 bit integer (read/write/measure).
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned 64 bit integer value.
 */

#[macro_export]
macro_rules! serialize_uint64 {
    ( $stream:expr, $value:expr ) => { $crate::serialize_bits!( $stream, $value, 64 ) };
}

/**
    The requirements serialize_uint128_internal puts on its 128 bit type: construction from uint64_t, operator<< and
    operator>> with int shift counts, operator|, and explicit conversion to uint64_t truncating to the low 64 bits.
    port: a C++ template's implicit requirements are this trait; it is implemented for native u128 and the emulated
    serialize_uint128_t
 */

pub trait SerializeUInt128: Copy + From<u64> + Shl<i32, Output = Self> + Shr<i32, Output = Self> + BitOr<Output = Self>
{
    /// uint64_t( value ): the low 64 bits
    fn low_u64( self ) -> u64;
}

impl SerializeUInt128 for u128 { #[inline(always)] fn low_u64( self ) -> u64 { self as u64 } }
impl SerializeUInt128 for serialize_uint128_t { #[inline(always)] fn low_u64( self ) -> u64 { self.lo } }

/**
    Serialize a 128 bit unsigned integer (read/write/measure), templated over the 128 bit type.
    The wire format is 128 bits raw: the low 64 bit half first, then the high half, following the lo-then-hi convention of serialize_bits.
    UInt128 may be the native unsigned __int128 (see serialize::uint128_t) or an emulated 128 bit unsigned integer type on compilers without native support, such as pure MSVC.
    The requirements on UInt128 are exactly: construction from uint64_t, operator\<\< and operator\>\> with int shift counts, operator|, and explicit conversion (static_cast) to uint64_t truncating to the low 64 bits.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The 128 bit unsigned integer value.
    @returns True if the serialize succeeded, false otherwise.
 */

pub fn serialize_uint128_internal<S: Stream, UInt128: SerializeUInt128>( stream: &mut S, value: &mut UInt128 ) -> bool
{
    // refuse narrower types at compile time: a uint64_t here would shift by 64 — undefined
    // behavior — and silently is not the 128 bit operation the caller asked for
    serialize_static_assert!( std::mem::size_of::<UInt128>() == 16, "serialize_uint128 requires a 128 bit type (did you mean serialize_uint64?)" );

    let mut low_half: u64 = 0;
    let mut high_half: u64 = 0;
    if S::IsWriting
    {
        low_half = value.low_u64();
        high_half = ( *value >> 64 ).low_u64();
    }
    serialize_bits!( stream, low_half, 64 );
    serialize_bits!( stream, high_half, 64 );
    if S::IsReading
    {
        *value = ( UInt128::from( high_half ) << 64 ) | UInt128::from( low_half );
    }
    true
}

/**
    Serialize unsigned 128 bit integer (read/write/measure).
    The wire format is 128 bits raw: the low 64 bit half first, then the high half, following the lo-then-hi convention of serialize_bits.
    The value may be serialize::uint128_t, or any 128 bit unsigned integer type meeting the requirements documented on serialize_uint128_internal. All representations produce identical bytes.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The 128 bit unsigned integer value.
 */

#[macro_export]
macro_rules! serialize_uint128 {
    ( $stream:expr, $value:expr ) => {
        {
            if !$crate::serialize::serialize_uint128_internal( &mut *$stream, &mut $value )
            {
                return false;
            }
        }
    };
}

/**
    Serialize an array of bytes to the stream (read/write/measure).
    This is a helper macro to make unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param data Pointer to the data to be serialized.
    @param bytes The number of bytes to serialize.
 */

// port: data is anything that indexes to [u8] (array, slice, &mut [u8], Vec<u8>)
#[macro_export]
macro_rules! serialize_bytes {
    ( $stream:expr, $data:expr, $bytes:expr ) => {
        {
            if !$crate::serialize::serialize_bytes_internal( &mut *$stream, &mut ( $data )[..], ( $bytes ) as i64 )
            {
                return false;
            }
        }
    };
}

/*
    UTF-8 well-formedness, one validator with two callers (STANDARD.md, adopted
    2026-08-15): the WRITE path's contract check — a debug-only assert per the
    writes-trusted doctrine, compiled out under NDEBUG — and the READ path's
    refusal rule ("Readers must refuse malformed string payloads"), which binds
    in every build mode, because the read side faces untrusted data. Rejects
    overlong encodings, surrogate code points, values above U+10FFFF, truncated
    sequences and stray continuation bytes. NUL bytes are VALID UTF-8: the
    interior-NUL refusal is a separate rule with its own reason.
*/

pub fn serialize_string_is_valid_utf8( string: &[u8], length: i32 ) -> bool
{
    let length = length as usize;
    let mut i: usize = 0;
    while i < length
    {
        let lead: u32 = string[i] as u32;
        if lead < 0x80
        {
            i += 1;
        }
        else if ( lead & 0xE0 ) == 0xC0
        {
            if lead < 0xC2                                                              // overlong
            {
                return false;
            }
            if i + 1 >= length
            {
                return false;
            }
            if ( string[i+1] & 0xC0 ) != 0x80
            {
                return false;
            }
            i += 2;
        }
        else if ( lead & 0xF0 ) == 0xE0
        {
            if i + 2 >= length
            {
                return false;
            }
            let byte1: u32 = string[i+1] as u32;
            let byte2: u32 = string[i+2] as u32;
            if ( byte1 & 0xC0 ) != 0x80 || ( byte2 & 0xC0 ) != 0x80
            {
                return false;
            }
            if lead == 0xE0 && byte1 < 0xA0                                             // overlong
            {
                return false;
            }
            if lead == 0xED && byte1 >= 0xA0                                            // surrogate code point
            {
                return false;
            }
            i += 3;
        }
        else if ( lead & 0xF8 ) == 0xF0
        {
            if lead > 0xF4                                                              // above U+10FFFF
            {
                return false;
            }
            if i + 3 >= length
            {
                return false;
            }
            let byte1: u32 = string[i+1] as u32;
            let byte2: u32 = string[i+2] as u32;
            let byte3: u32 = string[i+3] as u32;
            if ( byte1 & 0xC0 ) != 0x80 || ( byte2 & 0xC0 ) != 0x80 || ( byte3 & 0xC0 ) != 0x80
            {
                return false;
            }
            if lead == 0xF0 && byte1 < 0x90                                             // overlong
            {
                return false;
            }
            if lead == 0xF4 && byte1 >= 0x90                                            // above U+10FFFF
            {
                return false;
            }
            i += 4;
        }
        else
        {
            return false;                                                               // continuation or invalid lead byte
        }
    }
    true
}

// port: strlen over a NUL-terminated byte buffer; the end of the slice terminates it too
#[inline(always)]
pub fn serialize_strlen( string: &[u8] ) -> usize
{
    string.iter().position( |&c| c == 0 ).unwrap_or( string.len() )
}

// port: string is a NUL-terminated byte buffer of at least buffer_size bytes (README, "Strings": fixed char fields
// that go on the wire stay [u8; N])
pub fn serialize_string_internal<S: Stream>( stream: &mut S, string: &mut [u8], buffer_size: i32 ) -> bool
{
    let mut length: i32 = 0;
    if S::IsWriting
    {
        // the length assertion runs on the size_t strlen returns, before it narrows to int:
        // an assertion placed after the narrowing sees a length already truncated, and a
        // string of 2^32 + 5 bytes truncates to 5, which fits any buffer
        let string_length: usize = serialize_strlen( string );
        serialize_assert!( buffer_size > 0 );
        serialize_assert!( string_length < buffer_size as usize );
        length = string_length as i32;
        // the writer's contract, debug only. See serialize_string_is_valid_utf8.
        serialize_assert!( serialize_string_is_valid_utf8( string, length ) );
    }
    serialize_int!( stream, length, 0, buffer_size - 1 );
    serialize_bytes!( stream, string, length );
    if S::IsReading
    {
        // STANDARD.md, "Readers must refuse malformed string payloads" (adopted
        // 2026-08-15). Interior NUL first: a conforming writer derives the length
        // from strlen, so a zero byte among the transmitted bytes only arrives
        // doctored — and it gives the payload TWO lengths, the wire length and the
        // strlen every consumer downstream computes, with everything between them
        // riding invisibly past whichever side uses the other. NUL is valid UTF-8,
        // so the validator below cannot catch it.
        for i in 0..length as usize
        {
            if string[i] == 0
            {
                return serialize_fail( stream );
            }
        }
        if !serialize_string_is_valid_utf8( string, length )
        {
            return serialize_fail( stream );
        }
        string[length as usize] = 0;
    }
    true
}

// port: wchar_t is 2 bytes (UTF-16) on Windows and 4 bytes (UTF-32) elsewhere, as in C. Upstream's signed 4 byte
// wchar_t is u32 here: every use converts it to uint32_t first
#[cfg(windows)]
pub type wchar_t = u16;
#[cfg(not(windows))]
pub type wchar_t = u32;

// port: wcslen over a NUL-terminated wide buffer; the end of the slice terminates it too
#[inline(always)]
fn serialize_wcslen( string: &[wchar_t] ) -> usize
{
    string.iter().position( |&c| c == 0 ).unwrap_or( string.len() )
}

// Counts the UTF-16 code units a wide string transmits — which on a 4 byte wchar_t
// platform is more than its character count when astral text is present, and is the
// count the wstring length field carries (STANDARD.md: each 32 bit group is one UTF-16
// code unit). Shared by write and measure, so both agree on cost.

pub fn serialize_wstring_unit_count( string: &[wchar_t] ) -> i32
{
    let mut units: i32 = 0;
    let mut i: usize = 0;
    while i < string.len() && string[i] != 0
    {
        let character: u32 = string[i] as u32;
        units += if character >= 0x10000 && character <= 0x10FFFF { 2 } else { 1 };
        i += 1;
    }
    units
}

/*
    The wstring payload is well-formed UTF-16 BY CONTRACT (STANDARD.md, adopted
    2026-08-15): an unpaired surrogate is a writer contract violation, debug-asserted
    per the writes-trusted doctrine. On a 4 byte wchar_t platform the string is UTF-32,
    where a surrogate CODE POINT or a value above U+10FFFF is the malformation; on a
    2 byte platform it is UTF-16, where the pairing itself is checked. Referenced only
    from serialize_assert; compiles out under NDEBUG.
*/

pub fn serialize_wstring_is_valid_utf16( string: &[wchar_t] ) -> bool
{
    let wide_wchar: bool = std::mem::size_of::<wchar_t>() >= 4;
    let length = serialize_wcslen( string );
    let mut i: usize = 0;
    while i < length
    {
        let character: u32 = string[i] as u32;
        if wide_wchar
        {
            if character >= 0xD800 && character <= 0xDFFF       // a surrogate is not a code point
            {
                return false;
            }
            if character > 0x10FFFF                             // above Unicode
            {
                return false;
            }
            i += 1;
        }
        else
        {
            if character >= 0xD800 && character <= 0xDBFF
            {
                let next: u32 = if i + 1 < length { string[i+1] as u32 } else { 0 };        // port: the terminator past the end of the slice
                if next < 0xDC00 || next > 0xDFFF               // high surrogate without its pair
                {
                    return false;
                }
                i += 2;
            }
            else if character >= 0xDC00 && character <= 0xDFFF
            {
                return false;                                   // low surrogate with no high before it
            }
            else
            {
                i += 1;
            }
        }
    }
    true
}

// Wire format is 32 bits per group, EACH GROUP ONE UTF-16 CODE UNIT (STANDARD.md, adopted
// 2026-08-15), so streams are byte-identical between platforms with 2 and 4 byte wchar_t:
// the 4 byte platform converts at the boundary — an astral code point splits into its
// surrogate pair on write, and the pair recombines on read. The length field counts the
// units transmitted.
//
// On read, malformed payloads are REFUSED in every build mode (STANDARD.md, "Readers must
// refuse malformed wstring payloads", adopted 2026-08-15): a group above 0xFFFF is not a
// code unit; an unpaired surrogate fails the read — a high surrogate without its low, a
// low with no high before it, or a dangling high as the final group — and so does an
// interior NUL group, because a conforming writer derives the length from the terminator,
// so a zero group only arrives doctored and gives the payload two lengths. Well-formed
// surrogate PAIRS pass: they are how astral text travels.

pub fn serialize_wstring_internal<S: Stream>( stream: &mut S, string: &mut [wchar_t], buffer_size: i32 ) -> bool
{
    let mut length: i32 = 0;
    if S::IsWriting
    {
        // the writer's contract, debug only. See serialize_wstring_is_valid_utf16.
        serialize_assert!( serialize_wstring_is_valid_utf16( string ) );
        length = serialize_wstring_unit_count( string );
        serialize_assert!( length < buffer_size );
    }
    serialize_int!( stream, length, 0, buffer_size - 1 );
    if S::IsWriting
    {
        let mut i: usize = 0;
        while i < string.len() && string[i] != 0
        {
            let character: u32 = string[i] as u32;
            if character >= 0x10000 && character <= 0x10FFFF
            {
                // an astral code point in a 4 byte wchar_t: split into its surrogate
                // pair at the boundary, so the bytes are the ones a 2 byte wchar_t
                // platform produces
                let mut high_surrogate: u32 = 0xD800 + ( ( character - 0x10000 ) >> 10 );
                let mut low_surrogate: u32 = 0xDC00 + ( ( character - 0x10000 ) & 0x3FF );
                serialize_bits!( stream, high_surrogate, 32 );
                serialize_bits!( stream, low_surrogate, 32 );
            }
            else
            {
                let mut unit: u32 = character;
                serialize_bits!( stream, unit, 32 );
            }
            i += 1;
        }
    }
    else
    {
        // Each group is one UTF-16 code unit (STANDARD.md, adopted 2026-08-15), and
        // malformed payloads are REFUSED in every build mode: a group above 0xFFFF is
        // not a code unit and no conforming writer emits one; an interior NUL gives
        // the payload two lengths; the pair discipline refuses a high surrogate
        // without its low, a low with no high before it, and a dangling high as the
        // final group. Well-formed pairs pass — they are how astral text travels —
        // and on a 4 byte wchar_t they recombine at the boundary, the inverse of the
        // split the writer performed; a 2 byte wchar_t stores units as they arrive.
        let wide_wchar: bool = std::mem::size_of::<wchar_t>() >= 4;
        let mut pending: u32 = 0;                   // a high surrogate awaiting its pair
        let mut have_pending: bool = false;
        let mut output_index: usize = 0;
        for i in 0..length
        {
            let mut character: u32 = 0;
            serialize_bits!( stream, character, 32 );
            if character > 0xFFFF
            {
                return serialize_fail( stream );    // not a UTF-16 code unit: nothing conforming emits one
            }
            if character == 0
            {
                return serialize_fail( stream );    // interior NUL: the two-lengths smuggling primitive
            }
            if have_pending
            {
                if character < 0xDC00 || character > 0xDFFF
                {
                    return serialize_fail( stream );    // high surrogate without its low
                }
                if wide_wchar
                {
                    string[output_index] = ( 0x10000 + ( ( pending - 0xD800 ) << 10 ) + ( character - 0xDC00 ) ) as wchar_t;
                    output_index += 1;
                }
                else
                {
                    string[output_index] = pending as wchar_t;
                    output_index += 1;
                    string[output_index] = character as wchar_t;
                    output_index += 1;
                }
                have_pending = false;
                continue;
            }
            if character >= 0xDC00 && character <= 0xDFFF
            {
                return serialize_fail( stream );    // low surrogate with no high before it
            }
            if character >= 0xD800 && character <= 0xDBFF
            {
                pending = character;
                have_pending = true;
                continue;
            }
            string[output_index] = character as wchar_t;
            output_index += 1;
        }
        if have_pending
        {
            return serialize_fail( stream );        // the final group is a dangling high surrogate
        }
        string[output_index] = 0;
    }
    true
}

/**
    Serialize a string to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    On read, malformed payloads are refused (STANDARD.md, adopted 2026-08-15): invalid UTF-8 fails the read, and so does an interior NUL byte among the transmitted bytes.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param string The string to serialize write/measure. Pointer to buffer to be filled on read.
    @param buffer_size The size of the string buffer. String with terminating null character must fit into this buffer.
 */

// port: string is a NUL-terminated byte buffer (anything that indexes to [u8])
#[macro_export]
macro_rules! serialize_string {
    ( $stream:expr, $string:expr, $buffer_size:expr ) => {
        {
            if !$crate::serialize::serialize_string_internal( &mut *$stream, &mut ( $string )[..], ( $buffer_size ) as i32 )
            {
                return false;
            }
        }
    };
}

/**
    Serialize a wide string to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    The wire format is 32 bits per group, each group one UTF-16 code unit, so streams are byte-identical between platforms with 2 and 4 byte wchar_t: on a 4 byte wchar_t platform an astral code point splits into its surrogate pair on write and recombines on read. The payload is well-formed UTF-16 by the writer's contract (debug-asserted).
    On read, malformed payloads are refused (STANDARD.md, adopted 2026-08-15): a group above 0xFFFF is not a code unit and fails the read, an unpaired surrogate fails the read, and so does an interior NUL group among the transmitted groups.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param string The wide string to serialize write/measure. Pointer to buffer to be filled on read.
    @param buffer_size The size of the string buffer in wide characters. String with terminating null character must fit into this buffer.
 */

// port: string is a NUL-terminated wchar_t buffer (anything that indexes to [wchar_t])
#[macro_export]
macro_rules! serialize_wstring {
    ( $stream:expr, $string:expr, $buffer_size:expr ) => {
        {
            if !$crate::serialize::serialize_wstring_internal( &mut *$stream, &mut ( $string )[..], ( $buffer_size ) as i32 )
            {
                return false;
            }
        }
    };
}

/**
    Serialize an alignment to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
 */

#[macro_export]
macro_rules! serialize_align {
    ( $stream:expr ) => {
        {
            if !$crate::serialize::Stream::SerializeAlign( &mut *$stream )
            {
                return false;
            }
        }
    };
}

/**
    Serialize an object to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param object The object to serialize. Must have a serialize method on it.
 */

// port: object has a `fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool`
#[macro_export]
macro_rules! serialize_object {
    ( $stream:expr, $object:expr ) => {
        {
            if !( $object ).Serialize( &mut *$stream )
            {
                return false;
            }
        }
    };
}

/**
    The int_relative domain: 0 to 2^31 - 1 inclusive.
    Both previous and current lie in it. The domain is a property of the operation, not of the caller's storage type: a 64 bit or unsigned previous of 2^31 is caller error everywhere, exactly as a negative one is.
 */

pub const serialize_int_relative_max: i64 = 2147483647;

/**
    Is a value inside the int_relative domain?
    This is the write side domain check for serialize_int_relative and write_int_relative, and it runs on the caller's value before the macro narrows it to int. An assertion placed after the narrowing sees a value already truncated to int, so it cannot report the out of domain input it exists to diagnose: writing 2^32 + 5 arrives at serialize::serialize_int_relative_internal as 5, in the domain by construction.
    The value is widened rather than narrowed, so an input above the top of the domain fails wherever it came from. An unsigned 64 bit value above 2^63 - 1 widens to a negative int64_t and fails too, which is the right answer: it is above the domain, not below it.
    @param value The caller's value.
    @returns True if the value is in [0,2^31-1].
 */

#[inline(always)]
pub fn value_in_int_relative_domain<T: FixedPointInteger>( value: T ) -> bool
{
    let widened: i64 = value.to_i64();
    widened >= 0 && widened <= serialize_int_relative_max
}

/**
    Accept a reconstructed int_relative value, or refuse the read.
    Every tier reconstructs current in a width that cannot wrap and lands here, where the result is checked against the domain and against previous. current is written only once both checks pass, so a refused read leaves the caller's value exactly as it was, and the refusal fails the stream.
    @param stream The stream the value was read from.
    @param previous The previous value, in the domain.
    @param current The destination. Written only on success.
    @param reconstructed The reconstructed current, computed in a width wide enough that it cannot wrap.
    @returns True if the reconstruction is in the domain and strictly greater than previous, false otherwise.
 */

#[inline(always)]
pub fn serialize_int_relative_accept<S: Stream, T: FixedPointInteger>( stream: &mut S, previous: T, current: &mut T, reconstructed: i64 ) -> bool
{
    if reconstructed < 0 || reconstructed > serialize_int_relative_max || reconstructed <= previous.to_i64()
    {
        return serialize_fail( stream );
    }
    *current = T::from_i64( reconstructed );
    true
}

/**
    Serialize an integer relative to a previous one (read/write/measure).
    The encoding is a ladder of one-bit flags, each answering "does the difference fit in this tier?": a difference of 1 costs a single bit, then five bounded tiers of 3, 5, 9, 13 and 17 payload bits, then an absolute tier that transmits current itself as 32 raw bits.
    The sequence is strictly increasing and no wrap semantics exist: a caller with a wrapping counter unwraps it before serializing. The domain is 0 to 2^31 - 1 inclusive for both previous and current — previous is the caller's own state and never arrives off the wire, so a previous outside the domain is caller error and is asserted in checked builds.
    On read, every tier's reconstruction is checked: current is reconstructed in a width that cannot wrap, then compared against the domain and against previous, and the read is refused unless it lies in the domain and is strictly greater than previous. The absolute tier's 32 raw bits are read unsigned, so a value with the top bit set is outside the domain and is refused there. A refused read writes nothing to current and fails the stream.
    @param stream The stream object. May be a read, write or measure stream.
    @param previous The previous integer value, in [0,2^31-1].
    @param current The current integer value, in [0,2^31-1] and strictly greater than previous.
    @returns True if the serialize succeeded, false if the read was refused.
 */

pub fn serialize_int_relative_internal<S: Stream, T: FixedPointInteger>( stream: &mut S, previous: T, current: &mut T ) -> bool
{
    // previous is the caller's own state and never arrives off the wire, so one outside the domain is caller error. all checking is performed by debug asserts on it
    serialize_assert!( previous.to_i64() >= 0 );
    serialize_assert!( previous.to_i64() <= serialize_int_relative_max );

    let mut difference: u32 = 0;
    if S::IsWriting
    {
        serialize_assert!( previous < *current );
        serialize_assert!( current.to_i64() <= serialize_int_relative_max );
        difference = current.to_u32().wrapping_sub( previous.to_u32() );
    }

    let mut oneBit: bool = false;
    if S::IsWriting
    {
        oneBit = difference == 1;
    }
    serialize_bool!( stream, oneBit );
    if oneBit
    {
        if S::IsReading
        {
            return serialize_int_relative_accept( stream, previous, current, previous.to_i64() + 1 );
        }
        return true;
    }

    let mut twoBits: bool = false;
    if S::IsWriting
    {
        twoBits = difference <= 6;
    }
    serialize_bool!( stream, twoBits );
    if twoBits
    {
        serialize_int!( stream, difference, 2, 6 );
        if S::IsReading
        {
            return serialize_int_relative_accept( stream, previous, current, previous.to_i64() + difference as i64 );
        }
        return true;
    }

    let mut fourBits: bool = false;
    if S::IsWriting
    {
        fourBits = difference <= 23;
    }
    serialize_bool!( stream, fourBits );
    if fourBits
    {
        serialize_int!( stream, difference, 7, 23 );
        if S::IsReading
        {
            return serialize_int_relative_accept( stream, previous, current, previous.to_i64() + difference as i64 );
        }
        return true;
    }

    let mut eightBits: bool = false;
    if S::IsWriting
    {
        eightBits = difference <= 280;
    }
    serialize_bool!( stream, eightBits );
    if eightBits
    {
        serialize_int!( stream, difference, 24, 280 );
        if S::IsReading
        {
            return serialize_int_relative_accept( stream, previous, current, previous.to_i64() + difference as i64 );
        }
        return true;
    }

    let mut twelveBits: bool = false;
    if S::IsWriting
    {
        twelveBits = difference <= 4377;
    }
    serialize_bool!( stream, twelveBits );
    if twelveBits
    {
        serialize_int!( stream, difference, 281, 4377 );
        if S::IsReading
        {
            return serialize_int_relative_accept( stream, previous, current, previous.to_i64() + difference as i64 );
        }
        return true;
    }

    let mut sixteenBits: bool = false;
    if S::IsWriting
    {
        sixteenBits = difference <= 69914;
    }
    serialize_bool!( stream, sixteenBits );
    if sixteenBits
    {
        serialize_int!( stream, difference, 4378, 69914 );
        if S::IsReading
        {
            return serialize_int_relative_accept( stream, previous, current, previous.to_i64() + difference as i64 );
        }
        return true;
    }

    // the absolute tier transmits current, not the difference, as 32 raw bits. the group is
    // UNSIGNED, so a value with the top bit set is outside the domain and is refused below
    // rather than read as a negative sequence number
    let mut value: u32 = 0;
    if S::IsWriting
    {
        value = current.to_u32();
    }
    serialize_bits!( stream, value, 32 );
    if S::IsReading
    {
        return serialize_int_relative_accept( stream, previous, current, value as i64 );
    }

    true
}

/**
    Serialize an integer value relative to another (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param previous The previous integer value.
    @param current The current integer value.
 */

// port: previous and current have the same integer type T, as the C++ template deduces
#[macro_export]
macro_rules! serialize_int_relative {
    ( $stream:expr, $previous:expr, $current:expr ) => {
        {
            if !$crate::serialize::serialize_int_relative_internal( &mut *$stream, $previous, &mut $current )
            {
                return false;
            }
        }
    };
}

/**
    Compile time trait marking the integer types usable as fixed point storage.
    Written locally because std::is_integral is not guaranteed to cover __int128 on every compiler, and this header does not include \<type_traits\>.
 */

// port: a trait implemented for every integer type (a type without it fails to compile, where upstream's primary
// template has is_integer = 0 and a static assert fires). It also carries the C-style conversions the generic
// templates perform with casts (`int64_t( value )`, `Storage( raw )`, ...), which a Rust generic cannot spell with
// `as`; serialize_int_relative and value_fits_in_bits use the same conversions. BITS is 8 * sizeof( T ).
pub trait FixedPointInteger: Copy + PartialOrd
{
    const is_integer: i32;
    const is_signed: i32;
    const BITS: i32;

    /// int64_t( value ): truncates wider values, sign extends signed ones
    fn to_i64( self ) -> i64;
    /// uint64_t( value ): truncates wider values, sign extends signed ones
    fn to_u64( self ) -> u64;
    /// uint32_t( value )
    fn to_u32( self ) -> u32;
    /// the value in the unsigned 128 bit domain (the FixedPointUnsigned conversion): sign extends signed values
    fn to_u128( self ) -> u128;
    /// T( value ) from an int64_t: sign extends into wider types, truncates into narrower ones
    fn from_i64( value: i64 ) -> Self;
    /// T( value ) from a uint64_t: truncates
    fn from_u64( value: u64 ) -> Self;
    /// T( value ) from the unsigned 128 bit domain: truncates, two's complement for signed storage
    fn from_u128( value: u128 ) -> Self;
}

macro_rules! serialize_impl_fixed_point_integer {
    ( $t:ty, $is_signed:expr ) => {
        impl FixedPointInteger for $t
        {
            const is_integer: i32 = 1;
            const is_signed: i32 = $is_signed;
            const BITS: i32 = ( 8 * std::mem::size_of::<$t>() ) as i32;
            #[inline(always)] fn to_i64( self ) -> i64 { self as i64 }
            #[inline(always)] fn to_u64( self ) -> u64 { self as u64 }
            #[inline(always)] fn to_u32( self ) -> u32 { self as u32 }
            #[inline(always)] fn to_u128( self ) -> u128 { self as u128 }
            #[inline(always)] fn from_i64( value: i64 ) -> Self { value as $t }
            #[inline(always)] fn from_u64( value: u64 ) -> Self { value as $t }
            #[inline(always)] fn from_u128( value: u128 ) -> Self { value as $t }
        }
    };
}

serialize_impl_fixed_point_integer!( i8, 1 );
serialize_impl_fixed_point_integer!( u8, 0 );
serialize_impl_fixed_point_integer!( i16, 1 );
serialize_impl_fixed_point_integer!( u16, 0 );
serialize_impl_fixed_point_integer!( i32, 1 );
serialize_impl_fixed_point_integer!( u32, 0 );
serialize_impl_fixed_point_integer!( i64, 1 );
serialize_impl_fixed_point_integer!( u64, 0 );
serialize_impl_fixed_point_integer!( isize, 1 );
serialize_impl_fixed_point_integer!( usize, 0 );
serialize_impl_fixed_point_integer!( i128, 1 );
serialize_impl_fixed_point_integer!( u128, 0 );

// the emulated pair works as storage too. without native __int128 these ARE the serialize
// typedefs; with it they are a distinct set of types (present when tests are enabled, or
// when a sibling header defined the block first), so the specializations never collide

impl FixedPointInteger for serialize_int128_t
{
    const is_integer: i32 = 1;
    const is_signed: i32 = 1;
    const BITS: i32 = 128;
    #[inline(always)] fn to_i64( self ) -> i64 { self.lo as i64 }
    #[inline(always)] fn to_u64( self ) -> u64 { self.lo }
    #[inline(always)] fn to_u32( self ) -> u32 { self.lo as u32 }
    #[inline(always)] fn to_u128( self ) -> u128 { ( ( self.hi as u128 ) << 64 ) | self.lo as u128 }
    #[inline(always)] fn from_i64( value: i64 ) -> Self { serialize_int128_t::from( value ) }
    #[inline(always)] fn from_u64( value: u64 ) -> Self { serialize_int128_t::from( value ) }
    #[inline(always)] fn from_u128( value: u128 ) -> Self { serialize_int128_t { lo: value as u64, hi: ( value >> 64 ) as u64 } }
}

impl FixedPointInteger for serialize_uint128_t
{
    const is_integer: i32 = 1;
    const is_signed: i32 = 0;
    const BITS: i32 = 128;
    #[inline(always)] fn to_i64( self ) -> i64 { self.lo as i64 }
    #[inline(always)] fn to_u64( self ) -> u64 { self.lo }
    #[inline(always)] fn to_u32( self ) -> u32 { self.lo as u32 }
    #[inline(always)] fn to_u128( self ) -> u128 { ( ( self.hi as u128 ) << 64 ) | self.lo as u128 }
    #[inline(always)] fn from_i64( value: i64 ) -> Self { serialize_uint128_t::from( value ) }
    #[inline(always)] fn from_u64( value: u64 ) -> Self { serialize_uint128_t::from( value ) }
    #[inline(always)] fn from_u128( value: u128 ) -> Self { serialize_uint128_t { lo: value as u64, hi: ( value >> 64 ) as u64 } }
}

/**
    Compile time map from a 128 bit fixed point storage type to its unsigned counterpart,
    in which the wide codec runs its raw offset math. Both the native and the emulated types
    map to their unsigned partner; two's complement wrap around is exact in both, so the
    codec is representation generic and wide fixed point works on compilers without native
    __int128.
 */

// port: Rust always has native u128, so the wide codec runs its raw offset math in u128 for every storage type,
// native or emulated: FixedPointInteger::to_u128 / from_u128 are the conversions at the boundary. Two's complement
// wrap around is exact either way, so the wire is the same

/**
    Fixed point codec, specialized on storage width.
    The false specialization covers storage of 64 bits or fewer and works entirely in the 64 bit unsigned domain.
    The true specialization covers 128 bit storage. It is representation generic — the raw offset math runs in the storage type's unsigned counterpart via FixedPointUnsigned, and its compile time constants live in the 64 bit domain — so it works with native __int128 storage and with the emulated pair alike, and wide fixed point is available on every platform.
    Splitting on width keeps every shift and every compile time bit count valid for the domain it runs in.
    IMPORTANT: Generally, you don't use this directly. Use the serialize_fixed, read_fixed and write_fixed macros instead.
 */

// port: both specializations are instantiated for every storage type (the dispatch is an `if` on a constant, not
// template selection), so the static asserts of each only bind for the width it covers, and the shifts are wrapping
// so the unselected one stays well defined
pub struct FixedPointSerializer<const WideStorage: bool>;

impl FixedPointSerializer<false>
{
    pub fn Serialize<const IntegerBits: i32, const FractionalBits: i32, const MinUnits: i64, const MaxUnits: i64, S: Stream, Storage: FixedPointInteger>( stream: &mut S, value: &mut Storage ) -> bool
    {
        // the whole unit capacity of the Q format. computed in the unsigned domain so the widest formats (Q64.0 and friends) cannot overflow signed arithmetic
        const
        {
            if Storage::BITS <= 64
            {
                let min_representable_units: i64 = if Storage::is_signed != 0 {
                    0u64.wrapping_sub( 1u64 << ( IntegerBits - 1 ) ) as i64 } else { 0 };
                let max_representable_units: i64 = if Storage::is_signed != 0 {
                    ( ( 1u64 << ( IntegerBits - 1 ) ) - 1 ) as i64 } else {
                    if IntegerBits >= 64 { i64::MAX } else { ( ( 1u64 << ( if IntegerBits < 64 { IntegerBits } else { 0 } ) ) - 1 ) as i64 } };

                assert!( MinUnits >= min_representable_units, "serialize_fixed min bound in whole units does not fit the Q format" );
                assert!( MaxUnits <= max_representable_units, "serialize_fixed max bound in whole units does not fit the Q format" );
            }
        };

        // shift the whole unit bounds into raw fixed point units in the unsigned domain, so negative bounds wrap two's complement instead of invoking undefined behavior.
        // everything below is a compile time constant: the bounds, the range and the bit count all fold, so the call site carries no runtime bit width computation at all.
        let raw_min: u64 = ( MinUnits as u64 ).wrapping_shl( FractionalBits as u32 );
        let raw_max: u64 = ( MaxUnits as u64 ).wrapping_shl( FractionalBits as u32 );
        let raw_range: u64 = raw_max.wrapping_sub( raw_min );

        if MinUnits == MaxUnits
        {
            // degenerate range: the value IS the range, nothing to send (STANDARD.md: min == max costs zero bits, on every storage width).
            // the zero bit field still goes through the stream, as a degenerate ranged integer, because every read consults the failure state before it does anything else: a fixed point field on a stream that has already failed must refuse, exactly as a degenerate serialize_int does. On write and on measure this costs nothing and emits nothing
            let mut degenerate: i32 = 0;
            if !stream.SerializeInteger( &mut degenerate, 0, 0 )
            {
                return false;
            }
            if S::IsWriting
            {
                serialize_assert!( value.to_u64() == raw_min );        // all checking is performed by debug asserts on write
            }
            if S::IsReading
            {
                *value = Storage::from_u64( raw_min );
            }
            return true;
        }

        let bits: i32 = bits_required64_constexpr( raw_min, raw_max );         // BitsRequired64<raw_min, raw_max>::result

        let mut offset: u64 = 0;

        if S::IsWriting
        {
            // subtract in the unsigned domain: raw - raw_min overflows signed arithmetic when the range is wider than 2^63
            offset = value.to_u64().wrapping_sub( raw_min );
            serialize_assert!( offset <= raw_range );        // the value must be within [min,max] whole units. all checking is performed by debug asserts on write
        }

        if bits <= 32
        {
            let mut unsigned_value: u32 = offset as u32;
            if !stream.SerializeBits( &mut unsigned_value, bits )
            {
                return false;
            }
            offset = unsigned_value as u64;
        }
        else
        {
            // low dword first, then the high remainder: same convention as serialize_bits and serialize_int64
            let mut low_half: u32 = ( offset & 0xFFFFFFFF ) as u32;
            let mut high_half: u32 = ( offset >> 32 ) as u32;
            if !stream.SerializeBits( &mut low_half, 32 )
            {
                return false;
            }
            if !stream.SerializeBits( &mut high_half, bits - 32 )
            {
                return false;
            }
            offset = ( ( high_half as u64 ) << 32 ) | low_half as u64;
        }

        if S::IsReading
        {
            // reject raw values outside [raw_min,raw_max] smuggled into the bit headroom. reject, never clamp
            if offset > raw_range
            {
                return serialize_fail( stream );
            }
            // reconstruct in the unsigned domain, then convert: wraps two's complement for signed storage
            *value = Storage::from_u64( raw_min.wrapping_add( offset ) );
        }

        true
    }
}

impl FixedPointSerializer<true>
{
    pub fn Serialize<const IntegerBits: i32, const FractionalBits: i32, const MinUnits: i64, const MaxUnits: i64, S: Stream, Storage: FixedPointInteger>( stream: &mut S, value: &mut Storage ) -> bool
    {
        // the unsigned counterpart of the storage type. all raw offset math runs in this type,
        // where wrap around is exact two's complement in both representations, so this codec is
        // representation generic and needs no compiler guard at all.
        // port: Unsigned is u128 for every storage type (see FixedPointUnsigned above)

        // the whole unit capacity of the Q format, in the 64 bit compile time domain: with 65
        // or more integer bits the capacity covers any int64 bound, and below that the
        // capacity math fits 64 bits. the inner clamps keep the unselected ternary arms free
        // of invalid shift counts.
        const
        {
            if Storage::BITS > 64
            {
                let min_representable_units: i64 = if Storage::is_signed != 0 {
                    if IntegerBits >= 65 { i64::MIN } else { 0u64.wrapping_sub( 1u64 << ( ( if IntegerBits <= 64 { IntegerBits } else { 1 } ) - 1 ) ) as i64 } } else { 0 };
                let max_representable_units: i64 = if Storage::is_signed != 0 {
                    if IntegerBits >= 64 { i64::MAX } else { ( ( 1u64 << ( ( if IntegerBits < 64 { IntegerBits } else { 1 } ) - 1 ) ) - 1 ) as i64 } } else {
                    if IntegerBits >= 64 { i64::MAX } else { ( ( 1u64 << ( if IntegerBits < 64 { IntegerBits } else { 0 } ) ) - 1 ) as i64 } };

                assert!( MinUnits >= min_representable_units, "serialize_fixed min bound in whole units does not fit the Q format" );
                assert!( MaxUnits <= max_representable_units, "serialize_fixed max bound in whole units does not fit the Q format" );
            }
        };

        // shift the whole unit bounds into raw fixed point units in the unsigned 128 bit domain, so negative bounds wrap two's complement instead of invoking undefined behavior.
        // the storage constructor sign extends the int64 bounds for signed storage. everything below folds: the bounds, the range, the bit count and the group structure.
        let raw_min: u128 = Storage::from_i64( MinUnits ).to_u128().wrapping_shl( FractionalBits as u32 );
        let raw_max: u128 = Storage::from_i64( MaxUnits ).to_u128().wrapping_shl( FractionalBits as u32 );
        let raw_range: u128 = raw_max.wrapping_sub( raw_min );

        if MinUnits == MaxUnits
        {
            // degenerate range: the value IS the range, nothing to send. the wide path must agree
            // with the narrow path here — FractionalBits of zeros is NOT a degenerate encoding
            // (STANDARD.md: min == max costs zero bits, on every storage width) — and it must
            // consult the failure state through the stream for the same reason the narrow path does
            let mut degenerate: i32 = 0;
            if !stream.SerializeInteger( &mut degenerate, 0, 0 )
            {
                return false;
            }
            if S::IsWriting
            {
                serialize_assert!( value.to_u128() == raw_min );       // all checking is performed by debug asserts on write
            }
            if S::IsReading
            {
                *value = Storage::from_u128( raw_min );
            }
            return true;
        }

        // the wire cost, computed in the 64 bit compile time domain: the range in whole units
        // is exact in a uint64, and shifting it left by FractionalBits adds exactly
        // FractionalBits to its bit length.
        let bits: i32 = bits_required64_constexpr( MinUnits as u64, MaxUnits as u64 ) + FractionalBits;       // BitsRequired64< uint64_t( MinUnits ), uint64_t( MaxUnits ) >::result + FractionalBits

        let mut offset: u128 = 0;

        if S::IsWriting
        {
            // subtract in the unsigned domain: raw - raw_min overflows signed arithmetic when the range is wider than 2^127
            offset = value.to_u128().wrapping_sub( raw_min );
            serialize_assert!( offset <= raw_range );        // the value must be within [min,max] whole units. all checking is performed by debug asserts on write
        }

        // the offset is written in 32 bit groups, least significant group first: the same convention as serialize_bits.
        // the group structure is selected at compile time, so each SerializeBits call receives a constant bit count.
        let mut group0: u32 = 0;
        let mut group1: u32 = 0;
        let mut group2: u32 = 0;
        let mut group3: u32 = 0;

        if S::IsWriting
        {
            group0 = ( ( offset       ) as u64 & 0xFFFFFFFF ) as u32;
            group1 = ( ( offset >> 32 ) as u64 & 0xFFFFFFFF ) as u32;
            group2 = ( ( offset >> 64 ) as u64 & 0xFFFFFFFF ) as u32;
            group3 = ( ( offset >> 96 ) as u64 & 0xFFFFFFFF ) as u32;
        }

        if bits <= 32
        {
            if !stream.SerializeBits( &mut group0, bits )
            {
                return false;
            }
        }
        else if bits <= 64
        {
            if !stream.SerializeBits( &mut group0, 32 )
            {
                return false;
            }
            if !stream.SerializeBits( &mut group1, bits - 32 )
            {
                return false;
            }
        }
        else if bits <= 96
        {
            if !stream.SerializeBits( &mut group0, 32 )
            {
                return false;
            }
            if !stream.SerializeBits( &mut group1, 32 )
            {
                return false;
            }
            if !stream.SerializeBits( &mut group2, bits - 64 )
            {
                return false;
            }
        }
        else
        {
            if !stream.SerializeBits( &mut group0, 32 )
            {
                return false;
            }
            if !stream.SerializeBits( &mut group1, 32 )
            {
                return false;
            }
            if !stream.SerializeBits( &mut group2, 32 )
            {
                return false;
            }
            if !stream.SerializeBits( &mut group3, bits - 96 )
            {
                return false;
            }
        }

        if S::IsReading
        {
            offset = ( ( group3 as u128 ) << 96 ) | ( ( group2 as u128 ) << 64 ) | ( ( group1 as u128 ) << 32 ) | group0 as u128;

            // reject raw values outside [raw_min,raw_max] smuggled into the bit headroom. reject, never clamp
            if offset > raw_range
            {
                return serialize_fail( stream );
            }
            // reconstruct in the unsigned domain, then convert: wraps two's complement for signed storage
            *value = Storage::from_u128( raw_min.wrapping_add( offset ) );
        }

        true
    }
}

pub fn serialize_fixed_internal<const IntegerBits: i32, const FractionalBits: i32, const MinUnits: i64, const MaxUnits: i64, S: Stream, Storage: FixedPointInteger>( stream: &mut S, value: &mut Storage ) -> bool
{
    serialize_static_assert!( Storage::is_integer == 1, "serialize_fixed storage must be an integer type" );
    serialize_static_assert!( IntegerBits >= 1, "serialize_fixed needs at least one integer bit. the sign bit counts for signed storage" );
    serialize_static_assert!( FractionalBits >= 0, "serialize_fixed fractional bits can't be negative" );
    serialize_static_assert!( IntegerBits + FractionalBits == Storage::BITS, "serialize_fixed integer bits plus fractional bits must equal the number of bits in the storage type" );
    serialize_static_assert!( MinUnits <= MaxUnits, "serialize_fixed min must not exceed max" );

    if Storage::BITS > 64
    {
        FixedPointSerializer::<true>::Serialize::<IntegerBits, FractionalBits, MinUnits, MaxUnits, S, Storage>( stream, value )
    }
    else
    {
        FixedPointSerializer::<false>::Serialize::<IntegerBits, FractionalBits, MinUnits, MaxUnits, S, Storage>( stream, value )
    }
}

/**
    Serialize a fixed point value to the stream (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    The Q format and the bounds are compile time constants: integer_bits plus fraction_bits must equal the number of bits in the storage type, with the sign bit counting towards integer_bits for signed storage. For example, Q48.16 in an int64_t is ( 48, 16 ) and Q112.16 in a serialize::int128_t is ( 112, 16 ). Any integer storage type works, including 128 bit storage.
    The bounds are whole units and must be constant expressions: a runtime bound fails to compile, and bounds that don't fit the Q format fail with a static assert. The value is serialized as an offset from min in the minimal number of bits for the range — a constant of the call site — and the round trip is exact: fixed point values are integers underneath, so unlike compressed floats there is no quantization error and results are identical across platforms.
    A degenerate range where min == max is legal and costs zero bits on every storage width: nothing is written, and the reader recovers the value from the range alone — the raw value min << fraction_bits.
    For storage of 64 bits or fewer the wire format is byte identical to serialize_int64 of the raw value over the raw bounds.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The fixed point value to serialize, in [min,max] whole units. The storage type sets the width of the Q format.
    @param integer_bits The number of integer bits in the Q format, including the sign bit for signed storage. Compile time constant.
    @param fraction_bits The number of fractional bits in the Q format. Compile time constant.
    @param min The minimum value in whole units. Compile time constant.
    @param max The maximum value in whole units. Compile time constant.
 */

#[macro_export]
macro_rules! serialize_fixed {
    ( $stream:expr, $value:expr, $integer_bits:expr, $fraction_bits:expr, $min:expr, $max:expr ) => {
        {
            if !$crate::serialize::serialize_fixed_internal::<{ $integer_bits }, { $fraction_bits }, { $min }, { $max }, _, _>( &mut *$stream, &mut $value )
            {
                return false;
            }
        }
    };
}

// read macros corresponding to each serialize_*. useful when you want separate read and write functions.

#[macro_export]
macro_rules! read_bits {
    ( $stream:expr, $value:expr, $bits:expr ) => {
        {
            $crate::serialize_assert!( ( $bits ) > 0 );
            $crate::serialize_assert!( ( $bits ) <= 64 );
            if ( $bits ) <= 32
            {
                let mut uint32_value: u32 = 0;
                if !$crate::serialize::Stream::SerializeBits( &mut *$stream, &mut uint32_value, ( $bits ) as i32 )
                {
                    return false;
                }
                $value = uint32_value as _;
            }
            else
            {
                let mut lo: u32 = 0;
                let mut hi: u32 = 0;
                if !$crate::serialize::Stream::SerializeBits( &mut *$stream, &mut lo, 32 )
                {
                    return false;
                }
                if !$crate::serialize::Stream::SerializeBits( &mut *$stream, &mut hi, ( ( $bits ) - 32 ) as i32 )
                {
                    return false;
                }
                $value = ( ( ( hi as u64 ) << 32 ) | lo as u64 ) as _;
            }
        }
    };
}

#[macro_export]
macro_rules! read_int {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( $min ) as i64 <= ( $max ) as i64 );
            let mut int32_value: i32 = 0;
            if !$crate::serialize::Stream::SerializeInteger( &mut *$stream, &mut int32_value, ( $min ) as i32, ( $max ) as i32 )
            {
                return false;
            }
            $value = int32_value as _;
            $crate::serialize_assert!( ( $value ) as i64 == int32_value as i64 );
        }
    };
}

#[macro_export]
macro_rules! read_int64 {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( $min ) as i64 <= ( $max ) as i64 );
            let mut int64_value: i64 = 0;
            if !$crate::serialize::Stream::SerializeInteger64( &mut *$stream, &mut int64_value, ( $min ) as i64, ( $max ) as i64 )
            {
                return false;
            }
            $value = int64_value as _;
            $crate::serialize_assert!( ( $value ) as i64 == int64_value );
        }
    };
}

#[macro_export]
macro_rules! read_int128 {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( ( $min ) as $crate::serialize::int128_t ) <= ( ( $max ) as $crate::serialize::int128_t ) );
            let mut int128_value: $crate::serialize::int128_t = 0;
            if !$crate::serialize::Stream::SerializeInteger128( &mut *$stream, &mut int128_value, ( $min ) as $crate::serialize::int128_t, ( $max ) as $crate::serialize::int128_t )
            {
                return false;
            }
            $value = int128_value as _;
            $crate::serialize_assert!( ( ( $value ) as $crate::serialize::int128_t ) == int128_value );
        }
    };
}

#[macro_export]
macro_rules! read_fixed {
    ( $stream:expr, $value:expr, $integer_bits:expr, $fraction_bits:expr, $min:expr, $max:expr ) => {
        {
            if !$crate::serialize::serialize_fixed_internal::<{ $integer_bits }, { $fraction_bits }, { $min }, { $max }, _, _>( &mut *$stream, &mut $value )
            {
                return false;
            }
        }
    };
}

// port: read_bool reads a bool place (upstream's read_bits assigns the uint32_t to it, which C++ converts)
#[macro_export]
macro_rules! read_bool {
    ( $stream:expr, $value:expr ) => {
        {
            let mut uint32_bool_value: u32 = 0;
            $crate::read_bits!( $stream, uint32_bool_value, 1 );
            $value = uint32_bool_value != 0;
        }
    };
}

#[macro_export]
macro_rules! read_uint8 { ( $stream:expr, $value:expr ) => { $crate::read_bits!( $stream, $value, 8 ) }; }
#[macro_export]
macro_rules! read_uint16 { ( $stream:expr, $value:expr ) => { $crate::read_bits!( $stream, $value, 16 ) }; }
#[macro_export]
macro_rules! read_uint32 { ( $stream:expr, $value:expr ) => { $crate::read_bits!( $stream, $value, 32 ) }; }
#[macro_export]
macro_rules! read_uint64 { ( $stream:expr, $value:expr ) => { $crate::read_bits!( $stream, $value, 64 ) }; }

#[macro_export]
macro_rules! read_uint128 {
    ( $stream:expr, $value:expr ) => {
        {
            if !$crate::serialize::serialize_uint128_internal( &mut *$stream, &mut $value )
            {
                return false;
            }
        }
    };
}

#[macro_export]
macro_rules! read_float { ( $( $arguments:tt )* ) => { $crate::serialize_float!( $( $arguments )* ) }; }
#[macro_export]
macro_rules! read_double { ( $( $arguments:tt )* ) => { $crate::serialize_double!( $( $arguments )* ) }; }

#[macro_export]
macro_rules! read_bytes {
    ( $stream:expr, $data:expr, $bytes:expr ) => {
        {
            let data_ptr: &mut [u8] = &mut ( $data )[..];
            if !$crate::serialize::Stream::SerializeBytes( &mut *$stream, data_ptr, ( $bytes ) as i64 )
            {
                return false;
            }
        }
    };
}

#[macro_export]
macro_rules! read_string {
    ( $stream:expr, $string:expr, $buffer_size:expr ) => {
        {
            let string_ptr: &mut [u8] = &mut ( $string )[..];
            if !$crate::serialize::serialize_string_internal( &mut *$stream, string_ptr, ( $buffer_size ) as i32 )
            {
                return false;
            }
        }
    };
}

#[macro_export]
macro_rules! read_wstring {
    ( $stream:expr, $string:expr, $buffer_size:expr ) => {
        {
            let wstring_ptr: &mut [$crate::serialize::wchar_t] = &mut ( $string )[..];
            if !$crate::serialize::serialize_wstring_internal( &mut *$stream, wstring_ptr, ( $buffer_size ) as i32 )
            {
                return false;
            }
        }
    };
}

#[macro_export]
macro_rules! read_align { ( $( $arguments:tt )* ) => { $crate::serialize_align!( $( $arguments )* ) }; }
#[macro_export]
macro_rules! read_object { ( $( $arguments:tt )* ) => { $crate::serialize_object!( $( $arguments )* ) }; }
#[macro_export]
macro_rules! read_int_relative { ( $( $arguments:tt )* ) => { $crate::serialize_int_relative!( $( $arguments )* ) }; }

// write macros corresponding to each serialize_*. useful when you want separate read and write functions.

/**
    Write bits to the stream, the write-only companion to serialize_bits.
    Carries the same debug assertions: the width is in [1,64], and the value fits in that many bits, checked on the caller's value before it is narrowed to the group width.
    @param stream The stream object. Must be a write stream.
    @param value The unsigned integer value to write. Must be in [0,(1\<\<bits)-1].
    @param bits The number of bits to write in [1,64].
 */

#[macro_export]
macro_rules! write_bits {
    ( $stream:expr, $value:expr, $bits:expr ) => {
        {
            $crate::serialize_assert!( ( $bits ) > 0 );
            $crate::serialize_assert!( ( $bits ) <= 64 );
            $crate::serialize_assert!( $crate::serialize::value_fits_in_bits( $value, ( $bits ) as i32 ) );
            let uint64_value: u64 = ( $value ) as u64;
            if ( $bits ) <= 32
            {
                let mut uint32_value: u32 = uint64_value as u32;
                $crate::serialize::Stream::SerializeBits( &mut *$stream, &mut uint32_value, ( $bits ) as i32 );
            }
            else
            {
                let mut lo: u32 = ( uint64_value & 0xFFFFFFFF ) as u32;
                let mut hi: u32 = ( uint64_value >> 32 ) as u32;
                $crate::serialize::Stream::SerializeBits( &mut *$stream, &mut lo, 32 );
                $crate::serialize::Stream::SerializeBits( &mut *$stream, &mut hi, ( ( $bits ) - 32 ) as i32 );
            }
        }
    };
}

#[macro_export]
macro_rules! write_int {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( $min ) as i64 <= ( $max ) as i64 );
            $crate::serialize_assert!( ( $value ) as i64 >= ( $min ) as i64 );
            $crate::serialize_assert!( ( $value ) as i64 <= ( $max ) as i64 );
            let mut int32_value: i32 = ( $value ) as i32;
            $crate::serialize::Stream::SerializeInteger( &mut *$stream, &mut int32_value, ( $min ) as i32, ( $max ) as i32 );
        }
    };
}

#[macro_export]
macro_rules! write_int64 {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( $min ) as i64 <= ( $max ) as i64 );
            $crate::serialize_assert!( ( $value ) as i64 >= ( $min ) as i64 );
            $crate::serialize_assert!( ( $value ) as i64 <= ( $max ) as i64 );
            let mut int64_value: i64 = ( $value ) as i64;
            $crate::serialize::Stream::SerializeInteger64( &mut *$stream, &mut int64_value, ( $min ) as i64, ( $max ) as i64 );
        }
    };
}

#[macro_export]
macro_rules! write_int128 {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize_assert!( ( ( $min ) as $crate::serialize::int128_t ) <= ( ( $max ) as $crate::serialize::int128_t ) );
            $crate::serialize_assert!( ( ( $value ) as $crate::serialize::int128_t ) >= ( ( $min ) as $crate::serialize::int128_t ) );
            $crate::serialize_assert!( ( ( $value ) as $crate::serialize::int128_t ) <= ( ( $max ) as $crate::serialize::int128_t ) );
            let mut int128_value: $crate::serialize::int128_t = ( $value ) as $crate::serialize::int128_t;
            $crate::serialize::Stream::SerializeInteger128( &mut *$stream, &mut int128_value, ( $min ) as $crate::serialize::int128_t, ( $max ) as $crate::serialize::int128_t );
        }
    };
}

#[macro_export]
macro_rules! write_fixed {
    ( $stream:expr, $value:expr, $integer_bits:expr, $fraction_bits:expr, $min:expr, $max:expr ) => {
        {
            $crate::serialize::serialize_fixed_internal::<{ $integer_bits }, { $fraction_bits }, { $min }, { $max }, _, _>( &mut *$stream, &mut $value );
        }
    };
}

// port: write_bool takes a bool (upstream's write_bits converts it to uint64_t)
#[macro_export]
macro_rules! write_bool { ( $stream:expr, $value:expr ) => { $crate::write_bits!( $stream, ( if $value { 1u32 } else { 0u32 } ), 1 ) }; }
#[macro_export]
macro_rules! write_uint8 { ( $stream:expr, $value:expr ) => { $crate::write_bits!( $stream, $value, 8 ) }; }
#[macro_export]
macro_rules! write_uint16 { ( $stream:expr, $value:expr ) => { $crate::write_bits!( $stream, $value, 16 ) }; }
#[macro_export]
macro_rules! write_uint32 { ( $stream:expr, $value:expr ) => { $crate::write_bits!( $stream, $value, 32 ) }; }
#[macro_export]
macro_rules! write_uint64 { ( $stream:expr, $value:expr ) => { $crate::write_bits!( $stream, $value, 64 ) }; }

// port: value is a native integer (converted with `as` to u128)
#[macro_export]
macro_rules! write_uint128 {
    ( $stream:expr, $value:expr ) => {
        {
            let mut uint128_value: $crate::serialize::uint128_t = ( $value ) as $crate::serialize::uint128_t;
            $crate::serialize::serialize_uint128_internal( &mut *$stream, &mut uint128_value );
        }
    };
}

#[macro_export]
macro_rules! write_float {
    ( $stream:expr, $value:expr ) => {
        {
            let float_value: f32 = ( $value ) as f32;
            let mut int_value: u32 = float_value.to_bits();
            $crate::serialize::Stream::SerializeBits( &mut *$stream, &mut int_value, 32 );
        }
    };
}

#[macro_export]
macro_rules! write_double {
    ( $stream:expr, $value:expr ) => {
        {
            let double_value: f64 = ( $value ) as f64;
            let int64_value: u64 = double_value.to_bits();
            $crate::write_bits!( $stream, int64_value, 64 );
        }
    };
}

// port: data is anything that indexes to [u8]
#[macro_export]
macro_rules! write_bytes {
    ( $stream:expr, $data:expr, $bytes:expr ) => {
        {
            let data_ptr: &[u8] = &( $data )[..];
            $crate::serialize::Stream::SerializeBytesConst( &mut *$stream, data_ptr, ( $bytes ) as i64 );
        }
    };
}

#[macro_export]
macro_rules! write_string {
    ( $stream:expr, $string:expr, $buffer_size:expr ) => {
        {
            let string_ptr: &[u8] = &( $string )[..];
            // the length assertion runs on the size_t strlen returns, before it narrows
            // to int. See serialize::serialize_string_internal
            let string_length: usize = $crate::serialize::serialize_strlen( string_ptr );
            $crate::serialize_assert!( ( $buffer_size ) > 0 );
            $crate::serialize_assert!( string_length < ( $buffer_size ) as usize );
            let length: i32 = string_length as i32;
            // the writer's contract, debug only. See serialize_string_is_valid_utf8
            $crate::serialize_assert!( $crate::serialize::serialize_string_is_valid_utf8( string_ptr, length ) );
            $crate::write_int!( $stream, length, 0, ( $buffer_size ) - 1 );
            $crate::write_bytes!( $stream, string_ptr, length );
        }
    };
}

#[macro_export]
macro_rules! write_wstring {
    ( $stream:expr, $string:expr, $buffer_size:expr ) => {
        {
            let wstring_ptr: &[$crate::serialize::wchar_t] = &( $string )[..];
            // the writer's contract, debug only. See serialize_wstring_is_valid_utf16
            $crate::serialize_assert!( $crate::serialize::serialize_wstring_is_valid_utf16( wstring_ptr ) );
            let wstring_units: i32 = $crate::serialize::serialize_wstring_unit_count( wstring_ptr );
            $crate::serialize_assert!( wstring_units < ( $buffer_size ) as i32 );
            $crate::write_int!( $stream, wstring_units, 0, ( $buffer_size ) - 1 );
            let mut i: usize = 0;
            while i < wstring_ptr.len() && wstring_ptr[i] != 0
            {
                let wstring_character: u32 = wstring_ptr[i] as u32;
                if wstring_character >= 0x10000 && wstring_character <= 0x10FFFF
                {
                    // astral: split into the surrogate pair at the boundary, matching
                    // serialize_wstring_internal byte for byte
                    $crate::write_bits!( $stream, 0xD800u32 + ( ( wstring_character - 0x10000 ) >> 10 ), 32 );
                    $crate::write_bits!( $stream, 0xDC00u32 + ( ( wstring_character - 0x10000 ) & 0x3FF ), 32 );
                }
                else
                {
                    $crate::write_bits!( $stream, wstring_character, 32 );
                }
                i += 1;
            }
        }
    };
}

#[macro_export]
macro_rules! write_align {
    ( $stream:expr ) => {
        {
            $crate::serialize::Stream::SerializeAlign( &mut *$stream );
        }
    };
}

#[macro_export]
macro_rules! write_object {
    ( $stream:expr, $object:expr ) => {
        {
            ( $object ).Serialize( &mut *$stream );
        }
    };
}

/**
    Write an integer relative to a previous one, the write-only companion to serialize_int_relative.
    Carries the same debug assertion on the domain, checked on the caller's value before it is narrowed to int: an assertion inside the helper sees a value already truncated, and 2^32 + 5 truncates to 5, which is in the domain.
    @param stream The stream object. Must be a write stream.
    @param previous The previous integer value, in [0,2^31-1].
    @param current The current integer value, in [0,2^31-1] and strictly greater than previous.
 */

// port: previous converts to int with `as`, as the C++ template deduction requires it to match int current_value
#[macro_export]
macro_rules! write_int_relative {
    ( $stream:expr, $previous:expr, $current:expr ) => {
        {
            $crate::serialize_assert!( $crate::serialize::value_in_int_relative_domain( $current ) );
            let mut current_value: i32 = ( $current ) as i32;
            $crate::serialize::serialize_int_relative_internal( &mut *$stream, ( $previous ) as i32, &mut current_value );
        }
    };
}

// The compile time parameter surface below uses C++14 relaxed constexpr, and consumers vendor
// this header into pre-C++11 builds. The surface is additive and aimed at generated code, so
// language modes older than C++14 simply do not get it.
// port: always available (const generics and const fn)
pub const SERIALIZE_HAS_COMPILE_TIME_SURFACE: i32 = 1;

// ------------------------------------------------------------------------------------------
//
//      Compile time parameter surface (experimental, for generated code)
//
//      When serialize calls are generated from a schema, min/max/bits are known at code
//      generation time. The templates below move them into template argument position, so
//      the bit count is a compile time constant: no runtime bits_required call, no runtime
//      min/max parameter plumbing, and the 32/64 bit split resolves on a constant condition.
//      The wire bytes are identical to the runtime forms given identical inputs, so a code
//      generator can switch between forms without a wire change.
//
//      Humans keep the serialize_* macros above. Generated code calls these templates
//      directly and emits its own `if ( !... ) return false;`, or uses the thin
//      serialize_*_compile_time macro wrappers below.
//
// ------------------------------------------------------------------------------------------

/**
    Calculates the number of bits required to serialize an integer in range [min,max], as a constant expression.
    The constexpr companion to serialize::bits_required and serialize::bits_required64, for use in template argument position.
    @param min The minimum value, converted to the unsigned domain (sign extended for signed ranges).
    @param max The maximum value, converted to the unsigned domain (sign extended for signed ranges).
    @returns The number of bits required to serialize the integer in [0,64].
 */

pub const fn bits_required64_constexpr( min: u64, max: u64 ) -> i32
{
    // subtract in the unsigned domain: max - min overflows signed arithmetic when the range is wider than 2^63.
    // sign extended int32 bounds wrap to the same difference, so this one function covers both integer domains.
    let mut bits: i32 = 0;
    let mut diff: u64 = max.wrapping_sub( min );
    while diff != 0
    {
        bits += 1;
        diff >>= 1;
    }
    bits
}

/**
    Serialize an integer with compile time bounds (read/write/measure).
    The compile time companion to WriteStream::SerializeInteger and ReadStream::SerializeInteger: the bit count is a constant, so there is no runtime bits_required call and no min/max parameter traffic.
    Wire bytes are identical to the runtime form given identical inputs.
    On write, the value is checked by debug asserts only, matching the runtime form. On read, the value off the wire is validated against the constant bounds and the function returns false on out of range data.
    @tparam Min The minimum value. Must be less than Max (enforced at compile time).
    @tparam Max The maximum value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The integer value in [Min,Max]. Written on write/measure, filled in on read.
    @returns True if the serialize succeeded, false if the read data is truncated or out of range.
 */

pub fn SerializeIntConst<const Min: i32, const Max: i32, S: Stream>( stream: &mut S, value: &mut i32 ) -> bool
{
    serialize_static_assert!( Min < Max, "serialize: min must be less than max" );
    let bits: i32 = const { bits_required64_constexpr( Min as i64 as u64, Max as i64 as u64 ) };
    let mut unsigned_value: u32 = 0;
    if S::IsWriting
    {
        serialize_assert!( *value >= Min );
        serialize_assert!( *value <= Max );
        // subtract in the unsigned domain: value - min overflows signed arithmetic when the range is wider than 2^31
        unsigned_value = ( *value as u32 ).wrapping_sub( Min as u32 );
    }
    if !stream.SerializeBits( &mut unsigned_value, bits )
    {
        return false;
    }
    if S::IsReading
    {
        if unsigned_value > ( Max as u32 ).wrapping_sub( Min as u32 )
        {
            return serialize_fail( stream );
        }
        // add in the unsigned domain: unsigned_value + min overflows signed arithmetic when the range is wider than 2^31
        *value = unsigned_value.wrapping_add( Min as u32 ) as i32;
    }
    true
}

/**
    Serialize a 64 bit integer with compile time bounds (read/write/measure).
    The compile time companion to WriteStream::SerializeInteger64 and ReadStream::SerializeInteger64: the bit count is a constant, and the one dword vs two dword split resolves on a constant condition, so the dead branch folds.
    Wire bytes are identical to the runtime form given identical inputs: low dword first, then the high remainder, same convention as serialize_bits and serialize_uint64.
    On write, the value is checked by debug asserts only, matching the runtime form. On read, the value off the wire is validated against the constant bounds and the function returns false on out of range data.
    @tparam Min The minimum value. Must be less than Max (enforced at compile time).
    @tparam Max The maximum value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The integer value in [Min,Max]. Written on write/measure, filled in on read.
    @returns True if the serialize succeeded, false if the read data is truncated or out of range.
 */

pub fn SerializeInt64Const<const Min: i64, const Max: i64, S: Stream>( stream: &mut S, value: &mut i64 ) -> bool
{
    serialize_static_assert!( Min < Max, "serialize: min must be less than max" );
    let bits: i32 = const { bits_required64_constexpr( Min as u64, Max as u64 ) };
    let mut unsigned_value: u64 = 0;
    if S::IsWriting
    {
        serialize_assert!( *value >= Min );
        serialize_assert!( *value <= Max );
        // subtract in the unsigned domain: value - min overflows signed arithmetic when the range is wider than 2^63
        unsigned_value = ( *value as u64 ).wrapping_sub( Min as u64 );
    }
    if bits <= 32       // constant condition: the dead branch folds at compile time
    {
        let mut unsigned_value32: u32 = unsigned_value as u32;
        if !stream.SerializeBits( &mut unsigned_value32, bits )
        {
            return false;
        }
        if S::IsReading
        {
            unsigned_value = unsigned_value32 as u64;
        }
    }
    else
    {
        // low dword first, then the high remainder: same convention as serialize_bits and serialize_uint64
        let mut lo: u32 = ( unsigned_value & 0xFFFFFFFF ) as u32;
        let mut hi: u32 = ( unsigned_value >> 32 ) as u32;
        if !stream.SerializeBits( &mut lo, 32 )
        {
            return false;
        }
        if !stream.SerializeBits( &mut hi, bits - 32 )
        {
            return false;
        }
        if S::IsReading
        {
            unsigned_value = ( ( hi as u64 ) << 32 ) | lo as u64;
        }
    }
    if S::IsReading
    {
        if unsigned_value > ( Max as u64 ).wrapping_sub( Min as u64 )
        {
            return serialize_fail( stream );
        }
        // add in the unsigned domain: unsigned_value + min overflows signed arithmetic when the range is wider than 2^63
        *value = unsigned_value.wrapping_add( Min as u64 ) as i64;
    }
    true
}

/**
    Serialize a compile time number of bits (read/write/measure).
    The compile time companion to WriteStream::SerializeBits and ReadStream::SerializeBits for widths up to 32: the width is a constant, so there is no runtime bits parameter traffic.
    Wire bytes are identical to the runtime form given identical inputs.
    On write, the value is checked by debug asserts only, matching the runtime form (it must be in [0,(1<<Bits)-1]).
    @tparam Bits The number of bits to serialize, in [1,32] (enforced at compile time).
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned integer value. Written on write/measure, filled in on read.
    @returns True if the serialize succeeded, false if the read data is truncated.
 */

pub fn SerializeBitsConst<const Bits: i32, S: Stream>( stream: &mut S, value: &mut u32 ) -> bool
{
    serialize_static_assert!( Bits > 0, "serialize: bits must be greater than zero" );
    serialize_static_assert!( Bits <= 32, "serialize: bits must be less than or equal to 32. use SerializeBits64Const for wider values" );
    stream.SerializeBits( value, Bits )
}

/**
    Serialize a compile time number of bits from a 64 bit value (read/write/measure).
    The compile time companion to the serialize_bits macro for widths up to 64: the width is a constant, and the one dword vs two dword split resolves on a constant condition, so the dead branch folds.
    Wire bytes are identical to the runtime form given identical inputs: low dword first, then the high remainder.
    On write, the value is checked by debug asserts only, matching the runtime form (it must be in [0,(1<<Bits)-1]).
    @tparam Bits The number of bits to serialize, in [1,64] (enforced at compile time).
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned 64 bit integer value. Written on write/measure, filled in on read.
    @returns True if the serialize succeeded, false if the read data is truncated.
 */

pub fn SerializeBits64Const<const Bits: i32, S: Stream>( stream: &mut S, value: &mut u64 ) -> bool
{
    serialize_static_assert!( Bits > 0, "serialize: bits must be greater than zero" );
    serialize_static_assert!( Bits <= 64, "serialize: bits must be less than or equal to 64" );
    if Bits <= 32       // constant condition: the dead branch folds at compile time
    {
        let mut value32: u32 = *value as u32;
        if !stream.SerializeBits( &mut value32, Bits )
        {
            return false;
        }
        if S::IsReading
        {
            *value = value32 as u64;
        }
    }
    else
    {
        // low dword first, then the high remainder: same convention as serialize_bits and serialize_uint64
        let mut lo: u32 = ( *value & 0xFFFFFFFF ) as u32;
        let mut hi: u32 = ( *value >> 32 ) as u32;
        if !stream.SerializeBits( &mut lo, 32 )
        {
            return false;
        }
        if !stream.SerializeBits( &mut hi, Bits - 32 )
        {
            return false;
        }
        if S::IsReading
        {
            *value = ( ( hi as u64 ) << 32 ) | lo as u64;
        }
    }
    true
}

/**
    Serialize integer value with compile time bounds (read/write/measure).
    The compile time companion to serialize_int. min and max are expanded into template argument position, so they must be constant expressions: a runtime value fails to compile, deliberately.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The integer value to serialize in [min,max].
    @param min The minimum value. Must be a constant expression.
    @param max The maximum value. Must be a constant expression.
 */

#[macro_export]
macro_rules! serialize_int_compile_time {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            let mut int32_value: i32 = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                $crate::serialize_assert!( ( $value ) as i64 >= ( $min ) as i64 );
                $crate::serialize_assert!( ( $value ) as i64 <= ( $max ) as i64 );
                int32_value = ( $value ) as i32;
            }
            if !$crate::serialize::SerializeIntConst::<{ $min }, { $max }, _>( &mut *$stream, &mut int32_value )
            {
                return false;
            }
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = int32_value as _;
            }
        }
    };
}

/**
    Serialize a 64 bit integer value with compile time bounds (read/write/measure).
    The compile time companion to serialize_int64. min and max are expanded into template argument position, so they must be constant expressions: a runtime value fails to compile, deliberately.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The 64 bit integer value to serialize in [min,max].
    @param min The minimum value. Must be a constant expression.
    @param max The maximum value. Must be a constant expression.
 */

#[macro_export]
macro_rules! serialize_int64_compile_time {
    ( $stream:expr, $value:expr, $min:expr, $max:expr ) => {
        {
            let mut int64_value: i64 = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                int64_value = ( $value ) as i64;
            }
            if !$crate::serialize::SerializeInt64Const::<{ $min }, { $max }, _>( &mut *$stream, &mut int64_value )
            {
                return false;
            }
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = int64_value as _;
            }
        }
    };
}

/**
    Serialize a compile time number of bits to the stream (read/write/measure).
    The compile time companion to serialize_bits for widths up to 32. bits is expanded into template argument position, so it must be a constant expression: a runtime value fails to compile, deliberately.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned integer value to serialize.
    @param bits The number of bits to serialize in [1,32]. Must be a constant expression.
 */

#[macro_export]
macro_rules! serialize_bits_compile_time {
    ( $stream:expr, $value:expr, $bits:expr ) => {
        {
            let mut uint32_value: u32 = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                $crate::serialize_assert!( $crate::serialize::value_fits_in_bits( $value, ( $bits ) as i32 ) );
                uint32_value = ( $value ) as u32;
            }
            if !$crate::serialize::SerializeBitsConst::<{ $bits }, _>( &mut *$stream, &mut uint32_value )
            {
                return false;
            }
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = uint32_value as _;
            }
        }
    };
}

/**
    Serialize a compile time number of bits from a 64 bit value to the stream (read/write/measure).
    The compile time companion to serialize_bits for widths up to 64. bits is expanded into template argument position, so it must be a constant expression: a runtime value fails to compile, deliberately.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The unsigned 64 bit integer value to serialize.
    @param bits The number of bits to serialize in [1,64]. Must be a constant expression.
 */

#[macro_export]
macro_rules! serialize_bits64_compile_time {
    ( $stream:expr, $value:expr, $bits:expr ) => {
        {
            let mut uint64_value: u64 = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                $crate::serialize_assert!( $crate::serialize::value_fits_in_bits( $value, ( $bits ) as i32 ) );
                uint64_value = ( $value ) as u64;
            }
            if !$crate::serialize::SerializeBits64Const::<{ $bits }, _>( &mut *$stream, &mut uint64_value )
            {
                return false;
            }
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = uint64_value as _;
            }
        }
    };
}

/**
    Serialize a boolean value to the stream through the compile time surface (read/write/measure).
    The compile time companion to serialize_bool: one bit, width resolved at compile time.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param value The boolean value to serialize.
 */

#[macro_export]
macro_rules! serialize_bool_compile_time {
    ( $stream:expr, $value:expr ) => {
        {
            let mut uint32_bool_value: u32 = 0;
            if $crate::serialize::serialize_stream_is_writing( &*$stream )
            {
                uint32_bool_value = if $value { 1 } else { 0 };
            }
            if !$crate::serialize::SerializeBitsConst::<1, _>( &mut *$stream, &mut uint32_bool_value )
            {
                return false;
            }
            if $crate::serialize::serialize_stream_is_reading( &*$stream )
            {
                $value = if uint32_bool_value != 0 { true } else { false };
            }
        }
    };
}

// port: dest and source are NUL-terminated buffers; the end of the source slice terminates it too
pub fn serialize_copy_string( dest: &mut [u8], source: &[u8], dest_size: usize )
{
    serialize_assert!( dest_size >= 1 );
    for byte in dest[..dest_size].iter_mut()
    {
        *byte = 0;
    }
    for i in 0..dest_size - 1
    {
        if i >= source.len() || source[i] == 0
        {
            break;
        }
        dest[i] = source[i];
    }
}

pub fn serialize_copy_wstring( dest: &mut [wchar_t], source: &[wchar_t], dest_size: usize )
{
    serialize_assert!( dest_size >= 1 );
    for character in dest[..dest_size].iter_mut()
    {
        *character = 0;
    }
    for i in 0..dest_size - 1
    {
        if i >= source.len() || source[i] == 0
        {
            break;
        }
        dest[i] = source[i];
    }
}

// ---- tests (SERIALIZE_ENABLE_TESTS) ----


/*
    port: the tests (SERIALIZE_ENABLE_TESTS), first half: from the top of the test block up to test_uint128_differential.

    - Upstream compiles the tests in when SERIALIZE_ENABLE_TESTS is set; Rust always compiles them (dead_code is allowed
      crate-wide), and serialize_test() runs them.
    - serialize_check is a local macro_rules!, defined before every use (macros are textually scoped), so the second
      half of the tests below uses it too.
    - The streams borrow their buffer for as long as they are used. Where upstream touches the buffer (memset, memcmp,
      a read stream over it) and then still asks the write stream for a count, the count is read into a local first.
    - Upstream's "+ 8" read buffer padding is kept as written; the Rust reader does not need it (see BitReader).
    - The write and measure streams take value by value upstream; the trait takes &mut for all three, so constant
      arguments are passed as `&mut { value }`. A stream method called with const data (SerializeBytes on a const
      array) is the const overload, SerializeBytesConst.
    - char buffers are [u8; N]; sizeof( buffer ) of a local array is spelled as its size.
    - The C library helpers the tests use (memcmp, strcmp, wcscmp, fabs, memcpy of a float's bits) are slice
      comparisons, serialize_test_strcmp / serialize_test_wcscmp, f32::abs and f32::from_bits.
*/

/**
    Under a passing test, the test's name prints and nothing else. The suite's
    informational narration -- check counts, negative-control statistics, skip
    reasons, which contraction discipline this build exercised -- is opt-in:
    set SERIALIZE_TEST_VERBOSE=1 in the environment to restore it. Failures
    print everything relevant regardless, and no check runs or does not run
    because of this switch -- it gates narration only.
 */
pub fn serialize_test_verbose() -> bool
{
    match std::env::var_os( "SERIALIZE_TEST_VERBOSE" )
    {
        Some( value ) =>
        {
            let value = value.to_string_lossy();
            !value.is_empty() && !( value == "0" )
        }
        None => false,
    }
}

// port: prints, then exits. upstream also traps first in debug builds (__builtin_trap / __debugbreak), which has no Rust
// equivalent worth having in a test: the exit code already fails the run (as reliable's check_handler)
pub fn SerializeCheckHandler( condition: &str,
                              function: &str,
                              file: &str,
                              line: i32 )
{
    print!( "check failed: ( {} ), function {}, file {}, line {}\n", condition, function, file, line );
    let _ = std::io::Write::flush( &mut std::io::stdout() );       // the exit below skips nothing, but a pipe (CI) must not lose the line above
    std::process::exit( 1 );
}

// port: __FUNCTION__ is the name of the enclosing fn, recovered from the type name of a fn item declared inside it
macro_rules! serialize_check
{
    ( $condition:expr ) =>
    {
        if !( $condition )
        {
            fn f() {}
            fn type_name_of<T>( _: T ) -> &'static str { std::any::type_name::<T>() }
            let function = type_name_of( f );
            let function = function.strip_suffix( "::f" ).unwrap_or( function );
            let function = function.rsplit( "::" ).next().unwrap_or( function );
            $crate::serialize::SerializeCheckHandler( stringify!( $condition ), function, file!(), line!() as i32 );
        }
    };
}

// port: strcmp / wcscmp over NUL-terminated buffers (the end of a slice terminates it too)
fn serialize_test_compare_terminated<T: Copy + Ord + Default>( a: &[T], b: &[T] ) -> i32
{
    let zero = T::default();
    let mut i: usize = 0;
    loop
    {
        let x = if i < a.len() { a[i] } else { zero };
        let y = if i < b.len() { b[i] } else { zero };
        if x != y
        {
            return if x < y { -1 } else { 1 };
        }
        if x == zero
        {
            return 0;
        }
        i += 1;
    }
}

pub fn serialize_test_strcmp( a: &[u8], b: &[u8] ) -> i32
{
    serialize_test_compare_terminated( a, b )
}

pub fn serialize_test_wcscmp( a: &[wchar_t], b: &[wchar_t] ) -> i32
{
    serialize_test_compare_terminated( a, b )
}

pub fn test_endian()
{
    let value: u32 = 0x11223344;

    // port: the bytes of the value as it sits in memory
    let bytes: [u8; 4] = value.to_ne_bytes();

    if SERIALIZE_LITTLE_ENDIAN != 0
    {
        serialize_check!( bytes[0] == 0x44 );
        serialize_check!( bytes[1] == 0x33 );
        serialize_check!( bytes[2] == 0x22 );
        serialize_check!( bytes[3] == 0x11 );
    }
    else // #if SERIALIZE_LITTLE_ENDIAN
    {
        serialize_check!( bytes[3] == 0x44 );
        serialize_check!( bytes[2] == 0x33 );
        serialize_check!( bytes[1] == 0x22 );
        serialize_check!( bytes[0] == 0x11 );
    } // #if SERIALIZE_LITTLE_ENDIAN
}

pub fn test_bitpacker()
{
    const BufferSize: i32 = 256;

    let mut buffer = [0u8; BufferSize as usize];

    let buffer_pointer: *const u8 = buffer.as_ptr();       // port: writer.GetData() == buffer compares addresses

    let mut writer = BitWriter::new( &mut buffer, BufferSize as i64 );

    serialize_check!( writer.GetData().as_ptr() == buffer_pointer );
    serialize_check!( writer.GetBitsWritten() == 0 );
    serialize_check!( writer.GetBytesWritten() == 0 );
    serialize_check!( writer.GetBitsAvailable() == BufferSize as i64 * 8 );

    writer.WriteBits( 0, 1 );
    writer.WriteBits( 1, 1 );
    writer.WriteBits( 10, 8 );
    writer.WriteBits( 255, 8 );
    writer.WriteBits( 1000, 10 );
    writer.WriteBits( 50000, 16 );
    writer.WriteBits( 9999999, 32 );
    writer.FlushBits();

    const bitsWritten: i64 = 1 + 1 + 8 + 8 + 10 + 16 + 32;

    serialize_check!( writer.GetBytesWritten() == 10 );
    serialize_check!( writer.GetBitsWritten() == bitsWritten );
    serialize_check!( writer.GetBitsAvailable() == BufferSize as i64 * 8 - bitsWritten );

    let bytesWritten: i64 = writer.GetBytesWritten();

    serialize_check!( bytesWritten == 10 );

    for byte in buffer[bytesWritten as usize..].iter_mut()
    {
        *byte = 0;
    }

    let mut reader = BitReader::new( &buffer, bytesWritten );

    serialize_check!( reader.GetBitsRead() == 0 );
    serialize_check!( reader.GetBitsRemaining() == bytesWritten * 8 );

    let a: u32 = reader.ReadBits( 1 );
    let b: u32 = reader.ReadBits( 1 );
    let c: u32 = reader.ReadBits( 8 );
    let d: u32 = reader.ReadBits( 8 );
    let e: u32 = reader.ReadBits( 10 );
    let f: u32 = reader.ReadBits( 16 );
    let g: u32 = reader.ReadBits( 32 );

    serialize_check!( a == 0 );
    serialize_check!( b == 1 );
    serialize_check!( c == 10 );
    serialize_check!( d == 255 );
    serialize_check!( e == 1000 );
    serialize_check!( f == 50000 );
    serialize_check!( g == 9999999 );

    serialize_check!( reader.GetBitsRead() == bitsWritten );
    serialize_check!( reader.GetBitsRemaining() == bytesWritten * 8 - bitsWritten );
}

pub fn test_bits_required()
{
    serialize_check!( bits_required( 0, 0 ) == 0 );
    serialize_check!( bits_required( 0, 1 ) == 1 );
    serialize_check!( bits_required( 0, 2 ) == 2 );
    serialize_check!( bits_required( 0, 3 ) == 2 );
    serialize_check!( bits_required( 0, 4 ) == 3 );
    serialize_check!( bits_required( 0, 5 ) == 3 );
    serialize_check!( bits_required( 0, 6 ) == 3 );
    serialize_check!( bits_required( 0, 7 ) == 3 );
    serialize_check!( bits_required( 0, 8 ) == 4 );
    serialize_check!( bits_required( 0, 255 ) == 8 );
    serialize_check!( bits_required( 0, 65535 ) == 16 );
    serialize_check!( bits_required( 0, 4294967295 ) == 32 );
}

pub fn test_bits_required64()
{
    serialize_check!( bits_required64( 0, 0 ) == 0 );
    serialize_check!( bits_required64( 0, 1 ) == 1 );
    serialize_check!( bits_required64( 0, 255 ) == 8 );
    serialize_check!( bits_required64( 0, 4294967295u64 ) == 32 );
    serialize_check!( bits_required64( 0, 4294967296u64 ) == 33 );
    serialize_check!( bits_required64( 0, ( 1u64 << 40 ) ) == 41 );
    serialize_check!( bits_required64( 0, 0xFFFFFFFFFFFFFFFFu64 ) == 64 );
    serialize_check!( bits_required64( i64::MIN as u64, i64::MAX as u64 ) == 64 );
    serialize_check!( bits_required64( -5000000000i64 as u64, 5000000000i64 as u64 ) == 34 );
}

pub fn test_bits_required128()
{
    // port: the local typedef u128 is serialize::uint128_t, which is the primitive u128

    serialize_check!( bits_required128( 0u128, 0u128 ) == 0 );
    serialize_check!( bits_required128( 0u128, 1u128 ) == 1 );
    serialize_check!( bits_required128( 0u128, 255u128 ) == 8 );
    serialize_check!( bits_required128( 0u128, 4294967295u64 as u128 ) == 32 );
    serialize_check!( bits_required128( 0u128, 4294967296u64 as u128 ) == 33 );
    serialize_check!( bits_required128( 0u128, 0xFFFFFFFFFFFFFFFFu64 as u128 ) == 64 );

    // the boundary the 64 bit helper cannot reach: one past a full low lane needs the high lane
    serialize_check!( bits_required128( 0u128, 1u128 << 64 ) == 65 );
    serialize_check!( bits_required128( 0u128, ( 1u128 << 127 ) ) == 128 );
    serialize_check!( bits_required128( 0u128, !0u128 ) == 128 );

    // the two helpers must agree wherever the range fits 64 bits, or the wire identity claim in
    // STANDARD.md is false and serialize_int128 would silently disagree with serialize_int64
    serialize_check!( bits_required128( 0u128, 4294967296u64 as u128 ) == bits_required64( 0, 4294967296u64 ) );
    serialize_check!( bits_required128( 0u128, ( 1u64 << 40 ) as u128 ) == bits_required64( 0, ( 1u64 << 40 ) ) );

    // NEGATIVE BOUNDS MUST ARRIVE SIGN EXTENDED, which is what the codec does — it converts
    // serialize::int128_t bounds straight to the unsigned domain. This is the same 34 bits the 64
    // bit helper reports for the same signed range.
    serialize_check!( bits_required128( ( -5000000000 as int128_t ) as u128, ( 5000000000 as int128_t ) as u128 ) == 34 );

    // AND THE TRAP IT WOULD BE EASY TO WALK INTO, pinned so nobody "fixes" the conversion:
    // widening an ALREADY WRAPPED uint64_t bound zero extends instead of sign extending, so the
    // range comes out just under 2^128 and the field would cost 128 bits instead of 34. Correct
    // arithmetic on the wrong input — no assert would ever fire.
    serialize_check!( bits_required128( ( -5000000000i64 as u64 ) as u128, ( 5000000000i64 as u64 ) as u128 ) == 128 );

    // a range wider than 2^127: the subtraction must run in the unsigned domain or this wraps wrong
    serialize_check!( bits_required128( 1u128, !0u128 ) == 128 );
}

pub fn test_zigzag()
{
    serialize_check!( signed_to_unsigned( 0 ) == 0 );
    serialize_check!( signed_to_unsigned( -1 ) == 1 );
    serialize_check!( signed_to_unsigned( 1 ) == 2 );
    serialize_check!( signed_to_unsigned( -2 ) == 3 );
    serialize_check!( signed_to_unsigned( 2 ) == 4 );
    serialize_check!( signed_to_unsigned( i32::MAX ) == 0xFFFFFFFE );
    serialize_check!( signed_to_unsigned( i32::MIN ) == 0xFFFFFFFF );

    serialize_check!( unsigned_to_signed( 0 ) == 0 );
    serialize_check!( unsigned_to_signed( 1 ) == -1 );
    serialize_check!( unsigned_to_signed( 2 ) == 1 );
    serialize_check!( unsigned_to_signed( 3 ) == -2 );
    serialize_check!( unsigned_to_signed( 4 ) == 2 );
    serialize_check!( unsigned_to_signed( 0xFFFFFFFE ) == i32::MAX );
    serialize_check!( unsigned_to_signed( 0xFFFFFFFF ) == i32::MIN );

    let values: [i32; 9] = [ 0, -1, 1, -2, 2, 12345, -12345, i32::MAX, i32::MIN ];

    for i in 0..values.len()
    {
        serialize_check!( unsigned_to_signed( signed_to_unsigned( values[i] ) ) == values[i] );
    }
}

pub const MaxItems: i32 = 11;

// port: the three 8 bit bitfields d, e and f are whole u32 fields (every value the tests store fits). operator ==
// (a memcmp of the whole struct) is the derived PartialEq, field by field
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TestData
{
    pub a: i32, pub b: i32, pub c: i32,
    pub d: u32,
    pub e: u32,
    pub f: u32,
    pub g: bool,
    pub numItems: i32,
    pub items: [i32; MaxItems as usize],
    pub float_value: f32,
    pub compressed_float_value: f32,
    pub double_value: f64,
    pub uint8_value: u8,
    pub uint16_value: u16,
    pub uint32_value: u32,
    pub uint64_value: u64,
    pub int_relative: i32,
    pub int64_full: i64,
    pub int64_range: i64,
    pub bytes: [u8; 17],
    pub string: [u8; 256],
    pub wstring: [wchar_t; 256],
}

impl TestData
{
    // port: the constructor (memset of the whole struct to zero)
    pub fn new() -> TestData
    {
        TestData
        {
            a: 0, b: 0, c: 0,
            d: 0,
            e: 0,
            f: 0,
            g: false,
            numItems: 0,
            items: [0; MaxItems as usize],
            float_value: 0.0,
            compressed_float_value: 0.0,
            double_value: 0.0,
            uint8_value: 0,
            uint16_value: 0,
            uint32_value: 0,
            uint64_value: 0,
            int_relative: 0,
            int64_full: 0,
            int64_range: 0,
            bytes: [0; 17],
            string: [0; 256],
            wstring: [0; 256],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TestContext
{
    pub min: i32,
    pub max: i32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TestObject
{
    pub data: TestData,
}

impl TestObject
{
    pub fn new() -> TestObject
    {
        TestObject { data: TestData::new() }
    }

    pub fn Init( &mut self )
    {
        self.data.a = 1;
        self.data.b = -2;
        self.data.c = 150;
        self.data.d = 55;
        self.data.e = 255;
        self.data.f = 127;
        self.data.g = true;

        self.data.numItems = MaxItems / 2;
        for i in 0..self.data.numItems as usize
        {
            self.data.items[i] = i as i32 + 10;
        }

        self.data.compressed_float_value = 2.13;
        self.data.float_value = 3.1415926;
        self.data.double_value = 1.0 / 3.0;
        self.data.uint8_value = 123;
        self.data.uint16_value = 0x1234;
        self.data.uint32_value = 0x12345678;
        self.data.uint64_value = 0x1234567898765432;
        self.data.int_relative = 5;
        self.data.int64_full = -123456789012345;
        self.data.int64_range = 4123456789;

        for i in 0..self.data.bytes.len()
        {
            self.data.bytes[i] = ( ( ( i + 5 ) as u8 ) as i32 * 13 ) as u8;
        }

        let string_size = self.data.string.len();
        serialize_copy_string( &mut self.data.string, b"hello world!\0", string_size - 1 );

        // Explicit code points, not a cyrillic literal. This header carries no BOM, and MSVC
        // decodes a BOM-less UTF-8 source as the local ANSI code page, silently mangling wide
        // literals. Writing the code points makes this independent of source encoding entirely,
        // which also protects consumers who include this header without /utf-8. The assertions
        // further down already do this for the same family of reason.
        let hello_world: [wchar_t; 14] = [ 0x043F, 0x0440, 0x0438, 0x0432, 0x0456, 0x0442,    // privit
                                           0x002C, 0x0020,                                    // ", "
                                           0x0441, 0x0432, 0x0456, 0x0442, 0x0021, 0 ];       // svit!
        let wstring_size = self.data.wstring.len();
        serialize_copy_wstring( &mut self.data.wstring, &hello_world, wstring_size - 1 );
    }

    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        // port: the context (two ints) is copied out of the stream's context pointer
        let context: TestContext = unsafe { *( stream.GetContext() as *const TestContext ) };

        serialize_int!( stream, self.data.a, context.min, context.max );
        serialize_int!( stream, self.data.b, context.min, context.max );

        serialize_int!( stream, self.data.c, -100, 10000 );

        serialize_bits!( stream, self.data.d, 6 );
        serialize_bits!( stream, self.data.e, 8 );
        serialize_bits!( stream, self.data.f, 7 );

        serialize_align!( stream );

        serialize_bool!( stream, self.data.g );

        serialize_int!( stream, self.data.numItems, 0, MaxItems - 1 );
        for i in 0..self.data.numItems as usize
        {
            serialize_bits!( stream, self.data.items[i], 8 );
        }

        serialize_float!( stream, self.data.float_value );

        serialize_compressed_float!( stream, self.data.compressed_float_value, 0, 10, 0.01 );

        serialize_double!( stream, self.data.double_value );

        serialize_uint8!( stream, self.data.uint8_value );
        serialize_uint16!( stream, self.data.uint16_value );
        serialize_uint32!( stream, self.data.uint32_value );
        serialize_uint64!( stream, self.data.uint64_value );

        serialize_int_relative!( stream, self.data.a, self.data.int_relative );

        serialize_int64!( stream, self.data.int64_full, i64::MIN, i64::MAX );
        serialize_int64!( stream, self.data.int64_range, -5000000000i64, 5000000000i64 );

        serialize_bytes!( stream, self.data.bytes, 17 );

        serialize_string!( stream, self.data.string, 256 );
        serialize_wstring!( stream, self.data.wstring, 256 );

        true
    }
}

pub fn test_serialize()
{
    const BufferSize: usize = 1024;

    let mut buffer = [0u8; BufferSize];

    let mut context = TestContext { min: -10, max: 10 };

    let mut writeStream = WriteStream::new( &mut buffer, BufferSize as i64 );

    let mut writeObject = TestObject::new();
    writeObject.Init();
    writeStream.SetContext( &mut context as *mut TestContext as *mut c_void );
    writeObject.Serialize( &mut writeStream );
    writeStream.Flush();

    let bytesWritten: i64 = writeStream.GetBytesProcessed();

    for byte in buffer[bytesWritten as usize..].iter_mut()
    {
        *byte = 0;
    }

    let mut readObject = TestObject::new();
    let mut readStream = ReadStream::new( &buffer, bytesWritten );
    readStream.SetContext( &mut context as *mut TestContext as *mut c_void );
    readObject.Serialize( &mut readStream );

    serialize_check!( readObject == writeObject );
}

pub fn ReadFunction( readStream: &mut ReadStream ) -> bool
{
    // IMPORTANT: You wouldn't normally write a read function like this, but I'm just checking each value as it's read in
    // Note that the only thing the read function has to have is to return bool: true on success, false on failing to read.
    // This is important because protects you from maliciously crafted packets.

    {
        let mut value: u32 = 0;
        read_bits!( readStream, value, 4 );
        serialize_check!( value == 13 );
    }

    {
        let mut value: bool = false;
        read_bool!( readStream, value );
        serialize_check!( value == true );
    }

    {
        let mut value: u8 = 0;
        read_uint8!( readStream, value );
        serialize_check!( value == 255 );
    }

    {
        let mut value: u16 = 0;
        read_uint16!( readStream, value );
        serialize_check!( value == 65535 );
    }

    {
        let mut value: u32 = 0;
        read_uint32!( readStream, value );
        serialize_check!( value == 0xFFFFFFFF );
    }

    {
        let mut value: u64 = 0;
        read_uint64!( readStream, value );
        serialize_check!( value == 0xFFFFFFFFFFFFFFFFu64 );      // i am very full
    }

    {
        let mut value: i32 = 0;
        read_int!( readStream, value, 10, 90 );
        serialize_check!( value == 55 );
    }

    {
        let mut value: i64 = 0;
        read_int64!( readStream, value, -60000000000i64, 60000000000i64 );
        serialize_check!( value == -50000000001i64 );
    }

    {
        let mut value: i64 = 0;
        read_fixed!( readStream, value, 48, 16, -100000, 100000 );
        serialize_check!( value == 12345i64 * 65536 + 32768 );       // 12345.5 in Q48.16
    }

    {
        let mut value: uint128_t = 0;
        read_uint128!( readStream, value );
        serialize_check!( value == ( ( ( 0x0123456789ABCDEFu64 as uint128_t ) << 64 ) | 0xFEDCBA9876543210u64 as uint128_t ) );
    }

    {
        let mut value: f32 = 0.0;
        read_float!( readStream, value );
        serialize_check!( value == 100.0f32 );
    }

    {
        let mut value: f64 = 0.0;
        read_double!( readStream, value );
        serialize_check!( value == 1000000000.0 );
    }

    {
        let mut value = [0u8; 5];
        read_bytes!( readStream, value, 5 );
        serialize_check!( value[0] == 1 );
        serialize_check!( value[1] == 2 );
        serialize_check!( value[2] == 3 );
        serialize_check!( value[3] == 4 );
        serialize_check!( value[4] == 5 );
    }

    {
        let mut string = [0u8; 10];
        read_string!( readStream, string, 10 );
        serialize_check!( string[0] == b'h' );
        serialize_check!( string[1] == b'e' );
        serialize_check!( string[2] == b'l' );
        serialize_check!( string[3] == b'l' );
        serialize_check!( string[4] == b'o' );
        serialize_check!( string[5] == b'\0' );
    }

    {
        let mut wstring = [0 as wchar_t; 20];
        read_wstring!( readStream, wstring, 20 );
        // explicit code points rather than cyrillic literals: serialize_check stringizes its
        // condition into a narrow string, which warns as C4566 on MSVC with a western code page
        serialize_check!( wstring[0] == 0x043F );        // 'п'
        serialize_check!( wstring[1] == 0x0440 );        // 'р'
        serialize_check!( wstring[2] == 0x0438 );        // 'и'
        serialize_check!( wstring[3] == 0x0432 );        // 'в'
        serialize_check!( wstring[4] == 0x0456 );        // 'і'
        serialize_check!( wstring[5] == 0x0442 );        // 'т'
    }

    read_align!( readStream );

    let mut context = TestContext { min: -10, max: 10 };

    readStream.SetContext( &mut context as *mut TestContext as *mut c_void );
    {
        let mut expectedObject = TestObject::new();
        expectedObject.Init();

        let mut readObject = TestObject::new();

        read_object!( readStream, readObject );

        serialize_check!( readObject == expectedObject );
    }

    {
        let mut value: i32 = 0;
        read_int_relative!( readStream, 100, value );
        serialize_check!( value == 105 );
    }

    true
}

pub fn test_read_write()
{
    const BufferSize: usize = 10 * 1024;

    let mut buffer = [0u8; BufferSize];

    let mut bytesWritten: i64 = 0;

    // write to the buffer
    {
        let mut writeStream = WriteStream::default();
        writeStream.Initialize( &mut buffer, BufferSize as i64 );

        write_bits!( &mut writeStream, 13, 4 );
        write_bool!( &mut writeStream, true );
        write_uint8!( &mut writeStream, 255 );
        write_uint16!( &mut writeStream, 65535 );
        write_uint32!( &mut writeStream, 0xFFFFFFFFu32 );
        write_uint64!( &mut writeStream, 0xFFFFFFFFFFFFFFFFu64 );
        write_int!( &mut writeStream, 55, 10, 90 );
        write_int64!( &mut writeStream, -50000000001i64, -60000000000i64, 60000000000i64 );

        let mut fixed_point_value: i64 = 12345i64 * 65536 + 32768;               // 12345.5 in Q48.16
        write_fixed!( &mut writeStream, fixed_point_value, 48, 16, -100000, 100000 );

        let big_value: uint128_t = ( ( 0x0123456789ABCDEFu64 as uint128_t ) << 64 ) | 0xFEDCBA9876543210u64 as uint128_t;
        write_uint128!( &mut writeStream, big_value );

        write_float!( &mut writeStream, 100.0f32 );
        write_double!( &mut writeStream, 1000000000.0f32 );

        let data: [u8; 5] = [ 1, 2, 3, 4, 5 ];
        write_bytes!( &mut writeStream, data, 5 );

        let string: &[u8] = b"hello\0";
        write_string!( &mut writeStream, string, 10 );

        // explicit code points, see the note above
        let wstring_storage: [wchar_t; 7] = [ 0x043F, 0x0440, 0x0438, 0x0432, 0x0456, 0x0442, 0 ];
        let wstring: &[wchar_t] = &wstring_storage;
        write_wstring!( &mut writeStream, wstring, 20 );

        write_align!( &mut writeStream );

        let mut context = TestContext { min: -10, max: 10 };

        writeStream.SetContext( &mut context as *mut TestContext as *mut c_void );

        let mut object = TestObject::new();
        object.Init();

        write_object!( &mut writeStream, object );

        write_int_relative!( &mut writeStream, 100, 105 );

        writeStream.Flush();

        bytesWritten = writeStream.GetBytesProcessed();

        for byte in buffer[bytesWritten as usize..].iter_mut()
        {
            *byte = 0;
        }
    }

    // read from the buffer
    {
        let mut readStream = ReadStream::default();
        readStream.Initialize( &buffer, bytesWritten );
        serialize_check!( ReadFunction( &mut readStream ) );
    }
}

pub fn test_serialize_integer_validation()
{
    // bits_required(0,5) is 3 bits, so a malicious packet can encode 6 or 7. reads must reject values above max.
    let mut buffer = [0u8; 4 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

    let mut writeStream = WriteStream::new( &mut buffer, 8 );
    let mut out_of_range: u32 = 7;
    writeStream.SerializeBits( &mut out_of_range, 3 );
    writeStream.Flush();

    let mut readStream = ReadStream::new( &buffer, 4 );
    let mut value: i32 = 0;
    serialize_check!( readStream.SerializeInteger( &mut value, 0, 5 ) == false );
}

pub fn test_serialize_degenerate_range()
{
    // STANDARD.md: a degenerate range where min == max costs ZERO BITS -- the
    // value is known from the range alone and nothing is written. This is not
    // a curiosity: schema emits it for empty enums and empty types.
    //
    // The library used to assert( min < max ), so a debug build aborted on
    // exactly the case the format defines and the release build handled
    // correctly. This test is here so debug and release cannot drift apart
    // again.
    let mut buffer = [0u8; 16];

    let mut writeStream = WriteStream::new( &mut buffer, 16 );
    let mut degenerate: i32 = 5;
    let mut after: i32 = 3;
    serialize_check!( writeStream.SerializeInteger( &mut degenerate, 5, 5 ) );
    serialize_check!( writeStream.GetBitsProcessed() == 0 );      // nothing written
    serialize_check!( writeStream.SerializeInteger( &mut after, 0, 7 ) );
    serialize_check!( writeStream.GetBitsProcessed() == 3 );      // the NEXT field starts at bit 0
    writeStream.Flush();

    let bytesProcessed = writeStream.GetBytesProcessed();
    let mut readStream = ReadStream::new( &buffer, bytesProcessed );
    let mut read_degenerate: i32 = 0;
    let mut read_after: i32 = 0;
    serialize_check!( readStream.SerializeInteger( &mut read_degenerate, 5, 5 ) );
    serialize_check!( read_degenerate == 5 );                     // recovered from the range
    serialize_check!( readStream.GetBitsProcessed() == 0 );
    serialize_check!( readStream.SerializeInteger( &mut read_after, 0, 7 ) );
    serialize_check!( read_after == 3 );

    // and the measure stream must agree that it costs nothing
    let mut measureStream = MeasureStream::new();
    let mut measured: i32 = 5;
    serialize_check!( measureStream.SerializeInteger( &mut measured, 5, 5 ) );
    serialize_check!( measureStream.GetBitsProcessed() == 0 );
}

pub fn test_serialize_degenerate_range_64()
{
    // The 64 bit twin of the test above, and it did NOT hold when written.
    //
    // 1.6.x relaxed the degenerate range in nine places and missed the 64 bit
    // path entirely: SerializeInteger64 had no bits == 0 early return, so it
    // fell through to WriteBits( value, 0 ) -- which asserts bits > 0 -- while
    // serialize_int64, read_int64 and write_int64 all asserted min < max above
    // it, stricter than the very method they call (SerializeInteger64 already
    // asserted min <= max). So C++ aborted on a degenerate 64 bit range that
    // C, C#, Go and Rust all accept, and the divergence was invisible because
    // no vector in the family used one.
    //
    // The bounds below are deliberately wider than 2^32 so the field would
    // take the two-dword path if it took any path at all.
    let mut buffer = [0u8; 16];

    let point: i64 = 1i64 << 40;

    let mut writeStream = WriteStream::new( &mut buffer, 16 );
    let mut degenerate: i64 = point;
    let mut after: i32 = 3;
    serialize_check!( writeStream.SerializeInteger64( &mut degenerate, point, point ) );
    serialize_check!( writeStream.GetBitsProcessed() == 0 );      // nothing written
    serialize_check!( writeStream.SerializeInteger( &mut after, 0, 7 ) );
    serialize_check!( writeStream.GetBitsProcessed() == 3 );      // the NEXT field starts at bit 0
    writeStream.Flush();

    let bytesProcessed = writeStream.GetBytesProcessed();
    let mut readStream = ReadStream::new( &buffer, bytesProcessed );
    let mut read_degenerate: i64 = 0;
    let mut read_after: i32 = 0;
    serialize_check!( readStream.SerializeInteger64( &mut read_degenerate, point, point ) );
    serialize_check!( read_degenerate == point );                 // recovered from the range
    serialize_check!( readStream.GetBitsProcessed() == 0 );
    serialize_check!( readStream.SerializeInteger( &mut read_after, 0, 7 ) );
    serialize_check!( read_after == 3 );

    let mut measureStream = MeasureStream::new();
    let mut measured: i64 = point;
    serialize_check!( measureStream.SerializeInteger64( &mut measured, point, point ) );
    serialize_check!( measureStream.GetBitsProcessed() == 0 );
}

pub fn DegenerateInt128Serialize<S: Stream>( stream: &mut S, value: &mut int128_t, point: int128_t ) -> bool
{
    serialize_int128!( stream, *value, point, point );
    true
}

pub fn test_serialize_degenerate_range_128()
{
    // The 128 bit twin, and the width where the same omission survived longest: SerializeInteger128
    // had no bits == 0 early return, so a degenerate range reached WriteBits( group0, 0 ) on write
    // and ReadBits( 0 ) on read -- both of which assert bits > 0 -- while serialize_int128,
    // read_int128 and write_int128 asserted min < max above them, stricter than the standard and
    // than every narrower width in this header. min <= max is the legal relation on every ranged
    // operation, in every build mode.
    //
    // The point below is the conformance corpus's int128 vector: 2^100 + 7, far past 64 bits, so
    // the field would take the multi-group path if it took any path at all.
    let mut buffer = [0u8; 16];

    let point: int128_t = ( ( 1 as int128_t ) << 100 ) + 7;

    let mut writeStream = WriteStream::new( &mut buffer, 16 );
    let mut degenerate: int128_t = point;
    let mut after: i32 = 3;
    serialize_check!( DegenerateInt128Serialize( &mut writeStream, &mut degenerate, point ) );
    serialize_check!( writeStream.GetBitsProcessed() == 0 );      // nothing written
    serialize_check!( writeStream.SerializeInteger( &mut after, 0, 7 ) );
    serialize_check!( writeStream.GetBitsProcessed() == 3 );      // the NEXT field starts at bit 0
    writeStream.Flush();

    let bytesProcessed = writeStream.GetBytesProcessed();
    let mut readStream = ReadStream::new( &buffer, bytesProcessed );
    let mut read_degenerate: int128_t = 0;
    let mut read_after: i32 = 0;
    serialize_check!( DegenerateInt128Serialize( &mut readStream, &mut read_degenerate, point ) );
    serialize_check!( read_degenerate == point );                 // recovered from the range
    serialize_check!( readStream.GetBitsProcessed() == 0 );
    serialize_check!( readStream.SerializeInteger( &mut read_after, 0, 7 ) );
    serialize_check!( read_after == 3 );

    let mut measureStream = MeasureStream::new();
    let mut measured: int128_t = point;
    serialize_check!( DegenerateInt128Serialize( &mut measureStream, &mut measured, point ) );
    serialize_check!( measureStream.GetBitsProcessed() == 0 );
}

pub fn test_serialize_integer_full_range()
{
    // ranges wider than 2^31 overflow if [min,max] arithmetic is done signed (undefined behavior)
    let values: [i32; 7] = [ i32::MIN, i32::MIN + 1, -1, 0, 1, i32::MAX - 1, i32::MAX ];

    for i in 0..values.len()
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        serialize_check!( writeStream.SerializeInteger( &mut { values[i] }, i32::MIN, i32::MAX ) == true );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut value: i32 = 0;
        serialize_check!( readStream.SerializeInteger( &mut value, i32::MIN, i32::MAX ) == true );
        serialize_check!( value == values[i] );
    }

    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        serialize_check!( writeStream.SerializeInteger( &mut { 1000000000 }, -2000000000, 2000000000 ) == true );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut value: i32 = 0;
        serialize_check!( readStream.SerializeInteger( &mut value, -2000000000, 2000000000 ) == true );
        serialize_check!( value == 1000000000 );
    }
}

pub fn test_serialize_int64_full_range()
{
    // ranges wider than 2^63 overflow if [min,max] arithmetic is done signed (undefined behavior)
    {
        let values: [i64; 7] = [ i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX ];

        for i in 0..values.len()
        {
            let mut buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

            let mut writeStream = WriteStream::new( &mut buffer, 16 );
            serialize_check!( writeStream.SerializeInteger64( &mut { values[i] }, i64::MIN, i64::MAX ) == true );
            writeStream.Flush();

            let mut readStream = ReadStream::new( &buffer, 16 );
            let mut value: i64 = 0;
            serialize_check!( readStream.SerializeInteger64( &mut value, i64::MIN, i64::MAX ) == true );
            serialize_check!( value == values[i] );
        }
    }

    // ranges spanning more than 32 bits use the two dword path
    {
        let min: i64 = -5000000000;
        let max: i64 = 5000000000;
        let values: [i64; 8] = [ min, min + 1, -1, 0, 1, 4123456789, max - 1, max ];

        for i in 0..values.len()
        {
            let mut buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

            let mut writeStream = WriteStream::new( &mut buffer, 16 );
            serialize_check!( writeStream.SerializeInteger64( &mut { values[i] }, min, max ) == true );
            writeStream.Flush();

            let mut readStream = ReadStream::new( &buffer, 16 );
            let mut value: i64 = 0;
            serialize_check!( readStream.SerializeInteger64( &mut value, min, max ) == true );
            serialize_check!( value == values[i] );
        }
    }

    // small ranges use the single dword path and the minimal number of bits
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        serialize_check!( writeStream.SerializeInteger64( &mut { 55 }, -100, 100 ) == true );
        writeStream.Flush();

        serialize_check!( writeStream.GetBitsProcessed() == 8 );        // bits_required64(-100,100) == 8, same as the 32 bit path

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut value: i64 = 0;
        serialize_check!( readStream.SerializeInteger64( &mut value, -100, 100 ) == true );
        serialize_check!( value == 55 );
    }
}

pub fn test_serialize_int64_validation()
{
    // a malicious packet can smuggle an out of range value into the bit headroom of the two dword path. reads must reject it.
    {
        let mut buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let out_of_range: u64 = ( 1u64 << 34 ) + 5;               // range [0, 2^34] is 35 bits, so values above 2^34 fit in the headroom
        let mut lo: u32 = ( out_of_range & 0xFFFFFFFF ) as u32;
        let mut hi: u32 = ( out_of_range >> 32 ) as u32;
        writeStream.SerializeBits( &mut lo, 32 );
        writeStream.SerializeBits( &mut hi, 3 );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 16 );
        let mut value: i64 = 0;
        serialize_check!( readStream.SerializeInteger64( &mut value, 0, ( 1u64 << 34 ) as i64 ) == false );
    }

    // reads past the end of the buffer must fail cleanly
    {
        let buffer = [0u8; 4 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut readStream = ReadStream::new( &buffer, 4 );
        let mut value: i64 = 0;
        serialize_check!( readStream.SerializeInteger64( &mut value, i64::MIN, i64::MAX ) == false );
    }
}

pub fn test_serialize_bytes_validation()
{
    // negative and huge byte counts must be rejected, not overflow the bounds check in bits
    let buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data
    let mut data = [0u8; 16];

    {
        let mut readStream = ReadStream::new( &buffer, 16 );
        serialize_check!( readStream.SerializeBytes( &mut data, -1 ) == false );
    }

    {
        let mut readStream = ReadStream::new( &buffer, 16 );
        serialize_check!( readStream.SerializeBytes( &mut data, 1 << 29 ) == false );
    }
}

pub fn test_wstring_validation()
{
    // Wide-string coverage. Before this existed the only exercise of the wstring path
    // was incidental — a field inside test_serialize, a pair of calls in test_read_write,
    // and the golden vector. None of them covered the boundaries, and none covered the
    // documented failure behaviour at all. See STANDARD.md, "wstring".

    const BufferSize: i32 = 32;

    // empty string: length 0, no characters, and the reader appends the terminator
    {
        let mut buffer = [0u8; 256];
        let mut empty = [0 as wchar_t; BufferSize as usize];
        let mut writeStream = WriteStream::new( &mut buffer, 256 );
        serialize_check!( serialize_wstring_internal( &mut writeStream, &mut empty, BufferSize ) );
        writeStream.Flush();

        let mut read_back = [wchar_t::MAX; BufferSize as usize];        // memset 0xFF
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize ) );
        serialize_check!( read_back[0] == 0 );
    }

    // longest legal string: buffer_size - 1 characters, since the terminator is not sent
    {
        let mut buffer = [0u8; 512];
        let mut full = [0 as wchar_t; BufferSize as usize];
        for i in 0..( BufferSize - 1 ) as usize
        {
            full[i] = ( 0x0041 + ( i % 26 ) ) as wchar_t;
        }
        full[( BufferSize - 1 ) as usize] = 0;

        let mut writeStream = WriteStream::new( &mut buffer, 512 );
        serialize_check!( serialize_wstring_internal( &mut writeStream, &mut full, BufferSize ) );
        writeStream.Flush();

        let mut read_back = [wchar_t::MAX; BufferSize as usize];        // memset 0xFF
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize ) );
        serialize_check!( serialize_test_wcscmp( &read_back, &full ) == 0 );
    }

    // the measure stream must agree with the write stream on cost
    {
        let mut buffer = [0u8; 256];
        let mut text = [0 as wchar_t; BufferSize as usize];
        text[0] = 0x0041;
        text[1] = 0x0042;
        text[2] = 0x0043;

        let mut measureStream = MeasureStream::new();
        serialize_check!( serialize_wstring_internal( &mut measureStream, &mut text, BufferSize ) );

        let mut writeStream = WriteStream::new( &mut buffer, 256 );
        serialize_check!( serialize_wstring_internal( &mut writeStream, &mut text, BufferSize ) );
        writeStream.Flush();

        serialize_check!( measureStream.GetBitsProcessed() == writeStream.GetBitsProcessed() );
    }

    // A GROUP ABOVE 0xFFFF IS NOT A UTF-16 CODE UNIT (STANDARD.md, adopted 2026-08-15):
    // each 32 bit group carries one code unit, so no conforming writer can emit a larger
    // value — astral text travels as a surrogate pair. The doctored group is REFUSED on
    // every platform, subsuming the old width-dependent behaviour (accept on 4 byte
    // wchar_t, refuse on 2), whose acceptance half was a wire divergence between
    // platforms once each group became one unit. The value is planted with raw bit
    // operations so the test does not depend on the local width to produce it.
    {
        let mut buffer = [0u8; 256];
        let above_bmp: u32 = 0x0001F600;      // beyond 16 bits by construction

        let mut writeStream = WriteStream::new( &mut buffer, 256 );
        serialize_check!( writeStream.SerializeInteger( &mut { 1 }, 0, BufferSize - 1 ) );   // length 1
        serialize_check!( writeStream.SerializeBits( &mut { above_bmp }, 32 ) );
        writeStream.Flush();

        let mut read_back = [0 as wchar_t; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        let result: bool = serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize );

        serialize_check!( result == false );
        serialize_check!( read_back[0] != ( above_bmp & 0xFFFF ) as wchar_t );    // nothing truncated left behind
    }
}

pub fn test_wstring_utf16_code_units()
{
    // wstring transmits UTF-16 CODE UNITS: an astral code point is a surrogate pair on the
    // wire, and 2 and 4 byte wchar_t platforms produce IDENTICAL bytes — the 4 byte platform
    // converts at the boundary, splitting on write and recombining on read (STANDARD.md,
    // adopted 2026-08-15). The input is built per the local width, the expected bytes are the
    // code unit stream spelled out directly with raw bit operations, and the two must agree
    // everywhere. Mirrors the vector serialize.c pins in test/roundtrip.c.

    const BufferSize: i32 = 8;

    // U+1F600 is the surrogate pair 0xD83D 0xDE00: one character but two units on a 4 byte
    // wchar_t platform. On a 2 byte platform the string already holds the pair.
    let mut ws_in = [0 as wchar_t; 8];
    if std::mem::size_of::<wchar_t>() >= 4
    {
        ws_in[0] = 0x0001F600u32 as wchar_t;
        ws_in[1] = 0x0041;
        ws_in[2] = 0;
    }
    else
    {
        ws_in[0] = 0xD83Du32 as wchar_t;
        ws_in[1] = 0xDE00u32 as wchar_t;
        ws_in[2] = 0x0041;
        ws_in[3] = 0;
    }

    // the wire, spelled out with raw bit operations: three units in a [0,7] length field,
    // then each unit as a 32 bit group
    let mut expected_bytes = [0u8; 64];
    let mut expected_bytes_processed: i64 = 0;
    {
        let mut expectedStream = WriteStream::new( &mut expected_bytes, 64 );
        serialize_check!( expectedStream.SerializeInteger( &mut { 3 }, 0, BufferSize - 1 ) );
        let mut high_surrogate: u32 = 0xD83D;
        let mut low_surrogate: u32 = 0xDE00;
        let mut letter_a: u32 = 0x0041;
        serialize_check!( expectedStream.SerializeBits( &mut high_surrogate, 32 ) );
        serialize_check!( expectedStream.SerializeBits( &mut low_surrogate, 32 ) );
        serialize_check!( expectedStream.SerializeBits( &mut letter_a, 32 ) );
        expectedStream.Flush();
        expected_bytes_processed = expectedStream.GetBytesProcessed();
    }

    // write side: the unified serialize path must produce exactly those bytes
    let mut bits_written: i64 = 0;
    let mut buffer = [0u8; 64];
    {
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        serialize_check!( serialize_wstring_internal( &mut writeStream, &mut ws_in, BufferSize ) );
        writeStream.Flush();
        serialize_check!( writeStream.GetBytesProcessed() == expected_bytes_processed );
        bits_written = writeStream.GetBitsProcessed();          // port: read before the buffer compare below (the stream borrows the buffer)
        serialize_check!( buffer[..expected_bytes_processed as usize] == expected_bytes[..expected_bytes_processed as usize] );
    }

    // the measure counts the units transmitted, not the characters held
    {
        let mut measureStream = MeasureStream::new();
        serialize_check!( serialize_wstring_internal( &mut measureStream, &mut ws_in, BufferSize ) );
        serialize_check!( measureStream.GetBitsProcessed() == bits_written );
    }

    // the write-only macro form must stay byte-identical to the unified path
    // (STANDARD.md, "Read-only and write-only forms")
    {
        let mut macro_buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut macro_buffer, 64 );
        let wstring: &[wchar_t] = &ws_in;
        write_wstring!( &mut writeStream, wstring, BufferSize );
        writeStream.Flush();
        serialize_check!( writeStream.GetBytesProcessed() == expected_bytes_processed );
        serialize_check!( macro_buffer[..expected_bytes_processed as usize] == expected_bytes[..expected_bytes_processed as usize] );
    }

    // read side: the code unit stream decodes to the platform's own representation —
    // recombined on 4 byte wchar_t, the pair itself on 2 byte
    {
        let mut read_back = [wchar_t::MAX; BufferSize as usize];        // memset 0xFF
        let mut readStream = ReadStream::new( &expected_bytes, expected_bytes_processed );
        serialize_check!( serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize ) );
        serialize_check!( serialize_test_wcscmp( &read_back, &ws_in ) == 0 );
    }
}

pub fn test_string_read_validation()
{
    // STANDARD.md, "Readers must refuse malformed string payloads" (adopted 2026-08-15).
    // Every refused stream below is DOCTORED with raw bit operations — no conforming
    // writer can produce it — and the refusal binds in every build mode. Proven
    // red-then-green: against the pre-ruling reader, every doctored stream here was
    // ACCEPTED (harness run recorded with the ruling batch); with the refusals in
    // place they are REFUSED, and the valid-content controls are unchanged.

    const BufferSize: i32 = 16;

    // invalid UTF-8: 0xFF can never appear anywhere in well-formed UTF-8
    {
        let mut buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut length: i32 = 3;
        serialize_check!( writeStream.SerializeInteger( &mut length, 0, BufferSize - 1 ) );
        let payload: [u8; 3] = [ 0xFF, 0xFE, 0xFF ];
        serialize_check!( writeStream.SerializeBytesConst( &payload, 3 ) );
        writeStream.Flush();

        let mut read_back = [0u8; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_string_internal( &mut readStream, &mut read_back, BufferSize ) == false );
    }

    // truncated UTF-8: a 3 byte lead as the final transmitted byte
    {
        let mut buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut length: i32 = 2;
        serialize_check!( writeStream.SerializeInteger( &mut length, 0, BufferSize - 1 ) );
        let payload: [u8; 2] = [ b'a', 0xE2 ];
        serialize_check!( writeStream.SerializeBytesConst( &payload, 2 ) );
        writeStream.Flush();

        let mut read_back = [0u8; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_string_internal( &mut readStream, &mut read_back, BufferSize ) == false );
    }

    // interior NUL: wire length 3, strlen 1 — the TWO-LENGTHS smuggling primitive. A
    // conforming writer derives the length from strlen, so this stream is impossible
    // from conformance; accepted, it hands the application a payload whose wire length
    // and C length disagree, and everything between them travels invisibly.
    {
        let mut buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut length: i32 = 3;
        serialize_check!( writeStream.SerializeInteger( &mut length, 0, BufferSize - 1 ) );
        let payload: [u8; 3] = [ b'a', 0x00, b'b' ];
        serialize_check!( writeStream.SerializeBytesConst( &payload, 3 ) );
        writeStream.Flush();

        let mut read_back = [0u8; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_string_internal( &mut readStream, &mut read_back, BufferSize ) == false );
    }

    // control: valid multi-byte UTF-8 — 2, 3 and 4 byte sequences, built from explicit
    // bytes so the source file encoding can never change the test — still round trips.
    // The refusal costs no valid stream.
    {
        let mut buffer = [0u8; 64];
        let mut text = [0u8; BufferSize as usize];
        let utf8: [u8; 11] = [ b'h', 0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80, 0 ];  // h, e-acute, euro sign, U+1F600
        text[..utf8.len()].copy_from_slice( &utf8 );

        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        serialize_check!( serialize_string_internal( &mut writeStream, &mut text, BufferSize ) );
        writeStream.Flush();

        let mut read_back = [0u8; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_string_internal( &mut readStream, &mut read_back, BufferSize ) );
        serialize_check!( serialize_test_strcmp( &read_back, &text ) == 0 );
    }
}

pub fn test_wstring_read_validation()
{
    // STANDARD.md, "Readers must refuse malformed wstring payloads" (adopted 2026-08-15).
    // Same shape as the narrow test above: doctored streams refused in every build mode,
    // proven red-then-green, valid content unchanged.

    const BufferSize: i32 = 8;

    // high surrogate followed by a non-surrogate: unpaired, refused
    {
        let mut buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut length: i32 = 2;
        serialize_check!( writeStream.SerializeInteger( &mut length, 0, BufferSize - 1 ) );
        let mut group0: u32 = 0xD800;
        let mut group1: u32 = 0x0041;
        serialize_check!( writeStream.SerializeBits( &mut group0, 32 ) );
        serialize_check!( writeStream.SerializeBits( &mut group1, 32 ) );
        writeStream.Flush();

        let mut read_back = [0 as wchar_t; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize ) == false );
    }

    // low surrogate with no high before it: refused
    {
        let mut buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut length: i32 = 1;
        serialize_check!( writeStream.SerializeInteger( &mut length, 0, BufferSize - 1 ) );
        let mut group0: u32 = 0xDC00;
        serialize_check!( writeStream.SerializeBits( &mut group0, 32 ) );
        writeStream.Flush();

        let mut read_back = [0 as wchar_t; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize ) == false );
    }

    // high surrogate as the final transmitted group: dangling, refused
    {
        let mut buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut length: i32 = 1;
        serialize_check!( writeStream.SerializeInteger( &mut length, 0, BufferSize - 1 ) );
        let mut group0: u32 = 0xD83D;
        serialize_check!( writeStream.SerializeBits( &mut group0, 32 ) );
        writeStream.Flush();

        let mut read_back = [0 as wchar_t; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize ) == false );
    }

    // interior NUL group: wire length 3, wcslen 1 — the same two-lengths primitive as
    // the narrow string, refused
    {
        let mut buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut length: i32 = 3;
        serialize_check!( writeStream.SerializeInteger( &mut length, 0, BufferSize - 1 ) );
        let mut group0: u32 = 0x0041;
        let mut group1: u32 = 0x0000;
        let mut group2: u32 = 0x0042;
        serialize_check!( writeStream.SerializeBits( &mut group0, 32 ) );
        serialize_check!( writeStream.SerializeBits( &mut group1, 32 ) );
        serialize_check!( writeStream.SerializeBits( &mut group2, 32 ) );
        writeStream.Flush();

        let mut read_back = [0 as wchar_t; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize ) == false );
    }

    // control: a well-formed surrogate PAIR is valid UTF-16 — it is how astral text
    // travels — and must be ACCEPTED. Against main's reader the pair is stored as its
    // two units on every platform; recombination on 4 byte wchar_t is the surrogate
    // boundary branch's work and composes on top of this check.
    {
        let mut buffer = [0u8; 64];
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut length: i32 = 2;
        serialize_check!( writeStream.SerializeInteger( &mut length, 0, BufferSize - 1 ) );
        let mut group0: u32 = 0xD83D;
        let mut group1: u32 = 0xDE00;
        serialize_check!( writeStream.SerializeBits( &mut group0, 32 ) );
        serialize_check!( writeStream.SerializeBits( &mut group1, 32 ) );
        writeStream.Flush();

        let mut read_back = [0 as wchar_t; BufferSize as usize];
        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        serialize_check!( serialize_wstring_internal( &mut readStream, &mut read_back, BufferSize ) == true );
    }
}

pub fn test_int_relative_validation()
{
    // the absolute tier must reject values that violate the previous < current contract
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let mut six_false_bools: u32 = 0;
        writeStream.SerializeBits( &mut six_false_bools, 6 );
        let mut bad_current: u32 = 50;
        writeStream.SerializeBits( &mut bad_current, 32 );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let previous: i32 = 100;
        let mut current: i32 = 0;
        serialize_check!( serialize_int_relative_internal( &mut readStream, previous, &mut current ) == false );
        serialize_check!( current == 0 );        // a refused read writes nothing to the destination
    }

    // a legitimate absolute tier round trip must still succeed
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let previous: i32 = 100;
        let mut written: i32 = 100000;
        serialize_check!( serialize_int_relative_internal( &mut writeStream, previous, &mut written ) == true );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut current: i32 = 0;
        serialize_check!( serialize_int_relative_internal( &mut readStream, previous, &mut current ) == true );
        serialize_check!( current == written );
    }

    // the widest gap the domain allows: previous at the floor, current at the top. the difference
    // is 2^31 - 1, so a reader that reconstructs in a 32 bit signed width overflows on it
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let previous: i32 = 0;
        let mut written: i32 = i32::MAX;
        serialize_check!( serialize_int_relative_internal( &mut writeStream, previous, &mut written ) == true );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut current: i32 = 0;
        serialize_check!( serialize_int_relative_internal( &mut readStream, previous, &mut current ) == true );
        serialize_check!( current == written );
    }

    // every tier reconstructs current in a width that cannot wrap and refuses the read when the
    // result leaves the domain. previous sits at the top of the domain, so each tier's smallest
    // legal difference already runs past it: the read must fail and write nothing, never wrap
    {
        let differences: [i32; 6] = [ 1, 2, 7, 24, 281, 4378 ];        // the one-bit tier, then the five bounded tiers

        for d in 0..differences.len()
        {
            let mut buffer = [0u8; 8 + 8];      // + 8: read buffer allocations extend 8 bytes past the data

            let mut writeStream = WriteStream::new( &mut buffer, 8 );
            let prevWrite: i32 = 10;
            let mut curWrite: i32 = prevWrite + differences[d];
            serialize_check!( serialize_int_relative_internal( &mut writeStream, prevWrite, &mut curWrite ) == true );
            writeStream.Flush();

            let mut readStream = ReadStream::new( &buffer, 8 );
            let previous: i32 = i32::MAX;           // previous + difference is past the top of the domain
            let mut current: i32 = -1;
            serialize_check!( serialize_int_relative_internal( &mut readStream, previous, &mut current ) == false );
            serialize_check!( current == -1 );   // a refused read writes nothing to the destination
        }
    }

    // the absolute tier's 32 raw bits are UNSIGNED: a value with the top bit set is outside the
    // domain, and a reader that takes the group into a signed sequence type accepts it as negative
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let mut six_false_bools: u32 = 0;
        writeStream.SerializeBits( &mut six_false_bools, 6 );
        let mut top_bit_set: u32 = 0x80000000;
        writeStream.SerializeBits( &mut top_bit_set, 32 );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let previous: i32 = 100;
        let mut current: i32 = 0;
        serialize_check!( serialize_int_relative_internal( &mut readStream, previous, &mut current ) == false );
        serialize_check!( current == 0 );        // a refused read writes nothing to the destination
    }
}

// STANDARD.md, Reader Obligations: failure is terminal. The first refused read latches the stream,
// and every later read on it fails, consuming no bits and writing no destination, until the stream
// is re-initialized onto a new buffer. Each block below fails a stream a different way and then
// proves a read that would otherwise succeed does not.

pub fn test_read_stream_failure_is_terminal()
{
    let mut buffer = [0u8; 64 + 8];             // + 8: read buffer allocations extend 8 bytes past the data

    // a valid stream of known content: 8 bits of 0xAF, then a ranged int over [0,10]
    let mut writtenBytes: i32 = 0;
    {
        let mut writeStream = WriteStream::new( &mut buffer, 64 );
        let mut marker: u32 = 0xAF;
        writeStream.SerializeBits( &mut marker, 8 );
        writeStream.SerializeInteger( &mut { 7 }, 0, 10 );
        writeStream.Flush();
        writtenBytes = writeStream.GetBytesProcessed() as i32;
    }

    // failure before any consumption: the first read runs past the end of an empty stream
    {
        let mut readStream = ReadStream::new( &buffer, 0 );
        let mut value: u32 = 0xFFFFFFFF;
        serialize_check!( readStream.SerializeBits( &mut value, 8 ) == false );
        serialize_check!( value == 0xFFFFFFFF );
        let mut after: i32 = -1;
        serialize_check!( readStream.SerializeInteger( &mut after, 5, 5 ) == false );      // a zero bit read, which needs no bits at all
        serialize_check!( after == -1 );
    }

    // failure after partial consumption: the first read succeeds, the second runs past the end
    {
        let mut readStream = ReadStream::new( &buffer, writtenBytes as i64 );
        let mut marker: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut marker, 8 ) == true );
        serialize_check!( marker == 0xAF );
        let mut past_end: u32 = 0xFFFFFFFF;
        serialize_check!( readStream.SerializeBits( &mut past_end, 32 ) == false );
        serialize_check!( past_end == 0xFFFFFFFF );
        let mut after: u32 = 0xFFFFFFFF;
        serialize_check!( readStream.SerializeBits( &mut after, 1 ) == false );            // one bit was still available before the failure
        serialize_check!( after == 0xFFFFFFFF );
    }

    // failure on range headroom: 0xAF read as a ranged int over [0,10] is a value the range cannot hold
    {
        let mut readStream = ReadStream::new( &buffer, writtenBytes as i64 );
        let mut out_of_range: i32 = -1;
        serialize_check!( readStream.SerializeInteger( &mut out_of_range, 0, 10 ) == false );
        serialize_check!( out_of_range == -1 );
        let mut after: i32 = -1;
        serialize_check!( readStream.SerializeInteger( &mut after, 0, 255 ) == false );
        serialize_check!( after == -1 );
    }

    // failure on alignment: the padding bits after the 0xAF marker are not zero
    {
        let mut readStream = ReadStream::new( &buffer, writtenBytes as i64 );
        let mut bits: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut bits, 4 ) == true );              // leaves 4 non-zero padding bits, 0xA
        serialize_check!( readStream.SerializeAlign() == false );
        let mut after: u32 = 0xFFFFFFFF;
        serialize_check!( readStream.SerializeBits( &mut after, 4 ) == false );
        serialize_check!( after == 0xFFFFFFFF );
    }

    // failure on a malformed string: an interior NUL among the transmitted bytes
    {
        let mut stringBuffer = [0u8; 32 + 8];   // + 8: read buffer allocations extend 8 bytes past the data
        let mut stringBytes: i32 = 0;
        {
            let mut writeStream = WriteStream::new( &mut stringBuffer, 32 );
            writeStream.SerializeInteger( &mut { 3 }, 0, 15 );                                // length 3, buffer_size 16
            let payload: [u8; 3] = [ b'a', 0, b'b' ];
            writeStream.SerializeBytesConst( &payload, 3 );
            let mut trailing: u32 = 0x2A;
            writeStream.SerializeBits( &mut trailing, 8 );
            writeStream.Flush();
            stringBytes = writeStream.GetBytesProcessed() as i32;
        }

        let mut readStream = ReadStream::new( &stringBuffer, stringBytes as i64 );
        let mut string = [0u8; 16];
        serialize_check!( serialize_string_internal( &mut readStream, &mut string, 16 ) == false );
        let mut after: u32 = 0xFFFFFFFF;
        serialize_check!( readStream.SerializeBits( &mut after, 8 ) == false );             // the trailing byte is still in the stream
        serialize_check!( after == 0xFFFFFFFF );
    }

    // failure on int_relative: a reconstruction past the top of the domain
    {
        let mut relativeBuffer = [0u8; 8 + 8];  // + 8: read buffer allocations extend 8 bytes past the data
        {
            let mut writeStream = WriteStream::new( &mut relativeBuffer, 8 );
            let mut one_bit_tier: u32 = 1;
            writeStream.SerializeBits( &mut one_bit_tier, 1 );
            let mut trailing: u32 = 0x2A;
            writeStream.SerializeBits( &mut trailing, 8 );
            writeStream.Flush();
        }

        let mut readStream = ReadStream::new( &relativeBuffer, 8 );
        let previous: i32 = i32::MAX;
        let mut current: i32 = -1;
        serialize_check!( serialize_int_relative_internal( &mut readStream, previous, &mut current ) == false );
        serialize_check!( current == -1 );
        let mut after: u32 = 0xFFFFFFFF;
        serialize_check!( readStream.SerializeBits( &mut after, 8 ) == false );             // the trailing byte is still in the stream
        serialize_check!( after == 0xFFFFFFFF );
    }

    // re-initialization is what clears the latch: the same stream object reads cleanly afterwards
    {
        let mut readStream = ReadStream::new( &buffer, 0 );
        let mut value: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut value, 8 ) == false );
        readStream.Initialize( &buffer, writtenBytes as i64 );
        serialize_check!( readStream.SerializeBits( &mut value, 8 ) == true );
        serialize_check!( value == 0xAF );
    }
}

pub fn test_compressed_float_validation()
{
    // a malicious packet can encode integer values above maxIntegerValue in the bit headroom. reads must reject them.
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let mut out_of_range: u32 = 1023;                       // maxIntegerValue is 1000 for [0,10] at res 0.01 -> 10 bits
        writeStream.SerializeBits( &mut out_of_range, 10 );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut value: f32 = 0.0;
        serialize_check!( serialize_compressed_float_internal( &mut readStream, &mut value, 0.0, 10.0, 0.01 ) == false );
    }

    // huge delta / res ratios must not overflow the uint32 quantization range (undefined behavior)
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let mut written: f32 = 5000000000.0;
        serialize_check!( serialize_compressed_float_internal( &mut writeStream, &mut written, 0.0, 10000000000.0, 1.0 ) == true );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut value: f32 = 0.0;
        serialize_check!( serialize_compressed_float_internal( &mut readStream, &mut value, 0.0, 10000000000.0, 1.0 ) == true );
        serialize_check!( ( value - written ).abs() <= 4096.0 );
    }

    // writing NaN is non-conforming and asserts in debug (STANDARD.md, adopted 2026-08-15;
    // test_compressed_float_non_finite_asserts proves the assert fires). in release the
    // asserts compile out and the clamp is the backstop: a NaN value must not reach the
    // uint32 cast (clamp comparisons are all false for NaN).
    if cfg!( not( debug_assertions ) )      // #if defined( NDEBUG )
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let nan_bits: u32 = 0x7fc00000;                 // quiet NaN bit pattern, built without the NAN macro (finite-math builds reject it)
        let mut written: f32 = f32::from_bits( nan_bits );
        serialize_check!( serialize_compressed_float_internal( &mut writeStream, &mut written, 0.0, 10.0, 0.01 ) == true );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut value: f32 = -1.0;
        serialize_check!( serialize_compressed_float_internal( &mut readStream, &mut value, 0.0, 10.0, 0.01 ) == true );
        serialize_check!( value >= 0.0 && value <= 10.0 );      // NaN clamps to the low end of the range
    } // #if defined( NDEBUG )
}

// port: upstream (#if !defined( NDEBUG ) && !defined( _WIN32 )) runs fn in a forked child with stderr silenced and
// reports whether it died on a signal, which is what a fired debug assert looks like from outside. Rust has no portable
// fork, so the nearest equivalent observes the same event in process: the serialize assert hook is swapped for one that
// panics without printing, the panic message is silenced, and catch_unwind reports whether fn panicked. That works on
// Windows too, so the _WIN32 exclusion is dropped; the callers still require an assert-enabled build (debug_assertions,
// upstream's !NDEBUG). The helpers are compiled in every build. Afterwards the default assert handler is restored (there
// is no getter for the previous one)

fn serialize_test_silent_assert_handler( condition: &str, function: &str, file: &str, line: i32 )
{
    panic!( "serialize_assert failed: {}", condition );
}

pub fn serialize_test_assert_fires( function: fn() ) -> bool
{
    let _ = std::io::Write::flush( &mut std::io::stdout() );
    let _ = std::io::Write::flush( &mut std::io::stderr() );
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook( Box::new( |_| {} ) );        // the assert message is the expected outcome, not test noise
    serialize_set_assert_function( serialize_test_silent_assert_handler );
    let result = std::panic::catch_unwind( function );
    serialize_set_assert_function( serialize_default_assert_handler );
    std::panic::set_hook( previous_hook );
    result.is_err()
}

pub fn serialize_test_write_non_finite_declaration()
{
    // delta = max - min overflows float32 to +Inf: a non-conforming declaration
    let mut buffer = [0u8; 8];
    let mut writeStream = WriteStream::new( &mut buffer, 8 );
    let mut value: f32 = 0.0;
    serialize_compressed_float_internal( &mut writeStream, &mut value, -3e38, 3e38, 1.0 );
}

pub fn serialize_test_write_non_finite_value()
{
    // a NaN value over a perfectly good declaration: a non-conforming write
    let mut buffer = [0u8; 8];
    let mut writeStream = WriteStream::new( &mut buffer, 8 );
    let nan_bits: u32 = 0x7fc00000;             // quiet NaN bit pattern, built without the NAN macro (finite-math builds reject it)
    let mut value: f32 = f32::from_bits( nan_bits );
    serialize_compressed_float_internal( &mut writeStream, &mut value, 0.0, 10.0, 0.01 );
}

pub fn serialize_test_write_non_finite_value_precomputed()
{
    // the same non-conforming NaN write, through the precomputed entry point directly
    let mut buffer = [0u8; 8];
    let mut writeStream = WriteStream::new( &mut buffer, 8 );
    let nan_bits: u32 = 0x7fc00000;             // quiet NaN bit pattern, built without the NAN macro (finite-math builds reject it)
    let mut value: f32 = f32::from_bits( nan_bits );
    serialize_compressed_float_precomputed_internal( &mut writeStream, &mut value, 1000, 10, 10.0, 0.0 );
}

pub fn serialize_test_precomputed_inconsistent_bits()
{
    // a wire width that disagrees with the step count is a caller bug: the field would not
    // occupy the width every other conforming implementation of the declaration expects
    let mut buffer = [0u8; 8];
    let mut writeStream = WriteStream::new( &mut buffer, 8 );
    let mut value: f32 = 5.0;
    serialize_compressed_float_precomputed_internal( &mut writeStream, &mut value, 1000, 11, 10.0, 0.0 );
}

pub fn test_compressed_float_non_finite_asserts()
{
    // STANDARD.md, compressed_float (adopted 2026-08-15): a declaration whose delta or
    // values is not finite in float32 is non-conforming, and writing a non-finite value is
    // non-conforming -- conforming writers assert in debug builds. prove each assert fires,
    // in a forked child so the abort is observed rather than suffered.
    if cfg!( debug_assertions )
    {
        serialize_check!( serialize_test_assert_fires( serialize_test_write_non_finite_declaration ) == true );
        serialize_check!( serialize_test_assert_fires( serialize_test_write_non_finite_value ) == true );
    }
    else
    {
        // silently skipped: needs an assert-enabled build. An expected
        // skip is not information — the suite prints test names and failures only.
    }
}

pub fn test_compressed_float_precomputed_asserts()
{
    // the precomputed entry point carries the same write-side contract as
    // serialize_compressed_float (a non-finite value asserts, STANDARD.md) plus its own:
    // constants that are not what serialize_compressed_float_params derives are a caller
    // bug. prove each assert fires, in a forked child so the abort is observed rather
    // than suffered.
    if cfg!( debug_assertions )
    {
        serialize_check!( serialize_test_assert_fires( serialize_test_write_non_finite_value_precomputed ) == true );
        serialize_check!( serialize_test_assert_fires( serialize_test_precomputed_inconsistent_bits ) == true );
    }
    else
    {
        // silently skipped: needs an assert-enabled build. An expected
        // skip is not information — the suite prints test names and failures only.
    }
}

pub fn test_compressed_float_precomputed_validation()
{
    // the constants serialize_compressed_float derives on every call, derived once instead:
    // the precomputed read path must refuse the same smuggled integers and accept the same
    // conforming ones as the derive-per-call path.
    let mut max_integer_value: u32 = 0;
    let mut bits: i32 = 0;
    let mut delta: f32 = 0.0;
    serialize_compressed_float_params( 0.0, 10.0, 0.01, &mut max_integer_value, &mut bits, &mut delta );
    serialize_check!( max_integer_value == 1000 );
    serialize_check!( bits == 10 );
    serialize_check!( delta == 10.0f32 );

    // a malicious packet can encode integer values above max_integer_value in the bit headroom. reads must reject them.
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let mut out_of_range: u32 = 1023;                       // max_integer_value is 1000 for [0,10] at res 0.01 -> 10 bits
        writeStream.SerializeBits( &mut out_of_range, 10 );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut value: f32 = 0.0;
        serialize_check!( serialize_compressed_float_precomputed_internal( &mut readStream, &mut value, max_integer_value, bits, delta, 0.0 ) == false );
    }

    // the highest conforming integer still decodes
    {
        let mut buffer = [0u8; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let mut top_of_range: u32 = 1000;
        writeStream.SerializeBits( &mut top_of_range, 10 );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 8 );
        let mut value: f32 = 0.0;
        serialize_check!( serialize_compressed_float_precomputed_internal( &mut readStream, &mut value, max_integer_value, bits, delta, 0.0 ) == true );
        serialize_check!( value == 10.0f32 );                  // 1000 / 1000 * 10 + 0: exact at the top of the range
    }
}

// Fixed point test helpers. Every configuration in the matrix runs the same case list, and every
// round trip also runs the measure stream and requires exact agreement with the write stream:
// fixed point serialization involves no alignment, so measure is exact, not just conservative.

// port: the operations the C++ templates below perform on Storage implicitly, spelled as a trait bound. Implemented for
// every fixed point storage type with the arithmetic operators: the native integers and the emulated 128 bit pair.
// Storage( x ) of an int64_t is FixedPointInteger::from_i64. Native arithmetic wraps like the C++ (overflow-checks off)
pub trait SerializeTestFixedStorage: FixedPointInteger + PartialEq + std::fmt::Debug + Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> + Div<Output = Self> {}

impl<T> SerializeTestFixedStorage for T where T: FixedPointInteger + PartialEq + std::fmt::Debug + Add<Output = T> + Sub<Output = T> + Mul<Output = T> + Div<Output = T> {}

pub fn check_fixed_round_trip<const IntegerBits: i32, const FractionalBits: i32, const MinUnits: i64, const MaxUnits: i64, Storage: SerializeTestFixedStorage>( raw_value: Storage )
{
    let mut buffer = [0u8; 32 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

    let mut writeStream = WriteStream::new( &mut buffer, 32 );
    let mut written: Storage = raw_value;
    serialize_check!( ( serialize_fixed_internal::<IntegerBits, FractionalBits, MinUnits, MaxUnits, _, Storage>( &mut writeStream, &mut written ) ) == true );
    writeStream.Flush();

    let mut measureStream = MeasureStream::new();
    let mut measured: Storage = raw_value;
    serialize_check!( ( serialize_fixed_internal::<IntegerBits, FractionalBits, MinUnits, MaxUnits, _, Storage>( &mut measureStream, &mut measured ) ) == true );
    serialize_check!( measureStream.GetBitsProcessed() == writeStream.GetBitsProcessed() );

    let bytesProcessed = writeStream.GetBytesProcessed();
    let mut readStream = ReadStream::new( &buffer, bytesProcessed );
    let mut read_back: Storage = Storage::from_i64( 0 );
    serialize_check!( ( serialize_fixed_internal::<IntegerBits, FractionalBits, MinUnits, MaxUnits, _, Storage>( &mut readStream, &mut read_back ) ) == true );
    serialize_check!( read_back == raw_value );
}

pub fn check_fixed_cases<const IntegerBits: i32, const FractionalBits: i32, const MinUnits: i64, const MaxUnits: i64, Storage: SerializeTestFixedStorage>( one_unit: Storage )
{
    // the multiplications keep the Storage typed operand on the left, so the emulated 128 bit
    // types (member operators only) work as Storage here too
    let raw_min: Storage = one_unit * Storage::from_i64( MinUnits );
    let raw_max: Storage = one_unit * Storage::from_i64( MaxUnits );

    let one: Storage = Storage::from_i64( 1 );

    // exact raw bounds, and one raw step inside each
    check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( raw_min );
    check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( raw_max );
    check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( raw_min + one );
    check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( raw_max - one );

    // whole unit values one unit inside each bound
    check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( one_unit * Storage::from_i64( MinUnits + 1 ) );
    check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( one_unit * Storage::from_i64( MaxUnits - 1 ) );

    // a value with every fraction bit set
    check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( raw_min + one_unit - one );

    // the middle of the range, computed without overflowing the storage type
    check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( raw_min / Storage::from_i64( 2 ) + raw_max / Storage::from_i64( 2 ) );

    // zero, one and minus one whole units, where the bounds allow them
    if MinUnits <= 0 && MaxUnits >= 0
    {
        check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( Storage::from_i64( 0 ) );
    }
    if MinUnits <= 1 && MaxUnits >= 1
    {
        check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( one_unit );
    }
    if MinUnits <= -1 && MaxUnits >= -1
    {
        check_fixed_round_trip::<IntegerBits, FractionalBits, MinUnits, MaxUnits, Storage>( Storage::from_i64( 0 ) - one_unit );
    }
}

pub fn check_fixed_rejects_out_of_range<const IntegerBits: i32, const FractionalBits: i32, const MinUnits: i64, const MaxUnits: i64, Storage: SerializeTestFixedStorage>( _: Storage )
{
    // recompute the wire parameters independently of the codec, then hand build a stream encoding
    // an offset of exactly raw_range + 1: one raw step past raw_max, smuggled into the bit headroom
    let raw_range: u64 = ( MaxUnits as u64 ).wrapping_shl( FractionalBits as u32 ).wrapping_sub( ( MinUnits as u64 ).wrapping_shl( FractionalBits as u32 ) );
    let bits: i32 = bits_required64( 0, raw_range );

    let max_encodable: u64 = if bits < 64 { ( 1u64 << bits ) - 1 } else { 0xFFFFFFFFFFFFFFFF };
    if raw_range == max_encodable
    {
        return;                             // no headroom: every encoding decodes in range for this configuration
    }

    let smuggled: u64 = raw_range + 1;

    let mut buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

    let mut writeStream = WriteStream::new( &mut buffer, 16 );
    if bits <= 32
    {
        writeStream.SerializeBits( &mut ( smuggled as u32 ), bits );
    }
    else
    {
        writeStream.SerializeBits( &mut ( ( smuggled & 0xFFFFFFFF ) as u32 ), 32 );
        writeStream.SerializeBits( &mut ( ( smuggled >> 32 ) as u32 ), bits - 32 );
    }
    writeStream.Flush();

    let mut readStream = ReadStream::new( &buffer, 16 );
    let mut value: Storage = Storage::from_i64( 0 );
    serialize_check!( ( serialize_fixed_internal::<IntegerBits, FractionalBits, MinUnits, MaxUnits, _, Storage>( &mut readStream, &mut value ) ) == false );
}

pub fn test_serialize_fixed()
{
    // the storage x Q format matrix. every configuration runs the full case list in check_fixed_cases:
    // exact raw bounds, one raw step inside each, whole unit values inside each bound, all fraction
    // bits set, the middle of the range, and zero / +1.0 / -1.0 units where the bounds allow them.

    // int16_t
    check_fixed_cases::<8, 8, { -100 }, 100, i16>( 256 );
    check_fixed_cases::<12, 4, { -2000 }, 2000, i16>( 16 );

    // int32_t
    check_fixed_cases::<16, 16, { -30000 }, 30000, i32>( 65536 );
    check_fixed_cases::<24, 8, { -8000000 }, 8000000, i32>( 256 );
    check_fixed_cases::<32, 0, { -100000 }, 100000, i32>( 1 );                                 // pure integer Q: fraction_bits == 0 is legal

    // int64_t
    check_fixed_cases::<48, 16, { -100000000000 }, 100000000000, i64>( 65536 );
    check_fixed_cases::<32, 32, { -1000000 }, 1000000, i64>( 1i64 << 32 );
    check_fixed_cases::<64, 0, { -5000000000 }, 5000000000, i64>( 1 );                     // pure integer Q at full width

    // unsigned storage
    check_fixed_cases::<16, 0, 0, 60000, u16>( 1 );
    check_fixed_cases::<16, 16, 0, 60000, u32>( 65536 );
    check_fixed_cases::<48, 16, 0, 1000000000, u64>( 65536 );

    // single unit range: the whole wire is the fractional part
    check_fixed_cases::<16, 16, 0, 1, i32>( 65536 );

    // asymmetric bounds
    check_fixed_cases::<48, 16, { -3 }, 100000, i64>( 65536 );

    // the wire cost is a compile time constant of the call site. pin a few
    {
        let mut buffer = [0u8; 16];
        let mut stream = WriteStream::new( &mut buffer, 16 );
        let mut value: i64 = 12345i64 * 65536 + 32768;                                       // 12345.5 in Q48.16
        serialize_check!( ( serialize_fixed_internal::<48, 16, { -100000 }, 100000, _, _>( &mut stream, &mut value ) ) == true );
        serialize_check!( stream.GetBitsProcessed() == 34 );         // 200000 << 16 raw values needs 34 bits
    }
    {
        let mut buffer = [0u8; 8];
        let mut stream = WriteStream::new( &mut buffer, 8 );
        let mut value: i32 = 65536 / 2;                                                              // 0.5 in Q16.16
        serialize_check!( ( serialize_fixed_internal::<16, 16, 0, 1, _, _>( &mut stream, &mut value ) ) == true );
        serialize_check!( stream.GetBitsProcessed() == 17 );         // 1 << 16 raw values needs 17 bits
    }
    {
        let mut buffer = [0u8; 8];
        let mut stream = WriteStream::new( &mut buffer, 8 );
        let mut value: i16 = -832;                                                                   // -3.25 in Q8.8
        serialize_check!( ( serialize_fixed_internal::<8, 8, { -100 }, 100, _, _>( &mut stream, &mut value ) ) == true );
        serialize_check!( stream.GetBitsProcessed() == 16 );         // 200 << 8 raw values needs 16 bits
    }

    // compile time refusals. each of the following fails with a serialize_static_assert, which is the point.
    // kept as comments because a compile failure can't run inside the suite: uncomment one to verify.
    // port: the same refusals, spelled in Rust. They fail when the call is monomorphized (cargo build, not cargo check)
    //
    //     let mut value: i32 = 0;
    //     serialize_fixed_internal::<16, 8, 0, 100, _, _>( &mut stream, &mut value );                 // 16 + 8 != 32: the Q format doesn't fill the storage type
    //     serialize_fixed_internal::<16, 16, { -40000 }, 40000, _, _>( &mut stream, &mut value );     // bounds exceed the Q16.16 whole unit capacity [-32768,32767]
    //     serialize_fixed_internal::<16, 16, 200, 100, _, _>( &mut stream, &mut value );              // min must not exceed max (min == max is LEGAL: zero bits, see test_serialize_fixed_degenerate)
    //     let mut not_an_integer: f32 = 0.0;
    //     serialize_fixed_internal::<16, 16, 0, 100, _, _>( &mut stream, &mut not_an_integer );       // storage must be an integer type (f32 has no FixedPointInteger impl)
    //     let runtime_bound = 100;
    //     serialize_fixed!( &mut stream, value, 16, 16, 0, runtime_bound );                           // bounds must be compile time constants
}

pub fn test_serialize_fixed_validation()
{
    // a malicious packet can smuggle a raw value past raw_max into the bit headroom of the offset
    // encoding. reads must reject one raw step past the top of the range, on every configuration
    // in the matrix that has headroom.
    check_fixed_rejects_out_of_range::<8, 8, { -100 }, 100, i16>( 0 );
    check_fixed_rejects_out_of_range::<12, 4, { -2000 }, 2000, i16>( 0 );
    check_fixed_rejects_out_of_range::<16, 16, { -30000 }, 30000, i32>( 0 );
    check_fixed_rejects_out_of_range::<24, 8, { -8000000 }, 8000000, i32>( 0 );
    check_fixed_rejects_out_of_range::<32, 0, { -100000 }, 100000, i32>( 0 );
    check_fixed_rejects_out_of_range::<48, 16, { -100000000000 }, 100000000000, i64>( 0 );
    check_fixed_rejects_out_of_range::<32, 32, { -1000000 }, 1000000, i64>( 0 );
    check_fixed_rejects_out_of_range::<64, 0, { -5000000000 }, 5000000000, i64>( 0 );
    check_fixed_rejects_out_of_range::<16, 0, 0, 60000, u16>( 0 );
    check_fixed_rejects_out_of_range::<16, 16, 0, 60000, u32>( 0 );
    check_fixed_rejects_out_of_range::<48, 16, 0, 1000000000, u64>( 0 );
    check_fixed_rejects_out_of_range::<16, 16, 0, 1, i32>( 0 );
    check_fixed_rejects_out_of_range::<48, 16, { -3 }, 100000, i64>( 0 );

    // reads past the end of the buffer must fail cleanly
    {
        let buffer = [0u8; 4 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut readStream = ReadStream::new( &buffer, 2 );
        let mut value: i64 = 0;
        serialize_check!( ( serialize_fixed_internal::<48, 16, { -100000000000 }, 100000000000, _, _>( &mut readStream, &mut value ) ) == false );
    }
}

pub fn test_serialize_fixed_matches_int64()
{
    // fraction_bits == 0 is pure integer Q, and for storage of 64 bits or fewer the fixed point
    // wire format is byte identical to serialize_int64 of the raw value over the raw bounds.
    // sweep values and require identical bytes and identical bit counts: this equivalence binds
    // the new path to the proven one.

    let values: [i64; 8] = [ -5000000000, -4999999999, -1, 0, 1, 12345678, 4999999999, 5000000000 ];

    for i in 0..values.len()
    {
        // > 32 bit range: the two group path
        let mut fixed_buffer = [0u8; 16];
        let mut fixedStream = WriteStream::new( &mut fixed_buffer, 16 );
        let mut fixed_value: i64 = values[i];
        serialize_check!( ( serialize_fixed_internal::<64, 0, { -5000000000 }, 5000000000, _, _>( &mut fixedStream, &mut fixed_value ) ) == true );
        fixedStream.Flush();

        let mut int64_buffer = [0u8; 16];
        let mut int64Stream = WriteStream::new( &mut int64_buffer, 16 );
        serialize_check!( int64Stream.SerializeInteger64( &mut { values[i] }, -5000000000, 5000000000 ) == true );
        int64Stream.Flush();

        serialize_check!( fixedStream.GetBitsProcessed() == int64Stream.GetBitsProcessed() );
        serialize_check!( fixed_buffer == int64_buffer );
    }

    // <= 32 bit range: the single group path, on 32 bit storage
    let narrow_values: [i32; 8] = [ -100000, -99999, -1, 0, 1, 54321, 99999, 100000 ];

    for i in 0..narrow_values.len()
    {
        let mut fixed_buffer = [0u8; 16];
        let mut fixedStream = WriteStream::new( &mut fixed_buffer, 16 );
        let mut fixed_value: i32 = narrow_values[i];
        serialize_check!( ( serialize_fixed_internal::<32, 0, { -100000 }, 100000, _, _>( &mut fixedStream, &mut fixed_value ) ) == true );
        fixedStream.Flush();

        let mut int64_buffer = [0u8; 16];
        let mut int64Stream = WriteStream::new( &mut int64_buffer, 16 );
        serialize_check!( int64Stream.SerializeInteger64( &mut ( narrow_values[i] as i64 ), -100000, 100000 ) == true );
        int64Stream.Flush();

        serialize_check!( fixedStream.GetBitsProcessed() == int64Stream.GetBitsProcessed() );
        serialize_check!( fixed_buffer == int64_buffer );
    }

    // the equivalence is not limited to fraction_bits == 0: for any Q format the wire is
    // serialize_int64 of the raw value over the raw bounds. fixed point adds no wire structure,
    // only the compile time scaling convention.
    let q16_16_raw_values: [i32; 6] = [ -30000 * 65536, -( 3 * 65536 + 16384 ), 0, 65536 / 2, 12345 * 65536 + 1, 30000 * 65536 ];

    for i in 0..q16_16_raw_values.len()
    {
        let mut fixed_buffer = [0u8; 16];
        let mut fixedStream = WriteStream::new( &mut fixed_buffer, 16 );
        let mut fixed_value: i32 = q16_16_raw_values[i];
        serialize_check!( ( serialize_fixed_internal::<16, 16, { -30000 }, 30000, _, _>( &mut fixedStream, &mut fixed_value ) ) == true );
        fixedStream.Flush();

        let mut int64_buffer = [0u8; 16];
        let mut int64Stream = WriteStream::new( &mut int64_buffer, 16 );
        serialize_check!( int64Stream.SerializeInteger64( &mut ( q16_16_raw_values[i] as i64 ), -30000i64 * 65536, 30000i64 * 65536 ) == true );
        int64Stream.Flush();

        serialize_check!( fixedStream.GetBitsProcessed() == int64Stream.GetBitsProcessed() );
        serialize_check!( fixed_buffer == int64_buffer );
    }
}

pub fn check_fixed_wide_rejects_out_of_range<const IntegerBits: i32, const FractionalBits: i32, const MinUnits: i64, const MaxUnits: i64, Storage: SerializeTestFixedStorage>( _: Storage )
{
    // recompute the wire parameters independently of the codec, then hand build a stream encoding
    // an offset of exactly raw_range + 1: one raw step past raw_max, smuggled into the bit headroom
    let raw_min: uint128_t = ( ( MinUnits as int128_t ) as uint128_t ) << FractionalBits;
    let raw_max: uint128_t = ( ( MaxUnits as int128_t ) as uint128_t ) << FractionalBits;
    let raw_range: uint128_t = raw_max.wrapping_sub( raw_min );

    let mut bits: i32 = 0;
    let mut x: uint128_t = raw_range;
    while x != 0
    {
        bits += 1;
        x >>= 1;
    }

    let max_encodable: uint128_t = if bits < 128 { ( ( 1 as uint128_t ) << bits ) - 1 } else { !( 0 as uint128_t ) };
    if raw_range == max_encodable
    {
        return;                             // no headroom: every encoding decodes in range for this configuration
    }

    let mut smuggled: uint128_t = raw_range + 1;

    let mut buffer = [0u8; 24 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

    let mut writeStream = WriteStream::new( &mut buffer, 24 );
    let mut bits_left: i32 = bits;
    while bits_left > 0
    {
        let group_bits: i32 = if bits_left < 32 { bits_left } else { 32 };
        writeStream.SerializeBits( &mut ( ( ( smuggled as u64 ) & 0xFFFFFFFF ) as u32 ), group_bits );
        smuggled >>= group_bits;
        bits_left -= group_bits;
    }
    writeStream.Flush();

    let mut readStream = ReadStream::new( &buffer, 24 );
    let mut value: Storage = Storage::from_i64( 0 );
    serialize_check!( ( serialize_fixed_internal::<IntegerBits, FractionalBits, MinUnits, MaxUnits, _, Storage>( &mut readStream, &mut value ) ) == false );
}

pub fn test_serialize_fixed_wide()
{
    // #if defined(__SIZEOF_INT128__)
    // port: Rust always has native 128 bit integers, so the native only pieces always run
    // compile time bit counts in the 128 bit domain. the metafunction needs native __int128
    // template parameters, so these checks are the one native only piece of this test
    serialize_check!( ( BitsRequired128::<0, 0>::result ) == 0 );
    serialize_check!( ( BitsRequired128::<0, 1>::result ) == 1 );
    serialize_check!( ( BitsRequired128::<0, { ( 1 as uint128_t ) << 64 }>::result ) == 65 );
    serialize_check!( ( BitsRequired128::<0, { !( 0 as uint128_t ) }>::result ) == 128 );
    // #endif // #if defined(__SIZEOF_INT128__)

    // the matrix, wide: Q112.16 with a raw range past 64 bits (three groups on the wire), Q112.16
    // with a small range (a single group on wide storage), Q64.64 (the fraction alone spans 64 bits),
    // Q64.64 over the full unit range (128 bits on the wire, four groups), and the unsigned wide case.
    check_fixed_cases::<112, 16, { -1152921504606846976 }, 1152921504606846976, int128_t>( 65536 );     // ±2^60 units: 78 bits on the wire
    check_fixed_cases::<112, 16, { -2 }, 2, int128_t>( 65536 );
    check_fixed_cases::<64, 64, { -1000 }, 1000, int128_t>( ( 1 as int128_t ) << 64 );
    check_fixed_cases::<64, 64, { i64::MIN }, { i64::MAX }, int128_t>( ( 1 as int128_t ) << 64 );                              // full unit range: 128 bits on the wire
    check_fixed_cases::<112, 16, 0, 2305843009213693952, uint128_t>( 65536 );                          // 2^61 units, unsigned

    // the 33..64 bit two group band on wide storage: both boundaries exactly, plus the example's
    // own Q112.16 ±1e11 shape (54 bits), which used to live only in example.cpp and not in CI
    check_fixed_cases::<112, 16, { -32768 }, 32768, int128_t>( 65536 );                                     // 33 bits: the band's low edge
    check_fixed_cases::<112, 16, { -100000000000 }, 100000000000, int128_t>( 65536 );                   // 54 bits: the example's shape
    check_fixed_cases::<112, 16, { -140737488355328 }, 140737488355327, int128_t>( 65536 );             // 64 bits: the band's high edge

    // the wire cost is a compile time constant of the call site, wide paths included. pin a few
    {
        let mut buffer = [0u8; 16];
        let mut stream = WriteStream::new( &mut buffer, 16 );
        let mut value: int128_t = ( 12345 as int128_t ) * 65536;
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -1152921504606846976 }, 1152921504606846976, _, _>( &mut stream, &mut value ) ) == true );
        serialize_check!( stream.GetBitsProcessed() == 78 );         // 2^61 << 16 raw values needs 78 bits
    }
    {
        let mut buffer = [0u8; 24];
        let mut stream = WriteStream::new( &mut buffer, 24 );
        let mut value: int128_t = 0;
        serialize_check!( ( serialize_fixed_internal::<64, 64, { i64::MIN }, { i64::MAX }, _, _>( &mut stream, &mut value ) ) == true );
        serialize_check!( stream.GetBitsProcessed() == 128 );        // the full unit range costs the full storage width
    }
    {
        let mut buffer = [0u8; 16];
        let mut stream = WriteStream::new( &mut buffer, 16 );
        let mut value: int128_t = ( 12345678901 as int128_t ) * ( 65536 as int128_t );
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -100000000000 }, 100000000000, _, _>( &mut stream, &mut value ) ) == true );
        serialize_check!( stream.GetBitsProcessed() == 54 );         // the example's shape: 2e11 << 16 raw values needs 54 bits, inside the two group band
    }
    {
        let mut buffer = [0u8; 16];
        let mut stream = WriteStream::new( &mut buffer, 16 );
        let mut value: int128_t = 0;
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -32768 }, 32768, _, _>( &mut stream, &mut value ) ) == true );
        serialize_check!( stream.GetBitsProcessed() == 33 );         // the band's low edge
    }
    {
        let mut buffer = [0u8; 16];
        let mut stream = WriteStream::new( &mut buffer, 16 );
        let mut value: int128_t = 0;
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -140737488355328 }, 140737488355327, _, _>( &mut stream, &mut value ) ) == true );
        serialize_check!( stream.GetBitsProcessed() == 64 );         // the band's high edge
    }

    // one raw step past raw_max must be rejected on read, through every group structure —
    // the 33..64 bit two group band included
    check_fixed_wide_rejects_out_of_range::<112, 16, { -1152921504606846976 }, 1152921504606846976, int128_t>( 0 );
    check_fixed_wide_rejects_out_of_range::<112, 16, { -2 }, 2, int128_t>( 0 );
    check_fixed_wide_rejects_out_of_range::<64, 64, { -1000 }, 1000, int128_t>( 0 );
    check_fixed_wide_rejects_out_of_range::<112, 16, 0, 2305843009213693952, uint128_t>( 0 );
    check_fixed_wide_rejects_out_of_range::<112, 16, { -32768 }, 32768, int128_t>( 0 );
    check_fixed_wide_rejects_out_of_range::<112, 16, { -100000000000 }, 100000000000, int128_t>( 0 );
    check_fixed_wide_rejects_out_of_range::<112, 16, { -140737488355328 }, 140737488355327, int128_t>( 0 );

    // reads past the end of the buffer must fail cleanly
    {
        let buffer = [0u8; 4 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut readStream = ReadStream::new( &buffer, 4 );
        let mut value: int128_t = 0;
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -1152921504606846976 }, 1152921504606846976, _, _>( &mut readStream, &mut value ) ) == false );
    }
}

pub fn test_serialize_fixed_wide_emulated()
{
    // the wide codec is representation generic: the emulated 128 bit pair works as storage, which
    // is what makes wide fixed point available on compilers without native __int128. run the wide
    // case list through the emulated types explicitly, on every platform — where native exists
    // this doubles as proof that both representations drive the same codec.
    check_fixed_cases::<112, 16, { -1152921504606846976 }, 1152921504606846976, serialize_int128_t>( serialize_int128_t::from( 65536 ) );
    check_fixed_cases::<112, 16, { -2 }, 2, serialize_int128_t>( serialize_int128_t::from( 65536 ) );
    check_fixed_cases::<64, 64, { -1000 }, 1000, serialize_int128_t>( serialize_int128_t::from( 1 ) << 64 );
    check_fixed_cases::<64, 64, { i64::MIN }, { i64::MAX }, serialize_int128_t>( serialize_int128_t::from( 1 ) << 64 );
    check_fixed_cases::<112, 16, 0, 2305843009213693952, serialize_uint128_t>( serialize_uint128_t::from( 65536 ) );

    // the 33..64 bit two group band on emulated wide storage: both boundaries and the example's shape
    check_fixed_cases::<112, 16, { -32768 }, 32768, serialize_int128_t>( serialize_int128_t::from( 65536 ) );
    check_fixed_cases::<112, 16, { -100000000000 }, 100000000000, serialize_int128_t>( serialize_int128_t::from( 65536 ) );
    check_fixed_cases::<112, 16, { -140737488355328 }, 140737488355327, serialize_int128_t>( serialize_int128_t::from( 65536 ) );

    // one raw step past raw_max must be rejected through the emulated read path too
    check_fixed_wide_rejects_out_of_range::<112, 16, { -1152921504606846976 }, 1152921504606846976, serialize_int128_t>( serialize_int128_t::from( 0 ) );
    check_fixed_wide_rejects_out_of_range::<64, 64, { -1000 }, 1000, serialize_int128_t>( serialize_int128_t::from( 0 ) );
    check_fixed_wide_rejects_out_of_range::<112, 16, 0, 2305843009213693952, serialize_uint128_t>( serialize_uint128_t::from( 0 ) );
    check_fixed_wide_rejects_out_of_range::<112, 16, { -32768 }, 32768, serialize_int128_t>( serialize_int128_t::from( 0 ) );
    check_fixed_wide_rejects_out_of_range::<112, 16, { -100000000000 }, 100000000000, serialize_int128_t>( serialize_int128_t::from( 0 ) );
    check_fixed_wide_rejects_out_of_range::<112, 16, { -140737488355328 }, 140737488355327, serialize_int128_t>( serialize_int128_t::from( 0 ) );

    // #if defined(__SIZEOF_INT128__)
    // port: always (Rust always has native 128 bit integers)
    // cross representation wire identity: native and emulated storage must produce byte identical
    // wire through the same configuration, and each must read the other's bytes back exactly
    {
        let raw: i64 = -( 54321i64 * 65536 + 12345 );

        let mut native_buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data
        let mut nativeStream = WriteStream::new( &mut native_buffer, 16 );
        let mut native_value: int128_t = raw as int128_t;
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -1152921504606846976 }, 1152921504606846976, _, _>( &mut nativeStream, &mut native_value ) ) == true );
        nativeStream.Flush();

        let mut emulated_buffer = [0u8; 16 + 8];
        let mut emulatedStream = WriteStream::new( &mut emulated_buffer, 16 );
        let mut emulated_value = serialize_int128_t::from( raw );
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -1152921504606846976 }, 1152921504606846976, _, _>( &mut emulatedStream, &mut emulated_value ) ) == true );
        emulatedStream.Flush();

        serialize_check!( nativeStream.GetBitsProcessed() == emulatedStream.GetBitsProcessed() );
        let nativeBytesProcessed = nativeStream.GetBytesProcessed();        // port: read before the buffer compare below (the stream borrows the buffer)
        serialize_check!( native_buffer[..16] == emulated_buffer[..16] );

        // read the native bytes back through emulated storage
        let mut readStream = ReadStream::new( &native_buffer, nativeBytesProcessed );
        let mut read_back = serialize_int128_t::from( 0 );
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -1152921504606846976 }, 1152921504606846976, _, _>( &mut readStream, &mut read_back ) ) == true );
        serialize_check!( read_back == serialize_int128_t::from( raw ) );
    }
    // #endif // #if defined(__SIZEOF_INT128__)
}

pub fn test_serialize_fixed_degenerate()
{
    // STANDARD.md: a degenerate range where min == max is LEGAL and costs ZERO
    // BITS on every storage width -- nothing is written, and the reader
    // recovers the value from the range alone: the raw value min << fraction_bits.
    //
    // The wide path is why this test exists (serialize#54): ports computed the
    // wide bit count as bits_required( min, max ) + fraction_bits, which
    // degenerates to fraction_bits ZEROS when min == max while their narrow
    // paths wrote nothing -- the same library disagreeing with itself across
    // the 64/128 storage boundary. This library refused to compile the case
    // outright (static assert min < max), stricter than the format. Both
    // paths must write zero bits, and this test pins each of them.

    // narrow storage: Q16.16
    {
        let mut buffer = [0u8; 16];

        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let mut degenerate: i32 = 5 * 65536;                              // 5.0 in Q16.16: the raw value IS min << 16
        let mut after: i32 = 3;
        serialize_check!( ( serialize_fixed_internal::<16, 16, 5, 5, _, _>( &mut writeStream, &mut degenerate ) ) == true );
        serialize_check!( writeStream.GetBitsProcessed() == 0 );      // nothing written
        serialize_check!( writeStream.SerializeInteger( &mut after, 0, 7 ) );
        serialize_check!( writeStream.GetBitsProcessed() == 3 );      // the NEXT field starts at bit 0
        writeStream.Flush();

        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        let mut read_degenerate: i32 = 0;
        let mut read_after: i32 = 0;
        serialize_check!( ( serialize_fixed_internal::<16, 16, 5, 5, _, _>( &mut readStream, &mut read_degenerate ) ) == true );
        serialize_check!( read_degenerate == 5 * 65536 );             // recovered from the range
        serialize_check!( readStream.GetBitsProcessed() == 0 );
        serialize_check!( readStream.SerializeInteger( &mut read_after, 0, 7 ) );
        serialize_check!( read_after == 3 );

        let mut measureStream = MeasureStream::new();
        let mut measured: i32 = 5 * 65536;
        serialize_check!( ( serialize_fixed_internal::<16, 16, 5, 5, _, _>( &mut measureStream, &mut measured ) ) == true );
        serialize_check!( measureStream.GetBitsProcessed() == 0 );
    }

    // narrow storage, negative degenerate bound: Q48.16 at -7.0 -- the raw min
    // is negative, and the reader must still recover it exactly
    {
        let mut buffer = [0u8; 16];

        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let mut degenerate: i64 = -7i64 * 65536;
        let mut after: i32 = 3;
        serialize_check!( ( serialize_fixed_internal::<48, 16, { -7 }, { -7 }, _, _>( &mut writeStream, &mut degenerate ) ) == true );
        serialize_check!( writeStream.GetBitsProcessed() == 0 );
        serialize_check!( writeStream.SerializeInteger( &mut after, 0, 7 ) );
        writeStream.Flush();

        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        let mut read_degenerate: i64 = 0;
        let mut read_after: i32 = 0;
        serialize_check!( ( serialize_fixed_internal::<48, 16, { -7 }, { -7 }, _, _>( &mut readStream, &mut read_degenerate ) ) == true );
        serialize_check!( read_degenerate == -7i64 * 65536 );
        serialize_check!( readStream.SerializeInteger( &mut read_after, 0, 7 ) );
        serialize_check!( read_after == 3 );
    }

    // wide storage: Q112.16 -- the path that used to cost fraction_bits zeros
    // in the ports. zero bits here, exactly like the narrow path
    {
        let mut buffer = [0u8; 16];

        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let mut degenerate: int128_t = ( 9 * 65536 ) as int128_t;  // 9.0 in Q112.16
        let mut after: i32 = 3;
        serialize_check!( ( serialize_fixed_internal::<112, 16, 9, 9, _, _>( &mut writeStream, &mut degenerate ) ) == true );
        serialize_check!( writeStream.GetBitsProcessed() == 0 );      // zero bits, NOT fraction_bits
        serialize_check!( writeStream.SerializeInteger( &mut after, 0, 7 ) );
        serialize_check!( writeStream.GetBitsProcessed() == 3 );
        writeStream.Flush();

        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        let mut read_degenerate: int128_t = 0;
        let mut read_after: i32 = 0;
        serialize_check!( ( serialize_fixed_internal::<112, 16, 9, 9, _, _>( &mut readStream, &mut read_degenerate ) ) == true );
        serialize_check!( read_degenerate == ( 9 * 65536 ) as int128_t );
        serialize_check!( readStream.GetBitsProcessed() == 0 );
        serialize_check!( readStream.SerializeInteger( &mut read_after, 0, 7 ) );
        serialize_check!( read_after == 3 );

        let mut measureStream = MeasureStream::new();
        let mut measured: int128_t = ( 9 * 65536 ) as int128_t;
        serialize_check!( ( serialize_fixed_internal::<112, 16, 9, 9, _, _>( &mut measureStream, &mut measured ) ) == true );
        serialize_check!( measureStream.GetBitsProcessed() == 0 );
    }

    // wide storage, negative degenerate bound: Q112.16 at -9.0
    {
        let mut buffer = [0u8; 16];

        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let mut degenerate: int128_t = ( -9 * 65536 ) as int128_t;
        let mut after: i32 = 3;
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -9 }, { -9 }, _, _>( &mut writeStream, &mut degenerate ) ) == true );
        serialize_check!( writeStream.GetBitsProcessed() == 0 );
        serialize_check!( writeStream.SerializeInteger( &mut after, 0, 7 ) );
        writeStream.Flush();

        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        let mut read_degenerate: int128_t = 0;
        let mut read_after: i32 = 0;
        serialize_check!( ( serialize_fixed_internal::<112, 16, { -9 }, { -9 }, _, _>( &mut readStream, &mut read_degenerate ) ) == true );
        serialize_check!( read_degenerate == ( -9 * 65536 ) as int128_t );
        serialize_check!( readStream.SerializeInteger( &mut read_after, 0, 7 ) );
        serialize_check!( read_after == 3 );
    }

    // wide storage, emulated representation: Q64.64 over min == max == 0. the
    // old wide formula would have made this 64 bits of zeros -- the fraction
    // alone spans the full 64 bit fractional field. explicitly the emulated
    // pair, so the degenerate path is proven in both representations on every
    // platform
    {
        let mut buffer = [0u8; 16];

        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let mut degenerate = serialize_int128_t::from( 0 );
        let mut after: i32 = 3;
        serialize_check!( ( serialize_fixed_internal::<64, 64, 0, 0, _, _>( &mut writeStream, &mut degenerate ) ) == true );
        serialize_check!( writeStream.GetBitsProcessed() == 0 );      // zero bits, not the 64 bit fractional field
        serialize_check!( writeStream.SerializeInteger( &mut after, 0, 7 ) );
        writeStream.Flush();

        let bytesProcessed = writeStream.GetBytesProcessed();
        let mut readStream = ReadStream::new( &buffer, bytesProcessed );
        let mut read_degenerate = serialize_int128_t::from( 1 );                   // a wrong value, so recovery is observable
        let mut read_after: i32 = 0;
        serialize_check!( ( serialize_fixed_internal::<64, 64, 0, 0, _, _>( &mut readStream, &mut read_degenerate ) ) == true );
        serialize_check!( read_degenerate == serialize_int128_t::from( 0 ) );
        serialize_check!( readStream.SerializeInteger( &mut read_after, 0, 7 ) );
        serialize_check!( read_after == 3 );
    }
}

pub fn test_serialize_uint128()
{
    // round trips across the value patterns: zero, max, each half alone, alternating bits, distinct halves
    {
        let values: [uint128_t; 6] = [
            0,
            !( 0 as uint128_t ),
            ( 0xFFFFFFFFFFFFFFFFu64 as uint128_t ) << 64,                                // high half only
            0xFFFFFFFFFFFFFFFFu64 as uint128_t,                                          // low half only
            ( ( 0xAAAAAAAAAAAAAAAAu64 as uint128_t ) << 64 ) | 0x5555555555555555u64 as uint128_t,    // alternating bits
            ( ( 0x0123456789ABCDEFu64 as uint128_t ) << 64 ) | 0xFEDCBA9876543210u64 as uint128_t,    // distinct halves
        ];

        for i in 0..values.len()
        {
            let mut buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

            let mut writeStream = WriteStream::new( &mut buffer, 16 );
            let mut written: uint128_t = values[i];
            serialize_check!( serialize_uint128_internal( &mut writeStream, &mut written ) == true );
            writeStream.Flush();

            let mut measureStream = MeasureStream::new();
            let mut measured: uint128_t = values[i];
            serialize_check!( serialize_uint128_internal( &mut measureStream, &mut measured ) == true );
            serialize_check!( measureStream.GetBitsProcessed() == writeStream.GetBitsProcessed() );
            serialize_check!( writeStream.GetBitsProcessed() == 128 );

            let bytesProcessed = writeStream.GetBytesProcessed();
            let mut readStream = ReadStream::new( &buffer, bytesProcessed );
            let mut read_back: uint128_t = 0;
            serialize_check!( serialize_uint128_internal( &mut readStream, &mut read_back ) == true );
            serialize_check!( read_back == values[i] );
        }
    }

    // cross form consistency: serialize_uint128 must be byte identical to two serialize_uint64
    // operations on the halves, low half first. this is the portability story: an implementation
    // without a 128 bit type reproduces the wire exactly with two 64 bit operations.
    {
        let low_half: u64 = 0xFEDCBA9876543210;
        let high_half: u64 = 0x0123456789ABCDEF;

        let mut uint128_buffer = [0u8; 16 + 8];
        let mut uint128Stream = WriteStream::new( &mut uint128_buffer, 16 );
        let mut value: uint128_t = ( ( high_half as uint128_t ) << 64 ) | low_half as uint128_t;
        serialize_check!( serialize_uint128_internal( &mut uint128Stream, &mut value ) == true );
        uint128Stream.Flush();

        let mut halves_buffer = [0u8; 16 + 8];
        let mut halvesStream = WriteStream::new( &mut halves_buffer, 16 );
        write_uint64!( &mut halvesStream, low_half );
        write_uint64!( &mut halvesStream, high_half );
        halvesStream.Flush();

        serialize_check!( uint128Stream.GetBitsProcessed() == halvesStream.GetBitsProcessed() );
        serialize_check!( uint128_buffer[..16] == halves_buffer[..16] );
    }

    // golden pin: the wire format for a uint128 is its 16 bytes in little endian order, low half
    // first. pinned forever. additive: the pre-existing golden test below is untouched, and this
    // pin runs on every platform — serialize::uint128_t exists everywhere, so the native and
    // emulated representations must both reproduce exactly these bytes.
    {
        static golden_uint128_bytes: [u8; 16] =
        [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01
        ];

        let golden_value: uint128_t = ( ( 0x0123456789ABCDEFu64 as uint128_t ) << 64 ) | 0xFEDCBA9876543210u64 as uint128_t;

        let mut buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        {
            let mut writeStream = WriteStream::new( &mut buffer, 16 );
            let mut written: uint128_t = golden_value;
            serialize_check!( serialize_uint128_internal( &mut writeStream, &mut written ) == true );
            writeStream.Flush();
            serialize_check!( writeStream.GetBytesProcessed() == 16 );
        }
        serialize_check!( buffer[..16] == golden_uint128_bytes[..] );

        buffer[..16].copy_from_slice( &golden_uint128_bytes );
        let mut readStream = ReadStream::new( &buffer, 16 );
        let mut read_back: uint128_t = 0;
        serialize_check!( serialize_uint128_internal( &mut readStream, &mut read_back ) == true );
        serialize_check!( read_back == golden_value );
    }
}

pub fn test_serialize_int128()
{
    // port: the local typedef i128 is serialize::int128_t, which is the primitive i128

    // 1. WIRE IDENTITY WITH serialize_int64 wherever the range fits 64 bits. this is what lets a
    //    schema widen a field without a wire change, so it is pinned by memcmp rather than assumed.
    {
        let min64: i64 = -5000000000;
        let max64: i64 = 5000000000;
        let values: [i64; 8] = [ min64, min64 + 1, -1, 0, 1, 4123456789, max64 - 1, max64 ];

        for i in 0..values.len()
        {
            let mut buffer128 = [0u8; 32 + 8];          // + 8: read buffer allocations extend 8 bytes past the data
            let mut buffer64 = [0u8; 32 + 8];

            let mut w128 = WriteStream::new( &mut buffer128, 32 );
            serialize_check!( w128.SerializeInteger128( &mut ( values[i] as i128 ), min64 as i128, max64 as i128 ) == true );
            w128.Flush();

            let mut w64 = WriteStream::new( &mut buffer64, 32 );
            serialize_check!( w64.SerializeInteger64( &mut { values[i] }, min64, max64 ) == true );
            w64.Flush();

            serialize_check!( w128.GetBitsProcessed() == w64.GetBitsProcessed() );
            serialize_check!( w128.GetBytesProcessed() == w64.GetBytesProcessed() );
            let bytes64 = w64.GetBytesProcessed() as usize;          // port: read before the buffer compare below (the stream borrows the buffer)
            serialize_check!( buffer128[..bytes64] == buffer64[..bytes64] );

            let mut readStream = ReadStream::new( &buffer128, 32 );
            let mut read_back: i128 = 0;
            serialize_check!( readStream.SerializeInteger128( &mut read_back, min64 as i128, max64 as i128 ) == true );
            serialize_check!( read_back == values[i] as i128 );
        }
    }

    // 2. the wide bands the 64 bit path cannot express at all: three group and four group ranges,
    //    including the widest possible range, which exercises the fourth group and the unsigned
    //    domain subtraction that a signed one would overflow
    {
        let wide_min: i128 = -( ( 1 as i128 ) << 100 );
        let wide_max: i128 =  ( 1 as i128 ) << 100;
        let values: [i128; 8] = [ wide_min, wide_min + 1, -1, 0, 1, ( 1 as i128 ) << 99, wide_max - 1, wide_max ];

        for i in 0..values.len()
        {
            let mut buffer = [0u8; 32 + 8];

            let mut writeStream = WriteStream::new( &mut buffer, 32 );
            serialize_check!( writeStream.SerializeInteger128( &mut { values[i] }, wide_min, wide_max ) == true );
            writeStream.Flush();
            serialize_check!( writeStream.GetBitsProcessed() == 102 );        // bits_required128( -2^100, 2^100 ) == 102

            let mut readStream = ReadStream::new( &buffer, 32 );
            let mut read_back: i128 = 0;
            serialize_check!( readStream.SerializeInteger128( &mut read_back, wide_min, wide_max ) == true );
            serialize_check!( read_back == values[i] );
        }
    }

    // 3. the full 128 bit range: every group full, and the range is wider than 2^127
    {
        let full_min: i128 = ( ( 1 as uint128_t ) << 127 ) as i128;                  // INT128_MIN
        let full_max: i128 = ( !( ( 1 as uint128_t ) << 127 ) ) as i128;             // INT128_MAX
        let values: [i128; 7] = [ full_min, full_min + 1, -1, 0, 1, full_max - 1, full_max ];

        for i in 0..values.len()
        {
            let mut buffer = [0u8; 32 + 8];

            let mut writeStream = WriteStream::new( &mut buffer, 32 );
            serialize_check!( writeStream.SerializeInteger128( &mut { values[i] }, full_min, full_max ) == true );
            writeStream.Flush();
            serialize_check!( writeStream.GetBitsProcessed() == 128 );

            let mut readStream = ReadStream::new( &buffer, 32 );
            let mut read_back: i128 = 0;
            serialize_check!( readStream.SerializeInteger128( &mut read_back, full_min, full_max ) == true );
            serialize_check!( read_back == values[i] );
        }
    }

    // 4. the measure stream must agree with the write stream exactly, at every group width
    {
        let cases: [[i128; 3]; 4] =
        [
            [ 0, 0, 255 ],
            [ 7, -5000000000, 5000000000 ],
            [ 1, -( ( 1 as i128 ) << 100 ), ( 1 as i128 ) << 100 ],
            [ 0, ( ( 1 as uint128_t ) << 127 ) as i128, ( !( ( 1 as uint128_t ) << 127 ) ) as i128 ],
        ];

        for i in 0..cases.len()
        {
            let mut buffer = [0u8; 32 + 8];

            let mut writeStream = WriteStream::new( &mut buffer, 32 );
            serialize_check!( writeStream.SerializeInteger128( &mut { cases[i][0] }, cases[i][1], cases[i][2] ) == true );
            writeStream.Flush();

            let mut measureStream = MeasureStream::new();
            serialize_check!( measureStream.SerializeInteger128( &mut { cases[i][0] }, cases[i][1], cases[i][2] ) == true );
            serialize_check!( measureStream.GetBitsProcessed() == writeStream.GetBitsProcessed() );
        }
    }

    // 5. a value outside the bounds must be REFUSED on read. the bit count is identical for both
    //    bound pairs here, so the reader consumes the same bits and the range check is what
    //    convicts it — proving the refusal, not just the absence of a crash
    {
        let mut buffer = [0u8; 32 + 8];

        let mut writeStream = WriteStream::new( &mut buffer, 32 );
        serialize_check!( writeStream.SerializeInteger128( &mut { 255 }, 0, 255 ) == true );
        writeStream.Flush();

        serialize_check!( bits_required128( 0 as uint128_t, 200 as uint128_t ) == 8 );

        let mut readStream = ReadStream::new( &buffer, 32 );
        let mut read_back: i128 = 0;
        serialize_check!( readStream.SerializeInteger128( &mut read_back, 0, 200 ) == false );
    }

    // 6. a truncated buffer must be refused rather than read past the end
    {
        let buffer = [0u8; 32 + 8];

        let mut readStream = ReadStream::new( &buffer, 4 );          // 32 bits available, 128 required
        let mut read_back: i128 = 0;
        serialize_check!( readStream.SerializeInteger128( &mut read_back, ( ( 1 as uint128_t ) << 127 ) as i128, ( !( ( 1 as uint128_t ) << 127 ) ) as i128 ) == false );
    }

    // 7. THE GOLDEN PIN, and its bytes were derived from STANDARD.md's stated rule in the
    //    conformance checker's language, not read back out of this implementation — so this
    //    memcmp is the document and the code agreeing, rather than the code agreeing with itself.
    //    Bounds of +/- 2^70 need 72 bits, which is the THREE GROUP structure: 32, 32, then 8.
    {
        static golden_int128_bytes: [u8; 12] =
        [
            0x11, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
            0x3F, 0x00, 0x00, 0x00
        ];

        let golden_min: i128 = -( ( 1 as i128 ) << 70 );
        let golden_max: i128 =  ( 1 as i128 ) << 70;
        let golden_value: i128 = -( 0x0123456789ABCDEFi64 as i128 );

        let mut buffer = [0u8; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        {
            let mut writeStream = WriteStream::new( &mut buffer, 16 );
            serialize_check!( writeStream.SerializeInteger128( &mut { golden_value }, golden_min, golden_max ) == true );
            writeStream.Flush();
            serialize_check!( writeStream.GetBitsProcessed() == 72 );
        }
        serialize_check!( buffer[..golden_int128_bytes.len()] == golden_int128_bytes[..] );

        buffer[..golden_int128_bytes.len()].copy_from_slice( &golden_int128_bytes );
        let mut readStream = ReadStream::new( &buffer, 16 );
        let mut read_back: i128 = 0;
        serialize_check!( readStream.SerializeInteger128( &mut read_back, golden_min, golden_max ) == true );
        serialize_check!( read_back == golden_value );
    }
}

// builds an emulated 128 bit value from its two lanes. the emulated type is defined on every
// platform when tests are enabled — where native __int128 exists it coexists with it, so the
// tests below run everywhere and the differential test can compare the two representations.

pub fn uint128_emulated( hi: u64, lo: u64 ) -> serialize_uint128_t
{
    let mut result = serialize_uint128_t::from( lo );
    result.hi = hi;
    result
}

pub fn test_uint128_emulation()
{
    // known answer checks for the emulated 128 bit unsigned integer, unguarded so they run on
    // every platform — including the ones with no native __int128, where the emulation is the
    // only implementation and the differential test below cannot run.

    let lo: u64 = 0xFEDCBA9876543210;
    let hi: u64 = 0x0123456789ABCDEF;

    // construction from uint64_t fills the low lane. explicit conversion truncates back to it
    {
        let value = serialize_uint128_t::from( lo );
        serialize_check!( value.lo == lo && value.hi == 0 );
        serialize_check!( u64::from( value ) == lo );
        serialize_check!( u64::from( uint128_emulated( hi, lo ) ) == lo );
    }

    // construction from every standard integer type mirrors native conversion: signed sources
    // sign extend (negatives wrap modulo 2^128), unsigned sources zero extend. these are the
    // exact cross signed cases that diverged before the per-type constructors existed.
    {
        serialize_check!( serialize_uint128_t::from( -1i64 ) == uint128_emulated( 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF ) );
        serialize_check!( serialize_uint128_t::from( i64::MIN ) == uint128_emulated( 0xFFFFFFFFFFFFFFFF, 0x8000000000000000 ) );
        serialize_check!( serialize_uint128_t::from( 1u64 << 63 ) == uint128_emulated( 0, 0x8000000000000000 ) );
        serialize_check!( serialize_uint128_t::from( u64::MAX ) == uint128_emulated( 0, 0xFFFFFFFFFFFFFFFF ) );
        serialize_check!( serialize_uint128_t::from( -5i32 ) == uint128_emulated( 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFB ) );       // int: sign extends
        serialize_check!( serialize_uint128_t::from( 3000000000u32 ) == uint128_emulated( 0, 3000000000 ) );                          // unsigned: zero extends
        serialize_check!( serialize_uint128_t::from( 7i64 ) == uint128_emulated( 0, 7 ) );                                     // non negative signed: zero high lane
    }

    // all six comparisons, driven by the high lane, the low lane, and equality
    {
        let a: serialize_uint128_t = uint128_emulated( 1, 0 );
        let b: serialize_uint128_t = uint128_emulated( 0, 0xFFFFFFFFFFFFFFFF );
        let c: serialize_uint128_t = uint128_emulated( 1, 1 );
        serialize_check!( a > b );                                       // the high lane dominates
        serialize_check!( b < a );
        serialize_check!( c > a );                                       // the low lane breaks ties
        serialize_check!( a >= b && a <= a && a >= a );
        serialize_check!( b <= a && b != a && a == a );
        serialize_check!( !( a < b ) && !( a == b ) && !( a != a ) );
    }

    // left shift edges: 0, 1, 63, 64, 65, 127, and out of range counts
    {
        let value: serialize_uint128_t = uint128_emulated( hi, lo );
        serialize_check!( ( value << 0 ) == value );
        serialize_check!( ( value << 1 ) == uint128_emulated( ( hi << 1 ) | ( lo >> 63 ), lo << 1 ) );
        serialize_check!( ( value << 63 ) == uint128_emulated( ( hi << 63 ) | ( lo >> 1 ), lo << 63 ) );
        serialize_check!( ( value << 64 ) == uint128_emulated( lo, 0 ) );                    // the low lane becomes the high lane
        serialize_check!( ( value << 65 ) == uint128_emulated( lo << 1, 0 ) );
        serialize_check!( ( value << 127 ) == uint128_emulated( lo << 63, 0 ) );
        serialize_check!( ( value << 128 ) == serialize_uint128_t::from( 0 ) );                        // >= 128 yields zero, documented
        serialize_check!( ( value << 200 ) == serialize_uint128_t::from( 0 ) );
    }

    // right shift edges: the mirror image
    {
        let value: serialize_uint128_t = uint128_emulated( hi, lo );
        serialize_check!( ( value >> 0 ) == value );
        serialize_check!( ( value >> 1 ) == uint128_emulated( hi >> 1, ( lo >> 1 ) | ( hi << 63 ) ) );
        serialize_check!( ( value >> 63 ) == uint128_emulated( hi >> 63, ( lo >> 63 ) | ( hi << 1 ) ) );
        serialize_check!( ( value >> 64 ) == uint128_emulated( 0, hi ) );                    // the high lane becomes the low lane
        serialize_check!( ( value >> 65 ) == uint128_emulated( 0, hi >> 1 ) );
        serialize_check!( ( value >> 127 ) == uint128_emulated( 0, hi >> 63 ) );
        serialize_check!( ( value >> 128 ) == serialize_uint128_t::from( 0 ) );                        // >= 128 yields zero, documented
        serialize_check!( ( value >> 200 ) == serialize_uint128_t::from( 0 ) );
    }

    // addition carries out of the low lane, subtraction borrows back into it
    {
        let max64 = serialize_uint128_t::from( 0xFFFFFFFFFFFFFFFFu64 );
        let all_ones: serialize_uint128_t = uint128_emulated( 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF );
        serialize_check!( max64 + serialize_uint128_t::from( 1 ) == uint128_emulated( 1, 0 ) );        // carry
        serialize_check!( all_ones + serialize_uint128_t::from( 1 ) == serialize_uint128_t::from( 0 ) );         // wraps modulo 2^128
        serialize_check!( serialize_uint128_t::from( 0 ) - serialize_uint128_t::from( 1 ) == all_ones );         // borrow wraps back
        serialize_check!( uint128_emulated( 1, 0 ) - serialize_uint128_t::from( 1 ) == max64 );        // borrow out of the high lane

        let mut accumulator = serialize_uint128_t::from( 0xFFFFFFFFFFFFFFFFu64 );
        accumulator += serialize_uint128_t::from( 1 );
        serialize_check!( accumulator == uint128_emulated( 1, 0 ) );
        accumulator -= serialize_uint128_t::from( 1 );
        serialize_check!( accumulator == max64 );
    }

    // increment and decrement, both forms, across the lane boundary
    // port: value++ / ++value / value-- / --value are PostIncrement / PreIncrement / PostDecrement / PreDecrement
    {
        let mut value = serialize_uint128_t::from( 0xFFFFFFFFFFFFFFFFu64 );
        serialize_check!( value.PostIncrement() == serialize_uint128_t::from( 0xFFFFFFFFFFFFFFFFu64 ) );             // post returns the value before
        serialize_check!( value == uint128_emulated( 1, 0 ) );
        serialize_check!( *value.PreIncrement() == uint128_emulated( 1, 1 ) );                             // pre returns the value after
        serialize_check!( value.PostDecrement() == uint128_emulated( 1, 1 ) );
        serialize_check!( *value.PreDecrement() == serialize_uint128_t::from( 0xFFFFFFFFFFFFFFFFu64 ) );
    }

    // multiplication: lane crossing products with known answers
    {
        let two_to_32 = serialize_uint128_t::from( 1u64 << 32 );
        let max64 = serialize_uint128_t::from( 0xFFFFFFFFFFFFFFFFu64 );
        let all_ones: serialize_uint128_t = uint128_emulated( 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF );
        serialize_check!( serialize_uint128_t::from( 3 ) * serialize_uint128_t::from( 5 ) == serialize_uint128_t::from( 15 ) );
        serialize_check!( two_to_32 * two_to_32 == uint128_emulated( 1, 0 ) );                                       // 2^64 crosses into the high lane
        serialize_check!( max64 * max64 == uint128_emulated( 0xFFFFFFFFFFFFFFFE, 1 ) );                           // 2^128 - 2^65 + 1
        serialize_check!( uint128_emulated( 1, 0 ) * serialize_uint128_t::from( 5 ) == uint128_emulated( 5, 0 ) );             // the high lane path
        serialize_check!( all_ones * all_ones == serialize_uint128_t::from( 1 ) );                                             // ( 2^128 - 1 )^2 mod 2^128

        let mut accumulator = serialize_uint128_t::from( 3 );
        accumulator *= serialize_uint128_t::from( 5 );
        serialize_check!( accumulator == serialize_uint128_t::from( 15 ) );
    }

    // division and modulo: the small fast path, wide dividends, wide divisors, and the
    // TOTALITY of division by zero — the operation is undefined and these pin only that it
    // returns rather than traps, never that the value is a contract
    {
        let all_ones: serialize_uint128_t = uint128_emulated( 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF );
        serialize_check!( serialize_uint128_t::from( 100 ) / serialize_uint128_t::from( 7 ) == serialize_uint128_t::from( 14 ) );
        serialize_check!( serialize_uint128_t::from( 100 ) % serialize_uint128_t::from( 7 ) == serialize_uint128_t::from( 2 ) );
        serialize_check!( uint128_emulated( 1, 7 ) / serialize_uint128_t::from( 16 ) == serialize_uint128_t::from( 1u64 << 60 ) );      // 2^64 + 7 over 16
        serialize_check!( uint128_emulated( 1, 7 ) % serialize_uint128_t::from( 16 ) == serialize_uint128_t::from( 7 ) );
        serialize_check!( uint128_emulated( 1u64 << 63, 0 ) / uint128_emulated( 1, 0 ) == serialize_uint128_t::from( 1u64 << 63 ) );     // 2^127 over 2^64
        serialize_check!( all_ones / serialize_uint128_t::from( 3 ) == uint128_emulated( 0x5555555555555555, 0x5555555555555555 ) );
        serialize_check!( all_ones % serialize_uint128_t::from( 3 ) == serialize_uint128_t::from( 0 ) );
        serialize_check!( serialize_uint128_t::from( 7 ) / uint128_emulated( 1, 0 ) == serialize_uint128_t::from( 0 ) );                 // dividend below divisor
        serialize_check!( serialize_uint128_t::from( 7 ) % uint128_emulated( 1, 0 ) == serialize_uint128_t::from( 7 ) );
        serialize_check!( all_ones / serialize_uint128_t::from( 0 ) == serialize_uint128_t::from( 0 ) );                                 // by zero is UNDEFINED: this pins totality, not a value contract
        serialize_check!( all_ones % serialize_uint128_t::from( 0 ) == serialize_uint128_t::from( 0 ) );

        let mut accumulator = serialize_uint128_t::from( 100 );
        accumulator /= serialize_uint128_t::from( 7 );
        serialize_check!( accumulator == serialize_uint128_t::from( 14 ) );
        accumulator = serialize_uint128_t::from( 100 );
        accumulator %= serialize_uint128_t::from( 7 );
        serialize_check!( accumulator == serialize_uint128_t::from( 2 ) );
    }

    // bitwise operators work lane by lane
    {
        let a: serialize_uint128_t = uint128_emulated( 0xF0F0F0F0F0F0F0F0, 0xAAAAAAAAAAAAAAAA );
        let b: serialize_uint128_t = uint128_emulated( 0xFF00FF00FF00FF00, 0xCCCCCCCCCCCCCCCC );
        serialize_check!( ( a & b ) == uint128_emulated( 0xF000F000F000F000, 0x8888888888888888 ) );
        serialize_check!( ( a | b ) == uint128_emulated( 0xFFF0FFF0FFF0FFF0, 0xEEEEEEEEEEEEEEEE ) );
        serialize_check!( ( a ^ b ) == uint128_emulated( 0x0FF00FF00FF00FF0, 0x6666666666666666 ) );
        serialize_check!( !a == uint128_emulated( 0x0F0F0F0F0F0F0F0F, 0x5555555555555555 ) );

        let mut accumulator: serialize_uint128_t = a;
        accumulator &= b;
        serialize_check!( accumulator == ( a & b ) );
        accumulator = a;
        accumulator |= b;
        serialize_check!( accumulator == ( a | b ) );
        accumulator = a;
        accumulator ^= b;
        serialize_check!( accumulator == ( a ^ b ) );
        accumulator = a;
        accumulator <<= 64;
        serialize_check!( accumulator == ( a << 64 ) );
        accumulator = a;
        accumulator >>= 64;
        serialize_check!( accumulator == ( a >> 64 ) );
    }

    // unary plus is the identity, unary minus is two's complement negation
    // port: Rust has no unary plus (serialize.rs does not port it), so +value is value
    {
        let value: serialize_uint128_t = uint128_emulated( hi, lo );
        serialize_check!( value == value );
        serialize_check!( -serialize_uint128_t::from( 0 ) == serialize_uint128_t::from( 0 ) );
        serialize_check!( -serialize_uint128_t::from( 1 ) == uint128_emulated( 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF ) );
        serialize_check!( -value + value == serialize_uint128_t::from( 0 ) );
    }
}

pub fn int128_emulated( hi: u64, lo: u64 ) -> serialize_int128_t
{
    let mut result = serialize_int128_t::from( 0 );
    result.hi = hi;
    result.lo = lo;
    result
}

pub fn test_int128_emulation()
{
    // known answer checks for the emulated signed 128 bit integer, unguarded so they run on every
    // platform. the signed type is a thin two's complement layer over the unsigned lanes, so these
    // concentrate on the signed specific pieces: sign extension, signed ordering, the arithmetic
    // right shift, division sign quadrants, and the documented edge choices.

    let int128_min: serialize_int128_t = int128_emulated( 0x8000000000000000, 0 );
    let int128_max: serialize_int128_t = int128_emulated( 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF );

    // the int64_t constructor sign extends into the high lane; the explicit conversion truncates
    // back to the low lane; the unsigned conversions preserve the bit pattern both ways
    {
        serialize_check!( serialize_int128_t::from( -1 ) == int128_emulated( 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF ) );
        serialize_check!( serialize_int128_t::from( i64::MIN ) == int128_emulated( 0xFFFFFFFFFFFFFFFF, 0x8000000000000000 ) );
        serialize_check!( serialize_int128_t::from( i64::MAX ) == int128_emulated( 0, 0x7FFFFFFFFFFFFFFF ) );
        serialize_check!( serialize_int128_t::from( 1 ) == int128_emulated( 0, 1 ) );
        serialize_check!( i64::from( serialize_int128_t::from( -5 ) ) == -5 );
        serialize_check!( i64::from( serialize_int128_t::from( i64::MIN ) ) == i64::MIN );

        // unsigned sources are value preserving with a zero high lane, exactly like native: a
        // uint64 with the top bit set stays a large positive value, it does NOT wrap negative.
        // these are the exact cross signed cases that diverged before the per-type constructors.
        serialize_check!( serialize_int128_t::from( 1u64 << 63 ) == int128_emulated( 0, 0x8000000000000000 ) );
        serialize_check!( serialize_int128_t::from( 1u64 << 63 ) > serialize_int128_t::from( 0 ) );
        serialize_check!( serialize_int128_t::from( u64::MAX ) == int128_emulated( 0, 0xFFFFFFFFFFFFFFFF ) );
        serialize_check!( serialize_int128_t::from( u64::MAX ) > serialize_int128_t::from( 0 ) );
        serialize_check!( serialize_int128_t::from( -5 ) == int128_emulated( 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFB ) );     // int: sign extends
        serialize_check!( serialize_int128_t::from( 3000000000u32 ) == int128_emulated( 0, 3000000000 ) );                        // unsigned: zero extends

        let bit_pattern = serialize_uint128_t::from( serialize_int128_t::from( -1 ) );
        serialize_check!( bit_pattern.lo == 0xFFFFFFFFFFFFFFFF && bit_pattern.hi == 0xFFFFFFFFFFFFFFFF );
        serialize_check!( serialize_int128_t::from( bit_pattern ) == serialize_int128_t::from( -1 ) );
    }

    // signed ordering: negatives below positives, the high lane compares signed, the low lane
    // breaks ties unsigned
    {
        serialize_check!( serialize_int128_t::from( -1 ) < serialize_int128_t::from( 0 ) );
        serialize_check!( serialize_int128_t::from( 0 ) < serialize_int128_t::from( 1 ) );
        serialize_check!( int128_min < serialize_int128_t::from( i64::MIN ) );
        serialize_check!( int128_min < serialize_int128_t::from( -1 ) );
        serialize_check!( int128_max > serialize_int128_t::from( i64::MAX ) );
        serialize_check!( int128_min < int128_max );
        serialize_check!( int128_emulated( 0xFFFFFFFFFFFFFFFF, 5 ) < int128_emulated( 0xFFFFFFFFFFFFFFFF, 7 ) );       // low lane tiebreak among negatives
        serialize_check!( serialize_int128_t::from( -3 ) <= serialize_int128_t::from( -3 ) && serialize_int128_t::from( -3 ) >= serialize_int128_t::from( -3 ) );
        serialize_check!( serialize_int128_t::from( -3 ) != serialize_int128_t::from( 3 ) );
        serialize_check!( !( serialize_int128_t::from( 1 ) < serialize_int128_t::from( -1 ) ) );
    }

    // addition, subtraction and multiplication with mixed signs, and the documented wrap
    {
        serialize_check!( serialize_int128_t::from( -3 ) + serialize_int128_t::from( 5 ) == serialize_int128_t::from( 2 ) );
        serialize_check!( serialize_int128_t::from( 3 ) - serialize_int128_t::from( 5 ) == serialize_int128_t::from( -2 ) );
        serialize_check!( serialize_int128_t::from( -3 ) * serialize_int128_t::from( 5 ) == serialize_int128_t::from( -15 ) );
        serialize_check!( serialize_int128_t::from( -3 ) * serialize_int128_t::from( -5 ) == serialize_int128_t::from( 15 ) );
        serialize_check!( int128_max + serialize_int128_t::from( 1 ) == int128_min );                          // wraps two's complement, documented
        serialize_check!( int128_min - serialize_int128_t::from( 1 ) == int128_max );
        serialize_check!( serialize_int128_t::from( i64::MAX ) * serialize_int128_t::from( 4 ) == int128_emulated( 1, 0xFFFFFFFFFFFFFFFC ) );        // crosses the lane boundary
    }

    // the arithmetic right shift fills with the sign: edges 0, 1, 63, 64, 65, 127 and out of range
    {
        serialize_check!( ( int128_min >> 0 ) == int128_min );
        serialize_check!( ( int128_min >> 1 ) == int128_emulated( 0xC000000000000000, 0 ) );
        serialize_check!( ( int128_min >> 63 ) == int128_emulated( 0xFFFFFFFFFFFFFFFF, 0 ) );                             // -2^64
        serialize_check!( ( int128_min >> 64 ) == serialize_int128_t::from( i64::MIN ) );
        serialize_check!( ( int128_min >> 65 ) == serialize_int128_t::from( i64::MIN / 2 ) );
        serialize_check!( ( int128_min >> 127 ) == serialize_int128_t::from( -1 ) );
        serialize_check!( ( int128_min >> 128 ) == serialize_int128_t::from( -1 ) );                           // all sign bits, documented
        serialize_check!( ( int128_min >> 200 ) == serialize_int128_t::from( -1 ) );
        serialize_check!( ( serialize_int128_t::from( -7 ) >> 1 ) == serialize_int128_t::from( -4 ) );                   // arithmetic shift rounds toward negative infinity
        serialize_check!( ( int128_max >> 127 ) == serialize_int128_t::from( 0 ) );
        serialize_check!( ( int128_max >> 128 ) == serialize_int128_t::from( 0 ) );                            // non negative: sign fill is zero
        serialize_check!( ( ( serialize_int128_t::from( 1 ) << 100 ) >> 100 ) == serialize_int128_t::from( 1 ) );
    }

    // the left shift moves the bit pattern like hardware: negative values included
    {
        serialize_check!( ( serialize_int128_t::from( -1 ) << 1 ) == serialize_int128_t::from( -2 ) );
        serialize_check!( ( serialize_int128_t::from( -1 ) << 64 ) == int128_emulated( 0xFFFFFFFFFFFFFFFF, 0 ) );
        serialize_check!( ( serialize_int128_t::from( 1 ) << 127 ) == int128_min );
        serialize_check!( ( serialize_int128_t::from( -1 ) << 128 ) == serialize_int128_t::from( 0 ) );                  // out of range yields zero, documented
    }

    // division and modulo: all four sign quadrants, truncation toward zero, the remainder sign
    // follows the dividend, and the documented edge choices
    {
        serialize_check!( serialize_int128_t::from( 7 ) / serialize_int128_t::from( 3 ) == serialize_int128_t::from( 2 ) );
        serialize_check!( serialize_int128_t::from( 7 ) % serialize_int128_t::from( 3 ) == serialize_int128_t::from( 1 ) );
        serialize_check!( serialize_int128_t::from( -7 ) / serialize_int128_t::from( 3 ) == serialize_int128_t::from( -2 ) );
        serialize_check!( serialize_int128_t::from( -7 ) % serialize_int128_t::from( 3 ) == serialize_int128_t::from( -1 ) );
        serialize_check!( serialize_int128_t::from( 7 ) / serialize_int128_t::from( -3 ) == serialize_int128_t::from( -2 ) );
        serialize_check!( serialize_int128_t::from( 7 ) % serialize_int128_t::from( -3 ) == serialize_int128_t::from( 1 ) );
        serialize_check!( serialize_int128_t::from( -7 ) / serialize_int128_t::from( -3 ) == serialize_int128_t::from( 2 ) );
        serialize_check!( serialize_int128_t::from( -7 ) % serialize_int128_t::from( -3 ) == serialize_int128_t::from( -1 ) );
        serialize_check!( serialize_int128_t::from( -1 ) / serialize_int128_t::from( 2 ) == serialize_int128_t::from( 0 ) );       // truncation toward zero, not the floor
        serialize_check!( serialize_int128_t::from( -1 ) % serialize_int128_t::from( 2 ) == serialize_int128_t::from( -1 ) );
        serialize_check!( int128_min / serialize_int128_t::from( 2 ) == int128_emulated( 0xC000000000000000, 0 ) );
        serialize_check!( int128_min / serialize_int128_t::from( 1 ) == int128_min );
        serialize_check!( int128_min / serialize_int128_t::from( -1 ) == int128_min );                         // the one overflowing case wraps, documented
        serialize_check!( int128_min % serialize_int128_t::from( -1 ) == serialize_int128_t::from( 0 ) );
        serialize_check!( int128_max / serialize_int128_t::from( 0 ) == serialize_int128_t::from( 0 ) );                 // by zero is UNDEFINED: this pins totality, not a value contract
        serialize_check!( int128_max % serialize_int128_t::from( 0 ) == serialize_int128_t::from( 0 ) );
    }

    // unary minus is two's complement negation; ~ and the bitwise operators work on the pattern
    // port: Rust has no unary plus, so +x is x
    {
        serialize_check!( -serialize_int128_t::from( 5 ) == serialize_int128_t::from( -5 ) );
        serialize_check!( -serialize_int128_t::from( -5 ) == serialize_int128_t::from( 5 ) );
        serialize_check!( -int128_min == int128_min );                                               // -INT128_MIN wraps to itself, documented
        serialize_check!( serialize_int128_t::from( -5 ) == serialize_int128_t::from( -5 ) );
        serialize_check!( !serialize_int128_t::from( 0 ) == serialize_int128_t::from( -1 ) );
        serialize_check!( ( serialize_int128_t::from( -1 ) & serialize_int128_t::from( 5 ) ) == serialize_int128_t::from( 5 ) );
        serialize_check!( ( serialize_int128_t::from( 0 ) | serialize_int128_t::from( -1 ) ) == serialize_int128_t::from( -1 ) );
        serialize_check!( ( serialize_int128_t::from( -1 ) ^ serialize_int128_t::from( -1 ) ) == serialize_int128_t::from( 0 ) );
    }

    // increment and decrement, both forms, across zero and across the lane boundary
    {
        let mut value = serialize_int128_t::from( -1 );
        serialize_check!( *value.PreIncrement() == serialize_int128_t::from( 0 ) );
        serialize_check!( value.PostIncrement() == serialize_int128_t::from( 0 ) );
        serialize_check!( value == serialize_int128_t::from( 1 ) );
        serialize_check!( *value.PreDecrement() == serialize_int128_t::from( 0 ) );
        serialize_check!( value.PostDecrement() == serialize_int128_t::from( 0 ) );
        serialize_check!( value == serialize_int128_t::from( -1 ) );

        let mut boundary: serialize_int128_t = int128_emulated( 0, 0xFFFFFFFFFFFFFFFF );                      // 2^64 - 1
        serialize_check!( *boundary.PreIncrement() == int128_emulated( 1, 0 ) );

        let mut accumulator = serialize_int128_t::from( -10 );
        accumulator += serialize_int128_t::from( 4 );  serialize_check!( accumulator == serialize_int128_t::from( -6 ) );
        accumulator -= serialize_int128_t::from( -6 ); serialize_check!( accumulator == serialize_int128_t::from( 0 ) );
        accumulator = serialize_int128_t::from( -3 );
        accumulator *= serialize_int128_t::from( -3 ); serialize_check!( accumulator == serialize_int128_t::from( 9 ) );
        accumulator /= serialize_int128_t::from( -2 ); serialize_check!( accumulator == serialize_int128_t::from( -4 ) );
        accumulator %= serialize_int128_t::from( 3 );  serialize_check!( accumulator == serialize_int128_t::from( -1 ) );
        accumulator <<= 64;                            serialize_check!( accumulator == int128_emulated( 0xFFFFFFFFFFFFFFFF, 0 ) );
        accumulator >>= 64;                            serialize_check!( accumulator == serialize_int128_t::from( -1 ) );
        accumulator &= serialize_int128_t::from( 6 );  serialize_check!( accumulator == serialize_int128_t::from( 6 ) );
        accumulator |= serialize_int128_t::from( 1 );  serialize_check!( accumulator == serialize_int128_t::from( 7 ) );
        accumulator ^= serialize_int128_t::from( -1 ); serialize_check!( accumulator == serialize_int128_t::from( -8 ) );
    }
}

// #if defined(__SIZEOF_INT128__)
// port: always (Rust always has native 128 bit integers); the matching #endif is in the second half of the tests

pub fn uint128_native_from_emulated( value: serialize_uint128_t ) -> uint128_t
{
    ( ( value.hi as uint128_t ) << 64 ) | value.lo as uint128_t
}

pub fn check_uint128_agree( emulated: serialize_uint128_t, native: uint128_t )
{
    serialize_check!( emulated.lo == native as u64 );
    serialize_check!( emulated.hi == ( native >> 64 ) as u64 );
}

// port: serialize tests, second half (upstream serialize.h from test_uint128_differential to the end of the
// SERIALIZE_ENABLE_TESTS section). It is in the same module as the first half, so it uses the first half's check macro and helpers by their upstream names

// port: __SIZEOF_INT128__ is always defined for Rust: native u128 / i128 exist on every target, so the
// differential tests always run

pub fn test_uint128_differential()
{
    // where native __int128 exists, the emulated type is proven against it operator by operator:
    // a fixed seed LCG generates operand pairs, and every operator must agree exactly. this is
    // the test that keeps the sibling copies of the emulation block honest — drift fails loudly.

    let mut lcg: u64 = 0x123456789ABCDEF0;

    macro_rules! serialize_test_next_lcg {
        () => {
            {
                lcg = lcg.wrapping_mul( 6364136223846793005 ).wrapping_add( 1442695040888963407 );
                lcg
            }
        };
    }

    for i in 0..400i32
    {
        let mut a_hi: u64 = serialize_test_next_lcg!();
        let mut a_lo: u64 = serialize_test_next_lcg!();
        let mut b_hi: u64 = serialize_test_next_lcg!();
        let mut b_lo: u64 = serialize_test_next_lcg!();

        // bias some operands toward the interesting edges: empty lanes, saturated lanes, equal operands
        match i % 8
        {
            1 => { a_hi = 0; }
            2 => { a_lo = 0; }
            3 => { b_hi = 0; }
            4 => { b_lo = 0; }
            5 => { a_hi = 0xFFFFFFFFFFFFFFFF; a_lo = 0xFFFFFFFFFFFFFFFF; }
            6 => { b_hi = 0; b_lo = 1u64 << ( i % 63 ); }                     // powers of two divide cleanly
            7 => { b_hi = a_hi; b_lo = a_lo; }
            _ => {}
        }

        let ea: serialize_uint128_t = uint128_emulated( a_hi, a_lo );
        let eb: serialize_uint128_t = uint128_emulated( b_hi, b_lo );
        let na: uint128_t = ( ( a_hi as uint128_t ) << 64 ) | a_lo as uint128_t;
        let nb: uint128_t = ( ( b_hi as uint128_t ) << 64 ) | b_lo as uint128_t;

        check_uint128_agree( ea + eb, na.wrapping_add( nb ) );
        check_uint128_agree( ea - eb, na.wrapping_sub( nb ) );
        check_uint128_agree( ea * eb, na.wrapping_mul( nb ) );
        check_uint128_agree( ea & eb, na & nb );
        check_uint128_agree( ea | eb, na | nb );
        check_uint128_agree( ea ^ eb, na ^ nb );
        check_uint128_agree( !ea, !na );
        check_uint128_agree( -ea, ( 0 as uint128_t ).wrapping_sub( na ) );
        check_uint128_agree( ea, na );                          // port: unary + is the identity and is not ported (serialize.rs), so +ea is ea

        if eb != serialize_uint128_t::from( 0i32 )
        {
            check_uint128_agree( ea / eb, na / nb );            // zero divisors are excluded PERMANENTLY: by zero is undefined on both sides and native hardware disagrees with itself (arm64 x/0 is 0 but x%0 is the dividend; x86-64 traps), so agreement is not a property either side can promise. Totality is pinned in test_uint128_emulation instead
            check_uint128_agree( ea % eb, na % nb );
        }

        let shift: i32 = ( b_lo % 128 ) as i32;                 // native shifts of 128 or more are undefined; the emulated choice is pinned in test_uint128_emulation
        check_uint128_agree( ea << shift, na << shift );
        check_uint128_agree( ea >> shift, na >> shift );

        serialize_check!( ( ea == eb ) == ( na == nb ) );
        serialize_check!( ( ea != eb ) == ( na != nb ) );
        serialize_check!( ( ea <  eb ) == ( na <  nb ) );
        serialize_check!( ( ea >  eb ) == ( na >  nb ) );
        serialize_check!( ( ea <= eb ) == ( na <= nb ) );
        serialize_check!( ( ea >= eb ) == ( na >= nb ) );

        // construction agreement from both signednesses of the drawn lanes
        check_uint128_agree( serialize_uint128_t::from( a_lo ), a_lo as uint128_t );
        check_uint128_agree( serialize_uint128_t::from( a_lo as i64 ), a_lo as i64 as uint128_t );

        // port: ++x / x++ / --x / x-- are PreIncrement / PostIncrement / PreDecrement / PostDecrement on the
        // emulated type, and wrapping arithmetic on the native one
        let mut emulated_accumulator: serialize_uint128_t = ea;
        let mut native_accumulator: uint128_t = na;
        check_uint128_agree( *emulated_accumulator.PreIncrement(), { native_accumulator = native_accumulator.wrapping_add( 1 ); native_accumulator } );
        check_uint128_agree( emulated_accumulator.PostIncrement(), { let previous = native_accumulator; native_accumulator = native_accumulator.wrapping_add( 1 ); previous } );
        check_uint128_agree( emulated_accumulator, native_accumulator );
        check_uint128_agree( *emulated_accumulator.PreDecrement(), { native_accumulator = native_accumulator.wrapping_sub( 1 ); native_accumulator } );
        check_uint128_agree( emulated_accumulator.PostDecrement(), { let previous = native_accumulator; native_accumulator = native_accumulator.wrapping_sub( 1 ); previous } );
        check_uint128_agree( emulated_accumulator, native_accumulator );

        emulated_accumulator = ea;
        native_accumulator = na;
        emulated_accumulator += eb; native_accumulator = native_accumulator.wrapping_add( nb ); check_uint128_agree( emulated_accumulator, native_accumulator );
        emulated_accumulator -= eb; native_accumulator = native_accumulator.wrapping_sub( nb ); check_uint128_agree( emulated_accumulator, native_accumulator );
        emulated_accumulator *= eb; native_accumulator = native_accumulator.wrapping_mul( nb ); check_uint128_agree( emulated_accumulator, native_accumulator );
        emulated_accumulator &= eb; native_accumulator &= nb; check_uint128_agree( emulated_accumulator, native_accumulator );
        emulated_accumulator |= eb; native_accumulator |= nb; check_uint128_agree( emulated_accumulator, native_accumulator );
        emulated_accumulator ^= eb; native_accumulator ^= nb; check_uint128_agree( emulated_accumulator, native_accumulator );
        emulated_accumulator <<= shift; native_accumulator <<= shift; check_uint128_agree( emulated_accumulator, native_accumulator );
        emulated_accumulator >>= shift; native_accumulator >>= shift; check_uint128_agree( emulated_accumulator, native_accumulator );
        if eb != serialize_uint128_t::from( 0i32 )
        {
            emulated_accumulator = ea; native_accumulator = na;
            emulated_accumulator /= eb; native_accumulator /= nb; check_uint128_agree( emulated_accumulator, native_accumulator );
            emulated_accumulator = ea; native_accumulator = na;
            emulated_accumulator %= eb; native_accumulator %= nb; check_uint128_agree( emulated_accumulator, native_accumulator );
        }
    }

    // construction differential: the exact cross signed cases the audit proved uncovered.
    // identical source expressions must construct identical values in both representations.
    {
        check_uint128_agree( serialize_uint128_t::from( -1i64 ),         -1i64 as uint128_t );
        check_uint128_agree( serialize_uint128_t::from( i64::MIN ),      i64::MIN as uint128_t );
        check_uint128_agree( serialize_uint128_t::from( 1u64 << 63 ),    ( 1u64 << 63 ) as uint128_t );
        check_uint128_agree( serialize_uint128_t::from( u64::MAX ),      u64::MAX as uint128_t );
        check_uint128_agree( serialize_uint128_t::from( -5i32 ),         -5i32 as uint128_t );
        check_uint128_agree( serialize_uint128_t::from( 3000000000u32 ), 3000000000u32 as uint128_t );
    }

    // cross representation wire identity: the emulated type and native __int128 must produce
    // byte identical wire through serialize_uint128, and each must read the other's bytes back
    // exactly. this is what makes the emulation a drop in replacement on compilers without
    // native 128 bit support.
    {
        let lanes: [[u64; 2]; 5] =                              // { hi, lo }
        [
            [ 0, 0 ],
            [ 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF ],
            [ 0xFFFFFFFFFFFFFFFF, 0 ],                                          // high half only
            [ 0, 0xFFFFFFFFFFFFFFFF ],                                          // low half only
            [ 0x0123456789ABCDEF, 0xFEDCBA9876543210 ],                         // distinct halves
        ];

        for i in 0..lanes.len()
        {
            let mut emulated: serialize_uint128_t = uint128_emulated( lanes[i][0], lanes[i][1] );
            let mut native: uint128_t = uint128_native_from_emulated( emulated );

            let mut emulated_buffer: [u8; 16 + 8] = [0; 16 + 8];       // + 8: read buffer allocations extend 8 bytes past the data
            let mut emulatedStream = WriteStream::new( &mut emulated_buffer, 16 );
            serialize_check!( serialize_uint128_internal( &mut emulatedStream, &mut emulated ) == true );
            emulatedStream.Flush();

            let mut native_buffer: [u8; 16 + 8] = [0; 16 + 8];
            let mut nativeStream = WriteStream::new( &mut native_buffer, 16 );
            serialize_check!( serialize_uint128_internal( &mut nativeStream, &mut native ) == true );
            nativeStream.Flush();

            serialize_check!( emulatedStream.GetBitsProcessed() == nativeStream.GetBitsProcessed() );
            serialize_check!( emulated_buffer[..16] == native_buffer[..16] );

            // read the native bytes back through the emulated type
            let mut readStream = ReadStream::new( &native_buffer, 16 );
            let mut read_back: serialize_uint128_t = serialize_uint128_t::from( 0i32 );
            serialize_check!( serialize_uint128_internal( &mut readStream, &mut read_back ) == true );
            serialize_check!( read_back == uint128_emulated( lanes[i][0], lanes[i][1] ) );
        }
    }
}

pub fn int128_native_from_emulated( value: serialize_int128_t ) -> int128_t
{
    ( ( ( value.hi as uint128_t ) << 64 ) | value.lo as uint128_t ) as int128_t
}

pub fn check_int128_agree( emulated: serialize_int128_t, native: int128_t )
{
    serialize_check!( emulated.lo == ( native as uint128_t ) as u64 );
    serialize_check!( emulated.hi == ( ( native as uint128_t ) >> 64 ) as u64 );
}

pub fn test_int128_differential()
{
    // the signed counterpart of test_uint128_differential: a fixed seed LCG generates operand
    // pairs biased toward the sign boundaries, and every operator must agree exactly with native
    // signed __int128. where the native operation would be undefined behavior — signed overflow
    // in + - * << and unary minus — the native expectation is computed in the unsigned domain,
    // which is the defined spelling of the two's complement wrap the emulation implements.

    let native_int128_min: int128_t = ( ( 1 as uint128_t ) << 127 ) as int128_t;

    let mut lcg: u64 = 0xFEDCBA9876543210;

    macro_rules! serialize_test_next_lcg {
        () => {
            {
                lcg = lcg.wrapping_mul( 6364136223846793005 ).wrapping_add( 1442695040888963407 );
                lcg
            }
        };
    }

    for i in 0..400i32
    {
        let mut a_hi: u64 = serialize_test_next_lcg!();
        let mut a_lo: u64 = serialize_test_next_lcg!();
        let mut b_hi: u64 = serialize_test_next_lcg!();
        let mut b_lo: u64 = serialize_test_next_lcg!();

        // bias operands toward the sign boundaries: zero, ±1, INT64_MIN/MAX sign extended,
        // INT128_MIN/MAX, negated and equal pairs
        match i % 10
        {
            1 => { a_hi = 0; a_lo = 0; }
            2 => { a_hi = 0xFFFFFFFFFFFFFFFF; a_lo = 0xFFFFFFFFFFFFFFFF; }                  // -1
            3 => { a_hi = 0xFFFFFFFFFFFFFFFF; a_lo = 0x8000000000000000; }                  // INT64_MIN sign extended
            4 => { a_hi = 0; a_lo = 0x7FFFFFFFFFFFFFFF; }                                   // INT64_MAX
            5 => { a_hi = 0x8000000000000000; a_lo = 0; }                                   // INT128_MIN
            6 => { a_hi = 0x7FFFFFFFFFFFFFFF; a_lo = 0xFFFFFFFFFFFFFFFF; }                  // INT128_MAX
            7 => { b_hi = 0xFFFFFFFFFFFFFFFF; b_lo = 0xFFFFFFFFFFFFFFFF; }                  // -1: the overflowing divisor
            8 => { b_hi = !a_hi; b_lo = !a_lo; }                                            // ~a: b = -a - 1, mixed signs
            9 => { b_hi = a_hi; b_lo = a_lo; }
            _ => {}
        }

        let ea: serialize_int128_t = int128_emulated( a_hi, a_lo );
        let eb: serialize_int128_t = int128_emulated( b_hi, b_lo );
        let ua: uint128_t = ( ( a_hi as uint128_t ) << 64 ) | a_lo as uint128_t;
        let ub: uint128_t = ( ( b_hi as uint128_t ) << 64 ) | b_lo as uint128_t;
        let na: int128_t = ua as int128_t;
        let nb: int128_t = ub as int128_t;

        // + - * and unary minus: native expectations via the unsigned domain, avoiding native
        // signed overflow, which is undefined behavior. the wrap is the semantics under test.
        check_int128_agree( ea + eb, ua.wrapping_add( ub ) as int128_t );
        check_int128_agree( ea - eb, ua.wrapping_sub( ub ) as int128_t );
        check_int128_agree( ea * eb, ua.wrapping_mul( ub ) as int128_t );
        check_int128_agree( -ea, ( 0 as uint128_t ).wrapping_sub( ua ) as int128_t );
        check_int128_agree( ea, na );                           // port: unary + is the identity and is not ported (serialize.rs), so +ea is ea

        check_int128_agree( ea & eb, na & nb );
        check_int128_agree( ea | eb, na | nb );
        check_int128_agree( ea ^ eb, na ^ nb );
        check_int128_agree( !ea, !na );

        if nb != 0 && !( na == native_int128_min && nb == -1 )
        {
            check_int128_agree( ea / eb, na / nb );         // the excluded case is native undefined behavior; the emulated wrap is pinned in test_int128_emulation
            check_int128_agree( ea % eb, na % nb );
        }

        let shift: i32 = ( b_lo % 128 ) as i32;             // native shifts of 128 or more are undefined; the emulated choice is pinned in test_int128_emulation
        check_int128_agree( ea >> shift, na >> shift );                                             // native >> on negatives is the arithmetic shift on every target compiler
        check_int128_agree( ea << shift, ( ua << shift ) as int128_t );                             // native << on negatives is undefined pre C++20: the unsigned domain is the defined spelling

        serialize_check!( ( ea == eb ) == ( na == nb ) );
        serialize_check!( ( ea != eb ) == ( na != nb ) );
        serialize_check!( ( ea <  eb ) == ( na <  nb ) );
        serialize_check!( ( ea >  eb ) == ( na >  nb ) );
        serialize_check!( ( ea <= eb ) == ( na <= nb ) );
        serialize_check!( ( ea >= eb ) == ( na >= nb ) );

        // increments and decrements via the unsigned domain, since native ++ overflows at INT128_MAX
        let mut incremented: serialize_int128_t = ea;
        incremented.PreIncrement();
        check_int128_agree( incremented, ua.wrapping_add( 1 ) as int128_t );
        incremented.PostDecrement();
        check_int128_agree( incremented, na );
        let mut decremented: serialize_int128_t = ea;
        decremented.PreDecrement();
        check_int128_agree( decremented, ua.wrapping_sub( 1 ) as int128_t );

        // conversions: the sign extending and value preserving constructors and the truncating
        // conversion match native, from both signednesses of the drawn lane
        let seed64: i64 = a_lo as i64;
        check_int128_agree( serialize_int128_t::from( seed64 ), seed64 as int128_t );
        check_int128_agree( serialize_int128_t::from( a_lo ), a_lo as int128_t );
        serialize_check!( i64::from( ea ) == ( ua as u64 ) as i64 );

        // compound forms via the unsigned domain where overflow could occur
        let mut accumulator: serialize_int128_t = ea;
        accumulator += eb; check_int128_agree( accumulator, ua.wrapping_add( ub ) as int128_t );
        accumulator = ea;
        accumulator -= eb; check_int128_agree( accumulator, ua.wrapping_sub( ub ) as int128_t );
        accumulator = ea;
        accumulator *= eb; check_int128_agree( accumulator, ua.wrapping_mul( ub ) as int128_t );
        accumulator = ea;
        accumulator &= eb; check_int128_agree( accumulator, na & nb );
        accumulator = ea;
        accumulator |= eb; check_int128_agree( accumulator, na | nb );
        accumulator = ea;
        accumulator ^= eb; check_int128_agree( accumulator, na ^ nb );
        accumulator = ea;
        accumulator >>= shift; check_int128_agree( accumulator, na >> shift );
        accumulator = ea;
        accumulator <<= shift; check_int128_agree( accumulator, ( ua << shift ) as int128_t );
        if nb != 0 && !( na == native_int128_min && nb == -1 )
        {
            accumulator = ea;
            accumulator /= eb; check_int128_agree( accumulator, na / nb );
            accumulator = ea;
            accumulator %= eb; check_int128_agree( accumulator, na % nb );
        }
    }

    // construction differential: the exact cross signed cases the audit proved uncovered.
    // identical source expressions must construct identical values in both representations.
    {
        check_int128_agree( serialize_int128_t::from( -1i64 ),         -1i64 as int128_t );
        check_int128_agree( serialize_int128_t::from( i64::MIN ),      i64::MIN as int128_t );
        check_int128_agree( serialize_int128_t::from( 1u64 << 63 ),    ( 1u64 << 63 ) as int128_t );
        check_int128_agree( serialize_int128_t::from( u64::MAX ),      u64::MAX as int128_t );
        check_int128_agree( serialize_int128_t::from( -5i32 ),         -5i32 as int128_t );
        check_int128_agree( serialize_int128_t::from( 3000000000u32 ), 3000000000u32 as int128_t );
    }
}

// port: SERIALIZE_HAS_COMPILE_TIME_SURFACE is always defined for Rust (serialize.rs), so the compile time surface
// tests always run

// Compile time surface tests. Every compile time form is held to the coverage of its runtime twin
// (round trip, boundary values, read side rejection, measure agreement), and to the wire identity
// property: given identical inputs, the compile time form must produce byte identical wire data to
// the runtime form. That property is what lets a code generator switch forms without a wire change.

// each helper drives the actual macro form under test, so the tests cover the macros as well as the templates

pub fn serialize_int_runtime_form<S: Stream>( stream: &mut S, value: &mut i32, min: i32, max: i32 ) -> bool
{
    serialize_int!( stream, *value, min, max );
    true
}

pub fn serialize_int64_runtime_form<S: Stream>( stream: &mut S, value: &mut i64, min: i64, max: i64 ) -> bool
{
    serialize_int64!( stream, *value, min, max );
    true
}

pub fn serialize_bits64_runtime_form<S: Stream>( stream: &mut S, value: &mut u64, bits: i32 ) -> bool
{
    serialize_bits!( stream, *value, bits );
    true
}

pub fn serialize_int_compile_time_form<const Min: i32, const Max: i32, S: Stream>( stream: &mut S, value: &mut i32 ) -> bool
{
    serialize_int_compile_time!( stream, *value, Min, Max );
    true
}

pub fn serialize_int64_compile_time_form<const Min: i64, const Max: i64, S: Stream>( stream: &mut S, value: &mut i64 ) -> bool
{
    serialize_int64_compile_time!( stream, *value, Min, Max );
    true
}

pub fn serialize_bits_compile_time_form<const Bits: i32, S: Stream>( stream: &mut S, value: &mut u32 ) -> bool
{
    serialize_bits_compile_time!( stream, *value, Bits );
    true
}

pub fn serialize_bits64_compile_time_form<const Bits: i32, S: Stream>( stream: &mut S, value: &mut u64 ) -> bool
{
    serialize_bits64_compile_time!( stream, *value, Bits );
    true
}

pub fn test_compile_time_bits_required()
{
    // usable in template argument position by construction
    serialize_static_assert!( bits_required64_constexpr( 0, 255 ) == 8, "must be a constant expression" );

    // agrees with the runtime bits_required across the 32 bit table
    serialize_check!( bits_required64_constexpr( 0, 0 ) == 0 );
    serialize_check!( bits_required64_constexpr( 0, 1 ) == 1 );
    serialize_check!( bits_required64_constexpr( 0, 2 ) == 2 );
    serialize_check!( bits_required64_constexpr( 0, 3 ) == 2 );
    serialize_check!( bits_required64_constexpr( 0, 4 ) == 3 );
    serialize_check!( bits_required64_constexpr( 0, 7 ) == 3 );
    serialize_check!( bits_required64_constexpr( 0, 8 ) == 4 );
    serialize_check!( bits_required64_constexpr( 0, 255 ) == 8 );
    serialize_check!( bits_required64_constexpr( 0, 65535 ) == 16 );
    serialize_check!( bits_required64_constexpr( 0, 4294967295 ) == 32 );

    // agrees with the runtime bits_required64 on 64 bit ranges
    serialize_check!( bits_required64_constexpr( 0, 4294967296 ) == 33 );
    serialize_check!( bits_required64_constexpr( 0, 1u64 << 40 ) == 41 );
    serialize_check!( bits_required64_constexpr( 0, 0xFFFFFFFFFFFFFFFF ) == 64 );
    serialize_check!( bits_required64_constexpr( i64::MIN as u64, i64::MAX as u64 ) == 64 );
    serialize_check!( bits_required64_constexpr( -5000000000i64 as u64, 5000000000i64 as u64 ) == 34 );

    // sign extended int32 bounds wrap to the same difference as the uint32 runtime path
    serialize_check!( bits_required64_constexpr( -100i64 as u64, 100i64 as u64 ) == bits_required( -100i32 as u32, 100i32 as u32 ) );
    serialize_check!( bits_required64_constexpr( i32::MIN as i64 as u64, i32::MAX as i64 as u64 ) == 32 );

    // sweep agreement with the runtime form
    for max in 0..=1000u32
    {
        serialize_check!( bits_required64_constexpr( 0, max as u64 ) == bits_required( 0, max ) );
    }
}

pub fn check_compile_time_int_range<const Min: i32, const Max: i32>( values: &[i32], num_values: i32 )
{
    for i in 0..num_values as usize
    {
        let value: i32 = values[i];

        // measure: both forms agree on cost
        let mut measureRuntime = MeasureStream::new();
        let mut measure_value: i32 = value;
        serialize_check!( serialize_int_runtime_form( &mut measureRuntime, &mut measure_value, Min, Max ) == true );
        let mut measureCompileTime = MeasureStream::new();
        measure_value = value;
        serialize_check!( ( serialize_int_compile_time_form::<Min, Max, _>( &mut measureCompileTime, &mut measure_value ) == true ) );
        serialize_check!( measureRuntime.GetBitsProcessed() == measureCompileTime.GetBitsProcessed() );

        // write: the wire identity property, byte for byte
        let mut buffer_runtime: [u8; 8 + 8] = [0; 8 + 8];              // + 8: read buffer allocations extend 8 bytes past the data
        let mut buffer_compile_time: [u8; 8 + 8] = [0; 8 + 8];         // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeRuntime = WriteStream::new( &mut buffer_runtime, 8 );
        let mut write_value: i32 = value;
        serialize_check!( serialize_int_runtime_form( &mut writeRuntime, &mut write_value, Min, Max ) == true );
        writeRuntime.Flush();

        let mut writeCompileTime = WriteStream::new( &mut buffer_compile_time, 8 );
        write_value = value;
        serialize_check!( ( serialize_int_compile_time_form::<Min, Max, _>( &mut writeCompileTime, &mut write_value ) == true ) );
        writeCompileTime.Flush();

        serialize_check!( writeRuntime.GetBitsProcessed() == writeCompileTime.GetBitsProcessed() );
        // port: the byte counts are taken before the buffers are compared, because the write streams borrow them
        let writeRuntimeBytes: i64 = writeRuntime.GetBytesProcessed();
        let writeCompileTimeBytes: i64 = writeCompileTime.GetBytesProcessed();
        serialize_check!( buffer_runtime[..8] == buffer_compile_time[..8] );

        // round trip through the compile time form
        let mut readStream = ReadStream::new( &buffer_compile_time, writeCompileTimeBytes );
        let mut read_value: i32 = 0;
        serialize_check!( ( serialize_int_compile_time_form::<Min, Max, _>( &mut readStream, &mut read_value ) == true ) );
        serialize_check!( read_value == value );

        // cross decode: runtime written bytes through the compile time form
        let mut crossStream = ReadStream::new( &buffer_runtime, writeRuntimeBytes );
        read_value = 0;
        serialize_check!( ( serialize_int_compile_time_form::<Min, Max, _>( &mut crossStream, &mut read_value ) == true ) );
        serialize_check!( read_value == value );
    }
}

pub fn test_compile_time_int()
{
    {
        let values: [i32; 7] = [ -100, -99, -37, 0, 1, 99, 100 ];
        check_compile_time_int_range::<{ -100 }, 100>( &values, values.len() as i32 );
    }

    {
        let values: [i32; 6] = [ 0, 1, 255, 32768, 65534, 65535 ];
        check_compile_time_int_range::<0, 65535>( &values, values.len() as i32 );
    }

    // ranges wider than 2^31 overflow if [min,max] arithmetic is done signed (undefined behavior)
    {
        let values: [i32; 7] = [ i32::MIN, i32::MIN + 1, -1, 0, 1, i32::MAX - 1, i32::MAX ];
        check_compile_time_int_range::<{ i32::MIN }, { i32::MAX }>( &values, values.len() as i32 );
    }

    {
        let values: [i32; 5] = [ -2000000000, -1, 0, 1000000000, 2000000000 ];
        check_compile_time_int_range::<{ -2000000000 }, 2000000000>( &values, values.len() as i32 );
    }
}

pub fn check_compile_time_int64_range<const Min: i64, const Max: i64>( values: &[i64], num_values: i32 )
{
    for i in 0..num_values as usize
    {
        let value: i64 = values[i];

        // measure: both forms agree on cost
        let mut measureRuntime = MeasureStream::new();
        let mut measure_value: i64 = value;
        serialize_check!( serialize_int64_runtime_form( &mut measureRuntime, &mut measure_value, Min, Max ) == true );
        let mut measureCompileTime = MeasureStream::new();
        measure_value = value;
        serialize_check!( ( serialize_int64_compile_time_form::<Min, Max, _>( &mut measureCompileTime, &mut measure_value ) == true ) );
        serialize_check!( measureRuntime.GetBitsProcessed() == measureCompileTime.GetBitsProcessed() );

        // write: the wire identity property, byte for byte
        let mut buffer_runtime: [u8; 8 + 8] = [0; 8 + 8];              // + 8: read buffer allocations extend 8 bytes past the data
        let mut buffer_compile_time: [u8; 8 + 8] = [0; 8 + 8];         // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeRuntime = WriteStream::new( &mut buffer_runtime, 8 );
        let mut write_value: i64 = value;
        serialize_check!( serialize_int64_runtime_form( &mut writeRuntime, &mut write_value, Min, Max ) == true );
        writeRuntime.Flush();

        let mut writeCompileTime = WriteStream::new( &mut buffer_compile_time, 8 );
        write_value = value;
        serialize_check!( ( serialize_int64_compile_time_form::<Min, Max, _>( &mut writeCompileTime, &mut write_value ) == true ) );
        writeCompileTime.Flush();

        serialize_check!( writeRuntime.GetBitsProcessed() == writeCompileTime.GetBitsProcessed() );
        // port: the byte counts are taken before the buffers are compared, because the write streams borrow them
        let writeRuntimeBytes: i64 = writeRuntime.GetBytesProcessed();
        let writeCompileTimeBytes: i64 = writeCompileTime.GetBytesProcessed();
        serialize_check!( buffer_runtime[..8] == buffer_compile_time[..8] );

        // round trip through the compile time form
        let mut readStream = ReadStream::new( &buffer_compile_time, writeCompileTimeBytes );
        let mut read_value: i64 = 0;
        serialize_check!( ( serialize_int64_compile_time_form::<Min, Max, _>( &mut readStream, &mut read_value ) == true ) );
        serialize_check!( read_value == value );

        // cross decode: runtime written bytes through the compile time form
        let mut crossStream = ReadStream::new( &buffer_runtime, writeRuntimeBytes );
        read_value = 0;
        serialize_check!( ( serialize_int64_compile_time_form::<Min, Max, _>( &mut crossStream, &mut read_value ) == true ) );
        serialize_check!( read_value == value );
    }
}

pub fn test_compile_time_int64()
{
    // small ranges use the single dword path
    {
        let values: [i64; 8] = [ -100, -99, -1, 0, 1, 55, 99, 100 ];
        check_compile_time_int64_range::<{ -100 }, 100>( &values, values.len() as i32 );
    }

    // ranges spanning more than 32 bits use the two dword path
    {
        let values: [i64; 8] = [ -5000000000, -5000000000 + 1, -1, 0, 1, 4123456789, 5000000000 - 1, 5000000000 ];
        check_compile_time_int64_range::<{ -5000000000 }, 5000000000>( &values, values.len() as i32 );
    }

    // ranges wider than 2^63 overflow if [min,max] arithmetic is done signed (undefined behavior)
    {
        let values: [i64; 7] = [ i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX ];
        check_compile_time_int64_range::<{ i64::MIN }, { i64::MAX }>( &values, values.len() as i32 );
    }

    // the single dword path uses the minimal number of bits, same as the runtime form
    {
        let mut buffer: [u8; 8 + 8] = [0; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let mut value: i64 = 55;
        serialize_check!( ( SerializeInt64Const::<{ -100 }, 100, _>( &mut writeStream, &mut value ) == true ) );
        writeStream.Flush();
        serialize_check!( writeStream.GetBitsProcessed() == 8 );        // bits_required64(-100,100) == 8, same as the 32 bit path
    }
}

pub fn check_compile_time_bits_width<const Bits: i32>()
{
    // ( ( 1 << ( Bits - 1 ) ) << 1 ) - 1 is the all ones value without shifting by the full width (undefined behavior at Bits == 32)
    let max_value: u32 = ( ( ( 1u64 << ( Bits - 1 ) ) << 1 ).wrapping_sub( 1 ) ) as u32;
    let values: [u32; 4] = [ 0, 1, max_value >> 1, max_value ];

    for i in 0..values.len()
    {
        let value: u32 = values[i];

        // measure: both forms agree on cost
        let mut measureRuntime = MeasureStream::new();
        let mut measure_value64: u64 = value as u64;
        serialize_check!( serialize_bits64_runtime_form( &mut measureRuntime, &mut measure_value64, Bits ) == true );
        let mut measureCompileTime = MeasureStream::new();
        let mut measure_value: u32 = value;
        serialize_check!( serialize_bits_compile_time_form::<Bits, _>( &mut measureCompileTime, &mut measure_value ) == true );
        serialize_check!( measureRuntime.GetBitsProcessed() == measureCompileTime.GetBitsProcessed() );

        // write: the wire identity property, byte for byte
        let mut buffer_runtime: [u8; 8 + 8] = [0; 8 + 8];              // + 8: read buffer allocations extend 8 bytes past the data
        let mut buffer_compile_time: [u8; 8 + 8] = [0; 8 + 8];         // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeRuntime = WriteStream::new( &mut buffer_runtime, 8 );
        let mut write_value64: u64 = value as u64;
        serialize_check!( serialize_bits64_runtime_form( &mut writeRuntime, &mut write_value64, Bits ) == true );
        writeRuntime.Flush();

        let mut writeCompileTime = WriteStream::new( &mut buffer_compile_time, 8 );
        let mut write_value: u32 = value;
        serialize_check!( serialize_bits_compile_time_form::<Bits, _>( &mut writeCompileTime, &mut write_value ) == true );
        writeCompileTime.Flush();

        serialize_check!( writeRuntime.GetBitsProcessed() == writeCompileTime.GetBitsProcessed() );
        // port: the byte counts are taken before the buffers are compared, because the write streams borrow them
        let writeRuntimeBytes: i64 = writeRuntime.GetBytesProcessed();
        let writeCompileTimeBytes: i64 = writeCompileTime.GetBytesProcessed();
        serialize_check!( buffer_runtime[..8] == buffer_compile_time[..8] );

        // round trip through the compile time form
        let mut readStream = ReadStream::new( &buffer_compile_time, writeCompileTimeBytes );
        let mut read_value: u32 = 0;
        serialize_check!( serialize_bits_compile_time_form::<Bits, _>( &mut readStream, &mut read_value ) == true );
        serialize_check!( read_value == value );

        // cross decode: runtime written bytes through the compile time form
        let mut crossStream = ReadStream::new( &buffer_runtime, writeRuntimeBytes );
        read_value = 0;
        serialize_check!( serialize_bits_compile_time_form::<Bits, _>( &mut crossStream, &mut read_value ) == true );
        serialize_check!( read_value == value );
    }
}

pub fn check_compile_time_bits64_width<const Bits: i32>()
{
    // ( ( 1 << ( Bits - 1 ) ) << 1 ) - 1 is the all ones value without shifting by the full width (undefined behavior at Bits == 64)
    let max_value: u64 = ( ( 1u64 << ( Bits - 1 ) ) << 1 ).wrapping_sub( 1 );
    let values: [u64; 4] = [ 0, 1, max_value >> 1, max_value ];

    for i in 0..values.len()
    {
        let value: u64 = values[i];

        // measure: both forms agree on cost
        let mut measureRuntime = MeasureStream::new();
        let mut measure_value: u64 = value;
        serialize_check!( serialize_bits64_runtime_form( &mut measureRuntime, &mut measure_value, Bits ) == true );
        let mut measureCompileTime = MeasureStream::new();
        measure_value = value;
        serialize_check!( serialize_bits64_compile_time_form::<Bits, _>( &mut measureCompileTime, &mut measure_value ) == true );
        serialize_check!( measureRuntime.GetBitsProcessed() == measureCompileTime.GetBitsProcessed() );

        // write: the wire identity property, byte for byte
        let mut buffer_runtime: [u8; 8 + 8] = [0; 8 + 8];              // + 8: read buffer allocations extend 8 bytes past the data
        let mut buffer_compile_time: [u8; 8 + 8] = [0; 8 + 8];         // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeRuntime = WriteStream::new( &mut buffer_runtime, 8 );
        let mut write_value: u64 = value;
        serialize_check!( serialize_bits64_runtime_form( &mut writeRuntime, &mut write_value, Bits ) == true );
        writeRuntime.Flush();

        let mut writeCompileTime = WriteStream::new( &mut buffer_compile_time, 8 );
        write_value = value;
        serialize_check!( serialize_bits64_compile_time_form::<Bits, _>( &mut writeCompileTime, &mut write_value ) == true );
        writeCompileTime.Flush();

        serialize_check!( writeRuntime.GetBitsProcessed() == writeCompileTime.GetBitsProcessed() );
        // port: the byte counts are taken before the buffers are compared, because the write streams borrow them
        let writeRuntimeBytes: i64 = writeRuntime.GetBytesProcessed();
        let writeCompileTimeBytes: i64 = writeCompileTime.GetBytesProcessed();
        serialize_check!( buffer_runtime[..8] == buffer_compile_time[..8] );

        // round trip through the compile time form
        let mut readStream = ReadStream::new( &buffer_compile_time, writeCompileTimeBytes );
        let mut read_value: u64 = 0;
        serialize_check!( serialize_bits64_compile_time_form::<Bits, _>( &mut readStream, &mut read_value ) == true );
        serialize_check!( read_value == value );

        // cross decode: runtime written bytes through the compile time form
        let mut crossStream = ReadStream::new( &buffer_runtime, writeRuntimeBytes );
        read_value = 0;
        serialize_check!( serialize_bits64_compile_time_form::<Bits, _>( &mut crossStream, &mut read_value ) == true );
        serialize_check!( read_value == value );
    }
}

pub fn test_compile_time_bits()
{
    check_compile_time_bits_width::<1>();
    check_compile_time_bits_width::<2>();
    check_compile_time_bits_width::<7>();
    check_compile_time_bits_width::<8>();
    check_compile_time_bits_width::<13>();
    check_compile_time_bits_width::<23>();
    check_compile_time_bits_width::<31>();
    check_compile_time_bits_width::<32>();

    check_compile_time_bits64_width::<1>();
    check_compile_time_bits64_width::<20>();
    check_compile_time_bits64_width::<32>();
    check_compile_time_bits64_width::<33>();
    check_compile_time_bits64_width::<48>();
    check_compile_time_bits64_width::<63>();
    check_compile_time_bits64_width::<64>();
}

pub fn test_compile_time_int_validation()
{
    // bits_required(0,5) is 3 bits, so a malicious packet can encode 6 or 7. reads must reject values above max.
    {
        let mut buffer: [u8; 4 + 8] = [0; 4 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 8 );
        let mut out_of_range: u32 = 7;
        writeStream.SerializeBits( &mut out_of_range, 3 );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 4 );
        let mut value: i32 = 0;
        serialize_check!( ( SerializeIntConst::<0, 5, _>( &mut readStream, &mut value ) == false ) );
    }

    // reads past the end of the buffer must fail cleanly
    {
        let buffer: [u8; 8 + 8] = [0; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut readStream = ReadStream::new( &buffer, 1 );
        let mut value: i32 = 0;
        serialize_check!( ( SerializeIntConst::<0, 65535, _>( &mut readStream, &mut value ) == false ) );
    }
}

pub fn test_compile_time_int64_validation()
{
    // a malicious packet can smuggle an out of range value into the bit headroom of the two dword path. reads must reject it.
    {
        let mut buffer: [u8; 16 + 8] = [0; 16 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let out_of_range: u64 = ( 1u64 << 34 ) + 5;               // range [0, 2^34] is 35 bits, so values above 2^34 fit in the headroom
        let mut lo: u32 = ( out_of_range & 0xFFFFFFFF ) as u32;
        let mut hi: u32 = ( out_of_range >> 32 ) as u32;
        writeStream.SerializeBits( &mut lo, 32 );
        writeStream.SerializeBits( &mut hi, 3 );
        writeStream.Flush();

        let mut readStream = ReadStream::new( &buffer, 16 );
        let mut value: i64 = 0;
        serialize_check!( ( SerializeInt64Const::<0, { 1i64 << 34 }, _>( &mut readStream, &mut value ) ) == false );
    }

    // reads past the end of the buffer must fail cleanly (the low dword fits, the high remainder does not)
    {
        let buffer: [u8; 4 + 8] = [0; 4 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut readStream = ReadStream::new( &buffer, 4 );
        let mut value: i64 = 0;
        serialize_check!( ( SerializeInt64Const::<{ i64::MIN }, { i64::MAX }, _>( &mut readStream, &mut value ) ) == false );
    }
}

pub fn test_compile_time_bits_validation()
{
    // reads past the end of the buffer must fail cleanly
    {
        let buffer: [u8; 8 + 8] = [0; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut readStream = ReadStream::new( &buffer, 1 );
        let mut value: u32 = 0;
        serialize_check!( SerializeBitsConst::<13, _>( &mut readStream, &mut value ) == false );
    }

    // the two dword path: the low dword fits, the high remainder does not
    {
        let buffer: [u8; 4 + 8] = [0; 4 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

        let mut readStream = ReadStream::new( &buffer, 4 );
        let mut value: u64 = 0;
        serialize_check!( SerializeBits64Const::<48, _>( &mut readStream, &mut value ) == false );
    }
}

// a packet exercising every compile time form next to its runtime twin, field for field

// port: the zeroing constructor is Default, and operator == / != are the derived PartialEq (field for field, as
// upstream's operator ==)
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct CompileTimeTestPacket
{
    pub int_a: i32,             // [-100,+100]
    pub int_b: i32,             // [0,65535]
    pub int_c: i32,             // [INT32_MIN,INT32_MAX]
    pub int64_small: i64,       // [-100,+100]: single dword path
    pub int64_wide: i64,        // [-5000000000,+5000000000]: two dword path
    pub int64_full: i64,        // [INT64_MIN,INT64_MAX]
    pub bits1: u32,
    pub bits7: u32,
    pub bits13: u32,
    pub bits23: u32,
    pub bits32: u32,
    pub bits48: u64,            // the >32 bit serialize_bits case
    pub bits64: u64,
    pub flag_a: bool,
    pub flag_b: bool,
}

impl CompileTimeTestPacket
{
    pub fn new() -> CompileTimeTestPacket
    {
        CompileTimeTestPacket::default()
    }

    pub fn InitTypical( &mut self )
    {
        self.int_a = -37;
        self.int_b = 12345;
        self.int_c = -123456789;
        self.int64_small = 55;
        self.int64_wide = 4123456789;
        self.int64_full = -123456789012345;
        self.bits1 = 1;
        self.bits7 = 97;
        self.bits13 = 5000;
        self.bits23 = 1234567;
        self.bits32 = 0xDEADBEEF;
        self.bits48 = 0x123456789ABC;
        self.bits64 = 0x123456789ABCDEF0;
        self.flag_a = true;
        self.flag_b = false;
    }

    pub fn InitLow( &mut self )          // every field at its minimum legal value
    {
        self.int_a = -100;
        self.int_b = 0;
        self.int_c = i32::MIN;
        self.int64_small = -100;
        self.int64_wide = -5000000000;
        self.int64_full = i64::MIN;
        self.bits1 = 0;
        self.bits7 = 0;
        self.bits13 = 0;
        self.bits23 = 0;
        self.bits32 = 0;
        self.bits48 = 0;
        self.bits64 = 0;
        self.flag_a = false;
        self.flag_b = false;
    }

    pub fn InitHigh( &mut self )         // every field at its maximum legal value
    {
        self.int_a = 100;
        self.int_b = 65535;
        self.int_c = i32::MAX;
        self.int64_small = 100;
        self.int64_wide = 5000000000;
        self.int64_full = i64::MAX;
        self.bits1 = 1;
        self.bits7 = 127;
        self.bits13 = 8191;
        self.bits23 = 8388607;
        self.bits32 = 0xFFFFFFFF;
        self.bits48 = ( 1u64 << 48 ) - 1;
        self.bits64 = 0xFFFFFFFFFFFFFFFF;
        self.flag_a = true;
        self.flag_b = true;
    }

    pub fn SerializeRuntime<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_int!( stream, self.int_a, -100, 100 );
        serialize_int!( stream, self.int_b, 0, 65535 );
        serialize_int!( stream, self.int_c, i32::MIN, i32::MAX );
        serialize_int64!( stream, self.int64_small, -100, 100 );
        serialize_int64!( stream, self.int64_wide, -5000000000i64, 5000000000i64 );
        serialize_int64!( stream, self.int64_full, i64::MIN, i64::MAX );
        serialize_bits!( stream, self.bits1, 1 );
        serialize_bits!( stream, self.bits7, 7 );
        serialize_bits!( stream, self.bits13, 13 );
        serialize_bits!( stream, self.bits23, 23 );
        serialize_bits!( stream, self.bits32, 32 );
        serialize_bits!( stream, self.bits48, 48 );
        serialize_bits!( stream, self.bits64, 64 );
        serialize_bool!( stream, self.flag_a );
        serialize_bool!( stream, self.flag_b );
        true
    }

    pub fn SerializeCompileTime<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_int_compile_time!( stream, self.int_a, -100, 100 );
        serialize_int_compile_time!( stream, self.int_b, 0, 65535 );
        serialize_int_compile_time!( stream, self.int_c, i32::MIN, i32::MAX );
        serialize_int64_compile_time!( stream, self.int64_small, -100, 100 );
        serialize_int64_compile_time!( stream, self.int64_wide, -5000000000i64, 5000000000i64 );
        serialize_int64_compile_time!( stream, self.int64_full, i64::MIN, i64::MAX );
        serialize_bits_compile_time!( stream, self.bits1, 1 );
        serialize_bits_compile_time!( stream, self.bits7, 7 );
        serialize_bits_compile_time!( stream, self.bits13, 13 );
        serialize_bits_compile_time!( stream, self.bits23, 23 );
        serialize_bits_compile_time!( stream, self.bits32, 32 );
        serialize_bits64_compile_time!( stream, self.bits48, 48 );
        serialize_bits64_compile_time!( stream, self.bits64, 64 );
        serialize_bool_compile_time!( stream, self.flag_a );
        serialize_bool_compile_time!( stream, self.flag_b );
        true
    }
}

pub fn check_compile_time_packet( packet: &mut CompileTimeTestPacket )
{
    const BufferSize: usize = 64;

    let mut buffer_runtime: [u8; BufferSize + 8] = [0; BufferSize + 8];             // + 8: read buffer allocations extend 8 bytes past the data
    let mut buffer_compile_time: [u8; BufferSize + 8] = [0; BufferSize + 8];        // + 8: read buffer allocations extend 8 bytes past the data

    let mut writeRuntime = WriteStream::new( &mut buffer_runtime, BufferSize as i64 );
    serialize_check!( packet.SerializeRuntime( &mut writeRuntime ) == true );
    writeRuntime.Flush();

    let mut writeCompileTime = WriteStream::new( &mut buffer_compile_time, BufferSize as i64 );
    serialize_check!( packet.SerializeCompileTime( &mut writeCompileTime ) == true );
    writeCompileTime.Flush();

    // port: the counts are taken before the buffers are compared, because the write streams borrow them
    let writeRuntimeBits: i64 = writeRuntime.GetBitsProcessed();
    let writeCompileTimeBits: i64 = writeCompileTime.GetBitsProcessed();
    let writeRuntimeBytes: i64 = writeRuntime.GetBytesProcessed();

    // the wire identity property: byte identical, so a code generator can switch forms without a wire change
    serialize_check!( writeRuntimeBits == writeCompileTimeBits );
    serialize_check!( buffer_runtime[..BufferSize] == buffer_compile_time[..BufferSize] );

    // measure streams agree with the write streams (no aligns in this packet, so the measure is exact)
    let mut measureRuntime = MeasureStream::new();
    serialize_check!( packet.SerializeRuntime( &mut measureRuntime ) == true );
    let mut measureCompileTime = MeasureStream::new();
    serialize_check!( packet.SerializeCompileTime( &mut measureCompileTime ) == true );
    serialize_check!( measureRuntime.GetBitsProcessed() == writeRuntimeBits );
    serialize_check!( measureCompileTime.GetBitsProcessed() == writeCompileTimeBits );

    let bytesWritten: i64 = writeRuntimeBytes;

    // cross decode: runtime written bytes through the compile time form...
    {
        let mut readStream = ReadStream::new( &buffer_runtime, bytesWritten );
        let mut read_packet = CompileTimeTestPacket::new();
        serialize_check!( read_packet.SerializeCompileTime( &mut readStream ) == true );
        serialize_check!( read_packet == *packet );
    }

    // ...and compile time written bytes through the runtime form
    {
        let mut readStream = ReadStream::new( &buffer_compile_time, bytesWritten );
        let mut read_packet = CompileTimeTestPacket::new();
        serialize_check!( read_packet.SerializeRuntime( &mut readStream ) == true );
        serialize_check!( read_packet == *packet );
    }
}

pub fn test_compile_time_packet()
{
    let mut packet = CompileTimeTestPacket::new();

    packet.InitTypical();
    check_compile_time_packet( &mut packet );

    packet.InitLow();
    check_compile_time_packet( &mut packet );

    packet.InitHigh();
    check_compile_time_packet( &mut packet );
}

// Golden wire format test. The exact bytes produced by the serializer are pinned down here and must never change.
// If this test fails, the wire format has changed and previously written data no longer decodes: a breaking change.
// The values below are chosen so every platform quantizes identically (see the compressed float: 5.0 in [0,10]
// normalizes to exactly 0.5, so fp contraction differences between compilers cannot shift the quantized integer).

// port: the memset to zero is Default
#[derive(Clone, Copy, Default, Debug)]
pub struct GoldenWireData
{
    pub bits4: u32,
    pub bits11: u32,
    pub bits24: u32,
    pub bits32: u32,
    pub int_small: i32,
    pub int_full: i32,
    pub flag: bool,
    pub float_value: f32,
    pub compressed_float_value: f32,
    pub double_value: f64,
    pub uint8_value: u8,
    pub uint16_value: u16,
    pub uint32_value: u32,
    pub uint64_value: u64,
    pub relative_near: i32,
    pub relative_far: i32,
    pub bytes: [u8; 7],
    pub string: [u8; 16],
    pub wstring: [wchar_t; 8],
    pub fixed_q8_8: i16,
    pub fixed_q16_16: i32,
    pub fixed_q48_16: i64,
    pub fixed_q16_16_unsigned: u32,
    pub fixed_q112_16_wide: int128_t,
    pub fixed_q64_64_wide: int128_t,
}

// port: memcmp of two GoldenWireData. Rust has no well defined byte view of a struct with padding, so this
// compares every field in declaration order, the floats by bit pattern (exactly what memcmp sees of them)
pub fn golden_wire_data_memcmp_equal( a: &GoldenWireData, b: &GoldenWireData ) -> bool
{
    a.bits4 == b.bits4 &&
    a.bits11 == b.bits11 &&
    a.bits24 == b.bits24 &&
    a.bits32 == b.bits32 &&
    a.int_small == b.int_small &&
    a.int_full == b.int_full &&
    a.flag == b.flag &&
    a.float_value.to_bits() == b.float_value.to_bits() &&
    a.compressed_float_value.to_bits() == b.compressed_float_value.to_bits() &&
    a.double_value.to_bits() == b.double_value.to_bits() &&
    a.uint8_value == b.uint8_value &&
    a.uint16_value == b.uint16_value &&
    a.uint32_value == b.uint32_value &&
    a.uint64_value == b.uint64_value &&
    a.relative_near == b.relative_near &&
    a.relative_far == b.relative_far &&
    a.bytes == b.bytes &&
    a.string == b.string &&
    a.wstring == b.wstring &&
    a.fixed_q8_8 == b.fixed_q8_8 &&
    a.fixed_q16_16 == b.fixed_q16_16 &&
    a.fixed_q48_16 == b.fixed_q48_16 &&
    a.fixed_q16_16_unsigned == b.fixed_q16_16_unsigned &&
    a.fixed_q112_16_wide == b.fixed_q112_16_wide &&
    a.fixed_q64_64_wide == b.fixed_q64_64_wide
}

pub fn GoldenWireInit( data: &mut GoldenWireData )
{
    *data = GoldenWireData::default();
    data.bits4 = 13;
    data.bits11 = 1445;
    data.bits24 = 11259375;
    data.bits32 = 0xDEADBEEF;
    data.int_small = -37;
    data.int_full = -123456789;
    data.flag = true;
    data.float_value = 3.1415926f32;
    data.compressed_float_value = 5.0f32;
    data.double_value = 1.0 / 3.0;
    data.uint8_value = 0x7F;
    data.uint16_value = 0x1234;
    data.uint32_value = 0x12345678;
    data.uint64_value = 0x123456789ABCDEF0;
    data.relative_near = 101;                   // difference of 1 from the base: exercises the one bit branch
    data.relative_far = 2100;                   // difference of 2000 from the base: exercises the twelve bit bucket
    let golden_byte_data: [u8; 7] = [ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x01 ];
    data.bytes.copy_from_slice( &golden_byte_data );
    let string_size: usize = data.string.len();
    serialize_copy_string( &mut data.string, b"golden\0", string_size );
    // built from explicit code points so the source file encoding can never change the golden bytes
    let golden_wide_string: [wchar_t; 4] = [ 0x043C, 0x0438, 0x0440, 0 ];            // cyrillic, BMP only
    let wstring_size: usize = data.wstring.len();
    serialize_copy_wstring( &mut data.wstring, &golden_wide_string, wstring_size );
    data.fixed_q8_8 = ( -( 3 * 256 + 64 ) ) as i16;                                     // -3.25 in Q8.8
    data.fixed_q16_16 = 1234 * 65536 + 32768;                                           // 1234.5 in Q16.16
    data.fixed_q48_16 = -( 54321i64 * 65536 + 12345 );                                  // -54321.1883... in Q48.16
    data.fixed_q16_16_unsigned = 29999u32 * 65536 + 65535;                              // 29999.99998... in Q16.16: every fraction bit set
    data.fixed_q112_16_wide = ( -( 98765432109i64 * 65536 + 4321 ) ) as int128_t;       // -98765432109.066 in Q112.16: 75 bits on the wire, three groups
    data.fixed_q64_64_wide = ( ( 0x0123456789ABCDEFi64 as int128_t ) << 64 )
                           + ( 0x0FEDCBA987654321i64 as int128_t );                     // Q64.64 over the full unit range: 128 bits, four groups, every group distinct
}

pub fn GoldenWireSerialize<S: Stream>( stream: &mut S, data: &mut GoldenWireData ) -> bool
{
    let relative_base: i32 = 100;
    serialize_bits!( stream, data.bits4, 4 );
    serialize_bits!( stream, data.bits11, 11 );
    serialize_bits!( stream, data.bits24, 24 );
    serialize_bits!( stream, data.bits32, 32 );
    serialize_int!( stream, data.int_small, -100, 100 );
    serialize_int!( stream, data.int_full, i32::MIN, i32::MAX );
    serialize_bool!( stream, data.flag );
    serialize_float!( stream, data.float_value );
    serialize_compressed_float!( stream, data.compressed_float_value, 0.0f32, 10.0f32, 0.01f32 );
    serialize_double!( stream, data.double_value );
    serialize_uint8!( stream, data.uint8_value );
    serialize_uint16!( stream, data.uint16_value );
    serialize_uint32!( stream, data.uint32_value );
    serialize_uint64!( stream, data.uint64_value );
    serialize_int_relative!( stream, relative_base, data.relative_near );
    serialize_int_relative!( stream, relative_base, data.relative_far );
    serialize_align!( stream );
    // port: the sizeof values are taken first, because the macros borrow the arrays
    let bytes_size: i32 = data.bytes.len() as i32;
    let string_size: i32 = data.string.len() as i32;
    let wstring_size: i32 = data.wstring.len() as i32;
    serialize_bytes!( stream, data.bytes, bytes_size );
    serialize_string!( stream, data.string, string_size );
    serialize_wstring!( stream, data.wstring, wstring_size );
    serialize_align!( stream );                 // the fixed point section starts byte aligned, so every byte pinned above it stays put
    serialize_fixed!( stream, data.fixed_q8_8, 8, 8, -100, 100 );
    serialize_fixed!( stream, data.fixed_q16_16, 16, 16, -2000, 2000 );
    serialize_fixed!( stream, data.fixed_q48_16, 48, 16, -100000, 100000 );
    serialize_fixed!( stream, data.fixed_q16_16_unsigned, 16, 16, 0, 30000 );
    serialize_align!( stream );                 // the wide fixed section starts byte aligned, so every byte pinned above it stays put
    serialize_fixed!( stream, data.fixed_q112_16_wide, 112, 16, -144115188075855872i64, 144115188075855872i64 );     // ±2^57 units: 75 bits, the three group structure
    serialize_fixed!( stream, data.fixed_q64_64_wide, 64, 64, i64::MIN, i64::MAX );                                   // full unit range: 128 bits, the four group structure
    true
}

pub static golden_wire_bytes: &[u8] =
&[
    0x5D, 0xDA, 0xF7, 0xE6, 0xD5, 0x77, 0xDF, 0x56, 0xEF, 0x9F, 0x75, 0x19,
    0x52, 0xBC, 0xDA, 0x0F, 0x49, 0x40, 0xF4, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0xFF, 0xFC, 0xD1, 0x48, 0xE0, 0x59, 0xD1, 0x48, 0xC0, 0x7B,
    0xF3, 0x6A, 0xE2, 0x59, 0xD1, 0x48, 0x84, 0xB7, 0x06, 0xDE, 0xAD, 0xBE,
    0xEF, 0xCA, 0xFE, 0x01, 0x06, 0x67, 0x6F, 0x6C, 0x64, 0x65, 0x6E, 0xE3,
    0x21, 0x00, 0x00, 0xC0, 0x21, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
    0xC0, 0x60, 0x00, 0x80, 0xA2, 0x7C, 0xFC, 0xEC, 0x26, 0xCB, 0xFF, 0xFF,
    0x4B, 0x1D, 0x1F, 0xEF, 0xD2, 0x1A, 0x1F, 0x01, 0xE9, 0xFF, 0xFF, 0x09,
    0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x78, 0x6F, 0x5E, 0x4D, 0x3C,
    0x2B, 0x1A, 0x09, 0x04
];

pub fn test_golden_wire_format()
{
    // write side: serializing the golden values must produce exactly the golden bytes
    {
        let mut buffer: [u8; 256] = [0; 256];
        let buffer_size: i64 = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, buffer_size );
        let mut data = GoldenWireData::default();
        GoldenWireInit( &mut data );
        serialize_check!( GoldenWireSerialize( &mut stream, &mut data ) == true );
        stream.Flush();
        serialize_check!( stream.GetBytesProcessed() == golden_wire_bytes.len() as i64 );
        serialize_check!( buffer[..golden_wire_bytes.len()] == golden_wire_bytes[..] );
    }

    // read side: the golden bytes must decode to the expected values, on every platform, forever
    {
        let mut buffer: [u8; 256] = [0; 256];
        buffer[..golden_wire_bytes.len()].copy_from_slice( golden_wire_bytes );
        let mut stream = ReadStream::new( &buffer, golden_wire_bytes.len() as i64 );
        let mut data = GoldenWireData::default();
        serialize_check!( GoldenWireSerialize( &mut stream, &mut data ) == true );

        let mut expected = GoldenWireData::default();
        GoldenWireInit( &mut expected );
        serialize_check!( data.bits4 == expected.bits4 );
        serialize_check!( data.bits11 == expected.bits11 );
        serialize_check!( data.bits24 == expected.bits24 );
        serialize_check!( data.bits32 == expected.bits32 );
        serialize_check!( data.int_small == expected.int_small );
        serialize_check!( data.int_full == expected.int_full );
        serialize_check!( data.flag == expected.flag );
        serialize_check!( data.float_value == expected.float_value );
        serialize_check!( ( data.compressed_float_value - expected.compressed_float_value ).abs() <= 0.01f32 );
        serialize_check!( data.double_value == expected.double_value );
        serialize_check!( data.uint8_value == expected.uint8_value );
        serialize_check!( data.uint16_value == expected.uint16_value );
        serialize_check!( data.uint32_value == expected.uint32_value );
        serialize_check!( data.uint64_value == expected.uint64_value );
        serialize_check!( data.relative_near == expected.relative_near );
        serialize_check!( data.relative_far == expected.relative_far );
        serialize_check!( data.bytes == expected.bytes );
        // port: strcmp / wcscmp compare up to the terminator
        serialize_check!( data.string[..serialize_strlen( &data.string )] == expected.string[..serialize_strlen( &expected.string )] );
        serialize_check!( data.wstring[..serialize_wcslen( &data.wstring )] == expected.wstring[..serialize_wcslen( &expected.wstring )] );
        serialize_check!( data.fixed_q8_8 == expected.fixed_q8_8 );
        serialize_check!( data.fixed_q16_16 == expected.fixed_q16_16 );
        serialize_check!( data.fixed_q48_16 == expected.fixed_q48_16 );
        serialize_check!( data.fixed_q16_16_unsigned == expected.fixed_q16_16_unsigned );
        serialize_check!( data.fixed_q112_16_wide == expected.fixed_q112_16_wide );
        serialize_check!( data.fixed_q64_64_wide == expected.fixed_q64_64_wide );
    }
}

pub fn test_trailing_bits()
{
    // STANDARD.md, "Trailing bits" (adopted 2026-08-15): writers must emit zero in the unused
    // bits of the final byte; readers must not reject a stream for their contents. The third
    // rule — non-zero trailing bits as a provenance signal — belongs to tooling (see
    // tools/conformance), never to this read path, which is exactly what the reader half of
    // this test proves.

    // writer obligation: emit a message that ends 3 bits into its final byte, into a buffer
    // pre-filled with 0xFF so the zeros must come from the writer, not from the caller.
    {
        let mut buffer: [u8; 64] = [0xFF; 64];

        let buffer_size: i64 = buffer.len() as i64;
        let mut writeStream = WriteStream::new( &mut buffer, buffer_size );
        let mut head: u32 = 0xDEADBEEF;
        serialize_check!( writeStream.SerializeBits( &mut head, 32 ) == true );
        let mut tail: u32 = 5;
        serialize_check!( writeStream.SerializeBits( &mut tail, 3 ) == true );
        writeStream.Flush();

        let bytesWritten: i32 = writeStream.GetBytesProcessed() as i32;
        let bitsInFinalByte: i32 = ( writeStream.GetBitsProcessed() % 8 ) as i32;
        serialize_check!( bitsInFinalByte == 3 );                                       // the stream really does end unaligned
        let trailingMask: u8 = ( 0xFFu32 << bitsInFinalByte ) as u8;
        serialize_check!( ( buffer[( bytesWritten - 1 ) as usize] & trailingMask ) == 0 );      // writers must write zero

        // reader indifference, small stream: set every trailing bit and read back. the
        // doctored stream must be accepted and must decode the same values.
        buffer[( bytesWritten - 1 ) as usize] |= trailingMask;
        let mut readStream = ReadStream::new( &buffer, bytesWritten as i64 );
        let mut readHead: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut readHead, 32 ) == true );
        serialize_check!( readHead == 0xDEADBEEF );
        let mut readTail: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut readTail, 3 ) == true );
        serialize_check!( readTail == 5 );
    }

    // reader indifference, full message: doctor the trailing bits of the golden stream.
    // a conforming reader accepts the doctored stream and decodes byte-identical results.
    {
        let mut buffer: [u8; 256] = [0; 256];
        buffer[..golden_wire_bytes.len()].copy_from_slice( golden_wire_bytes );

        // port: the clean read runs on a copy, because the doctored stream below reads the buffer this one would borrow
        let cleanBuffer: [u8; 256] = buffer;
        let mut cleanStream = ReadStream::new( &cleanBuffer, golden_wire_bytes.len() as i64 );
        let mut cleanData = GoldenWireData::default();
        serialize_check!( GoldenWireSerialize( &mut cleanStream, &mut cleanData ) == true );

        let bitsInFinalByte: i32 = ( cleanStream.GetBitsProcessed() % 8 ) as i32;
        serialize_check!( bitsInFinalByte != 0 );                                       // golden ends unaligned, so this test can discriminate
        let trailingMask: u8 = ( 0xFFu32 << bitsInFinalByte ) as u8;
        serialize_check!( ( golden_wire_bytes[golden_wire_bytes.len() - 1] & trailingMask ) == 0 );     // the pinned emission met the writer obligation

        buffer[golden_wire_bytes.len() - 1] |= trailingMask;                            // set every trailing bit

        let mut doctoredStream = ReadStream::new( &buffer, golden_wire_bytes.len() as i64 );
        let mut doctoredData = GoldenWireData::default();
        serialize_check!( GoldenWireSerialize( &mut doctoredStream, &mut doctoredData ) == true );                  // readers must not reject
        serialize_check!( golden_wire_data_memcmp_equal( &doctoredData, &cleanData ) );                               // and must decode identically
        serialize_check!( doctoredStream.GetBitsProcessed() == cleanStream.GetBitsProcessed() );
    }
}

pub fn test_past_end_poison()
{
    // STANDARD.md, "Past-end memory is an implementation contract, not a format concern"
    // (ruled 2026-08-15: the draft stands). The C++ reader loads 64-bit windows at byte
    // granularity and requires its caller to allocate at least 8 bytes past the data; bytes
    // past the end are loaded but never interpreted. This proves the "never interpreted"
    // half: poison planted beyond the stream end must not change a single decoded byte, and
    // must not change refusal behavior.
    // port: the Rust reader takes the whole 256 byte buffer as its slice, so the bytes past the end are there for
    // it to load, as upstream's are

    // accept path: identical decode with a zeroed tail and a poisoned tail
    {
        let mut cleanBuffer: [u8; 256] = [0; 256];
        let mut poisonBuffer: [u8; 256] = [0xFF; 256];          // poison everywhere, including the loaded-but-never-interpreted window
        cleanBuffer[..golden_wire_bytes.len()].copy_from_slice( golden_wire_bytes );
        poisonBuffer[..golden_wire_bytes.len()].copy_from_slice( golden_wire_bytes );

        let mut cleanStream = ReadStream::new( &cleanBuffer, golden_wire_bytes.len() as i64 );
        let mut cleanData = GoldenWireData::default();
        serialize_check!( GoldenWireSerialize( &mut cleanStream, &mut cleanData ) == true );

        let mut poisonStream = ReadStream::new( &poisonBuffer, golden_wire_bytes.len() as i64 );
        let mut poisonData = GoldenWireData::default();
        serialize_check!( GoldenWireSerialize( &mut poisonStream, &mut poisonData ) == true );

        serialize_check!( golden_wire_data_memcmp_equal( &poisonData, &cleanData ) );        // byte-identical decode
        serialize_check!( poisonStream.GetBitsProcessed() == cleanStream.GetBitsProcessed() );
    }

    // refusal path: truncate the stream one byte short so the decode must fail. the bytes at
    // and past the truncated end are exactly where the reader's 64-bit window loads from, and
    // the refusal must be identical whether they are zero or poison.
    {
        let truncatedBytes: usize = golden_wire_bytes.len() - 1;

        let mut cleanBuffer: [u8; 256] = [0; 256];
        let mut poisonBuffer: [u8; 256] = [0xFF; 256];
        cleanBuffer[..truncatedBytes].copy_from_slice( &golden_wire_bytes[..truncatedBytes] );
        poisonBuffer[..truncatedBytes].copy_from_slice( &golden_wire_bytes[..truncatedBytes] );

        let mut cleanStream = ReadStream::new( &cleanBuffer, truncatedBytes as i64 );
        let mut cleanData = GoldenWireData::default();
        serialize_check!( GoldenWireSerialize( &mut cleanStream, &mut cleanData ) == false );

        let mut poisonStream = ReadStream::new( &poisonBuffer, truncatedBytes as i64 );
        let mut poisonData = GoldenWireData::default();
        serialize_check!( GoldenWireSerialize( &mut poisonStream, &mut poisonData ) == false );

        serialize_check!( poisonStream.GetBitsProcessed() == cleanStream.GetBitsProcessed() );   // both latched by the refusal, so both report the same position
        serialize_check!( golden_wire_data_memcmp_equal( &poisonData, &cleanData ) );            // with identical partial state
    }
}


// ---------------------------------------------------------------------------------------
// Does THIS build actually fuse, and does it fuse ACROSS statements?
//
// The compressed float's whole FMA discipline is a pair of stores through float locals that
// keep the quantization's two roundings distinct. Whether a build EXERCISES that discipline
// depends on two things the source cannot see: whether the target has an FMA instruction at
// all, and what the compiler's contraction setting is. -ffp-contract=on buys nothing on an
// x86-64 without FMA, and a build that prints a green log while fusing nothing has claimed a
// discipline it never ran. So measure it and say which.
//
// The three probes are deliberately different questions:
//
//   is_live               -- one contractible statement against the same arithmetic forced
//                            through a volatile store. If they ever differ, this target has
//                            an FMA and this build is permitted to use it.
//   crosses_statements    -- a PLAIN local store against the volatile one. The language
//                            rounds a float local, so only a compiler contracting ACROSS the
//                            statement boundary can make these two disagree. That is the
//                            -ffp-contract=fast behaviour (GCC's default at every -O level),
//                            and it is not a stricter `on`: it is a different mode, in which
//                            a plain float local suppresses nothing. The WIRE is safe in
//                            such a build -- the audited home pins both roundings with
//                            SERIALIZE_FLOAT_FORCE_ROUND, which no contraction mode fuses
//                            through -- but the frozen pre-split oracle in the differential
//                            below is a verbatim copy of code that predates the barrier, so
//                            it fuses, computes one-rounding values, and its comparisons
//                            stand down on such a build (the negative-control sentinels
//                            keep their teeth everywhere; see the differential).
//   barrier_holds         -- the audited home's shape, a store pinned by
//                            SERIALIZE_FLOAT_FORCE_ROUND, against the volatile reference.
//                            These must NEVER disagree: the barrier is what the wire's
//                            contraction invariance rests on, so a toolchain that fuses
//                            through it is refused by name before a single vector runs.
//
// crosses_statements has to be DETECTED rather than inferred from the flag, because GCC
// before 14 mapped -ffp-contract=on onto fast. On such a toolchain, asking for
// statement-local contraction silently gets cross-statement contraction instead, and the
// honest report says which mode is actually live -- not a bit pattern mismatch that reads
// like a port bug.
// ---------------------------------------------------------------------------------------

// port: Rust never contracts floating point (every f32 operation rounds to f32, and there is no fp-contract
// mode), so on every Rust build is_live and crosses_statements measure false and barrier_holds measures true.
// The probes are still ported and still run: they are measurements, and they say so if that ever changes

// The three spellings, each in its OWN function and each kept out of line. Out of line is
// deliberate: written as three expressions in one loop they share the subexpression `a * b`,
// the optimizer merges it, and a multiply with more than one use is not one the backend will
// fuse -- so the probe could report "does not fuse" about a build that fuses perfectly well.
// noinline keeps the three arithmetics from being merged into one and makes the probe a
// question about the compiler's setting rather than about its common-subexpression pass.
//
// One honest limit, measured rather than assumed: at -O0 no contraction setting produces an
// FMA at all, so an unoptimized build reports "not available" -- which is exactly true of
// that binary, and is why the report is printed rather than asserted.

// port: SERIALIZE_TEST_NOINLINE is #[inline(never)]

// contractible: one expression, so any compiler permitted to contract at all may fuse it
#[inline(never)]
pub fn serialize_test_fp_one_expression( a: f32, b: f32, c: f32 ) -> f32
{
    a * b + c
}

// two statements through a plain float local. The language rounds a float local, so only a
// compiler contracting ACROSS the statement boundary can fuse this -- which is the shape of
// the compressed float's audited home, and the property under test.
#[inline(never)]
pub fn serialize_test_fp_two_statements( a: f32, b: f32, c: f32 ) -> f32
{
    let product: f32 = a * b;
    product + c
}

// the reference: a volatile store forces the product to memory as float32, so no contraction
// setting on any compiler can fuse through it. This is what the other three are measured against.
// port: the volatile local is write_volatile / read_volatile
#[inline(never)]
pub fn serialize_test_fp_forced_unfused( a: f32, b: f32, c: f32 ) -> f32
{
    let mut product: f32 = 0.0;
    unsafe { std::ptr::write_volatile( &mut product, a * b ); }
    let stored: f32 = unsafe { std::ptr::read_volatile( &product ) };
    stored + c
}

// the audited home's shape: a local pinned by SERIALIZE_FLOAT_FORCE_ROUND. This is the
// mechanism the wire's contraction invariance rests on, probed directly.
#[inline(never)]
pub fn serialize_test_fp_two_statements_barriered( a: f32, b: f32, c: f32 ) -> f32
{
    let mut product: f32 = a * b;
    SERIALIZE_FLOAT_FORCE_ROUND( &mut product );
    product + c
}

pub fn serialize_test_fp_contraction_is_live() -> bool
{
    for code in 1..20000u32
    {
        let norm: f32 = code as f32 / 20000.0f32;
        let fused: f32 = serialize_test_fp_one_expression( norm, 200.0, -100.0 );
        let unfused: f32 = serialize_test_fp_forced_unfused( norm, 200.0, -100.0 );
        let pattern_fused: u32 = fused.to_bits();
        let pattern_unfused: u32 = unfused.to_bits();
        if pattern_fused != pattern_unfused
        {
            return true;
        }
    }
    false
}

pub fn serialize_test_fp_contraction_crosses_statements() -> bool
{
    for code in 1..20000u32
    {
        let norm: f32 = code as f32 / 20000.0f32;
        let across: f32 = serialize_test_fp_two_statements( norm, 200.0, -100.0 );
        let unfused: f32 = serialize_test_fp_forced_unfused( norm, 200.0, -100.0 );
        let pattern_across: u32 = across.to_bits();
        let pattern_unfused: u32 = unfused.to_bits();
        if pattern_across != pattern_unfused
        {
            return true;
        }
    }
    false
}

pub fn serialize_test_fp_barrier_holds() -> bool
{
    for code in 1..20000u32
    {
        let norm: f32 = code as f32 / 20000.0f32;
        let barriered: f32 = serialize_test_fp_two_statements_barriered( norm, 200.0, -100.0 );
        let unfused: f32 = serialize_test_fp_forced_unfused( norm, 200.0, -100.0 );
        let pattern_barriered: u32 = barriered.to_bits();
        let pattern_unfused: u32 = unfused.to_bits();
        if pattern_barriered != pattern_unfused
        {
            return false;
        }
    }
    true
}

// The caption for this build, so the two runs CMake performs are telling apart in a CI log.
// CMakeLists.txt defines it on the -ffp-contract=on target; the default covers a hand build
// and says nothing it cannot know.
// port: Rust has no contraction flag, so the caption is always the default

pub const SERIALIZE_TEST_FP_CONTRACT: &str = "the default flags";

// Conformance vector for compressed_float over a range with a NON-ZERO min. Additive: the
// golden wire test above is untouched and its bytes are pinned forever.
//
// The golden's compressed_float is 5.0 over [0,10]: min is 0, so the reader's final add
// contributes nothing and a reader whose multiply and add are fused into one FMA decodes
// the identical float — that vector is structurally blind to reader contraction. This one
// pins the decoded BIT PATTERNS, not just the wire bytes, over [-100,100] at resolution
// 0.01 (max_integer_value = 20000, 15 bits per value), where the add is load-bearing:
//
//   written value   quantized   pinned decode   what a wrong reading produces
//   0.0             10000       0x00000000      nothing — on-quantum sanity row, agrees everywhere
//   -99.875         13          0xC2C7BD71      a writer widened to double quantizes 12, not 13:
//                                               the scaled product is exactly 12.5, a boundary
//                                               value landing between quanta, and double resolves
//                                               it to 12.499999... — different wire bytes
//   -33.34          6666        0xC2055C2A      a reader contracted to an FMA decodes 0xC2055C29
//
// The last row is why this test exists: at plain -O2 on arm64 (clang's default
// -ffp-contract=on), the pre-fix single-expression reader decoded 0xC2055C29 — one ulp off
// every conformant runtime, so an arm64 re-encode produced different wire — and no vector
// in the family could see it. Under -ffast-math (the gate binaries' former flags) the 0.0
// row also breaks: reciprocal approximation of the division decodes 0xB6298800.

pub fn CompressedFloatNonZeroMinSerialize<S: Stream>( stream: &mut S, a: &mut f32, b: &mut f32, c: &mut f32 ) -> bool
{
    serialize_compressed_float!( stream, *a, -100.0f32, 100.0f32, 0.01f32 );
    serialize_compressed_float!( stream, *b, -100.0f32, 100.0f32, 0.01f32 );
    serialize_compressed_float!( stream, *c, -100.0f32, 100.0f32, 0.01f32 );
    serialize_align!( stream );
    true
}

pub fn test_compressed_float_conformance_nonzero_min()
{
    static pinned_bytes: [u8; 6] = [ 0x10, 0xA7, 0x06, 0x80, 0x82, 0x06 ];

    // write side: the strict two-rounding quantization must produce exactly these bytes
    {
        let mut buffer: [u8; 64] = [0; 64];
        let buffer_size: i64 = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, buffer_size );
        let mut a: f32 = 0.0;
        let mut b: f32 = -99.875;
        let mut c: f32 = -33.34;
        serialize_check!( CompressedFloatNonZeroMinSerialize( &mut stream, &mut a, &mut b, &mut c ) == true );
        stream.Flush();
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
        serialize_check!( buffer[..pinned_bytes.len()] == pinned_bytes[..] );
    }

    // read side: the decoded floats are pinned bit-exactly. tolerance comparison would
    // defeat the purpose — the divergence this detects is a single ulp.
    {
        let mut buffer: [u8; 64] = [0; 64];
        buffer[..pinned_bytes.len()].copy_from_slice( &pinned_bytes );
        let mut stream = ReadStream::new( &buffer, pinned_bytes.len() as i64 );
        let mut a: f32 = -1.0;
        let mut b: f32 = -1.0;
        let mut c: f32 = -1.0;
        serialize_check!( CompressedFloatNonZeroMinSerialize( &mut stream, &mut a, &mut b, &mut c ) == true );
        let bits_a: u32 = a.to_bits();
        let bits_b: u32 = b.to_bits();
        let bits_c: u32 = c.to_bits();
        // These stay pinned unconditionally on every build the library supports, under every
        // contraction mode including -ffp-contract=fast: the reader's two roundings are
        // pinned by SERIALIZE_FLOAT_FORCE_ROUND, which no contraction setting fuses through.
        // Before the barrier, a consumer building this header at gcc's arm64 defaults
        // reconstructed the last of these as 0xC2055C29 -- one ulp off every conformant
        // runtime -- and this check is the one that caught it (issue #95).
        serialize_check!( bits_a == 0x00000000u32 );
        serialize_check!( bits_b == 0xC2C7BD71u32 );
        serialize_check!( bits_c == 0xC2055C2Au32 );
    }
}

// Conformance vector for the WRITER's fusion class. Additive: every earlier vector is
// untouched. The nonzero-min vector above discriminates READER fusion (its write rows do not
// move under a fused writer -- measured), so a deleted writer barrier was invisible to the
// whole family. This one pins wire BYTES a fused writer cannot produce.
//
// The discriminating band is [2^23, 2^24) step counts -- the same band the normative integer
// clamp lives in (STANDARD.md, schema#109) -- because that is where the float32 ulp of the
// scaled product reaches 1 and the product's rounding decides the integer directly. Over
// [0, 16777215] at resolution 1 (max_integer_value = 2^24 - 1, 24 bits per value), measured
// exhaustively over every float in range on arm64: a writer whose product and +0.5 are fused
// into one FMA moves the quantized integer on 4,194,304 inputs -- every even float in the
// top binade -- and the first of them is 2^23 itself:
//
//   written value   pinned code   what a fused writer produces
//   8388608.0       8388608       8388609 -- one code up, different wire bytes
//   11184811.0      11184812      on-quantum-adjacent sanity row, agrees everywhere
//   16777215.0      16777215      the top code: the normative clamp's witness row
//
// The decoded BIT PATTERNS are pinned too. min is 0, so this vector is structurally blind to
// reader fusion -- that is the nonzero-min vector's job; the two vectors together cover both
// sides. serialize_test() runs on every supported build, including -ffp-contract=fast, so
// this is the vector that goes red if the writer's barrier is ever deleted.

pub fn CompressedFloatWriterFusionSerialize<S: Stream>( stream: &mut S, a: &mut f32, b: &mut f32, c: &mut f32 ) -> bool
{
    serialize_compressed_float!( stream, *a, 0.0f32, 16777215.0f32, 1.0f32 );
    serialize_compressed_float!( stream, *b, 0.0f32, 16777215.0f32, 1.0f32 );
    serialize_compressed_float!( stream, *c, 0.0f32, 16777215.0f32, 1.0f32 );
    serialize_align!( stream );
    true
}

pub fn test_compressed_float_conformance_writer_fusion()
{
    static pinned_bytes: [u8; 9] = [ 0x00, 0x00, 0x80, 0xAC, 0xAA, 0xAA, 0xFF, 0xFF, 0xFF ];

    // write side: the strict two-rounding quantization must produce exactly these bytes.
    // 8388608.0f is the row a fused writer moves; the pinned bytes are unreachable from a
    // build whose writer rounds once.
    {
        let mut buffer: [u8; 64] = [0; 64];
        let buffer_size: i64 = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, buffer_size );
        let mut a: f32 = 8388608.0;
        let mut b: f32 = 11184811.0;
        let mut c: f32 = 16777215.0;
        serialize_check!( CompressedFloatWriterFusionSerialize( &mut stream, &mut a, &mut b, &mut c ) == true );
        stream.Flush();
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
        serialize_check!( buffer[..pinned_bytes.len()] == pinned_bytes[..] );
    }

    // read side: the decoded floats are pinned bit-exactly, same terms as every conformance
    // vector -- the divergences this family detects are single ulps, and tolerance would
    // hide them.
    {
        let mut buffer: [u8; 64] = [0; 64];
        buffer[..pinned_bytes.len()].copy_from_slice( &pinned_bytes );
        let mut stream = ReadStream::new( &buffer, pinned_bytes.len() as i64 );
        let mut a: f32 = -1.0;
        let mut b: f32 = -1.0;
        let mut c: f32 = -1.0;
        serialize_check!( CompressedFloatWriterFusionSerialize( &mut stream, &mut a, &mut b, &mut c ) == true );
        let bits_a: u32 = a.to_bits();
        let bits_b: u32 = b.to_bits();
        let bits_c: u32 = c.to_bits();
        serialize_check!( bits_a == 0x4B000000u32 );       // 8388608.0
        serialize_check!( bits_b == 0x4B2AAAACu32 );       // 11184812.0
        serialize_check!( bits_c == 0x4B7FFFFFu32 );       // 16777215.0
    }
}

// The non-zero-min conformance vector again, through the PRECOMPUTED entry point, with the
// constants a schema compiler derives for [-100,100] at resolution 0.01 written as literals —
// exactly what generated code would pass. Same pinned bytes, same pinned decoded bit patterns:
// the precomputed path is held to the conformance law directly, independently of the
// differential below.

pub fn CompressedFloatPrecomputedConformanceSerialize<S: Stream>( stream: &mut S, a: &mut f32, b: &mut f32, c: &mut f32 ) -> bool
{
    serialize_compressed_float_precomputed!( stream, *a, 20000, 15, 200.0f32, -100.0f32 );
    serialize_compressed_float_precomputed!( stream, *b, 20000, 15, 200.0f32, -100.0f32 );
    serialize_compressed_float_precomputed!( stream, *c, 20000, 15, 200.0f32, -100.0f32 );
    serialize_align!( stream );
    true
}

pub fn test_compressed_float_precomputed_conformance()
{
    static pinned_bytes: [u8; 6] = [ 0x10, 0xA7, 0x06, 0x80, 0x82, 0x06 ];

    // write side: the precomputed quantization must produce exactly the pinned bytes
    {
        let mut buffer: [u8; 64] = [0; 64];
        let buffer_size: i64 = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, buffer_size );
        let mut a: f32 = 0.0;
        let mut b: f32 = -99.875;
        let mut c: f32 = -33.34;
        serialize_check!( CompressedFloatPrecomputedConformanceSerialize( &mut stream, &mut a, &mut b, &mut c ) == true );
        stream.Flush();
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
        serialize_check!( buffer[..pinned_bytes.len()] == pinned_bytes[..] );
    }

    // read side: the decoded floats are pinned bit-exactly, as in the derive-per-call vector above
    {
        let mut buffer: [u8; 64] = [0; 64];
        buffer[..pinned_bytes.len()].copy_from_slice( &pinned_bytes );
        let mut stream = ReadStream::new( &buffer, pinned_bytes.len() as i64 );
        let mut a: f32 = -1.0;
        let mut b: f32 = -1.0;
        let mut c: f32 = -1.0;
        serialize_check!( CompressedFloatPrecomputedConformanceSerialize( &mut stream, &mut a, &mut b, &mut c ) == true );
        let bits_a: u32 = a.to_bits();
        let bits_b: u32 = b.to_bits();
        let bits_c: u32 = c.to_bits();
        // pinned on the same terms as the derive-per-call vector above: see the note there
        serialize_check!( bits_a == 0x00000000u32 );
        serialize_check!( bits_b == 0xC2C7BD71u32 );
        serialize_check!( bits_c == 0xC2055C2Au32 );
    }
}

// The mas-bandwidth/schema#82 differential: the derive-per-call compressed float against the
// precomputed one. Three implementations must be indistinguishable in measured bits, wire
// bytes, read acceptance and decoded BIT PATTERNS on every input:
//
//   reference   -- serialize_compressed_float_frozen_reference below, a verbatim copy of the
//                  serialize_compressed_float_internal body as it stood BEFORE it was split
//                  into serialize_compressed_float_params plus the precomputed home. FROZEN:
//                  never edit it. it is the code the audited home replaced, kept so the
//                  differential proves the split changed nothing, forever.
//   legacy      -- serialize_compressed_float( stream, value, min, max, res ), which since the
//                  split derives the constants per call and forwards to the audited home.
//   precomputed -- serialize_compressed_float_precomputed( ... ) with constants derived once
//                  per declaration by serialize_compressed_float_params, exactly as a schema
//                  compiler derives them at generation time.
//
// the declaration corpus is every compressed float declaration the schema compiler's examples,
// bench corpus and test data emit (harvested from the mas-bandwidth/schema PR #79 differential,
// which proved the same property for the Go generation-time fold), plus this repo's golden,
// conformance, fuzz and example declarations, plus shapes at the edges of the derivation
// itself: resolution coarser than the range, a step count that exactly fills its wire width,
// a million steps, and the clamp at the largest float below 2^32.
//
// inputs per declaration: a dense sweep with overshoot past both bounds, the quantization step
// edges and midpoints with their one-ulp neighbors (the midpoints are where a fused or widened
// writer diverges — STANDARD.md's 0.005-over-[0,10] class), specials (bounds and their one-ulp
// neighbors, negative zero, subnormals, float extremes), LCG uniform in-range values and LCG
// uniform float32 bit patterns — and on the read side every representable wire integer
// including the bit headroom, exhaustively up to 16-bit widths and sampled with the boundary
// codes pinned above that. decoded values compare by BIT PATTERN, never by tolerance: the
// divergence a fused or widened decode produces is one ulp, invisible to any tolerance.

pub fn serialize_compressed_float_frozen_reference<S: Stream>( stream: &mut S, value: &mut f32, min: f32, max: f32, res: f32 ) -> bool
{
    // verbatim pre-split serialize_compressed_float_internal, comments elided, statements
    // identical (locals included: the float stores are what pin the two roundings). DO NOT EDIT.
    // port: uint32_t to float conversions are `as f32` (round to nearest, as in C)
    serialize_assert!( min < max && res > 0.0 );

    let delta: f32 = max - min;

    let mut values: f32 = delta / res;

    serialize_assert!( delta - delta == 0.0f32 );
    serialize_assert!( values - values == 0.0f32 );

    if !( values >= 1.0f32 )
    {
        values = 1.0f32;
    }
    else if values > 4294967040.0f32      // largest float below 2^32
    {
        values = 4294967040.0f32;
    }

    let maxIntegerValue: u32 = values.ceil() as u32;

    let bits: i32 = bits_required( 0, maxIntegerValue );

    let mut integerValue: u32 = 0;

    if S::IsWriting
    {
        serialize_assert!( *value - *value == 0.0f32 );

        let mut normalizedValue: f32 = ( *value - min ) / delta;
        if !( normalizedValue >= 0.0f32 )
        {
            normalizedValue = 0.0f32;
        }
        else if !( normalizedValue <= 1.0f32 )
        {
            normalizedValue = 1.0f32;
        }
        let scaled: f32 = normalizedValue * maxIntegerValue as f32;
        integerValue = ( scaled + 0.5f32 ).floor() as u32;
        // STANDARD.md: the integer clamp is normative (2026-08-23) -- same
        // clamp as serialize_compressed_float above, same reason.
        if integerValue > maxIntegerValue
        {
            integerValue = maxIntegerValue;
        }
    }

    if !stream.SerializeBits( &mut integerValue, bits )
    {
        return false;
    }

    if S::IsReading
    {
        if integerValue > maxIntegerValue
        {
            return false;
        }
        let normalizedValue: f32 = integerValue as f32 / maxIntegerValue as f32;
        let scaledValue: f32 = normalizedValue * delta;
        *value = scaledValue + min;
    }

    true
}

// each helper drives the actual macro form under test, so the differential covers the macros as
// well as the internals (the compile time surface tests established this pattern)

pub fn serialize_compressed_float_legacy_form<S: Stream>( stream: &mut S, value: &mut f32, min: f32, max: f32, res: f32 ) -> bool
{
    serialize_compressed_float!( stream, *value, min, max, res );
    true
}

pub fn serialize_compressed_float_precomputed_form<S: Stream>( stream: &mut S, value: &mut f32, max_integer_value: u32, bits: i32, delta: f32, min: f32 ) -> bool
{
    serialize_compressed_float_precomputed!( stream, *value, max_integer_value, bits, delta, min );
    true
}

// ---------------------------------------------------------------------------------------
// THE NEGATIVE CONTROLS -- proof that this differential's eyes are open.
//
// Every check below compares implementations that are SUPPOSED to agree, and a test where
// everything agrees cannot distinguish "the split changed nothing" from "the comparison
// cannot see this class of change". The distinction is not hypothetical here: the whole FMA
// discipline in the audited home is a pair of stores through float locals, and whether
// DELETING them is visible depends entirely on the build. Measured on clang 21 / arm64 by
// folding the reader's two roundings back into one expression in
// serialize_compressed_float_precomputed_internal and rebuilding:
//
//     -ffp-contract=off    the falsified build PASSES  -- no teeth
//     -ffp-contract=on     the falsified build is RED  -- teeth
//     -ffp-contract=fast   the falsified build PASSES  -- no teeth
//
// The two "safe" settings are blind for opposite reasons: `off` forbids contraction in the
// frozen oracle too, so the fused spelling and the stored one compute the same thing;
// `fast` fuses ACROSS statements, so the frozen oracle fuses as well and the two forms stop
// being distinguishable. The mode that looks strictest has no teeth, and the mode this repo
// pins for the wire is the other one with no teeth. That is why CMakeLists.txt builds this
// suite a SECOND time at -ffp-contract=on: `off` is correct for the wire and toothless for
// this property, and the second build adds back the discrimination it costs.
//
// That covers the compiler. The two sentinels below cover the rest, and they do it on EVERY
// host and under EVERY flag: they are the same one-rounding perturbations spelled in
// DOUBLE, where no FMA hardware and no contraction setting is required to produce the
// divergence. Each runs alongside the real path over the whole corpus, and the differential
// FAILS if either ever stops diverging -- i.e. if a future edit ever leaves the wire bytes
// or the decoded bit patterns blind to a single-rounding quantization.
//
// This is the part that generalises, and it is the reason a control beats a contraction
// sweep: a sweep is something a person has to remember to run, and it proved this property
// exactly once. A control that fails when it stops diverging is permanent, and it does not
// depend on anyone choosing the right flag. It pays for itself immediately: at
// -ffp-contract=fast the read control drops to ZERO, because the compiler fuses the audited
// home into exactly the one-rounding sentinel -- so this suite now fails a `fast` build BY
// ITSELF, naming the reason, instead of passing green while blind.
//
// The sentinels are deliberately NOT compared against the frozen oracle for equality. They
// are supposed to disagree. That is the whole point. The divergence counts are printed, so
// the mass is visible and not just the verdict.
// ---------------------------------------------------------------------------------------

// port: Rust has the -ffp-contract=off semantics on every build, so (as upstream says of that mode) the compiler
// half of the discrimination is not available; the two sentinels carry it, exactly as they do upstream

// port: the file statics are atomics (the tests are single threaded, as upstream; this only avoids static mut)
pub static compressed_float_sentinel_write_divergences: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new( 0 );
pub static compressed_float_sentinel_read_divergences: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new( 0 );

// Whether the frozen pre-split oracle computes conformant values in THIS build. The frozen
// reference is a verbatim copy of code that predates SERIALIZE_FLOAT_FORCE_ROUND, so under
// cross-statement contraction (-ffp-contract=fast, GCC's default) it fuses its two roundings
// into one while the barriered audited home does not. On such a build its comparisons assert
// the wrong thing and stand down; the sentinels above and the conformance vectors carry the
// teeth there. Set from the measured probe at the top of the differential -- detected, never
// inferred from flags.
pub static compressed_float_frozen_oracle_conformant: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new( true );

// the writer's quantization with the two float roundings collapsed: the product and the
// +0.5 both taken in double, rounded once by the floor. the "widened to double"
// perturbation, permanently on watch.
pub fn compressed_float_sentinel_write_code_one_rounding( value: f32, max_integer_value: u32, delta: f32, min: f32 ) -> u32
{
    let mut normalized: f32 = ( value - min ) / delta;
    if !( normalized >= 0.0f32 )
    {
        normalized = 0.0f32;
    }
    else if !( normalized <= 1.0f32 )
    {
        normalized = 1.0f32;
    }
    ( normalized as f64 * max_integer_value as f64 + 0.5 ).floor() as u32
}

// the reader's reconstruction with the multiply and the add collapsed into one rounding --
// exactly what an FMA contraction produces, spelled in double so it happens on hosts
// without an FMA instruction too.
pub fn compressed_float_sentinel_read_value_one_rounding( integer_value: u32, max_integer_value: u32, delta: f32, min: f32 ) -> f32
{
    let normalized: f32 = integer_value as f32 / max_integer_value as f32;
    ( normalized as f64 * delta as f64 + min as f64 ) as f32
}

pub static compressed_float_differential_check_count: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new( 0 );

macro_rules! serialize_differential_check {
    ( $condition:expr ) => {
        {
            serialize_check!( $condition );
            compressed_float_differential_check_count.fetch_add( 1, std::sync::atomic::Ordering::Relaxed );
        }
    };
}

// one written value through all three implementations: measured bits, wire bytes and decoded
// bit patterns must agree exactly
pub fn check_compressed_float_value_agrees( value: f32, min: f32, max: f32, res: f32, max_integer_value: u32, bits: i32, delta: f32 )
{
    let oracle_conformant: bool = compressed_float_frozen_oracle_conformant.load( std::sync::atomic::Ordering::Relaxed );

    // measure: all three forms agree on cost
    let mut measureReference = MeasureStream::new();
    let mut measure_value: f32 = value;
    serialize_differential_check!( serialize_compressed_float_frozen_reference( &mut measureReference, &mut measure_value, min, max, res ) == true );
    let mut measureLegacy = MeasureStream::new();
    measure_value = value;
    serialize_differential_check!( serialize_compressed_float_legacy_form( &mut measureLegacy, &mut measure_value, min, max, res ) == true );
    let mut measurePrecomputed = MeasureStream::new();
    measure_value = value;
    serialize_differential_check!( serialize_compressed_float_precomputed_form( &mut measurePrecomputed, &mut measure_value, max_integer_value, bits, delta, min ) == true );
    serialize_differential_check!( measureReference.GetBitsProcessed() == measureLegacy.GetBitsProcessed() );
    serialize_differential_check!( measureReference.GetBitsProcessed() == measurePrecomputed.GetBitsProcessed() );

    // write: byte identical wire from all three
    let mut buffer_reference: [u8; 8 + 8] = [0; 8 + 8];            // + 8: read buffer allocations extend 8 bytes past the data
    let mut buffer_legacy: [u8; 8 + 8] = [0; 8 + 8];               // + 8: read buffer allocations extend 8 bytes past the data
    let mut buffer_precomputed: [u8; 8 + 8] = [0; 8 + 8];          // + 8: read buffer allocations extend 8 bytes past the data

    let mut writeReference = WriteStream::new( &mut buffer_reference, 8 );
    let mut write_value: f32 = value;
    serialize_differential_check!( serialize_compressed_float_frozen_reference( &mut writeReference, &mut write_value, min, max, res ) == true );
    writeReference.Flush();

    let mut writeLegacy = WriteStream::new( &mut buffer_legacy, 8 );
    write_value = value;
    serialize_differential_check!( serialize_compressed_float_legacy_form( &mut writeLegacy, &mut write_value, min, max, res ) == true );
    writeLegacy.Flush();

    let mut writePrecomputed = WriteStream::new( &mut buffer_precomputed, 8 );
    write_value = value;
    serialize_differential_check!( serialize_compressed_float_precomputed_form( &mut writePrecomputed, &mut write_value, max_integer_value, bits, delta, min ) == true );
    writePrecomputed.Flush();

    serialize_differential_check!( writeReference.GetBitsProcessed() == writeLegacy.GetBitsProcessed() );
    serialize_differential_check!( writeReference.GetBitsProcessed() == writePrecomputed.GetBitsProcessed() );
    serialize_differential_check!( buffer_legacy[..8] == buffer_precomputed[..8] );
    if oracle_conformant
    {
        serialize_differential_check!( buffer_reference[..8] == buffer_legacy[..8] );
        serialize_differential_check!( buffer_reference[..8] == buffer_precomputed[..8] );
    }

    // read: decoded BIT PATTERNS agree exactly — one ulp of divergence must fail
    let mut readReference = ReadStream::new( &buffer_precomputed, 8 );
    let mut decoded_reference: f32 = 0.0;
    serialize_differential_check!( serialize_compressed_float_frozen_reference( &mut readReference, &mut decoded_reference, min, max, res ) == true );
    let mut readLegacy = ReadStream::new( &buffer_precomputed, 8 );
    let mut decoded_legacy: f32 = 0.0;
    serialize_differential_check!( serialize_compressed_float_legacy_form( &mut readLegacy, &mut decoded_legacy, min, max, res ) == true );
    let mut readPrecomputed = ReadStream::new( &buffer_precomputed, 8 );
    let mut decoded_precomputed: f32 = 0.0;
    serialize_differential_check!( serialize_compressed_float_precomputed_form( &mut readPrecomputed, &mut decoded_precomputed, max_integer_value, bits, delta, min ) == true );

    let pattern_reference: u32 = decoded_reference.to_bits();
    let pattern_legacy: u32 = decoded_legacy.to_bits();
    let pattern_precomputed: u32 = decoded_precomputed.to_bits();
    serialize_differential_check!( pattern_legacy == pattern_precomputed );
    if oracle_conformant
    {
        serialize_differential_check!( pattern_reference == pattern_legacy );
        serialize_differential_check!( pattern_reference == pattern_precomputed );
    }

    // the write-side negative control: the one-rounding quantization must still be able to
    // produce a DIFFERENT wire code than the audited home does, or the byte comparison above
    // has gone blind. The code is read back off the audited home's own wire rather than
    // recomputed, so the control is measured against the bytes the SHIPPED path actually
    // made — which keeps its teeth on every build, including one whose frozen oracle has
    // stood down.
    {
        let mut sentinelStream = ReadStream::new( &buffer_precomputed, 8 );
        let mut wire_code: u32 = 0;
        if sentinelStream.SerializeBits( &mut wire_code, bits )
        {
            if compressed_float_sentinel_write_code_one_rounding( value, max_integer_value, delta, min ) != wire_code
            {
                compressed_float_sentinel_write_divergences.fetch_add( 1, std::sync::atomic::Ordering::Relaxed );
            }
        }
    }
}

// one wire integer through all three read paths: acceptance must agree (the headroom refusal),
// and accepted codes must decode to identical bit patterns
pub fn check_compressed_float_code_agrees( code: u32, min: f32, max: f32, res: f32, max_integer_value: u32, bits: i32, delta: f32 )
{
    let mut buffer: [u8; 8 + 8] = [0; 8 + 8];              // + 8: read buffer allocations extend 8 bytes past the data
    let mut writeStream = WriteStream::new( &mut buffer, 8 );
    let mut raw: u32 = code;
    serialize_differential_check!( writeStream.SerializeBits( &mut raw, bits ) == true );
    writeStream.Flush();

    let mut readReference = ReadStream::new( &buffer, 8 );
    let mut decoded_reference: f32 = 0.0;
    let ok_reference: bool = serialize_compressed_float_frozen_reference( &mut readReference, &mut decoded_reference, min, max, res );

    let mut readLegacy = ReadStream::new( &buffer, 8 );
    let mut decoded_legacy: f32 = 0.0;
    let ok_legacy: bool = serialize_compressed_float_legacy_form( &mut readLegacy, &mut decoded_legacy, min, max, res );

    let mut readPrecomputed = ReadStream::new( &buffer, 8 );
    let mut decoded_precomputed: f32 = 0.0;
    let ok_precomputed: bool = serialize_compressed_float_precomputed_form( &mut readPrecomputed, &mut decoded_precomputed, max_integer_value, bits, delta, min );

    serialize_differential_check!( ok_reference == ok_legacy );
    serialize_differential_check!( ok_reference == ok_precomputed );
    serialize_differential_check!( ok_reference == ( code <= max_integer_value ) );      // the headroom refusal itself

    if ok_reference
    {
        let pattern_reference: u32 = decoded_reference.to_bits();
        let pattern_legacy: u32 = decoded_legacy.to_bits();
        let pattern_precomputed: u32 = decoded_precomputed.to_bits();
        serialize_differential_check!( pattern_legacy == pattern_precomputed );
        if compressed_float_frozen_oracle_conformant.load( std::sync::atomic::Ordering::Relaxed )
        {
            serialize_differential_check!( pattern_reference == pattern_legacy );
            serialize_differential_check!( pattern_reference == pattern_precomputed );
        }

        // the read-side negative control: a one-rounding reconstruction must still be able
        // to land on a DIFFERENT bit pattern, or the pattern comparison above has gone
        // blind. The divergence is one ulp, which is exactly why this differential never
        // compares decoded values with a tolerance. Measured against the SHIPPED path's
        // decode, so it keeps its teeth on every build: if the audited home's two roundings
        // are ever fused -- a deleted barrier under -ffp-contract=fast is exactly this --
        // the home decodes what the sentinel decodes, the divergences drop to zero, and the
        // nonzero assertion below the corpus fails by name.
        let sentinel_value: f32 = compressed_float_sentinel_read_value_one_rounding( code, max_integer_value, delta, min );
        let pattern_sentinel: u32 = sentinel_value.to_bits();
        if pattern_sentinel != pattern_precomputed
        {
            compressed_float_sentinel_read_divergences.fetch_add( 1, std::sync::atomic::Ordering::Relaxed );
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CompressedFloatShape
{
    pub min: f32,
    pub max: f32,
    pub res: f32,
    pub expected_max_integer_value: u32,        // pinned: the constants a schema compiler emits for this declaration
    pub expected_bits: i32,                     // (the first eleven rows are the values the schema PR #79 differential published)
}

// port: the aggregate initializer rows are struct literals through this shorthand
const fn compressed_float_shape( min: f32, max: f32, res: f32, expected_max_integer_value: u32, expected_bits: i32 ) -> CompressedFloatShape
{
    CompressedFloatShape { min, max, res, expected_max_integer_value, expected_bits }
}

pub static compressed_float_shapes: &[CompressedFloatShape] =
&[
    // the schema compiler's corpus: examples, bench/corpus/RealWorld.schema and its test data
    compressed_float_shape( 0.0,       2000.0,        0.1,       20000,       15 ),
    compressed_float_shape( -2.0,      2.0,           0.25,      16,          5  ),
    compressed_float_shape( -90.0,     90.0,          0.5,       360,         9  ),
    compressed_float_shape( 0.0,       30.0,          0.5,       60,          6  ),
    compressed_float_shape( -100.0,    100.0,         0.25,      800,         10 ),
    compressed_float_shape( 0.0,       2000.0,        1.0,       2000,        11 ),
    compressed_float_shape( 0.0,       10.0,          0.02,      500,         9  ),
    compressed_float_shape( 0.0,       100.0,         0.01,      10000,       14 ),
    compressed_float_shape( -180.0,    180.0,         0.01,      36000,       16 ),
    compressed_float_shape( 0.0,       10.0,          0.01,      1000,        10 ),       // also this repo's golden wire declaration
    compressed_float_shape( -5.0,      5.0,           0.001,     10000,       14 ),
    // this repo's own declarations
    compressed_float_shape( -100.0,    100.0,         0.01,      20000,       15 ),       // the non-zero-min conformance vector
    compressed_float_shape( -10.0,     10.0,          0.01,      2000,        11 ),       // the fuzz harness declaration
    compressed_float_shape( -1.0,      1.0,           0.001,     2000,        11 ),       // example.cpp's orientation declaration
    // shapes at the edges of the derivation itself
    compressed_float_shape( 0.0,       1.0,           2.0,       1,           1  ),       // resolution coarser than the range: values clamps up to 1
    compressed_float_shape( 0.0,       15.0,          1.0,       15,          4  ),       // step count exactly fills the wire width: no headroom to refuse
    compressed_float_shape( 0.0,       1000000.0,     1.0,       1000000,     20 ),       // a million steps
    compressed_float_shape( 0.0,       10000000000.0, 1.0,       4294967040,  32 ),       // values clamps down to the largest float below 2^32
    // shapes that discriminate the rounding rule itself: a fractional step count BELOW the half step,
    // where ceil and round disagree. Every row above lands on an integer or within half a step of one,
    // so all of them derive the same constants under either rule -- the corpus could not see a swap.
    compressed_float_shape( 0.0,       10.0,          0.3,       34,          6  ),       // 33.333332 steps: ceil 34, round 33 -- same width, different step count
    compressed_float_shape( 0.0,       63.3,          1.0,       64,          7  ),       // 63.3 steps: ceil 64 (7 bits), round 63 (6 bits) -- straddles a power of two, so the WIRE WIDTH moves
    // shapes in [2^23, 2^24), where the float32 ulp reaches 1 and the +0.5 rounding could
    // push the code past max_integer_value before the normative clamp (2026-08-23,
    // schema#109). The corpus was empty in this band, which is how the defect hid.
    compressed_float_shape( 0.0,       8388609.0,     1.0,       8388609,     24 ),       // 2^23+1: the reader-rejects witness
    compressed_float_shape( 0.0,       16777215.0,    1.0,       16777215,    24 ),       // 2^24-1: the wire-divergence witness
];

pub fn test_compressed_float_top_of_range_clamp()
{
    // STANDARD.md's normative integer clamp (2026-08-23, schema#109; ruling: Glenn, live).
    // In [2^23, 2^24) the float32 ulp is 1, so scaled + 0.5f lands on a tie and
    // round-to-even can push the code past max_integer_value. Before the clamp,
    // witness A wrote a top-of-range code its own reader rejected, and witness B
    // wrote a code one bit wider than the field.
    {
        // witness A: [0, 8388609] at resolution 1 -> max_integer_value 2^23+1, 24 bits
        let mut buffer: [u8; 16 + 8] = [0; 16 + 8];
        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let mut written: f32 = 8388609.0;
        serialize_check!( serialize_compressed_float_internal( &mut writeStream, &mut written, 0.0, 8388609.0, 1.0 ) == true );
        writeStream.Flush();
        let mut readStream = ReadStream::new( &buffer, 16 );
        let mut value: f32 = 0.0;
        serialize_check!( serialize_compressed_float_internal( &mut readStream, &mut value, 0.0, 8388609.0, 1.0 ) == true );
        serialize_check!( value == 8388609.0f32 );
    }
    {
        // witness B: [0, 16777215] at resolution 1 -> max_integer_value 2^24-1, 24 bits;
        // the unclamped code was 2^24, one bit wider than the field
        let mut buffer: [u8; 16 + 8] = [0; 16 + 8];
        let mut writeStream = WriteStream::new( &mut buffer, 16 );
        let mut written: f32 = 16777215.0;
        serialize_check!( serialize_compressed_float_internal( &mut writeStream, &mut written, 0.0, 16777215.0, 1.0 ) == true );
        writeStream.Flush();
        let mut readStream = ReadStream::new( &buffer, 16 );
        let mut value: f32 = 0.0;
        serialize_check!( serialize_compressed_float_internal( &mut readStream, &mut value, 0.0, 16777215.0, 1.0 ) == true );
        serialize_check!( value == 16777215.0f32 );
    }
}

// port: C's nextafterf. f32::next_up / next_down need Rust 1.86 and the crate's rust-version is 1.80, so this is
// the C definition spelled on the bit pattern
pub fn serialize_test_nextafterf( x: f32, y: f32 ) -> f32
{
    if x.is_nan() || y.is_nan()
    {
        return x + y;
    }
    if x == y
    {
        return y;
    }
    if x == 0.0
    {
        // the smallest subnormal, with the sign of the direction
        return if y > 0.0 { f32::from_bits( 1 ) } else { f32::from_bits( 0x80000001 ) };
    }
    let bits: u32 = x.to_bits();
    if ( x < y ) == ( x > 0.0 )
    {
        f32::from_bits( bits + 1 )          // away from zero
    }
    else
    {
        f32::from_bits( bits - 1 )          // toward zero
    }
}

pub fn test_compressed_float_precomputed_differential()
{
    // the frozen oracle predates the barrier: under cross-statement contraction it fuses,
    // so its comparisons stand down on such a build (see the declaration above)
    compressed_float_frozen_oracle_conformant.store( !serialize_test_fp_contraction_crosses_statements(), std::sync::atomic::Ordering::Relaxed );

    let float_max: f32 = 3.402823466e+38f32;               // FLT_MAX, spelled so the header needs no float.h

    let mut lcg: u64 = 0xC0FFEE1234567890;                   // fixed seed: failures reproduce

    macro_rules! serialize_differential_next_lcg {
        () => {
            {
                lcg = lcg.wrapping_mul( 6364136223846793005 ).wrapping_add( 1442695040888963407 );
                lcg
            }
        };
    }

    let num_shapes: i32 = compressed_float_shapes.len() as i32;

    for s in 0..num_shapes as usize
    {
        let min: f32 = compressed_float_shapes[s].min;
        let max: f32 = compressed_float_shapes[s].max;
        let res: f32 = compressed_float_shapes[s].res;

        let mut max_integer_value: u32 = 0;
        let mut bits: i32 = 0;
        let mut delta: f32 = 0.0;
        serialize_compressed_float_params( min, max, res, &mut max_integer_value, &mut bits, &mut delta );

        // the derived constants are pinned against the schema compiler's generation-time table
        serialize_differential_check!( max_integer_value == compressed_float_shapes[s].expected_max_integer_value );
        serialize_differential_check!( bits == compressed_float_shapes[s].expected_bits );
        serialize_differential_check!( delta == max - min );

        let dmin: f64 = min as f64;
        let ddelta: f64 = delta as f64;

        // dense sweep with overshoot a quarter of the range past both bounds
        {
            let sweep_steps: i32 = 2048;
            let lo: f64 = dmin - 0.25 * ddelta;
            let span: f64 = 1.5 * ddelta;
            for i in 0..=sweep_steps
            {
                let value: f32 = ( lo + span * i as f64 / sweep_steps as f64 ) as f32;
                check_compressed_float_value_agrees( value, min, max, res, max_integer_value, bits, delta );
            }
        }

        // quantization step edges and midpoints, with their one-ulp neighbors. the midpoints
        // are the discriminating band: 0.005 over [0,10] at 0.01 quantizes to 1 under the
        // required two roundings and to 0 under a fused or widened writer (STANDARD.md)
        {
            let stride: u32 = max_integer_value / 512 + 1;
            let mut k: u64 = 0;
            while k <= max_integer_value as u64      // 64 bit: k += stride must not wrap at the 2^32-clamped shape
            {
                let on_quantum: f32 = ( dmin + ddelta * ( k as f64 / max_integer_value as f64 ) ) as f32;
                let midpoint: f32 = ( dmin + ddelta * ( ( k as f64 + 0.5 ) / max_integer_value as f64 ) ) as f32;
                check_compressed_float_value_agrees( on_quantum, min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( serialize_test_nextafterf( on_quantum, -float_max ), min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( serialize_test_nextafterf( on_quantum, float_max ), min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( midpoint, min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( serialize_test_nextafterf( midpoint, -float_max ), min, max, res, max_integer_value, bits, delta );
                check_compressed_float_value_agrees( serialize_test_nextafterf( midpoint, float_max ), min, max, res, max_integer_value, bits, delta );
                k += stride as u64;
            }
        }

        // specials: the bounds and their one-ulp neighbors, both zeros, subnormals, extremes
        {
            let specials: [f32; 24] =
            [
                min,
                max,
                serialize_test_nextafterf( min, -float_max ),
                serialize_test_nextafterf( min, float_max ),
                serialize_test_nextafterf( max, -float_max ),
                serialize_test_nextafterf( max, float_max ),
                min - res,
                max + res,
                min + res * 0.5,
                max - res * 0.5,
                min - delta,
                max + delta,
                0.0f32,
                -0.0f32,
                res,
                -res,
                float_max,
                -float_max,
                1.175494351e-38f32,             // FLT_MIN
                -1.175494351e-38f32,
                1.401298464e-45f32,             // the smallest subnormal
                -1.401298464e-45f32,
                1.0e30f32,
                -1.0e30f32,
            ];
            for i in 0..specials.len()
            {
                check_compressed_float_value_agrees( specials[i], min, max, res, max_integer_value, bits, delta );
            }
        }

        // port: NDEBUG is !debug_assertions
        if !cfg!( debug_assertions )
        {
            // non-finite inputs are non-conforming and assert in debug (proven by the fork tests),
            // so the release build is where the differential can drive them: the clamp must force
            // NaN and both infinities to the same wire in all three implementations
            let non_finite_patterns: [u32; 5] = [ 0x7F800000, 0xFF800000, 0x7FC00000, 0x7F800001, 0xFFC00001 ];
            for i in 0..non_finite_patterns.len()
            {
                let value: f32 = f32::from_bits( non_finite_patterns[i] );
                check_compressed_float_value_agrees( value, min, max, res, max_integer_value, bits, delta );
            }
        }

        // LCG uniform values across the range and its overshoot band
        {
            for i in 0..2048
            {
                let fraction: f64 = ( serialize_differential_next_lcg!() >> 11 ) as f64 * ( 1.0 / 9007199254740992.0 );     // [0,1) in 53 bits
                let value: f32 = ( dmin - 0.25 * ddelta + fraction * 1.5 * ddelta ) as f32;
                check_compressed_float_value_agrees( value, min, max, res, max_integer_value, bits, delta );
            }
        }

        // LCG uniform float32 bit patterns, finite ones (non-finite writes assert in debug;
        // the release-only block above drives those deliberately)
        {
            for i in 0..2048
            {
                let pattern: u32 = ( serialize_differential_next_lcg!() >> 32 ) as u32;
                let value: f32 = f32::from_bits( pattern );
                if value - value == 0.0f32
                {
                    check_compressed_float_value_agrees( value, min, max, res, max_integer_value, bits, delta );
                }
            }
        }

        // the read side: every representable wire integer, including the bit headroom a
        // malicious packet can encode into. exhaustive up to 16-bit widths; above that the
        // boundary codes are pinned and the interior is sampled
        {
            let top_code: u32 = if bits == 32 { 0xFFFFFFFF } else { ( 1u32 << bits ) - 1 };
            if bits <= 16
            {
                for code in 0..=top_code
                {
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                }
            }
            else
            {
                for code in 0..=1024u32
                {
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                }
                let window_lo: u32 = max_integer_value - 512;                 // max_integer_value >= 2^16 here, so no underflow
                let window_hi: u32 = if top_code - max_integer_value < 512 { top_code } else { max_integer_value + 512 };
                let mut code: u32 = window_lo;
                while code <= window_hi && code >= window_lo
                {
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                    code = code.wrapping_add( 1 );
                }
                let mut code: u32 = top_code - 64;
                while code <= top_code && code >= top_code - 64
                {
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                    code = code.wrapping_add( 1 );
                }
                for i in 0..2048
                {
                    let code: u32 = ( ( serialize_differential_next_lcg!() >> 32 ) as u32 ) & top_code;
                    check_compressed_float_code_agrees( code, min, max, res, max_integer_value, bits, delta );
                }
            }
        }
    }

    // the coverage floor: if the differential ever silently shrinks below the mass it was
    // built with, that is a test bug, and it fails here instead of fading quietly. A build
    // whose frozen oracle stood down runs fewer comparisons, so it is held to its own
    // measured floor rather than the full one.
    let check_count: u64 = compressed_float_differential_check_count.load( std::sync::atomic::Ordering::Relaxed );
    serialize_check!( check_count >= ( if compressed_float_frozen_oracle_conformant.load( std::sync::atomic::Ordering::Relaxed ) { 2000000 } else { 1600000 } ) );

    if serialize_test_verbose()
    {
        println!( "    ({} checks, three implementations, {} declarations)", check_count, num_shapes );
    }

    // the negative controls, CHECKED rather than merely reported: if a one-rounding writer
    // ever stops producing a different wire code, or a one-rounding reader ever stops
    // producing a different bit pattern, then everything above agrees for a reason that has
    // nothing to do with the split being correct, and this differential is decoration.
    serialize_check!( compressed_float_sentinel_write_divergences.load( std::sync::atomic::Ordering::Relaxed ) > 0 );
    serialize_check!( compressed_float_sentinel_read_divergences.load( std::sync::atomic::Ordering::Relaxed ) > 0 );

    if serialize_test_verbose()
    {
        println!( "    (negative controls diverge on {} wire codes and {} decoded patterns -- both must be nonzero, or the comparison cannot see a single-rounding quantization)",
                  compressed_float_sentinel_write_divergences.load( std::sync::atomic::Ordering::Relaxed ),
                  compressed_float_sentinel_read_divergences.load( std::sync::atomic::Ordering::Relaxed ) );
    }
}

// Conformance vector for float/double BIT TRANSPARENCY (STANDARD.md, "Floating Point",
// ratified 2026-08-15 from the #56 re-audit). Additive: golden_wire_bytes is untouched.
//
// The golden's float is 3.1415926f and its double 1.0/3.0 — ordinary values that any
// sanitizing implementation reproduces — and the document-side checker compares them by
// TOLERANCE, which is structurally unable to see a canonicalized NaN payload, a quieted
// signaling bit, or a sign-of-zero flip. These patterns are the ones a sanitizer breaks,
// constructed by bit-cast (never by literal) and compared by bits (never by value: NaN
// compares unequal to itself and -0.0 == 0.0, so value comparison proves nothing here).

pub static golden_float_bytes: &[u8] =
&[
    0x01, 0x00, 0xC0, 0x7F,                             // f32 0x7FC00001: quiet NaN, payload 1
    0x01, 0x00, 0x80, 0x7F,                             // f32 0x7F800001: SIGNALING NaN
    0x00, 0x00, 0x80, 0xFF,                             // f32 0xFF800000: -Inf
    0x00, 0x00, 0x00, 0x80,                             // f32 0x80000000: -0.0
    0x01, 0x00, 0x00, 0x00,                             // f32 0x00000001: smallest denormal
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF4, 0x7F,     // f64 0x7FF4000000000001: signaling NaN, payload 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80      // f64 0x8000000000000000: -0.0
];

pub static golden_float_patterns: [u32; 5] = [ 0x7FC00001, 0x7F800001, 0xFF800000, 0x80000000, 0x00000001 ];
pub static golden_double_patterns: [u64; 2] = [ 0x7FF4000000000001, 0x8000000000000000 ];

pub fn GoldenFloatSerialize<S: Stream>( stream: &mut S, float_values: &mut [f32], double_values: &mut [f64] ) -> bool
{
    for i in 0..5
    {
        serialize_float!( stream, float_values[i] );
    }
    for i in 0..2
    {
        serialize_double!( stream, double_values[i] );
    }
    true
}

pub fn test_golden_float_bit_transparency()
{
    // write side: the bit patterns above, bit-cast into float/double and serialized, must
    // produce exactly the pinned little-endian bytes — no quieting, no canonicalization
    {
        let mut buffer: [u8; 64] = [0; 64];
        let buffer_size: i64 = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, buffer_size );
        let mut float_values: [f32; 5] = [0.0; 5];
        let mut double_values: [f64; 2] = [0.0; 2];
        for i in 0..5
        {
            float_values[i] = f32::from_bits( golden_float_patterns[i] );
        }
        for i in 0..2
        {
            double_values[i] = f64::from_bits( golden_double_patterns[i] );
        }
        serialize_check!( GoldenFloatSerialize( &mut stream, &mut float_values, &mut double_values ) == true );
        stream.Flush();
        serialize_check!( stream.GetBytesProcessed() == golden_float_bytes.len() as i64 );
        serialize_check!( buffer[..golden_float_bytes.len()] == golden_float_bytes[..] );
    }

    // read side: the recovered BIT PATTERNS must equal the transmitted ones exactly.
    // a tolerance-based harness passes a sanitizing reader forever — which is the point
    {
        let mut buffer: [u8; 64] = [0; 64];
        buffer[..golden_float_bytes.len()].copy_from_slice( golden_float_bytes );
        let mut stream = ReadStream::new( &buffer, golden_float_bytes.len() as i64 );
        let mut float_values: [f32; 5] = [0.0; 5];
        let mut double_values: [f64; 2] = [0.0; 2];
        serialize_check!( GoldenFloatSerialize( &mut stream, &mut float_values, &mut double_values ) == true );
        for i in 0..5
        {
            let bits: u32 = float_values[i].to_bits();
            serialize_check!( bits == golden_float_patterns[i] );
        }
        for i in 0..2
        {
            let bits: u64 = double_values[i].to_bits();
            serialize_check!( bits == golden_double_patterns[i] );
        }
    }
}

// Conformance vectors for the zero-count and unaligned bytes paths (STANDARD.md, "bytes —
// count may be zero", ratified 2026-08-15 from the #56 re-audit). Additive pins. Each one
// discriminates: the wrong-but-plausible implementation produces DIFFERENT bytes, spelled
// out per vector, so a port carrying the divergence fails the pin instead of agreeing with
// itself forever — round-trip self-tests cannot catch a skipped align, because both halves
// skip the same one.

pub fn ZeroLengthBytesSerialize<S: Stream>( stream: &mut S, head: &mut u32, data: &mut [u8], tail: &mut u32 ) -> bool
{
    serialize_bits!( stream, *head, 3 );
    serialize_bytes!( stream, data, 0 );
    serialize_bits!( stream, *tail, 8 );
    true
}

pub fn test_golden_zero_length_bytes()
{
    // { bits(5,3); bytes(count=0); bits(0xA5,8) }. The zero-length bytes still ALIGNS:
    // the pad lands in bits [3,8) and 0xA5 occupies byte 1. A port that early-returns on
    // count == 0 writes { 0x2D, 0x05 } — every later field shifted by five bits.
    static pinned_bytes: [u8; 2] = [ 0x05, 0xA5 ];

    {
        let mut buffer: [u8; 64] = [0; 64];
        let buffer_size: i64 = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, buffer_size );
        let mut head: u32 = 5;
        let mut tail: u32 = 0xA5;
        let mut data: [u8; 1] = [0];
        serialize_check!( ZeroLengthBytesSerialize( &mut stream, &mut head, &mut data, &mut tail ) == true );
        stream.Flush();
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
        serialize_check!( buffer[..pinned_bytes.len()] == pinned_bytes[..] );
    }

    {
        let mut buffer: [u8; 64] = [0; 64];
        buffer[..pinned_bytes.len()].copy_from_slice( &pinned_bytes );
        let mut stream = ReadStream::new( &buffer, pinned_bytes.len() as i64 );
        let mut head: u32 = 0;
        let mut tail: u32 = 0;
        let mut data: [u8; 1] = [0];
        serialize_check!( ZeroLengthBytesSerialize( &mut stream, &mut head, &mut data, &mut tail ) == true );
        serialize_check!( head == 5 );
        serialize_check!( tail == 0xA5 );
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
    }
}

pub fn ZeroLengthStringSerialize<S: Stream>( stream: &mut S, head: &mut u32, string: &mut [u8], tail: &mut u32 ) -> bool
{
    serialize_bits!( stream, *head, 3 );
    serialize_string!( stream, string, 8 );
    serialize_bits!( stream, *tail, 8 );
    true
}

pub fn test_golden_zero_length_string()
{
    // { bits(5,3); string("", buffer_size 8); bits(0xA5,8) }. The empty string is a 3-bit
    // length of 0, then the zero-length payload's align pads bits [6,8). A port whose
    // STRING path skips the empty-payload align writes { 0x45, 0x29 } — the exact hazard
    // the C port's comment names, and a separate code path from bytes in three ports.
    static pinned_bytes: [u8; 2] = [ 0x05, 0xA5 ];

    {
        let mut buffer: [u8; 64] = [0; 64];
        let buffer_size: i64 = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, buffer_size );
        let mut head: u32 = 5;
        let mut tail: u32 = 0xA5;
        let mut string: [u8; 8] = [0; 8];
        serialize_check!( ZeroLengthStringSerialize( &mut stream, &mut head, &mut string, &mut tail ) == true );
        stream.Flush();
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
        serialize_check!( buffer[..pinned_bytes.len()] == pinned_bytes[..] );
    }

    {
        let mut buffer: [u8; 64] = [0; 64];
        buffer[..pinned_bytes.len()].copy_from_slice( &pinned_bytes );
        let mut stream = ReadStream::new( &buffer, pinned_bytes.len() as i64 );
        let mut head: u32 = 0;
        let mut tail: u32 = 0;
        let mut string: [u8; 8] = [0xFF; 8];
        serialize_check!( ZeroLengthStringSerialize( &mut stream, &mut head, &mut string, &mut tail ) == true );
        serialize_check!( head == 5 );
        serialize_check!( string[0] == 0 );
        serialize_check!( tail == 0xA5 );
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
    }
}

pub fn UnalignedBytesSerialize<S: Stream>( stream: &mut S, head: &mut u32, data: &mut [u8], tail: &mut u32 ) -> bool
{
    serialize_bits!( stream, *head, 1 );
    serialize_bytes!( stream, data, 2 );
    serialize_bits!( stream, *tail, 4 );
    true
}

pub fn test_golden_unaligned_bytes()
{
    // { bits(1,1); bytes({0xEF,0xBE}, 2); bits(0x0F,4) }. Exercises serialize_bytes' OWN
    // align from bit index 1 — the case the golden vector structurally shadows, because an
    // explicit serialize_align immediately precedes its bytes field, making the operation's
    // internal align a no-op there.
    static pinned_bytes: [u8; 4] = [ 0x01, 0xEF, 0xBE, 0x0F ];

    {
        let mut buffer: [u8; 64] = [0; 64];
        let buffer_size: i64 = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, buffer_size );
        let mut head: u32 = 1;
        let mut tail: u32 = 0x0F;
        let mut data: [u8; 2] = [ 0xEF, 0xBE ];
        serialize_check!( UnalignedBytesSerialize( &mut stream, &mut head, &mut data, &mut tail ) == true );
        stream.Flush();
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
        serialize_check!( buffer[..pinned_bytes.len()] == pinned_bytes[..] );
    }

    {
        let mut buffer: [u8; 64] = [0; 64];
        buffer[..pinned_bytes.len()].copy_from_slice( &pinned_bytes );
        let mut stream = ReadStream::new( &buffer, pinned_bytes.len() as i64 );
        let mut head: u32 = 0;
        let mut tail: u32 = 0;
        let mut data: [u8; 2] = [ 0, 0 ];
        serialize_check!( UnalignedBytesSerialize( &mut stream, &mut head, &mut data, &mut tail ) == true );
        serialize_check!( head == 1 );
        serialize_check!( data[0] == 0xEF );
        serialize_check!( data[1] == 0xBE );
        serialize_check!( tail == 0x0F );
        serialize_check!( stream.GetBytesProcessed() == pinned_bytes.len() as i64 );
    }
}

pub fn test_measure_bound()
{
    // STANDARD.md, "The Measure Stream" (adopted 2026-08-15): a measure reports a size
    // sufficient at ANY starting bit position — a bound, not the packet size — and the
    // expected implementation charges worst-case 7 bits per alignment-performing
    // operation. Exact-from-zero accounting is non-conforming: it under-counts every
    // unaligned start.

    // the ruling's worked example: { bits(8); align; bits(8) }
    {
        let mut measureStream = MeasureStream::new();
        let mut byte_value: u32 = 0xAB;
        serialize_check!( measureStream.SerializeBits( &mut byte_value, 8 ) == true );
        serialize_check!( measureStream.SerializeAlign() == true );
        serialize_check!( measureStream.SerializeBits( &mut byte_value, 8 ) == true );
        serialize_check!( measureStream.GetBitsProcessed() == 23 );     // 8 + 7 + 8: the conservative charge.
                                                                        // an exact-from-zero measure reports 16 —
                                                                        // 2 bytes — which is NOT enough room when
                                                                        // the message lands at bit offset 1

        // written at every starting offset, the message's actual span never exceeds the
        // measure — the property the bound exists to guarantee
        for offset in 0..8
        {
            let mut buffer: [u8; 64] = [0; 64];
            let buffer_size: i64 = buffer.len() as i64;
            let mut writeStream = WriteStream::new( &mut buffer, buffer_size );
            for i in 0..offset
            {
                let mut one_bit: u32 = 1;
                serialize_check!( writeStream.SerializeBits( &mut one_bit, 1 ) == true );
            }
            let start: i64 = writeStream.GetBitsProcessed();
            serialize_check!( writeStream.SerializeBits( &mut byte_value, 8 ) == true );
            serialize_check!( writeStream.SerializeAlign() == true );
            serialize_check!( writeStream.SerializeBits( &mut byte_value, 8 ) == true );
            let span: i64 = writeStream.GetBitsProcessed() - start;
            serialize_check!( span <= measureStream.GetBitsProcessed() );
            if offset == 0
            {
                serialize_check!( span == 16 );                         // 2 bytes from an aligned start...
            }
            if offset == 1
            {
                serialize_check!( span == 23 );                         // ...3 bytes of room needed from offset 1
            }
        }
    }

    // measure >= written, across every message this suite pins. (The fuzz harness holds
    // the same inequality over arbitrary op programs on every run.)
    {
        let mut data = GoldenWireData::default();
        GoldenWireInit( &mut data );
        let mut measureStream = MeasureStream::new();
        serialize_check!( GoldenWireSerialize( &mut measureStream, &mut data ) == true );
        let mut buffer: [u8; 256] = [0; 256];
        let buffer_size: i64 = buffer.len() as i64;
        let mut writeStream = WriteStream::new( &mut buffer, buffer_size );
        serialize_check!( GoldenWireSerialize( &mut writeStream, &mut data ) == true );
        writeStream.Flush();
        serialize_check!( measureStream.GetBitsProcessed() >= writeStream.GetBitsProcessed() );
    }

    {
        let mut float_values: [f32; 5] = [0.0; 5];
        let mut double_values: [f64; 2] = [0.0; 2];
        for i in 0..5
        {
            float_values[i] = f32::from_bits( golden_float_patterns[i] );
        }
        for i in 0..2
        {
            double_values[i] = f64::from_bits( golden_double_patterns[i] );
        }
        let mut measureStream = MeasureStream::new();
        serialize_check!( GoldenFloatSerialize( &mut measureStream, &mut float_values, &mut double_values ) == true );
        serialize_check!( measureStream.GetBitsProcessed() >= 5 * 32 + 2 * 64 );    // no aligns: exact, and still a bound
    }

    {
        let mut head: u32 = 5;
        let mut tail: u32 = 0xA5;
        let mut data: [u8; 1] = [0];
        let mut measureStream = MeasureStream::new();
        serialize_check!( ZeroLengthBytesSerialize( &mut measureStream, &mut head, &mut data, &mut tail ) == true );
        serialize_check!( measureStream.GetBitsProcessed() >= 16 );                 // 3 + pad + 8 written; measure charges 3 + 7 + 8
    }

    {
        let mut head: u32 = 5;
        let mut tail: u32 = 0xA5;
        let mut string: [u8; 8] = [0; 8];
        let mut measureStream = MeasureStream::new();
        serialize_check!( ZeroLengthStringSerialize( &mut measureStream, &mut head, &mut string, &mut tail ) == true );
        serialize_check!( measureStream.GetBitsProcessed() >= 16 );
    }

    {
        let mut head: u32 = 1;
        let mut tail: u32 = 0x0F;
        let mut data: [u8; 2] = [ 0xEF, 0xBE ];
        let mut measureStream = MeasureStream::new();
        serialize_check!( UnalignedBytesSerialize( &mut measureStream, &mut head, &mut data, &mut tail ) == true );
        serialize_check!( measureStream.GetBitsProcessed() >= 28 );                 // 28 bits written; measure charges 1 + 7 + 16 + 4
    }
}

pub fn test_unaligned_writer()
{
    // the bit writer stores each dword with memcpy, so the write buffer does not need 4 byte alignment.
    // exercise every offset within a dword, covering the WriteBits, WriteBytes and FlushBits store paths.
    // port: the storage is a byte array, and each offset is a subslice of it. A byte array is not guaranteed 4 byte
    // aligned, but the Rust writer stores through byte slices, so every offset is the unaligned case the test covers

    let mut storage: [u8; 256 + 4] = [0; 256 + 4];

    for offset in 0..4usize
    {
        storage.fill( 0 );

        let mut data: [u8; 13] = [0; 13];
        for i in 0..data.len()
        {
            data[i] = ( i * 47 + offset ) as u8;
        }

        let buffer: &mut [u8] = &mut storage[offset..];

        let mut writeStream = WriteStream::new( buffer, 256 );
        let mut head: u32 = 0x12345678;                 // port: the trait takes &mut values, so the literals are locals
        writeStream.SerializeBits( &mut head, 32 );
        let mut middle: u32 = 123;
        writeStream.SerializeBits( &mut middle, 7 );
        let mut write_data: [u8; 13] = data;
        writeStream.SerializeBytes( &mut write_data, data.len() as i64 );
        let mut tail: u32 = 0xDEADBEEF;
        writeStream.SerializeBits( &mut tail, 32 );
        writeStream.Flush();

        let bytesWritten: i64 = writeStream.GetBytesProcessed();

        let mut readStream = ReadStream::new( &storage[offset..], bytesWritten );
        let mut a: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut a, 32 ) == true );
        serialize_check!( a == 0x12345678 );
        let mut b: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut b, 7 ) == true );
        serialize_check!( b == 123 );
        let mut read_data: [u8; 13] = [0; 13];
        serialize_check!( readStream.SerializeBytes( &mut read_data, data.len() as i64 ) == true );
        serialize_check!( read_data == data );
        let mut c: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut c, 32 ) == true );
        serialize_check!( c == 0xDEADBEEF );
    }
}

pub fn test_large_buffer()
{
    // bit counts are 64 bit, so buffers larger than the old 256 MB limit work. write a bulk
    // block that carries the stream past the 2^31 bit boundary (256 MB), then verify that
    // bitpacked values round trip on the far side of it.

    let bufferSize: i64 = 320i64 * 1024 * 1024;
    // port: malloc is a Vec reserved with try_reserve_exact, so an allocation failure skips the test as upstream
    let mut buffer: Vec<u8> = Vec::new();
    if buffer.try_reserve_exact( bufferSize as usize + 8 ).is_err()     // + 8: read buffer allocations extend 8 bytes past the data
    {
        if serialize_test_verbose()
        {
            println!( "(skipped test_large_buffer: could not allocate the buffer)" );
        }
        return;
    }
    buffer.resize( bufferSize as usize + 8, 0 );

    // port: the static 1 MB chunk arrays are heap vectors
    let mut chunk: Vec<u8> = vec![0u8; 1024 * 1024];
    for i in 0..chunk.len()
    {
        chunk[i] = ( i * 37 ) as u8;
    }

    let numChunks: i32 = 300;                                               // 300 MB of bulk data: past the 256 MB boundary

    let mut bytesWritten: i64 = 0;
    {
        let mut writeStream = WriteStream::new( &mut buffer[..], bufferSize );
        for i in 0..numChunks
        {
            let chunk_size: i64 = chunk.len() as i64;
            serialize_check!( writeStream.SerializeBytes( &mut chunk[..], chunk_size ) == true );
        }
        let mut sentinel: u32 = 0xDEADBEEF;
        serialize_check!( writeStream.SerializeBits( &mut sentinel, 32 ) == true );
        let mut value: i32 = -12345;
        serialize_check!( writeStream.SerializeInteger( &mut value, -100000, 100000 ) == true );
        writeStream.Flush();
        bytesWritten = writeStream.GetBytesProcessed();
        serialize_check!( writeStream.GetBitsProcessed() > 1i64 << 31 );        // the bit count really did cross the old 32 bit boundary
    }

    {
        let mut readStream = ReadStream::new( &buffer[..], bytesWritten );
        let mut readChunk: Vec<u8> = vec![0u8; 1024 * 1024];
        for i in 0..numChunks
        {
            let chunk_size: i64 = readChunk.len() as i64;
            serialize_check!( readStream.SerializeBytes( &mut readChunk[..], chunk_size ) == true );
        }
        serialize_check!( readChunk == chunk );                                 // the final chunk, decoded from past the boundary
        let mut sentinel: u32 = 0;
        serialize_check!( readStream.SerializeBits( &mut sentinel, 32 ) == true );
        serialize_check!( sentinel == 0xDEADBEEF );
        let mut value: i32 = 0;
        serialize_check!( readStream.SerializeInteger( &mut value, -100000, 100000 ) == true );
        serialize_check!( value == -12345 );
        serialize_check!( readStream.GetBitsProcessed() > 1i64 << 31 );
    }
}

macro_rules! SERIALIZE_RUN_TEST {
    ( $test_function:ident ) => {
        {
            println!( "{}", stringify!( $test_function ) );
            $test_function();
        }
    };
}

pub fn serialize_test()
{
    let fp_contraction_live: bool = serialize_test_fp_contraction_is_live();
    let fp_contraction_crosses_statements: bool = serialize_test_fp_contraction_crosses_statements();

    // port: SERIALIZE_TEST_FP_CONTRACT_REQUESTED_ON marks CMake's second, -ffp-contract=on build of the suite.
    // Rust has no contraction flag and no such build, so the stand-down for GCC before 14 is not ported

    // which build this is, and whether its contraction setting is buying anything on this
    // target. Reported under SERIALIZE_TEST_VERBOSE, never asserted: a host with no FMA
    // instruction cannot fuse however the flag is set, and that is a fact about the host,
    // not a failure. A green log must never claim a discipline it did not exercise — the
    // claim is on demand now, and the default log claims nothing beyond the names.
    if serialize_test_verbose()
    {
        println!( "built with {}; fp contraction is {} in this build\n",
                  SERIALIZE_TEST_FP_CONTRACT,
                  if !fp_contraction_live                 { "NOT AVAILABLE -- this target does not fuse, so the compressed float's rounding barriers are compiled but not exercised" }
                  else if fp_contraction_crosses_statements { "LIVE and CROSSING STATEMENTS -- the wire path is barriered against it; the frozen pre-split oracle fuses in this build, so its comparisons stand down" }
                  else                                      { "LIVE and statement-local -- the compressed float's rounding barriers are under test" } );
    }

    // port: __FAST_MATH__ (-ffast-math) has no Rust equivalent: Rust never licenses reciprocal approximation or
    // reassociation of f32 arithmetic, so the refusal by name is not ported

    // The barrier is what the wire's contraction invariance rests on: the audited home pins
    // the quantization's two roundings with SERIALIZE_FLOAT_FORCE_ROUND, so the wire bits do
    // not depend on the consumer's contraction flag -- a build at GCC's default
    // -ffp-contract=fast produces the same bytes and the same decoded bit patterns as one at
    // -ffp-contract=off (issues #92/#95; the conformance vectors hold this bit-exactly on
    // every build below). A toolchain that fuses THROUGH the barrier would take that
    // property back, so it is probed directly and refused by name, before a single vector
    // runs. The differential's negative controls guard the same property flag-independently
    // from the other side: if the audited home's roundings are ever fused, its decode
    // collapses onto the one-rounding sentinel, the divergence count drops to zero, and the
    // differential fails.
    if !serialize_test_fp_barrier_holds()
    {
        println!( "This toolchain contracts floating point THROUGH SERIALIZE_FLOAT_FORCE_ROUND. The compressed\n\
                   float's quantization requires TWO distinct roundings on write and on read (STANDARD.md), and\n\
                   the barrier is what pins them under every contraction mode. On this build it does not hold, so\n\
                   the wire cannot be conformant. Rebuild with -ffp-contract=off.\n" );
        // port: !"message" is false with the message in the stringified condition; is_empty() on the message is too
        serialize_check!( "SERIALIZE_FLOAT_FORCE_ROUND does not hold on this toolchain".is_empty() );
    }

    // while ( 1 )
    {
        SERIALIZE_RUN_TEST!( test_endian );
        SERIALIZE_RUN_TEST!( test_bitpacker );
        SERIALIZE_RUN_TEST!( test_bits_required );
        SERIALIZE_RUN_TEST!( test_bits_required64 );
        SERIALIZE_RUN_TEST!( test_bits_required128 );
        SERIALIZE_RUN_TEST!( test_zigzag );
        SERIALIZE_RUN_TEST!( test_serialize );
        SERIALIZE_RUN_TEST!( test_read_write );
        SERIALIZE_RUN_TEST!( test_serialize_integer_validation );
        SERIALIZE_RUN_TEST!( test_serialize_degenerate_range );
        SERIALIZE_RUN_TEST!( test_serialize_degenerate_range_64 );
        SERIALIZE_RUN_TEST!( test_serialize_degenerate_range_128 );
        SERIALIZE_RUN_TEST!( test_serialize_integer_full_range );
        SERIALIZE_RUN_TEST!( test_serialize_int64_full_range );
        SERIALIZE_RUN_TEST!( test_serialize_int64_validation );
        SERIALIZE_RUN_TEST!( test_serialize_bytes_validation );
        SERIALIZE_RUN_TEST!( test_wstring_validation );
        SERIALIZE_RUN_TEST!( test_wstring_utf16_code_units );
        SERIALIZE_RUN_TEST!( test_string_read_validation );
        SERIALIZE_RUN_TEST!( test_wstring_read_validation );
        SERIALIZE_RUN_TEST!( test_int_relative_validation );
        SERIALIZE_RUN_TEST!( test_read_stream_failure_is_terminal );
        SERIALIZE_RUN_TEST!( test_compressed_float_validation );
        SERIALIZE_RUN_TEST!( test_compressed_float_top_of_range_clamp );
        SERIALIZE_RUN_TEST!( test_compressed_float_non_finite_asserts );
        SERIALIZE_RUN_TEST!( test_compressed_float_precomputed_validation );
        SERIALIZE_RUN_TEST!( test_compressed_float_precomputed_asserts );
        SERIALIZE_RUN_TEST!( test_serialize_fixed );
        SERIALIZE_RUN_TEST!( test_serialize_fixed_validation );
        SERIALIZE_RUN_TEST!( test_serialize_fixed_matches_int64 );
        SERIALIZE_RUN_TEST!( test_serialize_fixed_wide );
        SERIALIZE_RUN_TEST!( test_serialize_fixed_wide_emulated );
        SERIALIZE_RUN_TEST!( test_serialize_fixed_degenerate );
        SERIALIZE_RUN_TEST!( test_serialize_uint128 );
        SERIALIZE_RUN_TEST!( test_serialize_int128 );
        SERIALIZE_RUN_TEST!( test_uint128_emulation );
        SERIALIZE_RUN_TEST!( test_int128_emulation );
        SERIALIZE_RUN_TEST!( test_uint128_differential );
        SERIALIZE_RUN_TEST!( test_int128_differential );
        SERIALIZE_RUN_TEST!( test_compile_time_bits_required );
        SERIALIZE_RUN_TEST!( test_compile_time_int );
        SERIALIZE_RUN_TEST!( test_compile_time_int64 );
        SERIALIZE_RUN_TEST!( test_compile_time_bits );
        SERIALIZE_RUN_TEST!( test_compile_time_int_validation );
        SERIALIZE_RUN_TEST!( test_compile_time_int64_validation );
        SERIALIZE_RUN_TEST!( test_compile_time_bits_validation );
        SERIALIZE_RUN_TEST!( test_compile_time_packet );
        SERIALIZE_RUN_TEST!( test_golden_wire_format );
        SERIALIZE_RUN_TEST!( test_trailing_bits );
        SERIALIZE_RUN_TEST!( test_past_end_poison );
        SERIALIZE_RUN_TEST!( test_compressed_float_conformance_nonzero_min );
        SERIALIZE_RUN_TEST!( test_compressed_float_conformance_writer_fusion );
        SERIALIZE_RUN_TEST!( test_compressed_float_precomputed_conformance );
        SERIALIZE_RUN_TEST!( test_compressed_float_precomputed_differential );
        SERIALIZE_RUN_TEST!( test_golden_float_bit_transparency );
        SERIALIZE_RUN_TEST!( test_golden_zero_length_bytes );
        SERIALIZE_RUN_TEST!( test_golden_zero_length_string );
        SERIALIZE_RUN_TEST!( test_golden_unaligned_bytes );
        SERIALIZE_RUN_TEST!( test_measure_bound );
        SERIALIZE_RUN_TEST!( test_unaligned_writer );
        SERIALIZE_RUN_TEST!( test_large_buffer );
    }
}
