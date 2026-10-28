/*
    Yojimbo Client/Server Network Library.

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

// Rust port of include/yojimbo_utils.h + source/yojimbo_utils.cpp (yojimbo 1.13.5).
//
// Port notes:
//   - yojimbo_random_int / yojimbo_random_float use the C library's rand() upstream. The port has its own small
//     generator behind yojimbo_srand / yojimbo_rand (mulberry32, RAND_MAX = 2^31 - 1, as the TypeScript port), so
//     the tests and the network simulator are reproducible from a seed. It is not the C library's sequence, and it
//     is not cryptographically secure.
//   - The templates are generic over PartialOrd + Copy and return by value.
//   - yojimbo_copy_string copies from a &str into a byte buffer, stopping at a NUL or at the end of the string.

use crate::*;
use std::sync::atomic::{AtomicU32, Ordering};

/**
    Template function to get the minimum of two values.
    @param a The first value.
    @param b The second value.
    @returns The minimum of a and b.
 */

pub fn yojimbo_min<T: PartialOrd + Copy>( a: T, b: T ) -> T
{
    if a < b { a } else { b }
}

/**
    Template function to get the maximum of two values.
    @param a The first value.
    @param b The second value.
    @returns The maximum of a and b.
 */

pub fn yojimbo_max<T: PartialOrd + Copy>( a: T, b: T ) -> T
{
    if a > b { a } else { b }
}

/**
    Template function to clamp a value.
    @param value The value to be clamped.
    @param a The minimum value.
    @param b The minimum value.
    @returns The clamped value in [a,b].
 */

pub fn yojimbo_clamp<T: PartialOrd + Copy>( value: T, a: T, b: T ) -> T
{
    if value < a
    {
        a
    }
    else if value > b
    {
        b
    }
    else
    {
        value
    }
}

/**
    Swap two values.
    @param a First value.
    @param b Second value.
 */

pub fn yojimbo_swap<T>( a: &mut T, b: &mut T )
{
    // port: T tmp = a; a = b; b = tmp;
    std::mem::swap( a, b );
}

/**
    Get the absolute value.

    @param value The input value.

    @returns The absolute value.
 */

pub fn yojimbo_abs<T: PartialOrd + Copy + Default + std::ops::Neg<Output = T>>( value: T ) -> T
{
    // port: Default::default() is the 0 upstream compares against
    if value < T::default() { -value } else { value }
}

/**
    Generate cryptographically secure random data.
    @param data The buffer to store the random data.
    @param bytes The number of bytes of random data to generate.
 */

pub fn yojimbo_random_bytes( data: &mut [u8], bytes: i32 )
{
    crate::netcode::netcode_random_bytes( data, bytes );
}

/// The largest value yojimbo_rand returns, like RAND_MAX on glibc and macOS. (port: rand() has no Rust equivalent)
pub const RAND_MAX: i32 = 0x7FFFFFFF;

static rand_state: AtomicU32 = AtomicU32::new( 1 );

/**
    Seed the pseudo random number generator behind yojimbo_rand, yojimbo_random_int and yojimbo_random_float
    (the network simulator and tests). The C srand equivalent. The initial state is as if seeded with 1.
    Port addition (upstream calls srand).
 */

pub fn yojimbo_srand( seed: u32 )
{
    rand_state.store( seed, Ordering::Relaxed );
}

/**
    Pseudo random integer in [0,RAND_MAX]. The C rand equivalent (mulberry32, as the TypeScript port). Not cryptographically secure.
    Port addition (upstream calls rand).
 */

pub fn yojimbo_rand() -> i32
{
    let state = rand_state.load( Ordering::Relaxed ).wrapping_add( 0x6D2B79F5 );
    rand_state.store( state, Ordering::Relaxed );
    let mut t: u32 = state;
    t = ( t ^ ( t >> 15 ) ).wrapping_mul( t | 1 );
    t ^= t.wrapping_add( ( t ^ ( t >> 7 ) ).wrapping_mul( t | 61 ) );
    ( ( t ^ ( t >> 14 ) ) >> 1 ) as i32
}

/**
    Generate a random integer between a and b (inclusive).
    IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
    @param a The minimum integer value to generate.
    @param b The maximum integer value to generate.
    @returns A pseudo random integer value in [a,b].
 */

pub fn yojimbo_random_int( a: i32, b: i32 ) -> i32
{
    yojimbo_assert!( a < b );
    let result: i32 = a + yojimbo_rand() % ( b - a + 1 );
    yojimbo_assert!( result >= a );
    yojimbo_assert!( result <= b );
    result
}

/**
    Generate a random float between a and b.
    IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
    @param a The minimum integer value to generate.
    @param b The maximum integer value to generate.
    @returns A pseudo random float value in [a,b].
 */

pub fn yojimbo_random_float( a: f32, b: f32 ) -> f32
{
    yojimbo_assert!( a < b );
    let random: f32 = ( yojimbo_rand() as f32 ) / RAND_MAX as f32;
    let diff: f32 = b - a;
    let r: f32 = random * diff;
    a + r
}

/**
    Compares two 16 bit sequence numbers and returns true if the first one is greater than the second (considering wrapping).
    IMPORTANT: This is not the same as s1 > s2!
    Greater than is defined specially to handle wrapping sequence numbers.
    If the two sequence numbers are close together, it is as normal, but they are far apart, it is assumed that they have wrapped around.
    Thus, sequence_greater_than( 1, 0 ) returns true, and so does sequence_greater_than( 0, 65535 )!
    @param s1 The first sequence number.
    @param s2 The second sequence number.
    @returns True if the s1 is greater than s2, with sequence number wrapping considered.
 */

pub fn yojimbo_sequence_greater_than( s1: u16, s2: u16 ) -> bool
{
    // port: the subtractions are int, as the integer promotions upstream
    let ( s1, s2 ) = ( s1 as i32, s2 as i32 );
    ( ( s1 > s2 ) && ( s1 - s2 <= 32768 ) ) ||
    ( ( s1 < s2 ) && ( s2 - s1  > 32768 ) )
}

/**
    Compares two 16 bit sequence numbers and returns true if the first one is less than the second (considering wrapping).
    IMPORTANT: This is not the same as s1 < s2!
    Greater than is defined specially to handle wrapping sequence numbers.
    If the two sequence numbers are close together, it is as normal, but they are far apart, it is assumed that they have wrapped around.
    Thus, sequence_less_than( 0, 1 ) returns true, and so does sequence_greater_than( 65535, 0 )!
    @param s1 The first sequence number.
    @param s2 The second sequence number.
    @returns True if the s1 is less than s2, with sequence number wrapping considered.
 */

pub fn yojimbo_sequence_less_than( s1: u16, s2: u16 ) -> bool
{
    yojimbo_sequence_greater_than( s2, s1 )
}

/**
    Copy a string without being stupid
    Because apparently in 2023 it's really really hard...
 */

pub fn yojimbo_copy_string( dest: &mut [u8], source: &str, dest_size: usize )
{
    // port: yojimbo_assert( dest ) / yojimbo_assert( source ) -- slices are never null
    yojimbo_assert!( dest_size >= 1 );
    yojimbo_assert!( dest_size <= dest.len() );
    let source = source.as_bytes();
    for b in dest[..dest_size].iter_mut()
    {
        *b = 0;
    }
    for i in 0..dest_size - 1
    {
        // port: the end of the &str stops the copy too (C finds the NUL there)
        if i >= source.len() || source[i] == b'\0'
        {
            break;
        }
        dest[i] = source[i];
    }
}

// ---------------------------------------------------------------------------------------------
// source/yojimbo_utils.cpp

// port: upstream's extern "C" netcode_random_bytes is crate::netcode::netcode_random_bytes

/**
    Print bytes with a label.
    Useful for printing out packets, encryption keys, nonce etc.
    @param label The label to print out before the bytes.
    @param data The data to print out to stdout.
    @param data_bytes The number of bytes of data to print.
 */

pub fn yojimbo_print_bytes( label: &str, data: &[u8], data_bytes: i32 )
{
    print!( "{}: ", label );
    for i in 0..data_bytes as usize
    {
        print!( "0x{:02x},", data[i] as i32 );
    }
    print!( " ({} bytes)\n", data_bytes );
}
