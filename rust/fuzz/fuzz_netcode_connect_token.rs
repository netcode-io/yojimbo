/*
    Fuzz target: netcode_read_connect_token_private().

    This is the parser for the *decrypted* private connect token — the server-side path that
    reads a client id, a timeout, and a variable-length list of server addresses (each tagged
    IPv4 or IPv6), plus the session keys and user data. It's a separate target from
    fuzz_netcode because the AEAD boundary makes it unreachable by mutation there: any change
    to the encrypted token bytes fails the MAC in netcode_read_packet, so the bytes that reach
    this parser in production are never attacker-mutated through that path. Fuzzing it directly
    exercises the address-list loop and length handling on arbitrary input.

    Includes netcode.c directly (the reader is internal to that TU, same as fuzz_netcode).

    Seed corpus: fuzz/corpus/fuzz_netcode_connect_token (a valid serialized private token).
*/

// port: the reader is `pub` in yojimbo::netcode (see the note in fuzz_netcode.rs)

use yojimbo::netcode::*;

use std::sync::atomic::{ AtomicI32, Ordering };

// port: a C file static. The driver is single threaded.
static mut g_init: i32 = 0;

/// port addition (as the C# port): the result of the last read (NETCODE_OK or NETCODE_ERROR), so the corpus replay
/// can check every seed still parses.
pub static fuzz_netcode_connect_token_last_result: AtomicI32 = AtomicI32::new( NETCODE_ERROR );

pub fn LLVMFuzzerTestOneInput( data: &[u8], size: usize ) -> i32
{
    fuzz_netcode_connect_token_last_result.store( NETCODE_ERROR, Ordering::Relaxed );

    unsafe
    {
        if g_init == 0
        {
            netcode_init();
            g_init = 1;
        }
    }

    // The reader requires a full private-token buffer (NETCODE_CONNECT_TOKEN_PRIVATE_BYTES)
    // and never reads past it; mirror the caller by copying the input into a zero-padded
    // buffer of exactly that size. Larger inputs are ignored, as in the real receive path.
    if size > NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize
    {
        return 0;
    }

    let mut buffer = [0u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize];
    buffer.fill( 0 );
    buffer[..size].copy_from_slice( &data[..size] );

    let mut token = netcode_connect_token_private_t::default();
    let result = netcode_read_connect_token_private( &buffer, std::mem::size_of_val( &buffer ) as i32, &mut token );

    fuzz_netcode_connect_token_last_result.store( result, Ordering::Relaxed );

    0
}
