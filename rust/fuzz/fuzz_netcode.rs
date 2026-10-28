/*
    Fuzz target: netcode_read_packet().

    Feeds arbitrary bytes into netcode's packet-read path — prefix/type parsing, length
    checks, sequence decoding, AEAD decryption and connect-token decryption — the code
    that runs on raw, attacker-controlled UDP payloads before a client or server trusts
    anything. Every packet type is allowed and fixed (zero) keys are used, so the header
    parse and the decrypt/MAC-reject paths are all exercised.

    netcode_read_packet and the replay-protection / packet-type symbols are internal to
    netcode.c (not declared in netcode.h), so the harness includes the translation unit
    directly. netcode.c's own tests are behind NETCODE_ENABLE_TESTS (off) and it defines
    no main, so this just pulls in the implementation.
*/

// port: the netcode internals are `pub` in yojimbo::netcode, so this uses the library rather than including it.
// fuzz_standalone.rs is the shared driver (upstream's fuzz_standalone.h, included at the bottom of each target).

use yojimbo::netcode::*;

use crate::fuzz_netcode_params::*;

use std::sync::atomic::{ AtomicI32, Ordering };

// port: C file statics. The driver is single threaded.
static mut g_init: i32 = 0;
static mut g_packet_key: [u8; NETCODE_KEY_BYTES as usize] = [0; NETCODE_KEY_BYTES as usize];
static mut g_private_key: [u8; NETCODE_KEY_BYTES as usize] = [0; NETCODE_KEY_BYTES as usize];

/// port addition (as the C# port): the packet type netcode_read_packet decoded, or -1 if it rejected the input. Lets
/// the corpus replay check every seed still decrypts.
pub static fuzz_netcode_last_packet_type: AtomicI32 = AtomicI32::new( -1 );

/// port addition (as the C# port)
pub const FUZZ_NETCODE_NUM_PACKET_TYPES: i32 = NETCODE_CONNECTION_NUM_PACKETS as i32;

fn ensure_init()
{
    unsafe
    {
        if g_init != 0
        {
            return;
        }
        netcode_init();
        g_packet_key.fill( 0 );
        g_private_key.fill( 0 );
        g_init = 1;
    }
}

pub fn LLVMFuzzerTestOneInput( data: &[u8], size: usize ) -> i32
{
    fuzz_netcode_last_packet_type.store( -1, Ordering::Relaxed );

    ensure_init();

    // Mirror the real receive path: netcode never hands more than a full UDP packet to
    // the reader, and it ignores empty buffers.
    if size == 0 || size > NETCODE_MAX_PACKET_BYTES as usize
    {
        return 0;
    }

    // netcode_read_packet takes a mutable buffer; copy the immutable fuzzer input.
    let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES as usize];
    buffer[..size].copy_from_slice( &data[..size] );

    let mut allowed_packets = [0u8; NETCODE_CONNECTION_NUM_PACKETS as usize];
    allowed_packets.fill( 1 );

    // Reset replay protection every input so a repeated sequence number never masks the
    // post-decrypt path on a later input.
    let mut replay_protection = netcode_replay_protection_t::default();
    netcode_replay_protection_reset( &mut replay_protection );

    let mut sequence: u64 = 0;

    let packet = unsafe
    {
        netcode_read_packet( &mut buffer,
                             size as i32,
                             &mut sequence,
                             Some( &g_packet_key[..] ),
                             FUZZ_PROTOCOL_ID,
                             FUZZ_TIMESTAMP,
                             0,                 // minimum expire timestamp: zero, so no connect token is refused for predating a server start and the fuzzer keeps reaching the parser
                             Some( &g_private_key[..] ),
                             &allowed_packets,
                             Some( &mut replay_protection ),
                             std::ptr::null_mut(),
                             None )
    };

    if let Some( packet ) = packet
    {
        fuzz_netcode_last_packet_type.store( packet.packet_type() as i32, Ordering::Relaxed );
        // port: netcode_default_free_function( NULL, packet ) is dropping the Box
        drop( packet );
    }

    0
}
