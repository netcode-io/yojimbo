/*
    Fuzz target: yojimbo::Connection::ProcessPacket(), stateful / multi-packet.

    Drives the yojimbo deserialization path on arbitrary bytes: the bitpacker ReadStream,
    ConnectionPacket / ChannelPacketData serialization, and per-channel message +
    block-fragment reading, over a reliable-ordered and an unreliable-unordered channel.
    This is the code that turns an authenticated but otherwise attacker-controlled packet
    payload into messages.

    One fuzz input is a *sequence* of packets fed to a single long-lived Connection, so the
    reliable-ordered channel's multi-packet state — block-fragment reassembly and the
    out-of-order message receive queue — is reachable (a single packet on a fresh connection
    can never complete a multi-fragment block). Input framing:

        [u8 config selector][u16 little-endian length][length bytes of packet] ...

    The first byte selects the ConnectionConfig (fuzz_config.rs); then length-prefixed packets
    repeat until the input is consumed. A length longer than what remains uses the rest. The
    messages use a factory (fuzz_messages.rs) that drives the whole serialize_* vocabulary, not
    just serialize_bits.

    Note: a malformed packet drops the Connection into an error state, after which it rejects
    everything — so reaching deep reassembly state requires several *valid* packets in a row.
    The committed seed corpus carries such sequences (see tools/gen_seed_corpus_connection.cpp);
    the structure-aware target fuzz_connection_structured.rs reaches the same state from a
    higher-level script.
*/

use yojimbo::*;

use crate::fuzz_messages::*;
use crate::fuzz_config::*;

use std::sync::atomic::{ AtomicBool, Ordering };

// port: a C file static. The driver is single threaded.
static mut g_init: bool = false;

/// port addition (as the C# port): true if every packet of the last input was read and the connection never went into
/// an error state. The corpus replay checks the seeds still read back.
pub static g_all_packets_accepted: AtomicBool = AtomicBool::new( false );

fn ensure_init()
{
    unsafe
    {
        if !g_init
        {
            // port: the driver has already called InitializeYojimbo (all the targets share one program); calling it
            // again would assert on the default allocator, so only the log level is set here
            // The message-leak check in ~MessageFactory reports at ERROR level before
            // calling exit(1); the default log level (NONE) would swallow the report.
            yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );
            g_init = true;
        }
    }
}

pub fn LLVMFuzzerTestOneInput( data: &[u8], size: usize ) -> i32
{
    g_all_packets_accepted.store( false, Ordering::Relaxed );

    ensure_init();

    if size < 1
    {
        return 0;
    }

    // first byte selects the connection config
    let mut config = ConnectionConfig::new();
    fuzz_make_config( data[0], &mut config );
    let mut pos: usize = 1;

    let mut messageFactory = FuzzMessageFactory::new( GetDefaultAllocator() );
    // port: the connection keeps a pointer to the factory, so the target reaches the factory through the same pointer
    let messageFactoryPtr: *mut dyn MessageFactory = &mut messageFactory;
    let mut connection = Connection::new( GetDefaultAllocator(), messageFactoryPtr, &config, 100.0 );

    // BitReader loads an 8-byte window from the byte at the read position, so a
    // read in the last data byte can touch 7 bytes past the packet. ProcessPacket
    // copies into packetBytes+8; the fuzzer mirrors that manufactured slack.
    // port: a local rather than a function static
    let mut buf = [0u8; 8 * 1024 + 16];
    if config.maxPacketSize + 16 > std::mem::size_of_val( &buf ) as i32
    {
        return 0;
    }

    let maxPacket = config.maxPacketSize;
    const MAX_PACKETS: i32 = 64;

    let mut time: f64 = 100.0;
    let mut sequence: u16 = 0;

    let mut accepted = true;    // port addition (as the C# port)

    let mut p = 0;
    while p < MAX_PACKETS && pos < size
    {
        // read a 2-byte length prefix (missing bytes read as zero)
        let mut len = data[pos] as usize;
        pos += 1;
        if pos < size
        {
            len |= ( data[pos] as usize ) << 8;
            pos += 1;
        }

        let avail = size - pos;
        if len > avail
        {
            len = avail;                 // last packet takes the remainder
        }

        let packetBytes = ( if len > maxPacket as usize { maxPacket as usize } else { len } ) as i32;

        if packetBytes > 0
        {
            buf[..packetBytes as usize + 16].fill( 0 );
            buf[..packetBytes as usize].copy_from_slice( &data[pos..pos + packetBytes as usize] );
            if !connection.ProcessPacket( std::ptr::null_mut(), sequence, &buf, packetBytes )
            {
                accepted = false;
            }
        }

        pos += len;
        sequence = sequence.wrapping_add( 1 );

        time += 0.1;
        connection.AdvanceTime( time );

        // drain anything delivered so messages don't accumulate across packets
        for channelIndex in 0..config.numChannels
        {
            loop
            {
                let message = connection.ReceiveMessage( channelIndex );
                if message.is_null()
                {
                    break;
                }
                unsafe { ( *messageFactoryPtr ).ReleaseMessage( message ); }
            }
        }

        p += 1;
    }

    g_all_packets_accepted.store( accepted && connection.GetErrorLevel() == CONNECTION_ERROR_NONE, Ordering::Relaxed );

    0
}
