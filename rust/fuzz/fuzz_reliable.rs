/*
    Fuzz target: reliable_endpoint_receive_packet().

    Feeds arbitrary bytes into the reliable.io packet-receive path — packet-header
    parsing, ack decoding, and fragment reassembly — the code that runs on raw,
    attacker-controlled UDP payloads. The process-packet callback accepts everything
    so reassembled payloads are exercised too.
*/

use yojimbo::reliable::*;

use std::ffi::c_void;
use std::sync::atomic::{ AtomicI32, Ordering };

// port: C file statics. The driver is single threaded.
static mut g_endpoint: Option<Box<reliable_endpoint_t>> = None;
static mut g_time: f64 = 100.0;

/// port addition (as the C# port): number of packets the endpoint delivered (directly or reassembled). The corpus
/// replay checks the seeds still deliver.
pub static g_received: AtomicI32 = AtomicI32::new( 0 );

fn fuzz_process_packet( context: *mut c_void, id: u64, sequence: u16, data: &[u8], bytes: i32 ) -> i32
{
    let _ = ( context, id, sequence, data, bytes );
    g_received.fetch_add( 1, Ordering::Relaxed );
    1 /* accept every packet */
}

fn fuzz_transmit_packet( context: *mut c_void, id: u64, sequence: u16, data: &[u8], bytes: i32 )
{
    let _ = ( context, id, sequence, data, bytes );
}

fn ensure_init()
{
    unsafe
    {
        if g_endpoint.is_some()
        {
            return;
        }
        reliable_init();
        let mut config = reliable_config_t::default();
        reliable_default_config( &mut config );
        config.transmit_packet_function = Some( fuzz_transmit_packet );
        config.process_packet_function = Some( fuzz_process_packet );
        g_endpoint = reliable_endpoint_create( &config, g_time );
        if g_endpoint.is_none()
        {
            std::process::abort();    /* creation is fallible in every build: a NULL here is a broken target, not an input finding */
        }
    }
}

/// port addition (as the C# port): drop the long-lived endpoint so a corpus replay starts from a fresh one.
pub fn reset()
{
    unsafe
    {
        if let Some( endpoint ) = g_endpoint.take()
        {
            reliable_endpoint_destroy( endpoint );
        }
        g_time = 100.0;
    }
    g_received.store( 0, Ordering::Relaxed );
}

pub fn LLVMFuzzerTestOneInput( data: &[u8], size: usize ) -> i32
{
    ensure_init();

    /* reliable_endpoint_receive_packet asserts packet_bytes > 0 and rejects packets
       larger than max_packet_size + headers; keep inputs in a sane range. */
    if size == 0 || size > 4096
    {
        return 0;
    }

    /* the API takes a mutable buffer, so copy the immutable fuzzer input */
    let mut buf = [0u8; 4096];
    buf[..size].copy_from_slice( &data[..size] );

    unsafe
    {
        let endpoint = g_endpoint.as_mut().unwrap();

        // port: the slice is the packet's size bytes, so a read past packet_bytes is caught rather than seeing the copy's slack
        reliable_endpoint_receive_packet( endpoint, &buf[..size], size as i32 );

        /* advance time so the reassembly / received-packet sequence buffers cycle */
        g_time += 0.01;
        reliable_endpoint_update( endpoint, g_time );
        reliable_endpoint_clear_acks( endpoint );
    }

    0
}
