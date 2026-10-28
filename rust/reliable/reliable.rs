/*
    reliable

    Copyright © 2017 - 2026, Más Bandwidth LLC

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
    "reliable - Glenn Fiedler and Rowan Claude" in your product credits. The
    license doesn't require this credit. It's an official request, and honoring
    it is appreciated.
*/

/*
    Rust port of reliable 1.4.5: reliable.h followed by reliable.c, in upstream order.

    port: deviations that apply to the whole file
      - the reliable_assert( pointer ) checks on struct and out-parameter arguments are dropped: those are Rust
        references, which can't be NULL. every other assert is kept.
      - the allocator callbacks stay in the config and the endpoint, but the endpoint holds its buffers in Vec/Box,
        as the C# port does: allocate_function and free_function are never called on them (a Vec can't be handed to
        a C-style free). so allocation can't fail after the config is accepted.
      - the sequence buffer is generic over its entry type instead of void * plus a stride.
      - RELIABLE_EXPORT, RELIABLE_CONST and extern "C" have no Rust meaning and are dropped.
*/

use std::ffi::c_void;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

// ---- reliable.h ----

pub const RELIABLE_VERSION_FULL: &str = "1.4.5";
pub const RELIABLE_VERSION_MAJOR: i32 = 1;
pub const RELIABLE_VERSION_MINOR: i32 = 4;
pub const RELIABLE_VERSION_PATCH: i32 = 5;

// port: RELIABLE_DEBUG / RELIABLE_RELEASE follow debug_assertions (upstream's !NDEBUG)
pub const RELIABLE_DEBUG: bool = cfg!(debug_assertions);
pub const RELIABLE_RELEASE: bool = !cfg!(debug_assertions);

// port: the byte order comes from the target, not from compiler macros
pub const RELIABLE_LITTLE_ENDIAN: i32 = cfg!(target_endian = "little") as i32;
pub const RELIABLE_BIG_ENDIAN: i32 = cfg!(target_endian = "big") as i32;

pub const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT: usize = 0;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED: usize = 1;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED: usize = 2;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_STALE: usize = 3;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID: usize = 4;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND: usize = 5;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE: usize = 6;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT: usize = 7;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED: usize = 8;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID: usize = 9;
pub const RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE: usize = 10;
pub const RELIABLE_ENDPOINT_NUM_COUNTERS: usize = 11;
// port: the counter indices are usize so they index the counters array directly

pub const RELIABLE_MAX_PACKET_HEADER_BYTES: i32 = 9;
pub const RELIABLE_FRAGMENT_HEADER_BYTES: i32 = 5;

pub const RELIABLE_LOG_LEVEL_NONE: i32 = 0;
pub const RELIABLE_LOG_LEVEL_ERROR: i32 = 1;
pub const RELIABLE_LOG_LEVEL_INFO: i32 = 2;
pub const RELIABLE_LOG_LEVEL_DEBUG: i32 = 3;

pub const RELIABLE_OK: i32 = 1;
pub const RELIABLE_ERROR: i32 = 0;

// initialize the library. call this once before creating any endpoints. returns RELIABLE_OK on success
// (reliable_init, below)

// shut down the library. call this once after all endpoints are destroyed
// (reliable_term, below)

#[derive(Clone, Copy)]
pub struct reliable_config_t
{
    // port: name stays a C char array, so reliable_copy_string, the forced terminator and the bounded name logs carry over
    pub name: [u8; 256],                                                        // name of the endpoint. used in log output
    pub context: *mut c_void,                                                   // passed to the transmit and process packet callbacks
    pub id: u64,                                                                // id of the endpoint. passed to callbacks so shared callbacks can tell endpoints apart
    pub max_packet_size: i32,                                                   // maximum packet size that can be sent or received (bytes)
    pub fragment_above: i32,                                                    // packets larger than this many bytes are sent as fragments
    pub max_fragments: i32,                                                     // maximum number of fragments per-packet. 256 max. must cover max_packet_size / fragment_size
    pub fragment_size: i32,                                                     // size of each fragment (bytes)
    pub ack_buffer_size: i32,                                                   // maximum number of acks buffered between calls to reliable_endpoint_clear_acks
    pub sent_packets_buffer_size: i32,                                          // number of sent packets tracked for acks, packet loss and bandwidth stats
    pub received_packets_buffer_size: i32,                                      // number of received packets tracked. also the window for stale and duplicate packet rejection
    pub fragment_reassembly_buffer_size: i32,                                   // number of packets that can be under reassembly from fragments at the same time
    pub rtt_smoothing_factor: f32,                                              // exponential smoothing factor for the rtt moving average
    pub rtt_history_size: i32,                                                  // number of rtt samples kept for min/max/avg rtt and jitter
    pub packet_loss_smoothing_factor: f32,                                      // exponential smoothing factor for packet loss
    pub bandwidth_smoothing_factor: f32,                                        // exponential smoothing factor for bandwidth
    pub packet_header_size: i32,                                                // assumed network header overhead per-packet, used only for bandwidth stats. 28 = IPv4 + UDP
    pub transmit_packet_function: Option<fn(*mut c_void, u64, u16, &[u8], i32)>,       // called to send a packet: (context, id, sequence, packet_data, packet_bytes). must not send packets on the same endpoint
    pub process_packet_function: Option<fn(*mut c_void, u64, u16, &[u8], i32) -> i32>, // called when a packet is received: (context, id, sequence, packet_data, packet_bytes). return 1 to accept and ack the packet, 0 to reject it (rejected packets are not acked and may be processed again if they arrive again)
    pub allocator_context: *mut c_void,                                         // passed to the allocate and free functions
    pub allocate_function: Option<fn(*mut c_void, usize) -> *mut c_void>,       // custom allocator. NULL = malloc. port: kept, but the endpoint's buffers are Vec (see the top of the file)
    pub free_function: Option<fn(*mut c_void, *mut c_void)>,                    // custom free. NULL = free. port: kept, as allocate_function
}

// port: the all-zero config upstream gets from memset( config, 0, sizeof( struct reliable_config_t ) )
impl Default for reliable_config_t
{
    fn default() -> Self
    {
        reliable_config_t
        {
            name: [0; 256],
            context: std::ptr::null_mut(),
            id: 0,
            max_packet_size: 0,
            fragment_above: 0,
            max_fragments: 0,
            fragment_size: 0,
            ack_buffer_size: 0,
            sent_packets_buffer_size: 0,
            received_packets_buffer_size: 0,
            fragment_reassembly_buffer_size: 0,
            rtt_smoothing_factor: 0.0,
            rtt_history_size: 0,
            packet_loss_smoothing_factor: 0.0,
            bandwidth_smoothing_factor: 0.0,
            packet_header_size: 0,
            transmit_packet_function: None,
            process_packet_function: None,
            allocator_context: std::ptr::null_mut(),
            allocate_function: None,
            free_function: None,
        }
    }
}

// pointer lifetimes across the callbacks and the config:
//
//   context, allocator_context      owned by you. the endpoint stores them and hands them
//                                   back unchanged, so they must outlive the endpoint. the
//                                   library never dereferences either one.
//
//   transmit_packet_function
//     packet_data                   points into the endpoint's own transmit scratch buffer
//                                   and is valid only for the duration of the call. the next
//                                   send on that endpoint overwrites it, which is why the
//                                   callback must not send on the same endpoint. copy the
//                                   bytes if you need them after you return.
//                                   port: the slice is exactly packet_bytes long.
//
//   process_packet_function
//     packet_data                   valid only for the duration of the call. for an
//                                   unfragmented packet it points into the buffer you passed
//                                   to reliable_endpoint_receive_packet, past the header. for
//                                   a reassembled packet it points into an internal buffer
//                                   that the endpoint may free as soon as you return. copy the
//                                   bytes if you need them after you return. it is yours to
//                                   read, not to free: reliable_endpoint_free_packet is for
//                                   memory you allocated with the endpoint's allocator.
//                                   port: the slice is exactly packet_bytes long.
//
//   allocate_function, free_function
//                                   called for every allocation the endpoint makes, including
//                                   during reliable_endpoint_create. returning NULL from
//                                   allocate_function is a supported outcome: create frees
//                                   whatever it had allocated and returns NULL. returning NULL
//                                   is also supported on the receive path: the fragment is
//                                   dropped, counted invalid, and the endpoint keeps running
//                                   without crash or corruption.
//                                   port: not called by the Rust port (see the top of the file).

// fills a config with sensible defaults for a client/server game exchanging packets at 60HZ
// (reliable_default_config, below)

// creates an endpoint. one endpoint per connection: a client has one, a server has one per client slot.
// endpoints are not thread safe: use one endpoint per-thread or protect each endpoint with your own lock.
// (the log level, printf and assert handlers are global to the process.)
//
// returns NULL in every build, debug and release, if the config is not valid or if any
// allocation fails. a refused config is one whose fields are out of range or whose
// relationships do not hold: fragment_above must not exceed max_packet_size, and
// max_fragments * fragment_size must cover max_packet_size. on failure nothing is retained:
// every allocation already made is handed back to free_function before create returns.
// check the result.
// (reliable_endpoint_create, below)

// returns the sequence number the next sent packet will have. use it to map acked sequence numbers back to the contents of packets you sent
// (reliable_endpoint_next_packet_sequence, below)

// sends a packet. the packet is handed to the transmit packet callback, split into fragments first if larger than config.fragment_above
// (reliable_endpoint_send_packet, below)

// call this for each packet received from your socket. valid packets are passed to the process packet callback. stale and duplicate packets are dropped
// (reliable_endpoint_receive_packet, below)

// frees a packet using the endpoint's allocator
// (reliable_endpoint_free_packet, below)

// returns a read only view of the sequence numbers of sent packets acked since the last clear.
// the array belongs to the endpoint. it stays valid until the next call to
// reliable_endpoint_receive_packet, reliable_endpoint_clear_acks, reliable_endpoint_reset or
// reliable_endpoint_destroy on that endpoint. copy what you need before calling any of those
// (reliable_endpoint_get_acks, below)

// clears the ack array. call this once per-frame after processing acks. if you don't, the ack buffer fills up and new acks are dropped
// (reliable_endpoint_clear_acks, below)

// resets the endpoint to its initial state: acks, counters, sequence number, all tracking
// buffers, the rtt history and every rtt, jitter, packet loss and bandwidth statistic are
// cleared. the config and the allocator are kept, so the endpoint is immediately usable again
// (reliable_endpoint_reset, below)

// updates rtt, jitter, packet loss and bandwidth stats. call once per-frame with the current time
// (reliable_endpoint_update, below)

// rtt and jitter are in milliseconds, packet loss is a percentage, bandwidth is in kilobits per-second
// (reliable_endpoint_rtt and the other stats getters, below)

// returns a read only view of the RELIABLE_ENDPOINT_NUM_COUNTERS counters, indexed with
// RELIABLE_ENDPOINT_COUNTER_*. the array belongs to the endpoint and stays valid until it is
// reset or destroyed
// (reliable_endpoint_counters, below)

// destroys an endpoint, freeing everything it allocated
// (reliable_endpoint_destroy, below)

// sets the log level (process-wide). RELIABLE_LOG_LEVEL_NONE by default
// (reliable_log_level, below)

// overrides where log output goes (process-wide). default is printf
// (reliable_set_printf_function, below)

// port: upstream's reliable_assert_function global is a Mutex holding the function (the libraries are single
// threaded by design; the Mutex just makes the global safe to touch)
pub static reliable_assert_function: Mutex<fn(&str, &str, &str, i32)> = Mutex::new(default_assert_handler);

// port: active in debug builds (upstream's RELIABLE_DEBUG). the function name is the module path: Rust has no __FUNCTION__
#[macro_export]
macro_rules! reliable_assert
{
    ( $condition:expr ) =>
    {
        if cfg!(debug_assertions)
        {
            if !( $condition )
            {
                let assert_function = *$crate::reliable::reliable_assert_function.lock().unwrap_or_else( |e| e.into_inner() );
                assert_function( stringify!( $condition ), module_path!(), file!(), line!() as i32 );
                std::process::exit( 1 );
            }
        }
    };
}

// (reliable_set_assert_function, below)

// (reliable_copy_string, below)

// ---- reliable.c ----

// port: RELIABLE_ENABLE_TESTS has no switch: reliable_test() at the end of the file is always compiled
pub const RELIABLE_ENABLE_LOGGING: bool = true;

// ------------------------------------------------------------------

// port: prints, then panics where upstream traps (__builtin_trap / __debugbreak). the panic stands in for exit( 1 )
pub fn default_assert_handler( condition: &str, function: &str, file: &str, line: i32 )
{
    print!( "assert failed: ( {} ), function {}, file {}, line {}\n", condition, function, file, line );
    use std::io::Write;
    let _ = std::io::stdout().flush();
    panic!( "assert failed: ( {} )", condition );
}

fn default_printf_function( text: &str )
{
    print!( "{}", text );
}

// port: upstream's file statics, as an atomic and a Mutex
pub static log_level: AtomicI32 = AtomicI32::new( 0 );
pub static printf_function: Mutex<fn(&str)> = Mutex::new( default_printf_function );

pub fn reliable_log_level( level: i32 )
{
    log_level.store( level, Ordering::Relaxed );
}

pub fn reliable_set_printf_function( function: fn(&str) )
{
    // port: reliable_assert( function ) is dropped: a fn can't be NULL
    *printf_function.lock().unwrap_or_else( |e| e.into_inner() ) = function;
}

pub fn reliable_set_assert_function( function: fn(&str, &str, &str, i32) )
{
    *reliable_assert_function.lock().unwrap_or_else( |e| e.into_inner() ) = function;
}

// port: reliable_printf( level, format, ... ) is the reliable_printf! macro, which takes a Rust format string and
// checks the level before formatting anything (upstream formats only after the same check). it calls this function.
// upstream formats into a 4K stack buffer, which truncates longer lines; the port does not truncate

pub fn reliable_printf( level: i32, args: std::fmt::Arguments )
{
    if RELIABLE_ENABLE_LOGGING
    {
        if level > log_level.load( Ordering::Relaxed )
        {
            return;
        }
        let buffer = std::fmt::format( args );
        let function = *printf_function.lock().unwrap_or_else( |e| e.into_inner() );
        function( &buffer );
    }
    else
    {
        let _ = level;
        let _ = args;
    }
}

#[macro_export]
macro_rules! reliable_printf
{
    ( $level:expr, $($arg:tt)* ) =>
    {
        {
            let level: i32 = $level;
            if level <= $crate::reliable::log_level.load( std::sync::atomic::Ordering::Relaxed )
            {
                $crate::reliable::reliable_printf( level, format_args!( $($arg)* ) );
            }
        }
    };
}

// port: malloc and free from the C runtime std already links, for the default allocator callbacks
extern "C"
{
    fn malloc( size: usize ) -> *mut c_void;
    fn free( pointer: *mut c_void );
}

pub fn reliable_default_allocate_function( context: *mut c_void, bytes: usize ) -> *mut c_void
{
    let _ = context;
    unsafe { malloc( bytes ) }
}

pub fn reliable_default_free_function( context: *mut c_void, pointer: *mut c_void )
{
    let _ = context;
    unsafe { free( pointer ) }
}

// multiplies an element count by an element size for an allocation. returns 0 if the count is
// negative or the product does not fit in a size_t, so a config that would wrap the arithmetic
// is refused instead of allocating a buffer smaller than the code goes on to use

pub fn reliable_checked_size( count: i32, element_bytes: usize, result: &mut usize ) -> i32
{
    if count <= 0 || element_bytes == 0
    {
        return 0;
    }
    if ( count as usize ) > usize::MAX / element_bytes
    {
        return 0;
    }
    *result = ( count as usize ) * element_bytes;
    return 1;
}

// ------------------------------------------------------------------

pub fn reliable_init() -> i32
{
    return RELIABLE_OK;
}

pub fn reliable_term()
{
}

// ---------------------------------------------------------------

pub fn reliable_sequence_greater_than( s1: u16, s2: u16 ) -> i32
{
    ( ( ( s1 > s2 ) && ( s1 - s2 <= 32768 ) ) ||
      ( ( s1 < s2 ) && ( s2 - s1  > 32768 ) ) ) as i32
}

pub fn reliable_sequence_less_than( s1: u16, s2: u16 ) -> i32
{
    return reliable_sequence_greater_than( s2, s1 );
}

// ---------------------------------------------------------------

// port: generic over the entry type T instead of void * entries of entry_stride bytes. entry_stride is kept (the
// caller passes size_of::<T>()) and the arrays are Vec
pub struct reliable_sequence_buffer_t<T>
{
    pub allocator_context: *mut c_void,
    pub allocate_function: Option<fn(*mut c_void, usize) -> *mut c_void>,
    pub free_function: Option<fn(*mut c_void, *mut c_void)>,
    pub sequence: u16,
    pub num_entries: i32,
    pub entry_stride: i32,
    pub entry_sequence: Vec<u32>,
    pub entry_data: Vec<T>,
}

pub fn reliable_sequence_buffer_create<T: Default>( num_entries: i32,
                                                    entry_stride: i32,
                                                    allocator_context: *mut c_void,
                                                    mut allocate_function: Option<fn(*mut c_void, usize) -> *mut c_void>,
                                                    mut free_function: Option<fn(*mut c_void, *mut c_void)> ) -> Option<Box<reliable_sequence_buffer_t<T>>>
{
    reliable_assert!( num_entries > 0 );
    reliable_assert!( entry_stride > 0 );

    if allocate_function.is_none()
    {
        allocate_function = Some( reliable_default_allocate_function );
    }

    if free_function.is_none()
    {
        free_function = Some( reliable_default_free_function );
    }

    let mut entry_sequence_bytes: usize = 0;
    let mut entry_data_bytes: usize = 0;

    if reliable_checked_size( num_entries, std::mem::size_of::<u32>(), &mut entry_sequence_bytes ) == 0
    {
        return None;
    }

    if reliable_checked_size( num_entries, entry_stride as usize, &mut entry_data_bytes ) == 0
    {
        return None;
    }

    // port: the struct and its two arrays are a Box and two Vecs, which can't come back NULL, so there is no
    // failure path to unwind here. the entry data is T::default() (upstream zeroes it)

    let mut entry_sequence: Vec<u32> = Vec::with_capacity( num_entries as usize );
    entry_sequence.resize( num_entries as usize, 0xFFFFFFFF );
    let mut entry_data: Vec<T> = Vec::with_capacity( num_entries as usize );
    entry_data.resize_with( num_entries as usize, T::default );

    let sequence_buffer = Box::new( reliable_sequence_buffer_t
    {
        allocator_context: allocator_context,
        allocate_function: allocate_function,
        free_function: free_function,
        sequence: 0,
        num_entries: num_entries,
        entry_stride: entry_stride,
        entry_sequence: entry_sequence,
        entry_data: entry_data,
    } );

    return Some( sequence_buffer );
}

pub fn reliable_sequence_buffer_destroy<T>( sequence_buffer: Box<reliable_sequence_buffer_t<T>> )
{
    // port: dropping the Box frees the entry arrays and the struct (upstream hands each to free_function)
    drop( sequence_buffer );
}

pub fn reliable_sequence_buffer_reset<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T> )
{
    sequence_buffer.sequence = 0;
    for entry in sequence_buffer.entry_sequence.iter_mut()
    {
        *entry = 0xFFFFFFFF;
    }
}

pub fn reliable_sequence_buffer_remove_entries<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T>,
                                                   start_sequence: i32,
                                                   mut finish_sequence: i32,
                                                   cleanup_function: Option<fn(&mut T, *mut c_void, Option<fn(*mut c_void, *mut c_void)>)> )
{
    if finish_sequence < start_sequence
    {
        finish_sequence += 65536;
    }
    if finish_sequence - start_sequence < sequence_buffer.num_entries
    {
        let mut sequence = start_sequence;
        while sequence <= finish_sequence
        {
            let index = ( sequence % sequence_buffer.num_entries ) as usize;
            if let Some( cleanup_function ) = cleanup_function
            {
                cleanup_function( &mut sequence_buffer.entry_data[index],
                                  sequence_buffer.allocator_context,
                                  sequence_buffer.free_function );
            }
            sequence_buffer.entry_sequence[index] = 0xFFFFFFFF;
            sequence += 1;
        }
    }
    else
    {
        for i in 0..sequence_buffer.num_entries as usize
        {
            if let Some( cleanup_function ) = cleanup_function
            {
                cleanup_function( &mut sequence_buffer.entry_data[i],
                                  sequence_buffer.allocator_context,
                                  sequence_buffer.free_function );
            }
            sequence_buffer.entry_sequence[i] = 0xFFFFFFFF;
        }
    }
}

pub fn reliable_sequence_buffer_test_insert<T>( sequence_buffer: &reliable_sequence_buffer_t<T>, sequence: u16 ) -> i32
{
    return if reliable_sequence_less_than( sequence, sequence_buffer.sequence.wrapping_sub( sequence_buffer.num_entries as u16 ) ) != 0 { 0 } else { 1 };
}

pub fn reliable_sequence_buffer_insert<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T>, sequence: u16 ) -> Option<&mut T>
{
    if reliable_sequence_less_than( sequence, sequence_buffer.sequence.wrapping_sub( sequence_buffer.num_entries as u16 ) ) != 0
    {
        return None;
    }
    if reliable_sequence_greater_than( sequence.wrapping_add( 1 ), sequence_buffer.sequence ) != 0
    {
        let start_sequence = sequence_buffer.sequence as i32;
        reliable_sequence_buffer_remove_entries( sequence_buffer, start_sequence, sequence as i32, None );
        sequence_buffer.sequence = sequence.wrapping_add( 1 );
    }
    let index = ( sequence as i32 % sequence_buffer.num_entries ) as usize;
    sequence_buffer.entry_sequence[index] = sequence as u32;
    return Some( &mut sequence_buffer.entry_data[index] );
}

pub fn reliable_sequence_buffer_advance<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T>, sequence: u16 )
{
    if reliable_sequence_greater_than( sequence.wrapping_add( 1 ), sequence_buffer.sequence ) != 0
    {
        let start_sequence = sequence_buffer.sequence as i32;
        reliable_sequence_buffer_remove_entries( sequence_buffer, start_sequence, sequence as i32, None );
        sequence_buffer.sequence = sequence.wrapping_add( 1 );
    }
}

pub fn reliable_sequence_buffer_insert_with_cleanup<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T>,
                                                        sequence: u16,
                                                        cleanup_function: Option<fn(&mut T, *mut c_void, Option<fn(*mut c_void, *mut c_void)>)> ) -> Option<&mut T>
{
    if reliable_sequence_greater_than( sequence.wrapping_add( 1 ), sequence_buffer.sequence ) != 0
    {
        let start_sequence = sequence_buffer.sequence as i32;
        reliable_sequence_buffer_remove_entries( sequence_buffer, start_sequence, sequence as i32, cleanup_function );
        sequence_buffer.sequence = sequence.wrapping_add( 1 );
    }
    else if reliable_sequence_less_than( sequence, sequence_buffer.sequence.wrapping_sub( sequence_buffer.num_entries as u16 ) ) != 0
    {
        return None;
    }
    let index = ( sequence as i32 % sequence_buffer.num_entries ) as usize;
    if sequence_buffer.entry_sequence[index] != 0xFFFFFFFF
    {
        ( cleanup_function.unwrap() )( &mut sequence_buffer.entry_data[index],
                                       sequence_buffer.allocator_context,
                                       sequence_buffer.free_function );
    }
    sequence_buffer.entry_sequence[index] = sequence as u32;
    return Some( &mut sequence_buffer.entry_data[index] );
}

pub fn reliable_sequence_buffer_advance_with_cleanup<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T>,
                                                         sequence: u16,
                                                         cleanup_function: Option<fn(&mut T, *mut c_void, Option<fn(*mut c_void, *mut c_void)>)> )
{
    if reliable_sequence_greater_than( sequence.wrapping_add( 1 ), sequence_buffer.sequence ) != 0
    {
        let start_sequence = sequence_buffer.sequence as i32;
        reliable_sequence_buffer_remove_entries( sequence_buffer, start_sequence, sequence as i32, cleanup_function );
        sequence_buffer.sequence = sequence.wrapping_add( 1 );
    }
}

pub fn reliable_sequence_buffer_remove_with_cleanup<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T>,
                                                        sequence: u16,
                                                        cleanup_function: Option<fn(&mut T, *mut c_void, Option<fn(*mut c_void, *mut c_void)>)> )
{
    let index = ( sequence as i32 % sequence_buffer.num_entries ) as usize;
    if sequence_buffer.entry_sequence[index] != 0xFFFFFFFF
    {
        sequence_buffer.entry_sequence[index] = 0xFFFFFFFF;
        ( cleanup_function.unwrap() )( &mut sequence_buffer.entry_data[index], sequence_buffer.allocator_context, sequence_buffer.free_function );
    }
}

pub fn reliable_sequence_buffer_exists<T>( sequence_buffer: &reliable_sequence_buffer_t<T>, sequence: u16 ) -> i32
{
    return ( sequence_buffer.entry_sequence[ ( sequence as i32 % sequence_buffer.num_entries ) as usize ] == sequence as u32 ) as i32;
}

pub fn reliable_sequence_buffer_find<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T>, sequence: u16 ) -> Option<&mut T>
{
    let index = ( sequence as i32 % sequence_buffer.num_entries ) as usize;
    return if sequence_buffer.entry_sequence[index] == sequence as u32 { Some( &mut sequence_buffer.entry_data[index] ) } else { None };

}

pub fn reliable_sequence_buffer_at_index<T>( sequence_buffer: &mut reliable_sequence_buffer_t<T>, index: i32 ) -> Option<&mut T>
{
    reliable_assert!( index >= 0 );
    reliable_assert!( index < sequence_buffer.num_entries );
    return if sequence_buffer.entry_sequence[index as usize] != 0xFFFFFFFF { Some( &mut sequence_buffer.entry_data[index as usize] ) } else { None };
}

pub fn reliable_sequence_buffer_generate_ack_bits<T>( sequence_buffer: &reliable_sequence_buffer_t<T>, ack: &mut u16, ack_bits: &mut u32 )
{
    *ack = sequence_buffer.sequence.wrapping_sub( 1 );
    *ack_bits = 0;
    let mut mask: u32 = 1;
    for i in 0..32
    {
        let sequence: u16 = ( *ack ).wrapping_sub( i as u16 );
        if reliable_sequence_buffer_exists( sequence_buffer, sequence ) != 0
        {
            *ack_bits |= mask;
        }
        mask <<= 1;
    }
}

// ---------------------------------------------------------------

// port: uint8_t ** p is a slice that advances past what was written or read

pub fn reliable_write_uint8( p: &mut &mut [u8], value: u8 )
{
    let buffer = std::mem::take( p );
    buffer[0] = value;
    *p = &mut buffer[1..];
}

pub fn reliable_write_uint16( p: &mut &mut [u8], value: u16 )
{
    let buffer = std::mem::take( p );
    buffer[0] = ( value & 0xFF ) as u8;
    buffer[1] = ( value >> 8 ) as u8;
    *p = &mut buffer[2..];
}

pub fn reliable_read_uint8( p: &mut &[u8] ) -> u8
{
    let value = ( *p )[0];
    *p = &( *p )[1..];
    return value;
}

pub fn reliable_read_uint16( p: &mut &[u8] ) -> u16
{
    let mut value: u16;
    value = ( *p )[0] as u16;
    value |= ( ( ( *p )[1] ) as u16 ) << 8;
    *p = &( *p )[2..];
    return value;
}

// port: memcpy( p, source, bytes ); p += bytes; for the advancing write slice
fn reliable_write_bytes( p: &mut &mut [u8], source: &[u8], bytes: usize )
{
    let buffer = std::mem::take( p );
    buffer[..bytes].copy_from_slice( &source[..bytes] );
    *p = &mut buffer[bytes..];
}

// ---------------------------------------------------------------

pub struct reliable_fragment_reassembly_data_t
{
    pub sequence: u16,
    pub ack: u16,
    pub ack_bits: u32,
    pub num_fragments_received: i32,
    pub num_fragments_total: i32,
    pub packet_data: Option<Vec<u8>>,           // port: NULL is None
    pub packet_bytes: i32,
    pub packet_header_bytes: i32,
    pub fragment_received: [u8; 256],
}

// port: the zeroed entry upstream gets from memset on the sequence buffer's entry data
impl Default for reliable_fragment_reassembly_data_t
{
    fn default() -> Self
    {
        reliable_fragment_reassembly_data_t
        {
            sequence: 0,
            ack: 0,
            ack_bits: 0,
            num_fragments_received: 0,
            num_fragments_total: 0,
            packet_data: None,
            packet_bytes: 0,
            packet_header_bytes: 0,
            fragment_received: [0; 256],
        }
    }
}

pub fn reliable_fragment_reassembly_data_cleanup( reassembly_data: &mut reliable_fragment_reassembly_data_t, allocator_context: *mut c_void, free_function: Option<fn(*mut c_void, *mut c_void)> )

{
    reliable_assert!( free_function.is_some() );
    let _ = allocator_context;
    if reassembly_data.packet_data.is_some()
    {
        // port: dropping the Vec frees it. free_function is not called (see the top of the file)
        reassembly_data.packet_data = None;
    }
}

// ---------------------------------------------------------------

pub struct reliable_endpoint_t
{
    pub allocator_context: *mut c_void,
    pub allocate_function: Option<fn(*mut c_void, usize) -> *mut c_void>,
    pub free_function: Option<fn(*mut c_void, *mut c_void)>,
    pub config: reliable_config_t,
    pub time: f64,
    pub rtt: f32,
    pub rtt_min: f32,
    pub rtt_max: f32,
    pub rtt_avg: f32,
    pub jitter_avg_vs_min_rtt: f32,
    pub jitter_max_vs_min_rtt: f32,
    pub jitter_stddev_vs_avg_rtt: f32,
    pub packet_loss: f32,
    pub sent_bandwidth_kbps: f32,
    pub received_bandwidth_kbps: f32,
    pub acked_bandwidth_kbps: f32,
    pub num_acks: i32,
    pub acks: Vec<u16>,
    pub sequence: u16,
    pub rtt_history_buffer: Vec<f32>,
    pub transmit_buffer: Vec<u8>,
    // port: the three sequence buffers are never NULL once create returns, so they are Box, not Option<Box>
    pub sent_packets: Box<reliable_sequence_buffer_t<reliable_sent_packet_data_t>>,
    pub received_packets: Box<reliable_sequence_buffer_t<reliable_received_packet_data_t>>,
    pub fragment_reassembly: Box<reliable_sequence_buffer_t<reliable_fragment_reassembly_data_t>>,
    pub counters: [u64; RELIABLE_ENDPOINT_NUM_COUNTERS],
}

#[derive(Clone, Copy, Default)]
pub struct reliable_sent_packet_data_t
{
    pub time: f64,
    pub acked: u32,             // port: the C bitfield acked : 1
    pub packet_bytes: u32,      // port: the C bitfield packet_bytes : 31, masked to 31 bits where it is stored
}

#[derive(Clone, Copy, Default)]
pub struct reliable_received_packet_data_t
{
    pub time: f64,
    pub packet_bytes: u32,
}

pub fn reliable_default_config( config: &mut reliable_config_t )
{
    *config = reliable_config_t::default();
    config.name[0] = b'e';
    config.name[1] = b'n';
    config.name[2] = b'd';
    config.name[3] = b'p';
    config.name[4] = b'o';
    config.name[5] = b'i';
    config.name[6] = b'n';
    config.name[7] = b't';
    config.name[8] = b'\0';
    config.max_packet_size = 16 * 1024;
    config.fragment_above = 1024;
    config.max_fragments = 16;
    config.fragment_size = 1024;
    config.ack_buffer_size = 256;
    config.sent_packets_buffer_size = 256;
    config.received_packets_buffer_size = 256;
    config.fragment_reassembly_buffer_size = 64;
    config.rtt_smoothing_factor = 0.0025;
    config.rtt_history_size = 512;
    config.packet_loss_smoothing_factor = 0.1;
    config.bandwidth_smoothing_factor = 0.1;
    config.packet_header_size = 28;                     // note: UDP over IPv4 = 20 + 8 bytes, UDP over IPv6 = 40 + 8 bytes
}

// the caller's name is not required to be NUL terminated, and reliable_config_valid runs before
// reliable_endpoint_create copies the name and terminates its own copy. so every log of the
// caller's name below prints it with this precision instead of a bare "%s": printf stops at the
// end of the array rather than reading past it

pub const RELIABLE_MAX_NAME_CHARS: i32 = 256 - 1;

// port: "%.*s" with RELIABLE_MAX_NAME_CHARS (and "%s" on a terminated copy): the name up to its first NUL, at most
// RELIABLE_MAX_NAME_CHARS bytes. no allocation when the name is valid UTF-8
pub fn reliable_name_string( name: &[u8] ) -> std::borrow::Cow<'_, str>
{
    let max = std::cmp::min( name.len(), RELIABLE_MAX_NAME_CHARS as usize );
    let end = name[..max].iter().position( |&c| c == 0 ).unwrap_or( max );
    String::from_utf8_lossy( &name[..end] )
}

// checks the config a caller hands to reliable_endpoint_create. every field is range checked
// and the two relationships between fields are checked: a fragment threshold above the maximum
// packet size can never fire, and a fragment count that does not cover the maximum packet size
// means a large packet has nowhere to go. logs what is wrong and returns 0 to refuse the config

pub fn reliable_config_valid( config: Option<&reliable_config_t> ) -> i32
{
    let config = match config
    {
        None =>
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[reliable] config is NULL\n" );
            return 0;
        }
        Some( config ) => config,
    };

    if config.max_packet_size <= 0
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] max_packet_size must be positive\n", reliable_name_string( &config.name ) );
        return 0;
    }

    if config.fragment_above <= 0
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] fragment_above must be positive\n", reliable_name_string( &config.name ) );
        return 0;
    }

    if config.fragment_size <= 0
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] fragment_size must be positive\n", reliable_name_string( &config.name ) );
        return 0;
    }

    if config.max_fragments <= 0 || config.max_fragments > 256
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] max_fragments must be between 1 and 256\n", reliable_name_string( &config.name ) );
        return 0;
    }

    if config.ack_buffer_size <= 0 || config.sent_packets_buffer_size <= 0 ||
       config.received_packets_buffer_size <= 0 || config.fragment_reassembly_buffer_size <= 0 ||
       config.rtt_history_size <= 0
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] buffer sizes must be positive\n", reliable_name_string( &config.name ) );
        return 0;
    }

    if config.transmit_packet_function.is_none() || config.process_packet_function.is_none()
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] transmit and process packet functions are required\n", reliable_name_string( &config.name ) );
        return 0;
    }

    if config.fragment_above > config.max_packet_size
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] fragment_above ({}) is above max_packet_size ({})\n",
                          reliable_name_string( &config.name ), config.fragment_above, config.max_packet_size );
        return 0;
    }

    // max_fragments * fragment_size must cover max_packet_size. written as a division of the
    // two values already known to be positive, so neither side can overflow

    if config.max_fragments <= ( config.max_packet_size - 1 ) / config.fragment_size
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] max_fragments ({}) times fragment_size ({}) does not cover max_packet_size ({})\n",
                          reliable_name_string( &config.name ), config.max_fragments, config.fragment_size, config.max_packet_size );
        return 0;
    }

    if ( config.max_fragments as i64 ) * ( config.fragment_size as i64 ) > ( i32::MAX as i64 ) - RELIABLE_MAX_PACKET_HEADER_BYTES as i64
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] max_fragments ({}) times fragment_size ({}) does not fit in a packet length\n",
                          reliable_name_string( &config.name ), config.max_fragments, config.fragment_size );
        return 0;
    }

    if config.max_packet_size > i32::MAX - RELIABLE_MAX_PACKET_HEADER_BYTES - RELIABLE_FRAGMENT_HEADER_BYTES
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] max_packet_size ({}) is too large for the receive length check\n",
                          reliable_name_string( &config.name ), config.max_packet_size );
        return 0;
    }

    if config.packet_header_size < 0
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] packet_header_size must not be negative\n", reliable_name_string( &config.name ) );
        return 0;
    }

    if ( config.packet_header_size as i64 ) + ( config.max_packet_size as i64 ) > i32::MAX as i64
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] packet_header_size ({}) plus max_packet_size ({}) does not fit a packet length\n",
                          reliable_name_string( &config.name ), config.packet_header_size, config.max_packet_size );
        return 0;
    }

    return 1;
}

pub fn reliable_endpoint_create( config: &reliable_config_t, time: f64 ) -> Option<Box<reliable_endpoint_t>>
{
    if reliable_config_valid( Some( config ) ) == 0
    {
        return None;
    }

    let allocator_context: *mut c_void = config.allocator_context;
    let mut allocate_function: Option<fn(*mut c_void, usize) -> *mut c_void> = config.allocate_function;
    let mut free_function: Option<fn(*mut c_void, *mut c_void)> = config.free_function;

    if allocate_function.is_none()
    {
        allocate_function = Some( reliable_default_allocate_function );
    }

    if free_function.is_none()
    {
        free_function = Some( reliable_default_free_function );
    }

    // every size the endpoint allocates, computed up front so an overflowing config is refused
    // before anything is allocated

    let mut acks_bytes: usize = 0;
    let mut rtt_history_bytes: usize = 0;

    if reliable_checked_size( config.ack_buffer_size, std::mem::size_of::<u16>(), &mut acks_bytes ) == 0
    {
        return None;
    }

    if reliable_checked_size( config.rtt_history_size, std::mem::size_of::<f32>(), &mut rtt_history_bytes ) == 0
    {
        return None;
    }

    // scratch buffer for outgoing packets, so the send path doesn't allocate. sized for whichever is larger: a regular packet or a fragment

    if config.max_packet_size > i32::MAX - RELIABLE_MAX_PACKET_HEADER_BYTES ||
       config.fragment_size > i32::MAX - RELIABLE_FRAGMENT_HEADER_BYTES - RELIABLE_MAX_PACKET_HEADER_BYTES
    {
        return None;
    }

    let mut transmit_buffer_size: i32 = config.max_packet_size + RELIABLE_MAX_PACKET_HEADER_BYTES;
    let fragment_transmit_buffer_size: i32 = RELIABLE_FRAGMENT_HEADER_BYTES + RELIABLE_MAX_PACKET_HEADER_BYTES + config.fragment_size;
    if fragment_transmit_buffer_size > transmit_buffer_size
    {
        transmit_buffer_size = fragment_transmit_buffer_size;
    }

    // from here on every allocation is checked and the failure path hands back everything
    // already taken, in every build, so the caller only ever sees a complete endpoint or NULL

    // port: the buffers are made before the endpoint struct, which is built from them in one go. the Vecs can't
    // fail, and a sequence buffer that comes back None drops whatever was already made on return, so the
    // failure path doesn't need reliable_endpoint_destroy

    let acks: Vec<u16> = vec![ 0; config.ack_buffer_size as usize ];

    let sent_packets = reliable_sequence_buffer_create::<reliable_sent_packet_data_t>( config.sent_packets_buffer_size,
                                                                                       std::mem::size_of::<reliable_sent_packet_data_t>() as i32,
                                                                                       allocator_context,
                                                                                       allocate_function,
                                                                                       free_function );

    let received_packets = reliable_sequence_buffer_create::<reliable_received_packet_data_t>( config.received_packets_buffer_size,
                                                                                               std::mem::size_of::<reliable_received_packet_data_t>() as i32,
                                                                                               allocator_context,
                                                                                               allocate_function,
                                                                                               free_function );

    let fragment_reassembly = reliable_sequence_buffer_create::<reliable_fragment_reassembly_data_t>( config.fragment_reassembly_buffer_size,
                                                                                                      std::mem::size_of::<reliable_fragment_reassembly_data_t>() as i32,
                                                                                                      allocator_context,
                                                                                                      allocate_function,
                                                                                                      free_function );

    let rtt_history_buffer: Vec<f32> = vec![ 0.0; config.rtt_history_size as usize ];

    let transmit_buffer: Vec<u8> = vec![ 0; transmit_buffer_size as usize ];

    if sent_packets.is_none() ||
       received_packets.is_none() ||
       fragment_reassembly.is_none()
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] failed to allocate endpoint\n", reliable_name_string( &config.name ) );
        return None;
    }

    let mut endpoint = Box::new( reliable_endpoint_t
    {
        allocator_context: allocator_context,
        allocate_function: allocate_function,
        free_function: free_function,
        config: *config,
        time: time,
        rtt: 0.0,
        rtt_min: 0.0,
        rtt_max: 0.0,
        rtt_avg: 0.0,
        jitter_avg_vs_min_rtt: 0.0,
        jitter_max_vs_min_rtt: 0.0,
        jitter_stddev_vs_avg_rtt: 0.0,
        packet_loss: 0.0,
        sent_bandwidth_kbps: 0.0,
        received_bandwidth_kbps: 0.0,
        acked_bandwidth_kbps: 0.0,
        num_acks: 0,
        acks: acks,
        sequence: 0,
        rtt_history_buffer: rtt_history_buffer,
        transmit_buffer: transmit_buffer,
        sent_packets: sent_packets.unwrap(),
        received_packets: received_packets.unwrap(),
        fragment_reassembly: fragment_reassembly.unwrap(),
        counters: [0; RELIABLE_ENDPOINT_NUM_COUNTERS],
    } );

    // force a terminator on the caller's name copy: reliable_printf logs it with "%s", so a caller
    // that fills all 256 bytes with no NUL would make that log read past the array.
    let name_size = endpoint.config.name.len();
    endpoint.config.name[name_size - 1] = b'\0';

    for i in 0..config.rtt_history_size as usize
    {
        endpoint.rtt_history_buffer[i] = -1.0;
    }

    // port: the acks Vec is already zeroed (upstream memsets it here)

    return Some( endpoint );
}

pub fn reliable_endpoint_destroy( mut endpoint: Box<reliable_endpoint_t> )
{
    // every member is checked rather than asserted, because reliable_endpoint_create hands a
    // partly built endpoint to this function to unwind an allocation failure
    // port: create never hands this a partly built endpoint, and the members can't be NULL

    for i in 0..endpoint.config.fragment_reassembly_buffer_size
    {
        let reassembly_data = reliable_sequence_buffer_at_index( &mut endpoint.fragment_reassembly, i );

        if let Some( reassembly_data ) = reassembly_data
        {
            if reassembly_data.packet_data.is_some()
            {
                // port: dropping the Vec frees it (upstream calls free_function)
                reassembly_data.packet_data = None;
            }
        }
    }

    // port: the acks, the rtt history, the transmit buffer and the endpoint drop with the Box. the sequence buffers
    // go through reliable_sequence_buffer_destroy, as upstream

    let endpoint = *endpoint;
    reliable_sequence_buffer_destroy( endpoint.sent_packets );
    reliable_sequence_buffer_destroy( endpoint.received_packets );
    reliable_sequence_buffer_destroy( endpoint.fragment_reassembly );
}

pub fn reliable_endpoint_next_packet_sequence( endpoint: &reliable_endpoint_t ) -> u16
{
    return endpoint.sequence;
}

pub fn reliable_write_packet_header( packet_data: &mut [u8], sequence: u16, ack: u16, ack_bits: u32 ) -> i32
{
    let packet_data_length = packet_data.len();

    let mut p: &mut [u8] = packet_data;

    let mut prefix_byte: u8 = 0;

    if ( ack_bits & 0x000000FF ) != 0x000000FF
    {
        prefix_byte |= 1<<1;
    }

    if ( ack_bits & 0x0000FF00 ) != 0x0000FF00
    {
        prefix_byte |= 1<<2;
    }

    if ( ack_bits & 0x00FF0000 ) != 0x00FF0000
    {
        prefix_byte |= 1<<3;
    }

    if ( ack_bits & 0xFF000000 ) != 0xFF000000
    {
        prefix_byte |= 1<<4;
    }

    let mut sequence_difference: i32 = sequence as i32 - ack as i32;
    if sequence_difference < 0
    {
        sequence_difference += 65536;
    }
    if sequence_difference <= 255
    {
        prefix_byte |= 1<<5;
    }

    reliable_write_uint8( &mut p, prefix_byte );

    reliable_write_uint16( &mut p, sequence );

    if sequence_difference <= 255
    {
        reliable_write_uint8( &mut p, sequence_difference as u8 );
    }
    else
    {
        reliable_write_uint16( &mut p, ack );
    }

    if ( ack_bits & 0x000000FF ) != 0x000000FF
    {
        reliable_write_uint8( &mut p, ( ack_bits & 0x000000FF ) as u8 );
    }

    if ( ack_bits & 0x0000FF00 ) != 0x0000FF00
    {
        reliable_write_uint8( &mut p, ( ( ack_bits & 0x0000FF00 ) >> 8 ) as u8 );
    }

    if ( ack_bits & 0x00FF0000 ) != 0x00FF0000
    {
        reliable_write_uint8( &mut p, ( ( ack_bits & 0x00FF0000 ) >> 16 ) as u8 );
    }

    if ( ack_bits & 0xFF000000 ) != 0xFF000000
    {
        reliable_write_uint8( &mut p, ( ( ack_bits & 0xFF000000 ) >> 24 ) as u8 );
    }

    // port: p - packet_data is the length consumed from the slice
    let bytes = ( packet_data_length - p.len() ) as i32;

    reliable_assert!( bytes <= RELIABLE_MAX_PACKET_HEADER_BYTES );

    return bytes;
}

pub fn reliable_endpoint_send_packet( endpoint: &mut reliable_endpoint_t, packet_data: &[u8], packet_bytes: i32 )
{
    reliable_assert!( packet_bytes > 0 );

    if packet_bytes > endpoint.config.max_packet_size
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] packet too large to send. packet is {} bytes, maximum is {}\n",
            reliable_name_string( &endpoint.config.name ), packet_bytes, endpoint.config.max_packet_size );
        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND] += 1;
        return;
    }

    let sequence: u16 = endpoint.sequence;
    endpoint.sequence = endpoint.sequence.wrapping_add( 1 );
    let mut ack: u16 = 0;
    let mut ack_bits: u32 = 0;

    reliable_sequence_buffer_generate_ack_bits( &endpoint.received_packets, &mut ack, &mut ack_bits );

    reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] sending packet {}\n", reliable_name_string( &endpoint.config.name ), sequence );

    let sent_packet_data = reliable_sequence_buffer_insert( &mut endpoint.sent_packets, sequence );

    reliable_assert!( sent_packet_data.is_some() );

    let sent_packet_data = sent_packet_data.unwrap();

    sent_packet_data.time = endpoint.time;
    sent_packet_data.packet_bytes = ( ( endpoint.config.packet_header_size + packet_bytes ) as u32 ) & 0x7FFFFFFF;
    sent_packet_data.acked = 0;

    let transmit_packet_function = endpoint.config.transmit_packet_function.unwrap();

    if packet_bytes <= endpoint.config.fragment_above
    {
        // regular packet

        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] sending packet {} without fragmentation\n", reliable_name_string( &endpoint.config.name ), sequence );

        let transmit_packet_data: &mut [u8] = &mut endpoint.transmit_buffer[..];

        let packet_header_bytes = reliable_write_packet_header( transmit_packet_data, sequence, ack, ack_bits );

        transmit_packet_data[packet_header_bytes as usize..( packet_header_bytes + packet_bytes ) as usize].copy_from_slice( &packet_data[..packet_bytes as usize] );

        let transmit_packet_bytes = packet_header_bytes + packet_bytes;

        transmit_packet_function( endpoint.config.context, endpoint.config.id, sequence, &endpoint.transmit_buffer[..transmit_packet_bytes as usize], transmit_packet_bytes );
    }
    else
    {
        // fragmented packet

        let mut packet_header = [0u8; RELIABLE_MAX_PACKET_HEADER_BYTES as usize];

        let packet_header_bytes = reliable_write_packet_header( &mut packet_header, sequence, ack, ack_bits );

        let num_fragments: i32 = ( packet_bytes / endpoint.config.fragment_size ) + if ( packet_bytes % endpoint.config.fragment_size ) != 0 { 1 } else { 0 };

        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] sending packet {} as {} fragments\n", reliable_name_string( &endpoint.config.name ), sequence, num_fragments );

        reliable_assert!( num_fragments >= 1 );
        reliable_assert!( num_fragments <= endpoint.config.max_fragments );

        // port: q and end are offsets into packet_data
        let mut q: i32 = 0;

        let end: i32 = q + packet_bytes;

        for fragment_id in 0..num_fragments
        {
            let fragment_packet_data: &mut [u8] = &mut endpoint.transmit_buffer[..];

            let fragment_packet_data_length = fragment_packet_data.len();

            let mut p: &mut [u8] = fragment_packet_data;

            reliable_write_uint8( &mut p, 1 );
            reliable_write_uint16( &mut p, sequence );
            reliable_write_uint8( &mut p, fragment_id as u8 );
            reliable_write_uint8( &mut p, ( num_fragments - 1 ) as u8 );

            if fragment_id == 0
            {
                reliable_write_bytes( &mut p, &packet_header, packet_header_bytes as usize );
            }

            let mut bytes_to_copy: i32 = endpoint.config.fragment_size;
            if q + bytes_to_copy > end
            {
                bytes_to_copy = end - q;
            }

            reliable_write_bytes( &mut p, &packet_data[q as usize..], bytes_to_copy as usize );

            q += bytes_to_copy;

            let fragment_packet_bytes = ( fragment_packet_data_length - p.len() ) as i32;

            transmit_packet_function( endpoint.config.context, endpoint.config.id, sequence, &endpoint.transmit_buffer[..fragment_packet_bytes as usize], fragment_packet_bytes );

            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT] += 1;
        }
    }

    endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT] += 1;
}

pub fn reliable_read_packet_header( name: &str, packet_data: &[u8], packet_bytes: i32, sequence: &mut u16, ack: &mut u16, ack_bits: &mut u32 ) -> i32
{
    if packet_bytes < 3
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] packet too small for packet header (1)\n", name );
        return -1;
    }

    let mut p: &[u8] = packet_data;

    let prefix_byte: u8 = reliable_read_uint8( &mut p );

    if ( prefix_byte & 1 ) != 0
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] prefix byte does not indicate a regular packet\n", name );
        return -1;
    }

    *sequence = reliable_read_uint16( &mut p );

    if ( prefix_byte & ( 1<<5 ) ) != 0
    {
        if packet_bytes < 3 + 1
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] packet too small for packet header (2)\n", name );
            return -1;
        }
        let sequence_difference: u8 = reliable_read_uint8( &mut p );
        *ack = ( *sequence ).wrapping_sub( sequence_difference as u16 );
    }
    else
    {
        if packet_bytes < 3 + 2
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] packet too small for packet header (3)\n", name );
            return -1;
        }
        *ack = reliable_read_uint16( &mut p );
    }

    let mut expected_bytes: i32 = 0;
    for i in 1..=4
    {
        if ( prefix_byte & ( 1<<i ) ) != 0
        {
            expected_bytes += 1;
        }
    }
    // port: p - packet_data is the length consumed from the slice
    if packet_bytes < ( packet_data.len() - p.len() ) as i32 + expected_bytes
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] packet too small for packet header (4)\n", name );
        return -1;
    }

    *ack_bits = 0xFFFFFFFF;

    if ( prefix_byte & ( 1<<1 ) ) != 0
    {
        *ack_bits &= 0xFFFFFF00;
        *ack_bits |= reliable_read_uint8( &mut p ) as u32;
    }

    if ( prefix_byte & ( 1<<2 ) ) != 0
    {
        *ack_bits &= 0xFFFF00FF;
        *ack_bits |= ( reliable_read_uint8( &mut p ) as u32 ) << 8;
    }

    if ( prefix_byte & ( 1<<3 ) ) != 0
    {
        *ack_bits &= 0xFF00FFFF;
        *ack_bits |= ( reliable_read_uint8( &mut p ) as u32 ) << 16;
    }

    if ( prefix_byte & ( 1<<4 ) ) != 0
    {
        *ack_bits &= 0x00FFFFFF;
        *ack_bits |= ( reliable_read_uint8( &mut p ) as u32 ) << 24;
    }

    return ( packet_data.len() - p.len() ) as i32;
}

pub fn reliable_read_fragment_header( name: &str,
                                      packet_data: &[u8],
                                      packet_bytes: i32,
                                      max_fragments: i32,
                                      fragment_size: i32,
                                      fragment_id: &mut i32,
                                      num_fragments: &mut i32,
                                      fragment_bytes: &mut i32,
                                      sequence: &mut u16,
                                      ack: &mut u16,
                                      ack_bits: &mut u32 ) -> i32
{
    if packet_bytes < RELIABLE_FRAGMENT_HEADER_BYTES
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] packet is too small to read fragment header\n", name );
        return -1;
    }

    let mut p: &[u8] = packet_data;

    let prefix_byte: u8 = reliable_read_uint8( &mut p );
    if prefix_byte != 1
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] prefix byte is not a fragment\n", name );
        return -1;
    }

    *sequence = reliable_read_uint16( &mut p );
    *fragment_id = reliable_read_uint8( &mut p ) as i32;
    *num_fragments = ( reliable_read_uint8( &mut p ) as i32 ) + 1;

    if *num_fragments > max_fragments
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] num fragments {} outside of range of max fragments {}\n", name, *num_fragments, max_fragments );
        return -1;
    }

    if *fragment_id >= *num_fragments
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] fragment id {} outside of range of num fragments {}\n", name, *fragment_id, *num_fragments );
        return -1;
    }

    *fragment_bytes = packet_bytes - RELIABLE_FRAGMENT_HEADER_BYTES;

    let mut packet_sequence: u16 = 0;
    let mut packet_ack: u16 = 0;
    let mut packet_ack_bits: u32 = 0;

    if *fragment_id == 0
    {
        let packet_header_bytes = reliable_read_packet_header( name,
                                                               &packet_data[RELIABLE_FRAGMENT_HEADER_BYTES as usize..],
                                                               packet_bytes - RELIABLE_FRAGMENT_HEADER_BYTES,
                                                               &mut packet_sequence,
                                                               &mut packet_ack,
                                                               &mut packet_ack_bits );

        if packet_header_bytes < 0
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] bad packet header in fragment\n", name );
            return -1;
        }

        if packet_sequence != *sequence
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] bad packet sequence in fragment. expected {}, got {}\n", name, *sequence, packet_sequence );
            return -1;
        }

        // the packet header is re-encoded canonically during reassembly, so a non-canonical
        // header would shift where the fragment payload lands. reject it here instead.

        let mut canonical_header = [0u8; RELIABLE_MAX_PACKET_HEADER_BYTES as usize];
        let canonical_header_bytes = reliable_write_packet_header( &mut canonical_header, packet_sequence, packet_ack, packet_ack_bits );
        if canonical_header_bytes != packet_header_bytes ||
           canonical_header[..canonical_header_bytes as usize] != packet_data[RELIABLE_FRAGMENT_HEADER_BYTES as usize..( RELIABLE_FRAGMENT_HEADER_BYTES + canonical_header_bytes ) as usize]
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] non-canonical packet header in fragment\n", name );
            return -1;
        }

        *fragment_bytes = packet_bytes - packet_header_bytes - RELIABLE_FRAGMENT_HEADER_BYTES;
    }

    *ack = packet_ack;
    *ack_bits = packet_ack_bits;

    if *fragment_bytes > fragment_size
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] fragment bytes {} > fragment size {}\n", name, *fragment_bytes, fragment_size );
        return - 1;
    }

    if *fragment_id != *num_fragments - 1 && *fragment_bytes != fragment_size
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] fragment {} is {} bytes, which is not the expected fragment size {}\n",
            name, *fragment_id, *fragment_bytes, fragment_size );
        return -1;
    }

    return ( packet_data.len() - p.len() ) as i32;
}

pub fn reliable_store_fragment_data( reassembly_data: &mut reliable_fragment_reassembly_data_t,
                                     sequence: u16,
                                     ack: u16,
                                     ack_bits: u32,
                                     fragment_id: i32,
                                     fragment_size: i32,
                                     mut fragment_data: &[u8],
                                     mut fragment_bytes: i32 )
{
    if fragment_id == 0
    {
        let mut packet_header = [0u8; RELIABLE_MAX_PACKET_HEADER_BYTES as usize];

        reassembly_data.packet_header_bytes = reliable_write_packet_header( &mut packet_header, sequence, ack, ack_bits );

        let packet_header_offset = ( RELIABLE_MAX_PACKET_HEADER_BYTES - reassembly_data.packet_header_bytes ) as usize;
        let packet_header_bytes = reassembly_data.packet_header_bytes as usize;
        reassembly_data.packet_data.as_mut().unwrap()[packet_header_offset..packet_header_offset + packet_header_bytes]
            .copy_from_slice( &packet_header[..packet_header_bytes] );

        fragment_data = &fragment_data[packet_header_bytes..];
        fragment_bytes -= reassembly_data.packet_header_bytes;
    }

    if fragment_id == reassembly_data.num_fragments_total - 1
    {
        let packet_bytes: i64 = ( reassembly_data.num_fragments_total - 1 ) as i64 * fragment_size as i64 + fragment_bytes as i64;
        if packet_bytes < 0 || packet_bytes > i32::MAX as i64
        {
            return;
        }
        reassembly_data.packet_bytes = packet_bytes as i32;
    }

    // port: size_t arithmetic in u64, so a negative fragment_bytes can't wrap before the check below
    let offset: u64 = RELIABLE_MAX_PACKET_HEADER_BYTES as u64 + ( fragment_id as u64 ) * ( fragment_size as u64 );
    let end_offset: u64 = ( offset as i64 + fragment_bytes as i64 ) as u64;
    let max_size: u64 = RELIABLE_MAX_PACKET_HEADER_BYTES as u64 +
                        ( reassembly_data.num_fragments_total as u64 ) * ( fragment_size as u64 );

    if fragment_bytes < 0 || end_offset > max_size
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG,
            "[reliable] invalid fragment size {} (would write past {}/{})\n",
            fragment_bytes, end_offset, max_size );
        return;
    }

    reassembly_data.packet_data.as_mut().unwrap()[offset as usize..end_offset as usize].copy_from_slice( &fragment_data[..fragment_bytes as usize] );
}

pub fn reliable_endpoint_receive_packet( endpoint: &mut reliable_endpoint_t, packet_data: &[u8], packet_bytes: i32 )
{
    reliable_assert!( packet_bytes > 0 );

    if ( packet_bytes as i64 ) > ( endpoint.config.max_packet_size as i64 ) + RELIABLE_MAX_PACKET_HEADER_BYTES as i64 + RELIABLE_FRAGMENT_HEADER_BYTES as i64
    {
        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] packet too large to receive. packet is at least {} bytes, maximum is {}\n",
            reliable_name_string( &endpoint.config.name ), packet_bytes - ( RELIABLE_MAX_PACKET_HEADER_BYTES + RELIABLE_FRAGMENT_HEADER_BYTES ), endpoint.config.max_packet_size );
        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE] += 1;
        return;
    }

    let prefix_byte: u8 = packet_data[0];

    if ( prefix_byte & 1 ) == 0
    {
        // regular packet

        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] += 1;

        let mut sequence: u16 = 0;
        let mut ack: u16 = 0;
        let mut ack_bits: u32 = 0;

        let packet_header_bytes = reliable_read_packet_header( &reliable_name_string( &endpoint.config.name ), packet_data, packet_bytes, &mut sequence, &mut ack, &mut ack_bits );
        if packet_header_bytes < 0
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] ignoring invalid packet. could not read packet header\n", reliable_name_string( &endpoint.config.name ) );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID] += 1;
            return;
        }

        reliable_assert!( packet_header_bytes <= packet_bytes );

        let packet_payload_bytes: i32 = packet_bytes - packet_header_bytes;

        if packet_payload_bytes > endpoint.config.max_packet_size
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] packet too large to receive. packet is at {} bytes, maximum is {}\n",
                reliable_name_string( &endpoint.config.name ), packet_payload_bytes, endpoint.config.max_packet_size );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE] += 1;
            return;
        }

        if reliable_sequence_buffer_test_insert( &endpoint.received_packets, sequence ) == 0
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] ignoring stale packet {}\n", reliable_name_string( &endpoint.config.name ), sequence );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_STALE] += 1;
            return;
        }

        if reliable_sequence_buffer_exists( &endpoint.received_packets, sequence ) != 0
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] ignoring duplicate packet {}\n", reliable_name_string( &endpoint.config.name ), sequence );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE] += 1;
            return;
        }

        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] processing packet {}\n", reliable_name_string( &endpoint.config.name ), sequence );

        if ( endpoint.config.process_packet_function.unwrap() )( endpoint.config.context,
                                                                 endpoint.config.id,
                                                                 sequence,
                                                                 &packet_data[packet_header_bytes as usize..packet_bytes as usize],
                                                                 packet_bytes - packet_header_bytes ) != 0
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] process packet {} successful\n", reliable_name_string( &endpoint.config.name ), sequence );

            let received_packet_data = reliable_sequence_buffer_insert( &mut endpoint.received_packets, sequence );

            reliable_sequence_buffer_advance_with_cleanup( &mut endpoint.fragment_reassembly, sequence, Some( reliable_fragment_reassembly_data_cleanup ) );

            reliable_assert!( received_packet_data.is_some() );

            let received_packet_data = received_packet_data.unwrap();

            received_packet_data.time = endpoint.time;
            received_packet_data.packet_bytes = ( endpoint.config.packet_header_size + packet_bytes ) as u32;

            for i in 0..32
            {
                if ( ack_bits & 1 ) != 0
                {
                    let ack_sequence: u16 = ack.wrapping_sub( i as u16 );

                    let sent_packet_data = reliable_sequence_buffer_find( &mut endpoint.sent_packets, ack_sequence );

                    if let Some( sent_packet_data ) = sent_packet_data
                    {
                        if sent_packet_data.acked == 0
                        {
                            if endpoint.num_acks < endpoint.config.ack_buffer_size
                            {
                                reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] acked packet {}\n", reliable_name_string( &endpoint.config.name ), ack_sequence );
                                endpoint.acks[endpoint.num_acks as usize] = ack_sequence;
                                endpoint.num_acks += 1;
                                endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED] += 1;
                                sent_packet_data.acked = 1;

                                let rtt: f32 = ( ( endpoint.time - sent_packet_data.time ) as f32 ) * 1000.0;

                                reliable_assert!( rtt >= 0.0 );

                                let index = ( ack_sequence as i32 % endpoint.config.rtt_history_size ) as usize;

                                endpoint.rtt_history_buffer[index] = rtt;

                                if ( endpoint.rtt == 0.0 && rtt > 0.0 ) || ( ( endpoint.rtt - rtt ).abs() as f64 ) < 0.00001
                                {
                                    endpoint.rtt = rtt;
                                }
                                else
                                {
                                    endpoint.rtt += ( rtt - endpoint.rtt ) * endpoint.config.rtt_smoothing_factor;
                                }
                            }
                            else
                            {
                                reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] ack buffer is full. dropped ack for packet {}. make sure you call reliable_endpoint_clear_acks\n",
                                    reliable_name_string( &endpoint.config.name ), ack_sequence );
                            }
                        }
                    }
                }
                ack_bits >>= 1;
            }
        }
        else
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] process packet failed\n", reliable_name_string( &endpoint.config.name ) );
        }
    }
    else
    {
        // fragment packet

        let mut fragment_id: i32 = 0;
        let mut num_fragments: i32 = 0;
        let mut fragment_bytes: i32 = 0;

        let mut sequence: u16 = 0;
        let mut ack: u16 = 0;
        let mut ack_bits: u32 = 0;

        let fragment_header_bytes = reliable_read_fragment_header( &reliable_name_string( &endpoint.config.name ),
                                                                   packet_data,
                                                                   packet_bytes,
                                                                   endpoint.config.max_fragments,
                                                                   endpoint.config.fragment_size,
                                                                   &mut fragment_id,
                                                                   &mut num_fragments,
                                                                   &mut fragment_bytes,
                                                                   &mut sequence,
                                                                   &mut ack,
                                                                   &mut ack_bits );

        if fragment_header_bytes < 0
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] ignoring invalid fragment. could not read fragment header\n", reliable_name_string( &endpoint.config.name ) );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] += 1;
            return;
        }

        if reliable_sequence_buffer_exists( &endpoint.received_packets, sequence ) != 0
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] ignoring fragment {} of packet {}. packet already received\n",
                reliable_name_string( &endpoint.config.name ), fragment_id, sequence );
            return;
        }

        // port: find, then a second find after the insert: the borrow checker can't see that a None from the first
        // find ends its borrow of the reassembly buffer
        if reliable_sequence_buffer_find( &mut endpoint.fragment_reassembly, sequence ).is_none()
        {
            let reassembly_data = reliable_sequence_buffer_insert_with_cleanup( &mut endpoint.fragment_reassembly, sequence, Some( reliable_fragment_reassembly_data_cleanup ) );

            let reassembly_data = match reassembly_data
            {
                None =>
                {
                    reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] ignoring invalid fragment. could not insert in reassembly buffer (stale)\n", reliable_name_string( &endpoint.config.name ) );
                    endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] += 1;
                    return;
                }
                Some( reassembly_data ) => reassembly_data,
            };

            reliable_sequence_buffer_advance( &mut endpoint.received_packets, sequence );

            let packet_buffer_size: usize = RELIABLE_MAX_PACKET_HEADER_BYTES as usize + ( num_fragments as usize ) * ( endpoint.config.fragment_size as usize ) + 8;

            reassembly_data.sequence = sequence;
            reassembly_data.ack = 0;
            reassembly_data.ack_bits = 0;
            reassembly_data.num_fragments_received = 0;
            reassembly_data.num_fragments_total = num_fragments;

            // port: the reassembly buffer is a zeroed Vec, which can't come back NULL. upstream allocates it with
            // allocate_function, drops the fragment (counted invalid) when that returns NULL, and zeroes it:
            //
            // allocate_function hands back uninitialized memory (malloc-shaped, not zeroed). completeness
            // is guaranteed by the fragment bitmap plus validated offsets today, but zeroing means any
            // future logic error that skips storing a fragment leaks zeros into the delivered packet
            // instead of stale heap contents.
            reassembly_data.packet_data = Some( vec![ 0u8; packet_buffer_size ] );

            reassembly_data.packet_bytes = 0;
            reassembly_data.packet_header_bytes = 0;
            reassembly_data.fragment_received = [0; 256];
        }

        let reassembly_data = reliable_sequence_buffer_find( &mut endpoint.fragment_reassembly, sequence ).unwrap();

        if num_fragments != reassembly_data.num_fragments_total
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] ignoring invalid fragment. fragment count mismatch. expected {}, got {}\n",
                reliable_name_string( &endpoint.config.name ), reassembly_data.num_fragments_total, num_fragments );
            endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] += 1;
            return;
        }

        if reassembly_data.fragment_received[fragment_id as usize] != 0
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_ERROR, "[{}] ignoring fragment {} of packet {}. fragment already received\n",
                reliable_name_string( &endpoint.config.name ), fragment_id, sequence );
            return;
        }

        reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] received fragment {} of packet {} ({}/{})\n",
            reliable_name_string( &endpoint.config.name ), fragment_id, sequence, reassembly_data.num_fragments_received+1, num_fragments );

        reassembly_data.num_fragments_received += 1;
        reassembly_data.fragment_received[fragment_id as usize] = 1;

        reliable_store_fragment_data( reassembly_data,
                                      sequence,
                                      ack,
                                      ack_bits,
                                      fragment_id,
                                      endpoint.config.fragment_size,
                                      &packet_data[fragment_header_bytes as usize..],
                                      packet_bytes - fragment_header_bytes );

        if reassembly_data.num_fragments_received == reassembly_data.num_fragments_total
        {
            reliable_printf!( RELIABLE_LOG_LEVEL_DEBUG, "[{}] completed reassembly of packet {}\n", reliable_name_string( &endpoint.config.name ), sequence );

            // port: the reassembled buffer is moved out of the entry for the call, since the call needs the whole
            // endpoint. it drops at the end of this block, where upstream's cleanup in the remove below frees it
            let packet_header_bytes = reassembly_data.packet_header_bytes;
            let reassembled_packet_bytes = reassembly_data.packet_bytes;
            let reassembled_packet_data = reassembly_data.packet_data.take().unwrap();

            reliable_endpoint_receive_packet( endpoint,
                                              &reassembled_packet_data[( RELIABLE_MAX_PACKET_HEADER_BYTES - packet_header_bytes ) as usize..],
                                              packet_header_bytes + reassembled_packet_bytes );

            reliable_sequence_buffer_remove_with_cleanup( &mut endpoint.fragment_reassembly, sequence, Some( reliable_fragment_reassembly_data_cleanup ) );
        }

        endpoint.counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] += 1;
    }
}

// port: takes the Vec it frees (README: the matching *_free_packet takes the Vec<u8>). dropping it frees it;
// free_function is not called (see the top of the file)
pub fn reliable_endpoint_free_packet( endpoint: &mut reliable_endpoint_t, packet: Vec<u8> )
{
    let _ = endpoint;
    drop( packet );
}

// port: returns the whole acks array, as upstream returns its pointer; only the first *num_acks entries are meaningful
pub fn reliable_endpoint_get_acks<'a>( endpoint: &'a reliable_endpoint_t, num_acks: &mut i32 ) -> &'a [u16]
{
    *num_acks = endpoint.num_acks;
    return &endpoint.acks[..];
}

pub fn reliable_endpoint_clear_acks( endpoint: &mut reliable_endpoint_t )
{
    endpoint.num_acks = 0;
}

pub fn reliable_endpoint_reset( endpoint: &mut reliable_endpoint_t )
{
    endpoint.num_acks = 0;
    endpoint.sequence = 0;

    // every value a getter can return goes back to what it was at create, so the header's
    // promise holds for the statistics as well as for the buffers

    endpoint.rtt = 0.0;
    endpoint.rtt_min = 0.0;
    endpoint.rtt_max = 0.0;
    endpoint.rtt_avg = 0.0;
    endpoint.jitter_avg_vs_min_rtt = 0.0;
    endpoint.jitter_max_vs_min_rtt = 0.0;
    endpoint.jitter_stddev_vs_avg_rtt = 0.0;
    endpoint.packet_loss = 0.0;
    endpoint.sent_bandwidth_kbps = 0.0;
    endpoint.received_bandwidth_kbps = 0.0;
    endpoint.acked_bandwidth_kbps = 0.0;

    for ack in endpoint.acks.iter_mut()
    {
        *ack = 0;
    }
    endpoint.counters = [0; RELIABLE_ENDPOINT_NUM_COUNTERS];

    for rtt_index in 0..endpoint.config.rtt_history_size as usize
    {
        endpoint.rtt_history_buffer[rtt_index] = -1.0;
    }

    for i in 0..endpoint.config.fragment_reassembly_buffer_size
    {
        let reassembly_data = reliable_sequence_buffer_at_index( &mut endpoint.fragment_reassembly, i );

        if let Some( reassembly_data ) = reassembly_data
        {
            if reassembly_data.packet_data.is_some()
            {
                // port: dropping the Vec frees it (upstream calls free_function)
                reassembly_data.packet_data = None;
            }
        }
    }

    reliable_sequence_buffer_reset( &mut endpoint.sent_packets );
    reliable_sequence_buffer_reset( &mut endpoint.received_packets );
    reliable_sequence_buffer_reset( &mut endpoint.fragment_reassembly );
}

pub fn reliable_endpoint_update( endpoint: &mut reliable_endpoint_t, time: f64 )
{
    endpoint.time = time;

    // calculate min and max rtt
    {
        let mut min_rtt: f32 = f32::MAX;
        let mut max_rtt: f32 = 0.0;
        let mut sum_rtt: f32 = 0.0;
        let mut count: i32 = 0;
        for i in 0..endpoint.config.rtt_history_size as usize
        {
            let rtt: f32 = endpoint.rtt_history_buffer[i];
            if rtt >= 0.0
            {
                if rtt < min_rtt
                {
                    min_rtt = rtt;
                }
                if rtt > max_rtt
                {
                    max_rtt = rtt;
                }
                sum_rtt += rtt;
                count += 1;
            }
        }
        // the sample count, not the value of min_rtt, says whether the history is empty. a
        // sentinel compared against a real rtt reports 0 for a link slow enough to reach it

        if count > 0
        {
            endpoint.rtt_min = min_rtt;
            endpoint.rtt_max = max_rtt;
            endpoint.rtt_avg = sum_rtt / count as f32;
        }
        else
        {
            endpoint.rtt_min = 0.0;
            endpoint.rtt_max = 0.0;
            endpoint.rtt_avg = 0.0;
        }
    }

    // calculate average jitter vs. min rtt
    {
        let mut sum: f32 = 0.0;
        let mut count: i32 = 0;
        for i in 0..endpoint.config.rtt_history_size as usize
        {
            if endpoint.rtt_history_buffer[i] >= 0.0
            {
                sum += endpoint.rtt_history_buffer[i] - endpoint.rtt_min;
                count += 1;
            }
        }
        if count > 0
        {
            endpoint.jitter_avg_vs_min_rtt = sum / count as f32;
        }
        else
        {
            endpoint.jitter_avg_vs_min_rtt = 0.0;
        }
    }

    // calculate max jitter vs. min rtt
    {
        let mut max: f32 = 0.0;
        for i in 0..endpoint.config.rtt_history_size as usize
        {
            if endpoint.rtt_history_buffer[i] >= 0.0
            {
                let difference: f32 = endpoint.rtt_history_buffer[i] - endpoint.rtt_min;
                if difference > max
                {
                    max = difference;
                }
            }
        }
        endpoint.jitter_max_vs_min_rtt = max;
    }

    // calculate stddev jitter vs. avg rtt
    {
        let mut sum: f32 = 0.0;
        let mut count: i32 = 0;
        for i in 0..endpoint.config.rtt_history_size as usize
        {
            if endpoint.rtt_history_buffer[i] >= 0.0
            {
                let deviation: f32 = endpoint.rtt_history_buffer[i] - endpoint.rtt_avg;
                sum += deviation * deviation;
                count += 1;
            }
        }
        if count > 0
        {
            endpoint.jitter_stddev_vs_avg_rtt = ( ( sum / count as f32 ) as f64 ).powf( 0.5 ) as f32;
        }
        else
        {
            endpoint.jitter_stddev_vs_avg_rtt = 0.0;
        }
    }

    // calculate packet loss
    {
        let base_sequence: u32 = ( ( endpoint.sent_packets.sequence as i32 - endpoint.config.sent_packets_buffer_size + 1 ) + 0xFFFF ) as u32;
        let mut num_sent: i32 = 0;
        let mut num_dropped: i32 = 0;
        let num_samples: i32 = endpoint.config.sent_packets_buffer_size / 2;
        for i in 0..num_samples
        {
            let sequence: u16 = base_sequence.wrapping_add( i as u32 ) as u16;
            let sent_packet_data = reliable_sequence_buffer_find( &mut endpoint.sent_packets, sequence );
            if let Some( sent_packet_data ) = sent_packet_data
            {
                num_sent += 1;
                if sent_packet_data.acked == 0
                {
                    num_dropped += 1;
                }
            }
        }
        if num_sent > 0
        {
            let packet_loss: f32 = ( num_dropped as f32 ) / ( num_sent as f32 ) * 100.0;
            if ( ( endpoint.packet_loss - packet_loss ).abs() as f64 ) > 0.00001
            {
                endpoint.packet_loss += ( packet_loss - endpoint.packet_loss ) * endpoint.config.packet_loss_smoothing_factor;
            }
            else
            {
                endpoint.packet_loss = packet_loss;
            }
        }
        else
        {
            endpoint.packet_loss = 0.0;
        }
    }

    // calculate sent bandwidth
    {
        let base_sequence: u32 = ( ( endpoint.sent_packets.sequence as i32 - endpoint.config.sent_packets_buffer_size + 1 ) + 0xFFFF ) as u32;
        let mut bytes_sent: i64 = 0;
        let mut start_time: f64 = f32::MAX as f64;
        let mut finish_time: f64 = 0.0;
        let num_samples: i32 = endpoint.config.sent_packets_buffer_size / 2;
        for i in 0..num_samples
        {
            let sequence: u16 = base_sequence.wrapping_add( i as u32 ) as u16;
            let sent_packet_data = match reliable_sequence_buffer_find( &mut endpoint.sent_packets, sequence )
            {
                None => continue,
                Some( sent_packet_data ) => sent_packet_data,
            };
            bytes_sent += sent_packet_data.packet_bytes as i64;
            if sent_packet_data.time < start_time
            {
                start_time = sent_packet_data.time;
            }
            if sent_packet_data.time > finish_time
            {
                finish_time = sent_packet_data.time;
            }
        }
        if start_time != f32::MAX as f64 && finish_time > start_time
        {
            let sent_bandwidth_kbps: f32 = ( ( bytes_sent as f64 ) / ( finish_time - start_time ) * 8.0 / 1000.0 ) as f32;
            if ( ( endpoint.sent_bandwidth_kbps - sent_bandwidth_kbps ).abs() as f64 ) > 0.00001
            {
                endpoint.sent_bandwidth_kbps += ( sent_bandwidth_kbps - endpoint.sent_bandwidth_kbps ) * endpoint.config.bandwidth_smoothing_factor;
            }
            else
            {
                endpoint.sent_bandwidth_kbps = sent_bandwidth_kbps;
            }
        }
    }

    // calculate received bandwidth
    {
        let base_sequence: u32 = ( ( endpoint.received_packets.sequence as i32 - endpoint.config.received_packets_buffer_size + 1 ) + 0xFFFF ) as u32;
        let mut bytes_sent: i64 = 0;
        let mut start_time: f64 = f32::MAX as f64;
        let mut finish_time: f64 = 0.0;
        let num_samples: i32 = endpoint.config.received_packets_buffer_size / 2;
        for i in 0..num_samples
        {
            let sequence: u16 = base_sequence.wrapping_add( i as u32 ) as u16;
            let received_packet_data = match reliable_sequence_buffer_find( &mut endpoint.received_packets, sequence )
            {
                None => continue,
                Some( received_packet_data ) => received_packet_data,
            };
            bytes_sent += received_packet_data.packet_bytes as i64;
            if received_packet_data.time < start_time
            {
                start_time = received_packet_data.time;
            }
            if received_packet_data.time > finish_time
            {
                finish_time = received_packet_data.time;
            }
        }
        if start_time != f32::MAX as f64 && finish_time > start_time
        {
            let received_bandwidth_kbps: f32 = ( ( bytes_sent as f64 ) / ( finish_time - start_time ) * 8.0 / 1000.0 ) as f32;
            if ( ( endpoint.received_bandwidth_kbps - received_bandwidth_kbps ).abs() as f64 ) > 0.00001
            {
                endpoint.received_bandwidth_kbps += ( received_bandwidth_kbps - endpoint.received_bandwidth_kbps ) * endpoint.config.bandwidth_smoothing_factor;
            }
            else
            {
                endpoint.received_bandwidth_kbps = received_bandwidth_kbps;
            }
        }
    }

    // calculate acked bandwidth
    {
        let base_sequence: u32 = ( ( endpoint.sent_packets.sequence as i32 - endpoint.config.sent_packets_buffer_size + 1 ) + 0xFFFF ) as u32;
        let mut bytes_sent: i64 = 0;
        let mut start_time: f64 = f32::MAX as f64;
        let mut finish_time: f64 = 0.0;
        let num_samples: i32 = endpoint.config.sent_packets_buffer_size / 2;
        for i in 0..num_samples
        {
            let sequence: u16 = base_sequence.wrapping_add( i as u32 ) as u16;
            let sent_packet_data = match reliable_sequence_buffer_find( &mut endpoint.sent_packets, sequence )
            {
                None => continue,
                Some( sent_packet_data ) => sent_packet_data,
            };
            if sent_packet_data.acked == 0
            {
                continue;
            }
            bytes_sent += sent_packet_data.packet_bytes as i64;
            if sent_packet_data.time < start_time
            {
                start_time = sent_packet_data.time;
            }
            if sent_packet_data.time > finish_time
            {
                finish_time = sent_packet_data.time;
            }
        }
        if start_time != f32::MAX as f64 && finish_time > start_time
        {
            let acked_bandwidth_kbps: f32 = ( ( bytes_sent as f64 ) / ( finish_time - start_time ) * 8.0 / 1000.0 ) as f32;
            if ( ( endpoint.acked_bandwidth_kbps - acked_bandwidth_kbps ).abs() as f64 ) > 0.00001
            {
                endpoint.acked_bandwidth_kbps += ( acked_bandwidth_kbps - endpoint.acked_bandwidth_kbps ) * endpoint.config.bandwidth_smoothing_factor;
            }
            else
            {
                endpoint.acked_bandwidth_kbps = acked_bandwidth_kbps;
            }
        }
    }
}

pub fn reliable_endpoint_rtt( endpoint: &reliable_endpoint_t ) -> f32
{
    return endpoint.rtt;
}

pub fn reliable_endpoint_rtt_min( endpoint: &reliable_endpoint_t ) -> f32
{
    return endpoint.rtt_min;
}

pub fn reliable_endpoint_rtt_max( endpoint: &reliable_endpoint_t ) -> f32
{
    return endpoint.rtt_max;
}

pub fn reliable_endpoint_rtt_avg( endpoint: &reliable_endpoint_t ) -> f32
{
    return endpoint.rtt_avg;
}

pub fn reliable_endpoint_jitter_avg_vs_min_rtt( endpoint: &reliable_endpoint_t ) -> f32
{
    return endpoint.jitter_avg_vs_min_rtt;
}

pub fn reliable_endpoint_jitter_max_vs_min_rtt( endpoint: &reliable_endpoint_t ) -> f32
{
    return endpoint.jitter_max_vs_min_rtt;
}


pub fn reliable_endpoint_jitter_stddev_vs_avg_rtt( endpoint: &reliable_endpoint_t ) -> f32
{
    return endpoint.jitter_stddev_vs_avg_rtt;
}

pub fn reliable_endpoint_packet_loss( endpoint: &reliable_endpoint_t ) -> f32
{
    return endpoint.packet_loss;
}

pub fn reliable_endpoint_bandwidth( endpoint: &reliable_endpoint_t, sent_bandwidth_kbps: &mut f32, received_bandwidth_kbps: &mut f32, acked_bandwidth_kbps: &mut f32 )
{
    *sent_bandwidth_kbps = endpoint.sent_bandwidth_kbps;
    *received_bandwidth_kbps = endpoint.received_bandwidth_kbps;
    *acked_bandwidth_kbps = endpoint.acked_bandwidth_kbps;
}

pub fn reliable_endpoint_counters( endpoint: &reliable_endpoint_t ) -> &[u64]
{
    return &endpoint.counters[..];
}

// port: source is &str, so the copy also stops at its end; dest is the caller's char array
pub fn reliable_copy_string( dest: &mut [u8], source: &str, dest_size: usize )
{
    reliable_assert!( dest_size >= 1 );
    let source = source.as_bytes();
    for byte in dest[..dest_size].iter_mut()
    {
        *byte = 0;
    }
    for i in 0..dest_size - 1
    {
        if i >= source.len() || source[i] == b'\0'
        {
            break;
        }
        dest[i] = source[i];
    }
}

// ---------------------------------------------------------------

// ---- tests (RELIABLE_ENABLE_TESTS) ----

// port: the tests keep upstream's shapes with these Rust deviations, which apply to the whole section
//   - a test context is passed to the callbacks as void * context, and both the test and the callbacks reach it, so its
//     mutable fields are Cell / RefCell and both sides only ever take shared references to it (no aliasing &mut).
//   - the endpoints in a test context are raw pointers, as upstream, so a transmit callback running inside a call on one
//     endpoint can reach the other one. test_context_t::sender() / receiver() turn them into the &mut the library takes,
//     set_sender() / set_receiver() store what reliable_endpoint_create returns, and take_sender() / take_receiver() hand
//     the Box back for reliable_endpoint_destroy.
//   - upstream's file statics are atomics or a Mutex.
//   - the custom allocate/free functions are kept and installed, but the Rust endpoint does not call them (see the top of
//     the file): checks that only hold because the allocator was called are skipped where they are, with a port note.

use std::cell::{Cell, RefCell};

// port: prints, then exits. upstream also traps first in debug builds (__builtin_trap / __debugbreak), which has no Rust
// equivalent worth having in a test: the exit code already fails the run
fn check_handler( condition: &str,
                  function: &str,
                  file: &str,
                  line: i32 )
{
    print!( "check failed: ( {} ), function {}, file {}, line {}\n", condition, function, file, line );
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit( 1 );
}

// port: __FUNCTION__ is the name of the enclosing fn, recovered from the type name of a fn item declared inside it
macro_rules! check
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
            check_handler( stringify!( $condition ), function, file!(), line!() as i32 );
        }
    };
}

fn test_endian()
{
    let value: u32 = 0x11223344;

    // port: the bytes of the value in memory order
    let bytes: [u8; 4] = value.to_ne_bytes();

    if RELIABLE_LITTLE_ENDIAN != 0
    {
        check!( bytes[0] == 0x44 );
        check!( bytes[1] == 0x33 );
        check!( bytes[2] == 0x22 );
        check!( bytes[3] == 0x11 );
    }
    else // #if RELIABLE_LITTLE_ENDIAN
    {
        check!( bytes[3] == 0x44 );
        check!( bytes[2] == 0x33 );
        check!( bytes[1] == 0x22 );
        check!( bytes[0] == 0x11 );
    } // #if RELIABLE_LITTLE_ENDIAN
}

#[derive(Clone, Copy, Default)]
struct test_sequence_data_t
{
    sequence: u16,
}

const TEST_SEQUENCE_BUFFER_SIZE: i32 = 256;

fn test_sequence_buffer()
{
    let sequence_buffer = reliable_sequence_buffer_create::<test_sequence_data_t>( TEST_SEQUENCE_BUFFER_SIZE,
                                                                                   std::mem::size_of::<test_sequence_data_t>() as i32,
                                                                                   std::ptr::null_mut(),
                                                                                   None,
                                                                                   None );

    check!( sequence_buffer.is_some() );
    let mut sequence_buffer = sequence_buffer.unwrap();
    check!( sequence_buffer.sequence == 0 );
    check!( sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE );
    check!( sequence_buffer.entry_stride == std::mem::size_of::<test_sequence_data_t>() as i32 );

    for i in 0..TEST_SEQUENCE_BUFFER_SIZE
    {
        check!( reliable_sequence_buffer_find( &mut sequence_buffer, i as u16 ).is_none() );
    }

    for i in 0..=TEST_SEQUENCE_BUFFER_SIZE*4
    {
        let entry = reliable_sequence_buffer_insert( &mut sequence_buffer, i as u16 );
        check!( entry.is_some() );
        entry.unwrap().sequence = i as u16;
        check!( sequence_buffer.sequence as i32 == i + 1 );
    }

    for i in 0..=TEST_SEQUENCE_BUFFER_SIZE
    {
        let entry = reliable_sequence_buffer_insert( &mut sequence_buffer, i as u16 );
        check!( entry.is_none() );
    }

    let mut index: i32 = TEST_SEQUENCE_BUFFER_SIZE * 4;
    for _i in 0..TEST_SEQUENCE_BUFFER_SIZE
    {
        let entry = reliable_sequence_buffer_find( &mut sequence_buffer, index as u16 );
        check!( entry.is_some() );
        check!( entry.unwrap().sequence as u32 == index as u32 );
        index -= 1;
    }

    reliable_sequence_buffer_reset( &mut sequence_buffer );

    // port: check( sequence_buffer ) is the Box, which can't be NULL
    check!( sequence_buffer.sequence == 0 );
    check!( sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE );
    check!( sequence_buffer.entry_stride == std::mem::size_of::<test_sequence_data_t>() as i32 );

    for i in 0..TEST_SEQUENCE_BUFFER_SIZE
    {
        check!( reliable_sequence_buffer_find( &mut sequence_buffer, i as u16 ).is_none() );
    }

    reliable_sequence_buffer_destroy( sequence_buffer );
}

fn test_generate_ack_bits()
{
    let mut sequence_buffer = reliable_sequence_buffer_create::<test_sequence_data_t>( TEST_SEQUENCE_BUFFER_SIZE,
                                                                                       std::mem::size_of::<test_sequence_data_t>() as i32,
                                                                                       std::ptr::null_mut(),
                                                                                       None,
                                                                                       None ).unwrap();

    let mut ack: u16 = 0;
    let mut ack_bits: u32 = 0xFFFFFFFF;

    reliable_sequence_buffer_generate_ack_bits( &sequence_buffer, &mut ack, &mut ack_bits );
    check!( ack == 0xFFFF );
    check!( ack_bits == 0 );

    for i in 0..=TEST_SEQUENCE_BUFFER_SIZE
    {
        let _ = reliable_sequence_buffer_insert( &mut sequence_buffer, i as u16 );
    }

    reliable_sequence_buffer_generate_ack_bits( &sequence_buffer, &mut ack, &mut ack_bits );
    check!( ack as i32 == TEST_SEQUENCE_BUFFER_SIZE );
    check!( ack_bits == 0xFFFFFFFF );

    reliable_sequence_buffer_reset( &mut sequence_buffer );

    let input_acks: [u16; 4] = [ 1, 5, 9, 11 ];
    let input_num_acks = input_acks.len();
    for i in 0..input_num_acks
    {
        let _ = reliable_sequence_buffer_insert( &mut sequence_buffer, input_acks[i] );
    }

    reliable_sequence_buffer_generate_ack_bits( &sequence_buffer, &mut ack, &mut ack_bits );

    check!( ack == 11 );
    check!( ack_bits == ( 1 | (1<<(11-9)) | (1<<(11-5)) | (1<<(11-1)) ) );

    reliable_sequence_buffer_destroy( sequence_buffer );
}

fn test_packet_header()
{
    let mut write_sequence: u16;
    let mut write_ack: u16;
    let mut write_ack_bits: u32;

    let mut read_sequence: u16 = 0;
    let mut read_ack: u16 = 0;
    let mut read_ack_bits: u32 = 0;

    let mut packet_data = [0u8; RELIABLE_MAX_PACKET_HEADER_BYTES as usize];

    // worst case, sequence and ack are far apart, no packets acked.

    write_sequence = 10000;
    write_ack = 100;
    write_ack_bits = 0;

    let mut bytes_written = reliable_write_packet_header( &mut packet_data, write_sequence, write_ack, write_ack_bits );

    check!( bytes_written == RELIABLE_MAX_PACKET_HEADER_BYTES );

    let mut bytes_read = reliable_read_packet_header( "test_packet_header", &packet_data[..bytes_written as usize], bytes_written, &mut read_sequence, &mut read_ack, &mut read_ack_bits );

    check!( bytes_read == bytes_written );

    check!( read_sequence == write_sequence );
    check!( read_ack == write_ack );
    check!( read_ack_bits == write_ack_bits );

    // rare case. sequence and ack are far apart, significant # of acks are missing

    write_sequence = 10000;
    write_ack = 100;
    write_ack_bits = 0xFEFEFFFE;

    bytes_written = reliable_write_packet_header( &mut packet_data, write_sequence, write_ack, write_ack_bits );

    check!( bytes_written == 1 + 2 + 2 + 3 );

    bytes_read = reliable_read_packet_header( "test_packet_header", &packet_data[..bytes_written as usize], bytes_written, &mut read_sequence, &mut read_ack, &mut read_ack_bits );

    check!( bytes_read == bytes_written );

    check!( read_sequence == write_sequence );
    check!( read_ack == write_ack );
    check!( read_ack_bits == write_ack_bits );

    // common case under packet loss. sequence and ack are close together, some acks are missing

    write_sequence = 200;
    write_ack = 100;
    write_ack_bits = 0xFFFEFFFF;

    bytes_written = reliable_write_packet_header( &mut packet_data, write_sequence, write_ack, write_ack_bits );

    check!( bytes_written == 1 + 2 + 1 + 1 );

    bytes_read = reliable_read_packet_header( "test_packet_header", &packet_data[..bytes_written as usize], bytes_written, &mut read_sequence, &mut read_ack, &mut read_ack_bits );

    check!( bytes_read == bytes_written );

    check!( read_sequence == write_sequence );
    check!( read_ack == write_ack );
    check!( read_ack_bits == write_ack_bits );

    // ideal case. no packet loss.

    write_sequence = 200;
    write_ack = 100;
    write_ack_bits = 0xFFFFFFFF;

    bytes_written = reliable_write_packet_header( &mut packet_data, write_sequence, write_ack, write_ack_bits );

    check!( bytes_written == 1 + 2 + 1 );

    bytes_read = reliable_read_packet_header( "test_packet_header", &packet_data[..bytes_written as usize], bytes_written, &mut read_sequence, &mut read_ack, &mut read_ack_bits );

    check!( bytes_read == bytes_written );

    check!( read_sequence == write_sequence );
    check!( read_ack == write_ack );
    check!( read_ack_bits == write_ack_bits );
}

// port: repr(C) so the contexts that embed it as their first field (base) can be read through a pointer to it, as upstream
#[repr(C)]
struct test_context_t
{
    drop: Cell<i32>,
    allow_packets: Cell<i32>,
    sender: Cell<*mut reliable_endpoint_t>,
    receiver: Cell<*mut reliable_endpoint_t>,
}

// port: the zeroed context upstream declares on the stack and memsets
impl test_context_t
{
    fn new() -> Self
    {
        test_context_t
        {
            drop: Cell::new( 0 ),
            allow_packets: Cell::new( 0 ),
            sender: Cell::new( std::ptr::null_mut() ),
            receiver: Cell::new( std::ptr::null_mut() ),
        }
    }

    // port: the endpoint pointers as the references the library takes (see the top of the section)

    fn sender( &self ) -> &mut reliable_endpoint_t
    {
        reliable_assert!( !self.sender.get().is_null() );
        unsafe { &mut *self.sender.get() }
    }

    fn receiver( &self ) -> &mut reliable_endpoint_t
    {
        reliable_assert!( !self.receiver.get().is_null() );
        unsafe { &mut *self.receiver.get() }
    }

    fn set_sender( &self, endpoint: Option<Box<reliable_endpoint_t>> )
    {
        self.sender.set( match endpoint { Some( endpoint ) => Box::into_raw( endpoint ), None => std::ptr::null_mut() } );
    }

    fn set_receiver( &self, endpoint: Option<Box<reliable_endpoint_t>> )
    {
        self.receiver.set( match endpoint { Some( endpoint ) => Box::into_raw( endpoint ), None => std::ptr::null_mut() } );
    }

    fn take_sender( &self ) -> Box<reliable_endpoint_t>
    {
        reliable_assert!( !self.sender.get().is_null() );
        let endpoint = unsafe { Box::from_raw( self.sender.get() ) };
        self.sender.set( std::ptr::null_mut() );
        endpoint
    }

    fn take_receiver( &self ) -> Box<reliable_endpoint_t>
    {
        reliable_assert!( !self.receiver.get().is_null() );
        let endpoint = unsafe { Box::from_raw( self.receiver.get() ) };
        self.receiver.set( std::ptr::null_mut() );
        endpoint
    }
}

// port: the context as the void * the config carries
fn test_context_pointer<T>( context: &T ) -> *mut c_void
{
    context as *const T as *mut c_void
}

fn test_default_context( context: &test_context_t )
{
    // port: memset( context, 0, sizeof( *context ) )
    context.drop.set( 0 );
    context.allow_packets.set( 0 );
    context.sender.set( std::ptr::null_mut() );
    context.receiver.set( std::ptr::null_mut() );
    context.allow_packets.set( -1 );
}

fn test_transmit_packet_function( _context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 )
{
    let _ = sequence;

    let context = unsafe { &*( _context as *const test_context_t ) };

    if context.drop.get() != 0
    {
        return;
    }

    if context.allow_packets.get() >= 0
    {
        if context.allow_packets.get() == 0
        {
            return;
        }

        context.allow_packets.set( context.allow_packets.get() - 1 );
    }

    if id == 0
    {
        reliable_endpoint_receive_packet( context.receiver(), packet_data, packet_bytes );
    }
    else if id == 1
    {
        reliable_endpoint_receive_packet( context.sender(), packet_data, packet_bytes );
    }
}

fn test_process_packet_function( _context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 ) -> i32
{
    let context = _context;

    let _ = context;
    let _ = id;
    let _ = sequence;
    let _ = packet_data;
    let _ = packet_bytes;

    return 1;
}

const TEST_ACKS_NUM_ITERATIONS: usize = 256;

fn test_acks()
{
    let mut time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    let delta_time: f64 = 0.01;

    for _i in 0..TEST_ACKS_NUM_ITERATIONS
    {
        let dummy_packet = [0u8; 8];

        reliable_endpoint_send_packet( context.sender(), &dummy_packet, dummy_packet.len() as i32 );
        reliable_endpoint_send_packet( context.receiver(), &dummy_packet, dummy_packet.len() as i32 );

        reliable_endpoint_update( context.sender(), time );
        reliable_endpoint_update( context.receiver(), time );

        time += delta_time;
    }

    let mut sender_acked_packet = [0u8; TEST_ACKS_NUM_ITERATIONS];
    let mut sender_num_acks: i32 = 0;
    let sender_acks = reliable_endpoint_get_acks( context.sender(), &mut sender_num_acks );
    for i in 0..sender_num_acks as usize
    {
        if ( sender_acks[i] as usize ) < TEST_ACKS_NUM_ITERATIONS
        {
            sender_acked_packet[sender_acks[i] as usize] = 1;
        }
    }
    for i in 0..TEST_ACKS_NUM_ITERATIONS / 2
    {
        check!( sender_acked_packet[i] == 1 );
    }

    let mut receiver_acked_packet = [0u8; TEST_ACKS_NUM_ITERATIONS];
    let mut receiver_num_acks: i32 = 0;
    let receiver_acks = reliable_endpoint_get_acks( context.receiver(), &mut receiver_num_acks );
    for i in 0..receiver_num_acks as usize
    {
        if ( receiver_acks[i] as usize ) < TEST_ACKS_NUM_ITERATIONS
        {
            receiver_acked_packet[receiver_acks[i] as usize] = 1;
        }
    }
    for i in 0..TEST_ACKS_NUM_ITERATIONS / 2
    {
        check!( receiver_acked_packet[i] == 1 );
    }

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

fn test_acks_packet_loss()
{
    let mut time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    // port: 0.1f is a float widened to double, as upstream
    let delta_time: f64 = 0.1f32 as f64;

    for i in 0..TEST_ACKS_NUM_ITERATIONS
    {
        let dummy_packet = [0u8; 8];

        context.drop.set( ( i % 2 ) as i32 );

        reliable_endpoint_send_packet( context.sender(), &dummy_packet, dummy_packet.len() as i32 );
        reliable_endpoint_send_packet( context.receiver(), &dummy_packet, dummy_packet.len() as i32 );

        reliable_endpoint_update( context.sender(), time );
        reliable_endpoint_update( context.receiver(), time );

        time += delta_time;
    }

    let mut sender_acked_packet = [0u8; TEST_ACKS_NUM_ITERATIONS];
    let mut sender_num_acks: i32 = 0;
    let sender_acks = reliable_endpoint_get_acks( context.sender(), &mut sender_num_acks );
    for i in 0..sender_num_acks as usize
    {
        if ( sender_acks[i] as usize ) < TEST_ACKS_NUM_ITERATIONS
        {
            sender_acked_packet[sender_acks[i] as usize] = 1;
        }
    }
    for i in 0..TEST_ACKS_NUM_ITERATIONS / 2
    {
        check!( sender_acked_packet[i] as usize == (i+1) % 2 );
    }

    let mut receiver_acked_packet = [0u8; TEST_ACKS_NUM_ITERATIONS];
    let mut receiver_num_acks: i32 = 0;
    let receiver_acks = reliable_endpoint_get_acks( context.receiver(), &mut receiver_num_acks );
    for i in 0..receiver_num_acks as usize
    {
        if ( receiver_acks[i] as usize ) < TEST_ACKS_NUM_ITERATIONS
        {
            receiver_acked_packet[receiver_acks[i] as usize] = 1;
        }
    }
    for i in 0..TEST_ACKS_NUM_ITERATIONS / 2
    {
        check!( receiver_acked_packet[i] as usize == (i+1) % 2 );
    }

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

static test_duplicate_packets_num_processed: AtomicI32 = AtomicI32::new( 0 );

fn test_duplicate_packets_transmit_packet_function( _context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 )
{
    let _ = sequence;

    let context = unsafe { &*( _context as *const test_context_t ) };

    if id == 0
    {
        // deliver each packet to the receiver twice, simulating duplication on the network
        reliable_endpoint_receive_packet( context.receiver(), packet_data, packet_bytes );
        reliable_endpoint_receive_packet( context.receiver(), packet_data, packet_bytes );
    }
}

fn test_duplicate_packets_process_packet_function( context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 ) -> i32
{
    let _ = context;
    let _ = id;
    let _ = sequence;
    let _ = packet_data;
    let _ = packet_bytes;

    test_duplicate_packets_num_processed.fetch_add( 1, Ordering::Relaxed );

    return 1;
}

const TEST_DUPLICATE_PACKETS_NUM_ITERATIONS: i32 = 16;

fn test_duplicate_packets()
{
    let time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_duplicate_packets_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_duplicate_packets_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_duplicate_packets_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    test_duplicate_packets_num_processed.store( 0, Ordering::Relaxed );

    for _i in 0..TEST_DUPLICATE_PACKETS_NUM_ITERATIONS
    {
        let dummy_packet = [0u8; 8];
        reliable_endpoint_send_packet( context.sender(), &dummy_packet, dummy_packet.len() as i32 );
    }

    check!( test_duplicate_packets_num_processed.load( Ordering::Relaxed ) == TEST_DUPLICATE_PACKETS_NUM_ITERATIONS );

    let receiver_counters = reliable_endpoint_counters( context.receiver() );

    check!( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == 2 * TEST_DUPLICATE_PACKETS_NUM_ITERATIONS as u64 );
    check!( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE] == TEST_DUPLICATE_PACKETS_NUM_ITERATIONS as u64 );

    // duplicate fragments arriving after their packet was delivered must not restart reassembly

    let fragmented_sequence: u16 = reliable_endpoint_next_packet_sequence( context.sender() );

    let large_packet = [0u8; 2048];
    reliable_endpoint_send_packet( context.sender(), &large_packet, large_packet.len() as i32 );

    check!( test_duplicate_packets_num_processed.load( Ordering::Relaxed ) == TEST_DUPLICATE_PACKETS_NUM_ITERATIONS + 1 );
    check!( reliable_sequence_buffer_exists( &context.receiver().fragment_reassembly, fragmented_sequence ) == 0 );

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

static test_stale_packets_first_packet: Mutex<[u8; 64]> = Mutex::new( [0; 64] );
static test_stale_packets_first_packet_bytes: AtomicI32 = AtomicI32::new( 0 );
static test_stale_packets_num_processed: AtomicI32 = AtomicI32::new( 0 );

fn test_stale_packets_transmit_packet_function( _context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 )
{
    let context = unsafe { &*( _context as *const test_context_t ) };

    if id == 0
    {
        if sequence == 0 && test_stale_packets_first_packet_bytes.load( Ordering::Relaxed ) == 0
        {
            reliable_assert!( packet_bytes <= 64 );
            test_stale_packets_first_packet.lock().unwrap()[..packet_bytes as usize].copy_from_slice( &packet_data[..packet_bytes as usize] );
            test_stale_packets_first_packet_bytes.store( packet_bytes, Ordering::Relaxed );
        }

        reliable_endpoint_receive_packet( context.receiver(), packet_data, packet_bytes );
    }
}

fn test_stale_packets_process_packet_function( context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 ) -> i32
{
    let _ = context;
    let _ = id;
    let _ = sequence;
    let _ = packet_data;
    let _ = packet_bytes;

    test_stale_packets_num_processed.fetch_add( 1, Ordering::Relaxed );

    return 1;
}

const TEST_STALE_PACKETS_NUM_ITERATIONS: i32 = 300;

fn test_stale_packets()
{
    let time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_stale_packets_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_stale_packets_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_stale_packets_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    test_stale_packets_first_packet_bytes.store( 0, Ordering::Relaxed );
    test_stale_packets_num_processed.store( 0, Ordering::Relaxed );

    // send enough packets that sequence 0 falls out of the receive window (256 entries)

    for _i in 0..TEST_STALE_PACKETS_NUM_ITERATIONS
    {
        let dummy_packet = [0u8; 8];
        reliable_endpoint_send_packet( context.sender(), &dummy_packet, dummy_packet.len() as i32 );
    }

    check!( test_stale_packets_num_processed.load( Ordering::Relaxed ) == TEST_STALE_PACKETS_NUM_ITERATIONS );
    check!( test_stale_packets_first_packet_bytes.load( Ordering::Relaxed ) > 0 );

    // replaying the first packet must be rejected as stale, not processed

    {
        let first_packet_bytes = test_stale_packets_first_packet_bytes.load( Ordering::Relaxed );
        let first_packet = *test_stale_packets_first_packet.lock().unwrap();
        reliable_endpoint_receive_packet( context.receiver(), &first_packet[..first_packet_bytes as usize], first_packet_bytes );
    }

    check!( test_stale_packets_num_processed.load( Ordering::Relaxed ) == TEST_STALE_PACKETS_NUM_ITERATIONS );

    let receiver_counters = reliable_endpoint_counters( context.receiver() );

    check!( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_STALE] == 1 );

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

const TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS: i32 = 32;
const TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE: i32 = 16;

fn test_ack_buffer_overflow()
{
    let time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    // undersized ack buffer on the sender, so a single received packet acking 32 sent packets overflows it

    sender_config.ack_buffer_size = TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE;

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    for _i in 0..TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS
    {
        let dummy_packet = [0u8; 8];
        reliable_endpoint_send_packet( context.sender(), &dummy_packet, dummy_packet.len() as i32 );
    }

    // one packet back from the receiver acks all 32, but only 16 fit in the ack buffer. the rest are dropped

    {
        let dummy_packet = [0u8; 8];
        reliable_endpoint_send_packet( context.receiver(), &dummy_packet, dummy_packet.len() as i32 );
    }

    let mut num_acks: i32 = 0;
    reliable_endpoint_get_acks( context.sender(), &mut num_acks );
    check!( num_acks == TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE );

    let sender_counters = reliable_endpoint_counters( context.sender() );
    check!( sender_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED] == TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE as u64 );

    // once the caller clears acks, the dropped acks are reported on the next packet that covers them

    reliable_endpoint_clear_acks( context.sender() );

    {
        let dummy_packet = [0u8; 8];
        reliable_endpoint_send_packet( context.receiver(), &dummy_packet, dummy_packet.len() as i32 );
    }

    reliable_endpoint_get_acks( context.sender(), &mut num_acks );
    check!( num_acks == TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS - TEST_ACK_BUFFER_OVERFLOW_BUFFER_SIZE );
    // port: the counters are read again: upstream keeps the pointer from above, a borrow that can't live across the sends
    let sender_counters = reliable_endpoint_counters( context.sender() );
    check!( sender_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED] == TEST_ACK_BUFFER_OVERFLOW_NUM_PACKETS as u64 );

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

const TEST_MAX_PACKET_BYTES: i32 = 4*1024;

fn generate_packet_data_with_size( sequence: u16, packet_data: &mut [u8], packet_bytes: i32 )
{
    reliable_assert!( packet_bytes >= 2 );
    reliable_assert!( packet_bytes <= TEST_MAX_PACKET_BYTES );

    packet_data[0] = ( sequence & 0xFF ) as u8;
    packet_data[1] = ( (sequence>>8) & 0xFF ) as u8;
    for i in 2..packet_bytes
    {
        packet_data[i as usize] = ( ( i + sequence as i32 ) % 256 ) as u8;
    }
}

fn generate_packet_data( sequence: u16, packet_data: &mut [u8] ) -> i32
{
    let packet_bytes: i32 = ( ( sequence as i32 * 1023 ) % ( TEST_MAX_PACKET_BYTES - 2 ) ) + 2;
    generate_packet_data_with_size( sequence, packet_data, packet_bytes );
    return packet_bytes;
}

fn validate_packet_data( packet_data: &[u8], packet_bytes: i32 )
{
    reliable_assert!( packet_bytes >= 2 );
    reliable_assert!( packet_bytes <= TEST_MAX_PACKET_BYTES );
    let mut sequence: u16 = 0;
    sequence |= packet_data[0] as u16;
    sequence |= ( packet_data[1] as u16 ) << 8;
    check!( packet_bytes == ( ( sequence as i32 * 1023 ) % ( TEST_MAX_PACKET_BYTES - 2 ) ) + 2 );
    for i in 2..packet_bytes
    {
        check!( packet_data[i as usize] == ( ( i + sequence as i32 ) % 256 ) as u8 );
    }
}

fn test_process_packet_function_validate( context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 ) -> i32
{
    // port: reliable_assert( packet_data ) is dropped: a slice can't be NULL
    reliable_assert!( packet_bytes > 0 );
    reliable_assert!( packet_bytes <= TEST_MAX_PACKET_BYTES );

    let _ = context;
    let _ = id;
    let _ = sequence;

    validate_packet_data( packet_data, packet_bytes );

    return 1;
}

fn generate_packet_data_large( packet_data: &mut [u8] ) -> i32
{
    let data_bytes: i32 = TEST_MAX_PACKET_BYTES - 2;
    reliable_assert!( data_bytes >= 2 );
    reliable_assert!( data_bytes <= (1 << 16) );

    packet_data[0] = ( data_bytes & 0xFF ) as u8;
    packet_data[1] = ( (data_bytes >> 8) & 0xFF ) as u8;
    for i in 2..data_bytes
    {
        packet_data[i as usize] = ( i % 256 ) as u8;
    }
    return data_bytes + 2;
}

fn test_process_packet_function_validate_large( context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 ) -> i32
{
    // port: reliable_assert( packet_data ) is dropped: a slice can't be NULL
    reliable_assert!( packet_bytes >= 2 );
    reliable_assert!( packet_bytes <= TEST_MAX_PACKET_BYTES );

    let _ = context;
    let _ = id;
    let _ = sequence;

    let mut data_bytes: u16 = 0;
    data_bytes |= packet_data[0] as u16;
    data_bytes |= ( packet_data[1] as u16 ) << 8;
    check!( packet_bytes == data_bytes as i32 + 2 );
    for i in 2..data_bytes as i32
    {
        check!( packet_data[i as usize] == ( i % 256 ) as u8 );
    }

    return 1;
}

fn test_packets()
{
    let mut time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    sender_config.fragment_above = 500;
    receiver_config.fragment_above = 500;

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function_validate );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function_validate );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    let delta_time: f64 = 0.1;

    for _i in 0..16
    {
        {
            let mut packet_data = [0u8; TEST_MAX_PACKET_BYTES as usize];
            let sequence: u16 = reliable_endpoint_next_packet_sequence( context.sender() );
            let packet_bytes = generate_packet_data( sequence, &mut packet_data );
            reliable_endpoint_send_packet( context.sender(), &packet_data, packet_bytes );
        }

        {
            let mut packet_data = [0u8; TEST_MAX_PACKET_BYTES as usize];
            let sequence: u16 = reliable_endpoint_next_packet_sequence( context.sender() );
            let packet_bytes = generate_packet_data( sequence, &mut packet_data );
            reliable_endpoint_send_packet( context.sender(), &packet_data, packet_bytes );
        }

        reliable_endpoint_update( context.sender(), time );
        reliable_endpoint_update( context.receiver(), time );

        reliable_endpoint_clear_acks( context.sender() );
        reliable_endpoint_clear_acks( context.receiver() );

        time += delta_time;
    }

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

fn test_large_packets()
{
    let time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    sender_config.max_packet_size = TEST_MAX_PACKET_BYTES;
    receiver_config.max_packet_size = TEST_MAX_PACKET_BYTES;

    sender_config.fragment_above = TEST_MAX_PACKET_BYTES;
    receiver_config.fragment_above = TEST_MAX_PACKET_BYTES;

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function_validate_large );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function_validate_large );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    {
        let mut packet_data = [0u8; TEST_MAX_PACKET_BYTES as usize];
        let packet_bytes = generate_packet_data_large( &mut packet_data );
        check!( packet_bytes == TEST_MAX_PACKET_BYTES );
        reliable_endpoint_send_packet( context.sender(), &packet_data, packet_bytes );
    }

    reliable_endpoint_update( context.sender(), time );
    reliable_endpoint_update( context.receiver(), time );

    reliable_endpoint_clear_acks( context.sender() );
    reliable_endpoint_clear_acks( context.receiver() );

    let receiver_counters = reliable_endpoint_counters( context.receiver() );
    check!( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE] == 0 );
    check!( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == 1 );

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

fn test_sequence_buffer_rollover()
{
    let time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    sender_config.fragment_above = 500;
    receiver_config.fragment_above = 500;

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    let packet_data = [0u8; TEST_MAX_PACKET_BYTES as usize];

    let mut num_packets_sent: i32 = 0;
    for _i in 0..=32767
    {
        let packet_data = [0u8; 16];
        let packet_bytes = packet_data.len() as i32;
        reliable_endpoint_next_packet_sequence( context.sender() );
        reliable_endpoint_send_packet( context.sender(), &packet_data, packet_bytes );

        num_packets_sent += 1;
    }

    let packet_bytes = packet_data.len() as i32;
    reliable_endpoint_next_packet_sequence( context.sender() );
    reliable_endpoint_send_packet( context.sender(), &packet_data, packet_bytes );
    num_packets_sent += 1;

    let receiver_counters = reliable_endpoint_counters( context.receiver() );

    check!( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == ( num_packets_sent as u16 ) as u64 );
    check!( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == 0 );

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

// port: ARRAY_LENGTH( x ) is .len()

const TEST_TRACKING_ALLOCATIONS: usize = 1024;

struct test_tracking_allocate_context_t
{
    active_allocations: [Cell<*mut c_void>; TEST_TRACKING_ALLOCATIONS],
    fail_allocations: Cell<i32>,       // when set, the allocator returns NULL (simulates memory pressure)
}

// port: the zeroed context upstream memsets
impl test_tracking_allocate_context_t
{
    fn new() -> Self
    {
        test_tracking_allocate_context_t
        {
            active_allocations: std::array::from_fn( |_| Cell::new( std::ptr::null_mut() ) ),
            fail_allocations: Cell::new( 0 ),
        }
    }
}

fn test_tracking_allocate_function( context: *mut c_void, bytes: usize ) -> *mut c_void
{
    let tracking_context = unsafe { &*( context as *const test_tracking_allocate_context_t ) };
    if tracking_context.fail_allocations.get() != 0
    {
        return std::ptr::null_mut();
    }
    let allocation = unsafe { malloc( bytes ) };
    let mut tracking_index: usize = 0;
    while tracking_index < tracking_context.active_allocations.len()
    {
        if tracking_context.active_allocations[tracking_index].get().is_null()
        {
            break;
        }
        tracking_index += 1;
    }

    reliable_assert!( tracking_index < tracking_context.active_allocations.len() );
    tracking_context.active_allocations[tracking_index].set( allocation );
    return allocation;
}

fn test_tracking_free_function( context: *mut c_void, pointer: *mut c_void )
{
    let tracking_context = unsafe { &*( context as *const test_tracking_allocate_context_t ) };
    let mut tracking_index: usize = 0;
    while tracking_index < tracking_context.active_allocations.len()
    {
        if tracking_context.active_allocations[tracking_index].get() == pointer
        {
            break;
        }
        tracking_index += 1;
    }

    reliable_assert!( tracking_index < tracking_context.active_allocations.len() );
    tracking_context.active_allocations[tracking_index].set( std::ptr::null_mut() );
    unsafe { free( pointer ) };
}

// port: reliable.c checks for leaks with the tracking allocator, which the Rust endpoint doesn't call, so that check holds
// trivially. this is the equivalent check the C# port makes: no reassembly slot that is not in use still holds a buffer
// (which is what the leak was: an evicted entry kept its packet_data)
fn check_no_stale_reassembly_buffers( endpoint: &reliable_endpoint_t )
{
    let fragment_reassembly = &endpoint.fragment_reassembly;
    for i in 0..fragment_reassembly.num_entries as usize
    {
        if fragment_reassembly.entry_sequence[i] == 0xFFFFFFFF
        {
            check!( fragment_reassembly.entry_data[i].packet_data.is_none() );
        }
    }
}

fn test_fragment_cleanup()
{
    let mut time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let tracking_alloc_context = test_tracking_allocate_context_t::new();

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    receiver_config.allocator_context = test_context_pointer( &tracking_alloc_context );
    receiver_config.allocate_function = Some( test_tracking_allocate_function );
    receiver_config.free_function = Some( test_tracking_free_function );
    receiver_config.fragment_reassembly_buffer_size = 4;

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    let delta_time: f64 = 0.1;

    let packet_sizes: [i32; 5] = [
        sender_config.fragment_size + sender_config.fragment_size/2,
        10,
        10,
        10,
        10,
    ];

    // Make sure we're sending more than receiver_config.fragment_reassembly_buffer_size packets, so the buffer wraps around.
    reliable_assert!( packet_sizes.len() as i32 > receiver_config.fragment_reassembly_buffer_size );

    for i in 0..packet_sizes.len()
    {
        // Only allow one packet per transmit, so that our fragmented packets are only partially
        // delivered.
        context.allow_packets.set( 1 );
        {
            let mut packet_data = [0u8; TEST_MAX_PACKET_BYTES as usize];
            let sequence: u16 = reliable_endpoint_next_packet_sequence( context.sender() );
            generate_packet_data_with_size( sequence, &mut packet_data, packet_sizes[i] );
            reliable_endpoint_send_packet( context.sender(), &packet_data, packet_sizes[i] );
        }

        reliable_endpoint_update( context.sender(), time );
        reliable_endpoint_update( context.receiver(), time );

        reliable_endpoint_clear_acks( context.sender() );
        reliable_endpoint_clear_acks( context.receiver() );

        time += delta_time;
    }

    // port: see check_no_stale_reassembly_buffers
    check_no_stale_reassembly_buffers( context.receiver() );

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );

    // Make sure that there is no memory that hasn't been freed.
    for tracking_index in 0..tracking_alloc_context.active_allocations.len()
    {
        check!( tracking_alloc_context.active_allocations[tracking_index].get().is_null() );
    }
}

fn test_fragment_reassembly_alloc_failure()
{
    // Regression: a NULL-returning allocator on the fragment reassembly receive path must fail the
    // fragment (bump NUM_FRAGMENTS_INVALID) rather than crash the process. Before the fix, the receive
    // path guarded the reassembly allocation with an assert only, so a release build segfaulted on a
    // NULL+offset memcpy. reliable.h documents NULL-returning allocators as a supported outcome.

    // port: the Rust endpoint holds the reassembly buffer in a Vec and never calls allocate_function, so the allocation
    // can't fail and the fragment is not refused. the scenario still runs (it must not crash), the leak check holds, and
    // only the NUM_FRAGMENTS_INVALID check is skipped. C# leaves this test out ("C only")
    print!( "    skipped: the NUM_FRAGMENTS_INVALID check (the Rust endpoint does not call allocate_function)\n" );

    let time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let tracking_alloc_context = test_tracking_allocate_context_t::new();

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    receiver_config.allocator_context = test_context_pointer( &tracking_alloc_context );
    receiver_config.allocate_function = Some( test_tracking_allocate_function );
    receiver_config.free_function = Some( test_tracking_free_function );

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    // create succeeded with a live allocator; now make every subsequent allocation fail, so the
    // failing allocation is specifically the reassembly buffer on the receive path.
    tracking_alloc_context.fail_allocations.set( 1 );

    // send a fragmented packet (larger than one fragment) from sender to receiver
    context.allow_packets.set( 1 );
    {
        let mut packet_data = [0u8; TEST_MAX_PACKET_BYTES as usize];
        let packet_bytes = sender_config.fragment_size + sender_config.fragment_size / 2;
        let sequence: u16 = reliable_endpoint_next_packet_sequence( context.sender() );
        generate_packet_data_with_size( sequence, &mut packet_data, packet_bytes );
        reliable_endpoint_send_packet( context.sender(), &packet_data, packet_bytes );
    }

    reliable_endpoint_update( context.sender(), time );
    reliable_endpoint_update( context.receiver(), time );   // <-- receive path hits the NULL allocation; must not crash

    // the fragment must have been refused, not crashed through
    let receiver_counters = reliable_endpoint_counters( context.receiver() );
    // port: skipped, see above: check( receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] > 0 );
    let _ = receiver_counters[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID];

    // let the allocator work again so destroy can clean up, and confirm no leak
    tracking_alloc_context.fail_allocations.set( 0 );
    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );

    for tracking_index in 0..tracking_alloc_context.active_allocations.len()
    {
        check!( tracking_alloc_context.active_allocations[tracking_index].get().is_null() );
    }
}

// security#26-2: the reassembly buffer is allocated through the caller's allocator, which is
// malloc-shaped and returns uninitialized memory. Completeness is guaranteed today by the
// fragment bitmap plus validated offsets, but zeroing the buffer means a future logic error that
// skips storing a fragment leaks zeros into the delivered packet instead of stale heap contents.

// port: the Rust endpoint doesn't call the poison allocator (its reassembly buffer is a zeroed Vec), so this checks that
// the port keeps the buffer zeroed and keeps the 8 bytes of slack reliable.c allocates, as the C# port does

struct test_poison_allocate_context_t
{
    poison: Cell<i32>,             // when set, freshly returned memory is filled with 0xCC
}

fn test_poison_allocate_function( context: *mut c_void, bytes: usize ) -> *mut c_void
{
    let poison_context = unsafe { &*( context as *const test_poison_allocate_context_t ) };

    let allocation = unsafe { malloc( bytes ) };
    check!( !allocation.is_null() );

    if poison_context.poison.get() != 0
    {
        unsafe { std::ptr::write_bytes( allocation as *mut u8, 0xCC, bytes ) };
    }

    return allocation;
}

fn test_poison_free_function( context: *mut c_void, pointer: *mut c_void )
{
    let _ = context;
    unsafe { free( pointer ) };
}

fn test_fragment_reassembly_buffer_zeroed()
{
    let time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let poison_context = test_poison_allocate_context_t { poison: Cell::new( 0 ) };

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    receiver_config.allocator_context = test_context_pointer( &poison_context );
    receiver_config.allocate_function = Some( test_poison_allocate_function );
    receiver_config.free_function = Some( test_poison_free_function );

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );
    check!( !context.sender.get().is_null() );
    check!( !context.receiver.get().is_null() );

    // from here on the receive path's allocations are filled with the poison byte, so a buffer
    // that is not explicitly zeroed is visibly non-zero
    poison_context.poison.set( 1 );

    // deliver only the first fragment: the reassembly buffer is allocated and fragment 0 is
    // stored, but the tail of the buffer is never written
    context.allow_packets.set( 1 );

    let mut packet_data = [0u8; TEST_MAX_PACKET_BYTES as usize];
    let packet_bytes = sender_config.fragment_size + sender_config.fragment_size / 2;
    let sequence: u16 = reliable_endpoint_next_packet_sequence( context.sender() );
    generate_packet_data_with_size( sequence, &mut packet_data, packet_bytes );
    reliable_endpoint_send_packet( context.sender(), &packet_data, packet_bytes );

    let reassembly_data = reliable_sequence_buffer_find( &mut context.receiver().fragment_reassembly, sequence );

    check!( reassembly_data.is_some() );
    let reassembly_data = reassembly_data.unwrap();
    check!( reassembly_data.packet_data.is_some() );

    let packet_buffer_size: usize = RELIABLE_MAX_PACKET_HEADER_BYTES as usize +
        reassembly_data.num_fragments_total as usize * sender_config.fragment_size as usize + 8;

    let reassembly_packet_data = reassembly_data.packet_data.as_ref().unwrap();

    // port: the buffer is a Vec, so its length is checked too (as the C# port does)
    check!( reassembly_packet_data.len() == packet_buffer_size );

    // fragment 0 only writes near the front of the buffer, so the last byte is untouched and must
    // be zero. before the fix it still held the allocator's 0xCC poison.
    check!( reassembly_packet_data[packet_buffer_size - 1] == 0 );

    poison_context.poison.set( 0 );

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

fn test_endpoint_reset()
{
    let mut time: f64 = 100.0;

    let context = test_context_t::new();
    test_default_context( &context );

    let tracking_alloc_context = test_tracking_allocate_context_t::new();

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    sender_config.fragment_above = 500;
    receiver_config.fragment_above = 500;

    receiver_config.allocator_context = test_context_pointer( &tracking_alloc_context );
    receiver_config.allocate_function = Some( test_tracking_allocate_function );
    receiver_config.free_function = Some( test_tracking_free_function );

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    // exchange packets both ways so acks and counters accumulate

    for _i in 0..8
    {
        let dummy_packet = [0u8; 8];

        reliable_endpoint_send_packet( context.sender(), &dummy_packet, dummy_packet.len() as i32 );
        reliable_endpoint_send_packet( context.receiver(), &dummy_packet, dummy_packet.len() as i32 );

        reliable_endpoint_update( context.sender(), time );
        reliable_endpoint_update( context.receiver(), time );

        time += 0.01;
    }

    let mut num_acks: i32 = 0;
    reliable_endpoint_get_acks( context.sender(), &mut num_acks );
    check!( num_acks > 0 );
    check!( reliable_endpoint_counters( context.sender() )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT] > 0 );

    // leave a fragment reassembly in progress on the receiver by delivering only the first fragment of a large packet

    context.allow_packets.set( 1 );
    {
        let large_packet = [0u8; 1500];
        reliable_endpoint_send_packet( context.sender(), &large_packet, large_packet.len() as i32 );
    }
    context.allow_packets.set( -1 );

    // port: reliable.c checks with the tracking allocator, which the Rust endpoint doesn't call, that reset freed the
    // in-progress reassembly buffer. the equivalent check is on the reassembly entries, as the C# port does: one buffer
    // is in progress here, and none is left after the reset
    {
        let mut in_progress = 0;
        for entry in context.receiver().fragment_reassembly.entry_data.iter()
        {
            if entry.packet_data.is_some()
            {
                in_progress += 1;
            }
        }
        check!( in_progress == 1 );
    }

    reliable_endpoint_reset( context.sender() );
    reliable_endpoint_reset( context.receiver() );

    check!( reliable_endpoint_next_packet_sequence( context.sender() ) == 0 );
    check!( reliable_endpoint_next_packet_sequence( context.receiver() ) == 0 );

    reliable_endpoint_get_acks( context.sender(), &mut num_acks );
    check!( num_acks == 0 );

    for i in 0..RELIABLE_ENDPOINT_NUM_COUNTERS
    {
        check!( reliable_endpoint_counters( context.sender() )[i] == 0 );
        check!( reliable_endpoint_counters( context.receiver() )[i] == 0 );
    }

    // port: see above
    for entry in context.receiver().fragment_reassembly.entry_data.iter()
    {
        check!( entry.packet_data.is_none() );
    }

    // the endpoints must work normally after reset

    for _i in 0..8
    {
        let dummy_packet = [0u8; 8];

        reliable_endpoint_send_packet( context.sender(), &dummy_packet, dummy_packet.len() as i32 );
        reliable_endpoint_send_packet( context.receiver(), &dummy_packet, dummy_packet.len() as i32 );

        reliable_endpoint_update( context.sender(), time );
        reliable_endpoint_update( context.receiver(), time );

        time += 0.01;
    }

    reliable_endpoint_get_acks( context.sender(), &mut num_acks );
    check!( num_acks > 0 );
    check!( reliable_endpoint_counters( context.receiver() )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] > 0 );

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );

    // reset must have freed the in-progress reassembly buffer, and destroy must not double-free it

    for tracking_index in 0..tracking_alloc_context.active_allocations.len()
    {
        check!( tracking_alloc_context.active_allocations[tracking_index].get().is_null() );
    }
}

fn test_rtt()
{
    let mut time: f64 = 100.0;
    let delta_time: f64 = 0.01;

    let context = test_context_t::new();
    test_default_context( &context );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_process_packet_function );

    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_process_packet_function );

    context.set_sender( reliable_endpoint_create( &sender_config, time ) );
    context.set_receiver( reliable_endpoint_create( &receiver_config, time ) );

    for _i in 0..1000
    {
        let dummy_packet = [0u8; 8];

        reliable_endpoint_send_packet( context.sender(), &dummy_packet, dummy_packet.len() as i32 );
        reliable_endpoint_send_packet( context.receiver(), &dummy_packet, dummy_packet.len() as i32 );

        reliable_endpoint_update( context.sender(), time );
        reliable_endpoint_update( context.receiver(), time );

        time += delta_time;
    }

    let rtt: f32 = reliable_endpoint_rtt( context.sender() );
    let rtt_min: f32 = reliable_endpoint_rtt_min( context.sender() );
    let rtt_max: f32 = reliable_endpoint_rtt_max( context.sender() );
    let rtt_avg: f32 = reliable_endpoint_rtt_avg( context.sender() );

    check!( rtt == rtt && rtt >= 0.0 ); // Check rtt is finite and non-negative
    check!( rtt_min >= 0.0 && rtt_min <= rtt_avg && rtt_avg <= rtt_max );
    check!( rtt_max < 1000.0 ); // Assume RTT is in milliseconds

    reliable_endpoint_destroy( context.take_sender() );
    reliable_endpoint_destroy( context.take_receiver() );
}

// a pair of endpoints wired to each other through test_transmit_packet_function

struct test_pair_t
{
    context: test_context_t,
    sender_config: reliable_config_t,
    receiver_config: reliable_config_t,
}

// port: the uninitialized pair upstream declares on the stack; test_pair_configs fills it in
impl test_pair_t
{
    fn new() -> Self
    {
        test_pair_t
        {
            context: test_context_t::new(),
            sender_config: reliable_config_t::default(),
            receiver_config: reliable_config_t::default(),
        }
    }
}

// port: the configs point at the pair's context, so after this the pair is only used through shared references
fn test_pair_configs( pair: &mut test_pair_t )
{
    test_default_context( &pair.context );

    reliable_default_config( &mut pair.sender_config );
    reliable_default_config( &mut pair.receiver_config );

    let name_size = pair.sender_config.name.len();
    reliable_copy_string( &mut pair.sender_config.name, "sender", name_size );
    pair.sender_config.context = test_context_pointer( &pair.context );
    pair.sender_config.id = 0;
    pair.sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    pair.sender_config.process_packet_function = Some( test_process_packet_function );

    reliable_copy_string( &mut pair.receiver_config.name, "receiver", name_size );
    pair.receiver_config.context = test_context_pointer( &pair.context );
    pair.receiver_config.id = 1;
    pair.receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    pair.receiver_config.process_packet_function = Some( test_process_packet_function );
}

fn test_pair_create( pair: &test_pair_t, time: f64 )
{
    pair.context.set_sender( reliable_endpoint_create( &pair.sender_config, time ) );
    pair.context.set_receiver( reliable_endpoint_create( &pair.receiver_config, time ) );
    check!( !pair.context.sender.get().is_null() );
    check!( !pair.context.receiver.get().is_null() );
}

fn test_pair_destroy( pair: &test_pair_t )
{
    reliable_endpoint_destroy( pair.context.take_sender() );
    reliable_endpoint_destroy( pair.context.take_receiver() );
}

// RL-02: a round trip long enough to reach any fixed sentinel must still be reported

fn test_rtt_min_large()
{
    let mut time: f64 = 100.0;

    let mut pair = test_pair_t::new();
    test_pair_configs( &mut pair );
    let pair = &pair;
    test_pair_create( pair, time );

    let packet = [0u8; 8];

    reliable_endpoint_send_packet( pair.context.sender(), &packet, packet.len() as i32 );

    // ten seconds pass before the acknowledgment comes back, so the one rtt sample is 10,000 ms

    time += 10.0;

    reliable_endpoint_update( pair.context.sender(), time );
    reliable_endpoint_update( pair.context.receiver(), time );

    reliable_endpoint_send_packet( pair.context.receiver(), &packet, packet.len() as i32 );

    reliable_endpoint_update( pair.context.sender(), time );

    let mut num_acks: i32 = 0;
    reliable_endpoint_get_acks( pair.context.sender(), &mut num_acks );
    check!( num_acks == 1 );

    check!( reliable_endpoint_rtt_min( pair.context.sender() ) == 10000.0f32 );
    check!( reliable_endpoint_rtt_max( pair.context.sender() ) == 10000.0f32 );
    check!( reliable_endpoint_rtt_avg( pair.context.sender() ) == 10000.0f32 );
    check!( reliable_endpoint_jitter_avg_vs_min_rtt( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_jitter_max_vs_min_rtt( pair.context.sender() ) == 0.0f32 );

    // and an endpoint with no samples at all still reports zero

    check!( reliable_endpoint_rtt_min( pair.context.receiver() ) == 0.0f32 );

    test_pair_destroy( pair );
}

// RL-03: reset clears every field a getter can return, the rtt history included

fn test_endpoint_reset_clears_stats()
{
    let mut time: f64 = 100.0;

    let mut pair = test_pair_t::new();
    test_pair_configs( &mut pair );
    let pair = &pair;
    test_pair_create( pair, time );

    // enough packets that the bandwidth window, which samples half the sent packets buffer,
    // lands on packets that were actually sent

    for _i in 0..300
    {
        let packet = [0u8; 64];

        // the reply comes back a step later, so the acknowledgment carries a real round trip

        reliable_endpoint_send_packet( pair.context.sender(), &packet, packet.len() as i32 );

        time += 0.1;
        reliable_endpoint_update( pair.context.sender(), time );
        reliable_endpoint_update( pair.context.receiver(), time );

        reliable_endpoint_send_packet( pair.context.receiver(), &packet, packet.len() as i32 );

        time += 0.1;
        reliable_endpoint_update( pair.context.sender(), time );
        reliable_endpoint_update( pair.context.receiver(), time );

        reliable_endpoint_clear_acks( pair.context.sender() );
        reliable_endpoint_clear_acks( pair.context.receiver() );
    }

    check!( reliable_endpoint_rtt( pair.context.sender() ) > 0.0f32 );
    check!( reliable_endpoint_rtt_min( pair.context.sender() ) > 0.0f32 );
    check!( reliable_endpoint_rtt_max( pair.context.sender() ) > 0.0f32 );
    check!( reliable_endpoint_rtt_avg( pair.context.sender() ) > 0.0f32 );

    let mut sent_bandwidth: f32 = 0.0;
    let mut received_bandwidth: f32 = 0.0;
    let mut acked_bandwidth: f32 = 0.0;
    reliable_endpoint_bandwidth( pair.context.sender(), &mut sent_bandwidth, &mut received_bandwidth, &mut acked_bandwidth );
    check!( sent_bandwidth > 0.0f32 );
    check!( received_bandwidth > 0.0f32 );
    check!( acked_bandwidth > 0.0f32 );

    reliable_endpoint_reset( pair.context.sender() );

    check!( reliable_endpoint_rtt( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_rtt_min( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_rtt_max( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_rtt_avg( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_jitter_avg_vs_min_rtt( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_jitter_max_vs_min_rtt( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_jitter_stddev_vs_avg_rtt( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_packet_loss( pair.context.sender() ) == 0.0f32 );

    reliable_endpoint_bandwidth( pair.context.sender(), &mut sent_bandwidth, &mut received_bandwidth, &mut acked_bandwidth );
    check!( sent_bandwidth == 0.0f32 );
    check!( received_bandwidth == 0.0f32 );
    check!( acked_bandwidth == 0.0f32 );

    // the rtt history is part of the state, so recomputing the statistics after a reset must
    // not resurrect the samples that were in it

    time += 0.1;
    reliable_endpoint_update( pair.context.sender(), time );

    check!( reliable_endpoint_rtt_min( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_rtt_max( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_rtt_avg( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_jitter_avg_vs_min_rtt( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_jitter_max_vs_min_rtt( pair.context.sender() ) == 0.0f32 );
    check!( reliable_endpoint_jitter_stddev_vs_avg_rtt( pair.context.sender() ) == 0.0f32 );

    test_pair_destroy( pair );
}

// RL-06: a config the library cannot honor is refused instead of asserted

fn test_endpoint_create_invalid_config()
{
    let mut valid = reliable_config_t::default();

    reliable_default_config( &mut valid );
    valid.transmit_packet_function = Some( test_transmit_packet_function );
    valid.process_packet_function = Some( test_process_packet_function );

    let mut endpoint = reliable_endpoint_create( &valid, 0.0 );
    check!( endpoint.is_some() );
    reliable_endpoint_destroy( endpoint.unwrap() );

    // port: reliable_endpoint_create takes a reference, which can't be NULL. the NULL config is refused by
    // reliable_config_valid, which create calls first
    check!( reliable_config_valid( None ) == 0 );

    let mut config: reliable_config_t;

    // the two relationships between fields

    config = valid;
    config.fragment_above = config.max_packet_size + 1;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid;
    config.max_fragments = 4;
    config.fragment_size = 1024;
    config.max_packet_size = 4 * 1024 + 1;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    // exactly covering is allowed, one fragment short is not

    config = valid;
    config.max_fragments = 4;
    config.fragment_size = 1024;
    config.max_packet_size = 4 * 1024;
    config.fragment_above = 1024;
    endpoint = reliable_endpoint_create( &config, 0.0 );
    check!( endpoint.is_some() );
    reliable_endpoint_destroy( endpoint.unwrap() );

    // ranges

    config = valid; config.max_packet_size = 0;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.fragment_above = 0;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.fragment_size = 0;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.max_fragments = 0;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.max_fragments = 257;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.max_fragments = 256; config.fragment_size = 8421505;
    config.max_packet_size = config.fragment_size;
    config.fragment_above = 1;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.max_packet_size = i32::MAX - 10;
    config.fragment_above = 1;
    config.fragment_size = config.max_packet_size;
    config.max_fragments = 1;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.ack_buffer_size = 0;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.sent_packets_buffer_size = -1;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.received_packets_buffer_size = 0;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.fragment_reassembly_buffer_size = 0;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.rtt_history_size = 0;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.packet_header_size = -1;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.packet_header_size = i32::MAX;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.transmit_packet_function = None;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    config = valid; config.process_packet_function = None;
    check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

    // the size arithmetic behind every one of those buffers

    let mut bytes: usize = 0;

    check!( reliable_checked_size( 1, 4, &mut bytes ) != 0 );
    check!( bytes == 4 );

    check!( reliable_checked_size( 256, std::mem::size_of::<u16>(), &mut bytes ) != 0 );
    check!( bytes == 512 );

    check!( reliable_checked_size( 0, 4, &mut bytes ) == 0 );
    check!( reliable_checked_size( -1, 4, &mut bytes ) == 0 );
    check!( reliable_checked_size( 4, 0, &mut bytes ) == 0 );

    // a product that does not fit in a size_t is refused rather than wrapped

    check!( reliable_checked_size( 4, usize::MAX / 2, &mut bytes ) == 0 );
    check!( reliable_checked_size( i32::MAX, usize::MAX / 3, &mut bytes ) == 0 );
}

// RL-06: every allocation failure returns NULL, in every build, having freed what it took

const TEST_FAILING_ALLOCATOR_SLOTS: usize = 64;

struct test_failing_allocate_context_t
{
    fail_on: Cell<i32>,
    num_allocations: Cell<i32>,
    active_allocations: [Cell<*mut c_void>; TEST_FAILING_ALLOCATOR_SLOTS],
}

// port: memset( context, 0, sizeof( *context ) ), through the Cells
fn test_failing_allocate_context_clear( failing_context: &test_failing_allocate_context_t )
{
    failing_context.fail_on.set( 0 );
    failing_context.num_allocations.set( 0 );
    for allocation in failing_context.active_allocations.iter()
    {
        allocation.set( std::ptr::null_mut() );
    }
}

fn test_failing_allocate_function( context: *mut c_void, bytes: usize ) -> *mut c_void
{
    let failing_context = unsafe { &*( context as *const test_failing_allocate_context_t ) };

    let num_allocations = failing_context.num_allocations.get();
    failing_context.num_allocations.set( num_allocations + 1 );
    if num_allocations == failing_context.fail_on.get()
    {
        return std::ptr::null_mut();
    }

    let allocation = unsafe { malloc( bytes ) };

    for i in 0..TEST_FAILING_ALLOCATOR_SLOTS
    {
        if failing_context.active_allocations[i].get().is_null()
        {
            failing_context.active_allocations[i].set( allocation );
            return allocation;
        }
    }

    check!( false );
    return allocation;
}

fn test_failing_free_function( context: *mut c_void, pointer: *mut c_void )
{
    let failing_context = unsafe { &*( context as *const test_failing_allocate_context_t ) };

    for i in 0..TEST_FAILING_ALLOCATOR_SLOTS
    {
        if failing_context.active_allocations[i].get() == pointer
        {
            failing_context.active_allocations[i].set( std::ptr::null_mut() );
            unsafe { free( pointer ) };
            return;
        }
    }

    check!( false );
}

fn test_endpoint_create_allocation_failure()
{
    // port: the Rust endpoint never calls allocate_function (see the top of the file), so there is no allocation to fail:
    // create makes no allocations through it and the fail-each-one-in-turn loop runs zero times. what still holds is
    // checked: create and destroy with the allocator installed succeed and leave nothing allocated. C# leaves this test
    // out ("C only")
    print!( "    skipped: allocation failure injection (the Rust endpoint does not call allocate_function)\n" );

    let allocator = test_failing_allocate_context_t
    {
        fail_on: Cell::new( 0 ),
        num_allocations: Cell::new( 0 ),
        active_allocations: std::array::from_fn( |_| Cell::new( std::ptr::null_mut() ) ),
    };

    let mut config = reliable_config_t::default();
    reliable_default_config( &mut config );
    config.transmit_packet_function = Some( test_transmit_packet_function );
    config.process_packet_function = Some( test_process_packet_function );
    config.allocator_context = test_context_pointer( &allocator );
    config.allocate_function = Some( test_failing_allocate_function );
    config.free_function = Some( test_failing_free_function );

    // how many allocations a successful create makes

    test_failing_allocate_context_clear( &allocator );
    allocator.fail_on.set( -1 );

    let endpoint = reliable_endpoint_create( &config, 0.0 );
    check!( endpoint.is_some() );

    let num_allocations: i32 = allocator.num_allocations.get();
    // port: skipped, see above: check( num_allocations > 1 );

    reliable_endpoint_destroy( endpoint.unwrap() );

    for i in 0..TEST_FAILING_ALLOCATOR_SLOTS
    {
        check!( allocator.active_allocations[i].get().is_null() );
    }

    // fail each one in turn

    for fail_on in 0..num_allocations
    {
        test_failing_allocate_context_clear( &allocator );
        allocator.fail_on.set( fail_on );

        check!( reliable_endpoint_create( &config, 0.0 ).is_none() );

        for i in 0..TEST_FAILING_ALLOCATOR_SLOTS
        {
            check!( allocator.active_allocations[i].get().is_null() );
        }
    }
}

// security#26-3: reliable_printf logs the endpoint name with "%s". A caller that fills all 256
// bytes of config.name with no NUL would make that log read past the array, so create forces a
// terminator on its own copy.

fn test_endpoint_name_terminated()
{
    let mut config = reliable_config_t::default();
    reliable_default_config( &mut config );

    // a caller is allowed to fill the whole name with no terminator
    config.name = [b'x'; 256];

    config.transmit_packet_function = Some( test_transmit_packet_function );
    config.process_packet_function = Some( test_process_packet_function );

    let endpoint = reliable_endpoint_create( &config, 0.0 );
    check!( endpoint.is_some() );
    let endpoint = endpoint.unwrap();
    check!( endpoint.config.name[endpoint.config.name.len() - 1] == b'\0' );

    reliable_endpoint_destroy( endpoint );
}

// security#26-3, create-time error paths: reliable_config_valid runs before create copies the
// config and terminates the name, so its rejection logs print the caller's own buffer. a caller
// that fills all 256 bytes with no NUL would make one of those logs read past the array and on
// past the end of whatever holds it, so every one of them bounds the read with a precision.

static test_name_log_line: Mutex<String> = Mutex::new( String::new() );
static test_name_log_calls: AtomicI32 = AtomicI32::new( 0 );

fn test_name_log_printf_function( text: &str )
{
    // port: upstream formats into an 8K buffer with vsnprintf; the text arrives formatted
    *test_name_log_line.lock().unwrap() = text.to_string();
    test_name_log_calls.fetch_add( 1, Ordering::Relaxed );
}

fn test_config_name_bounded_in_rejection_log()
{
    // the config goes on the heap with no zero byte anywhere in it, so an unbounded "%s" on the name
    // runs off the end of the allocation. every int field reads as -1, so reliable_config_valid
    // refuses at the first check and logs the name. under ASan the over-read is a heap-buffer-overflow
    // READ; without a sanitizer the logged name is simply longer than the array, and the check below
    // catches it either way

    // port: memset( config, 0xFF, ... ) is spelled out field by field: every int is -1, every float is the 0xFFFFFFFF
    // bit pattern, the pointers are all ones and the function pointers are set (non-NULL)
    let mut config = Box::new( reliable_config_t::default() );
    config.context = usize::MAX as *mut c_void;
    config.id = u64::MAX;
    config.max_packet_size = -1;
    config.fragment_above = -1;
    config.max_fragments = -1;
    config.fragment_size = -1;
    config.ack_buffer_size = -1;
    config.sent_packets_buffer_size = -1;
    config.received_packets_buffer_size = -1;
    config.fragment_reassembly_buffer_size = -1;
    config.rtt_smoothing_factor = f32::from_bits( 0xFFFFFFFF );
    config.rtt_history_size = -1;
    config.packet_loss_smoothing_factor = f32::from_bits( 0xFFFFFFFF );
    config.bandwidth_smoothing_factor = f32::from_bits( 0xFFFFFFFF );
    config.packet_header_size = -1;
    config.transmit_packet_function = Some( test_transmit_packet_function );
    config.process_packet_function = Some( test_process_packet_function );
    config.allocator_context = usize::MAX as *mut c_void;
    config.allocate_function = Some( test_failing_allocate_function );
    config.free_function = Some( test_failing_free_function );
    config.name = [b'x'; 256];

    let previous_printf_function: fn(&str) = *printf_function.lock().unwrap_or_else( |e| e.into_inner() );
    let previous_log_level: i32 = log_level.load( Ordering::Relaxed );

    test_name_log_line.lock().unwrap().clear();
    test_name_log_calls.store( 0, Ordering::Relaxed );

    reliable_set_printf_function( test_name_log_printf_function );
    reliable_log_level( RELIABLE_LOG_LEVEL_ERROR );

    let endpoint = reliable_endpoint_create( &config, 0.0 );

    reliable_log_level( previous_log_level );
    reliable_set_printf_function( previous_printf_function );

    check!( endpoint.is_none() );
    check!( test_name_log_calls.load( Ordering::Relaxed ) == 1 );

    // the line is "[<name>] ...", so the name is everything between the bracket and the next one.
    // it must stop at the last byte of the array

    let test_name_log_line_copy = test_name_log_line.lock().unwrap().clone();
    let name_end = test_name_log_line_copy.find( ']' );
    check!( name_end.is_some() );
    check!( name_end.unwrap() as i32 - 1 == config.name.len() as i32 - 1 );

    drop( config );
}

// RL-07: the sequence number crosses 65535 to 0

static test_wrap_acked: Mutex<[u8; 65536]> = Mutex::new( [0; 65536] );

fn test_sequence_wrap()
{
    let time: f64 = 100.0;

    let mut pair = test_pair_t::new();
    test_pair_configs( &mut pair );
    let pair = &pair;
    test_pair_create( pair, time );

    let mut test_wrap_acked_guard = test_wrap_acked.lock().unwrap();
    let test_wrap_acked_array: &mut [u8; 65536] = &mut test_wrap_acked_guard;

    *test_wrap_acked_array = [0; 65536];

    let num_iterations: i32 = 65536 + 64;

    for _i in 0..num_iterations
    {
        let packet = [0u8; 8];

        reliable_endpoint_send_packet( pair.context.sender(), &packet, packet.len() as i32 );
        reliable_endpoint_send_packet( pair.context.receiver(), &packet, packet.len() as i32 );

        let mut num_acks: i32 = 0;
        let acks = reliable_endpoint_get_acks( pair.context.sender(), &mut num_acks );

        for j in 0..num_acks as usize
        {
            test_wrap_acked_array[acks[j] as usize] = 1;
        }

        reliable_endpoint_clear_acks( pair.context.sender() );
        reliable_endpoint_clear_acks( pair.context.receiver() );
    }

    check!( reliable_endpoint_next_packet_sequence( pair.context.sender() ) == num_iterations as u16 );

    // the sequences either side of the wrap were acked like any others

    check!( test_wrap_acked_array[65533] != 0 );
    check!( test_wrap_acked_array[65534] != 0 );
    check!( test_wrap_acked_array[65535] != 0 );
    check!( test_wrap_acked_array[0] != 0 );
    check!( test_wrap_acked_array[1] != 0 );
    check!( test_wrap_acked_array[2] != 0 );

    for i in 0..65536
    {
        check!( test_wrap_acked_array[i] != 0 );
    }

    check!( reliable_endpoint_counters( pair.context.receiver() )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED] == num_iterations as u64 );

    test_pair_destroy( pair );
}

// RL-07: fragment counts at both ends of the range, and a payload that is an exact multiple
// of the fragment size

#[repr(C)]
struct test_fragment_context_t
{
    base: test_context_t,
    num_processed: Cell<i32>,
    processed_bytes: Cell<i32>,
    processed: RefCell<Vec<u8>>,        // port: uint8_t processed[64 * 1024], on the heap
}

fn test_fragment_process_packet_function( _context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 ) -> i32
{
    let _ = id;
    let _ = sequence;

    let context = unsafe { &*( _context as *const test_fragment_context_t ) };

    check!( packet_bytes <= context.processed.borrow().len() as i32 );

    context.num_processed.set( context.num_processed.get() + 1 );
    context.processed_bytes.set( packet_bytes );
    context.processed.borrow_mut()[..packet_bytes as usize].copy_from_slice( &packet_data[..packet_bytes as usize] );

    return 1;
}

fn test_fragment_case( fragment_size: i32, max_fragments: i32, packet_bytes: i32, expected_fragments: i32 )
{
    let context = test_fragment_context_t
    {
        base: test_context_t::new(),
        num_processed: Cell::new( 0 ),
        processed_bytes: Cell::new( 0 ),
        processed: RefCell::new( vec![ 0u8; 64 * 1024 ] ),
    };
    context.base.allow_packets.set( -1 );

    let mut sender_config = reliable_config_t::default();
    let mut receiver_config = reliable_config_t::default();

    reliable_default_config( &mut sender_config );
    reliable_default_config( &mut receiver_config );

    sender_config.fragment_size = fragment_size;
    sender_config.max_fragments = max_fragments;
    sender_config.max_packet_size = fragment_size * max_fragments;
    sender_config.fragment_above = fragment_size;
    receiver_config = sender_config;

    let name_size = sender_config.name.len();
    reliable_copy_string( &mut sender_config.name, "sender", name_size );
    sender_config.context = test_context_pointer( &context );
    sender_config.id = 0;
    sender_config.transmit_packet_function = Some( test_transmit_packet_function );
    sender_config.process_packet_function = Some( test_fragment_process_packet_function );

    reliable_copy_string( &mut receiver_config.name, "receiver", name_size );
    receiver_config.context = test_context_pointer( &context );
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = Some( test_transmit_packet_function );
    receiver_config.process_packet_function = Some( test_fragment_process_packet_function );

    context.base.set_sender( reliable_endpoint_create( &sender_config, 100.0 ) );
    context.base.set_receiver( reliable_endpoint_create( &receiver_config, 100.0 ) );
    check!( !context.base.sender.get().is_null() );
    check!( !context.base.receiver.get().is_null() );

    let mut packet: Vec<u8> = vec![ 0u8; packet_bytes as usize ];
    // port: check( packet ) is dropped: a Vec can't be NULL

    for i in 0..packet_bytes
    {
        packet[i as usize] = ( ( i * 31 ) + 7 ) as u8;
    }

    reliable_endpoint_send_packet( context.base.sender(), &packet, packet_bytes );

    check!( context.num_processed.get() == 1 );
    check!( context.processed_bytes.get() == packet_bytes );
    check!( context.processed.borrow()[..packet_bytes as usize] == packet[..packet_bytes as usize] );

    let fragments_sent: u64 = reliable_endpoint_counters( context.base.sender() )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT];
    let fragments_received: u64 = reliable_endpoint_counters( context.base.receiver() )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED];

    if expected_fragments == 0
    {
        // below the threshold: sent whole, no fragments at all
        check!( fragments_sent == 0 );
        check!( fragments_received == 0 );
    }
    else
    {
        check!( fragments_sent == expected_fragments as u64 );
        check!( fragments_received == expected_fragments as u64 );
    }

    drop( packet );

    reliable_endpoint_destroy( context.base.take_sender() );
    reliable_endpoint_destroy( context.base.take_receiver() );
}

fn test_fragment_counts()
{
    // an exact multiple of the fragment size, where the last fragment is full rather than a remainder
    test_fragment_case( 512, 16, 512 * 4, 4 );

    // the largest packet the config allows, again an exact multiple
    test_fragment_case( 512, 16, 512 * 16, 16 );

    // one fragment: above the threshold by a single byte
    test_fragment_case( 512, 16, 513, 2 );
    test_fragment_case( 64, 256, 65, 2 );

    // 256 fragments, the maximum the wire format can express
    test_fragment_case( 64, 256, 64 * 256, 256 );
    test_fragment_case( 64, 256, 64 * 255 + 1, 256 );

    // at or below the threshold the packet is not fragmented
    test_fragment_case( 512, 16, 512, 0 );
    test_fragment_case( 512, 16, 1, 0 );
}

// RL-07: truncated packets and fragments are rejected rather than acted on

#[repr(C)]
struct test_truncation_context_t
{
    base: test_context_t,
    num_processed: Cell<i32>,
    num_captured: Cell<i32>,
    captured_bytes: RefCell<[i32; 300]>,
    captured: RefCell<Vec<[u8; 1024]>>,      // port: uint8_t captured[300][1024], on the heap
}

fn test_truncation_transmit_packet_function( _context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 )
{
    let _ = id;
    let _ = sequence;

    let context = unsafe { &*( _context as *const test_truncation_context_t ) };

    let num_captured = context.num_captured.get();
    if num_captured < context.captured_bytes.borrow().len() as i32 && packet_bytes <= context.captured.borrow()[0].len() as i32
    {
        context.captured.borrow_mut()[num_captured as usize][..packet_bytes as usize].copy_from_slice( &packet_data[..packet_bytes as usize] );
        context.captured_bytes.borrow_mut()[num_captured as usize] = packet_bytes;
        context.num_captured.set( num_captured + 1 );
    }
}

fn test_truncation_process_packet_function( _context: *mut c_void, id: u64, sequence: u16, packet_data: &[u8], packet_bytes: i32 ) -> i32
{
    let _ = id;
    let _ = sequence;
    let _ = packet_data;
    let _ = packet_bytes;

    let context = unsafe { &*( _context as *const test_truncation_context_t ) };
    context.num_processed.set( context.num_processed.get() + 1 );
    return 1;
}

fn test_truncated_packets()
{
    let context = test_truncation_context_t
    {
        base: test_context_t::new(),
        num_processed: Cell::new( 0 ),
        num_captured: Cell::new( 0 ),
        captured_bytes: RefCell::new( [0; 300] ),
        captured: RefCell::new( vec![ [0u8; 1024]; 300 ] ),
    };
    context.base.allow_packets.set( -1 );

    let mut config = reliable_config_t::default();
    reliable_default_config( &mut config );
    config.fragment_size = 256;
    config.max_fragments = 16;
    config.max_packet_size = 256 * 16;
    config.fragment_above = 256;
    config.context = test_context_pointer( &context );
    config.id = 0;
    config.transmit_packet_function = Some( test_truncation_transmit_packet_function );
    config.process_packet_function = Some( test_truncation_process_packet_function );

    let sender = reliable_endpoint_create( &config, 100.0 );
    let receiver = reliable_endpoint_create( &config, 100.0 );
    check!( sender.is_some() );
    check!( receiver.is_some() );
    let mut sender = sender.unwrap();
    let mut receiver = receiver.unwrap();

    // an unfragmented packet, captured on the wire

    let packet = [0xABu8; 200];
    reliable_endpoint_send_packet( &mut sender, &packet, packet.len() as i32 );
    check!( context.num_captured.get() == 1 );

    let whole_bytes: i32 = context.captured_bytes.borrow()[0];

    // every truncation of it shorter than the header is rejected, and none is processed

    // port: each receive gets a slice exactly as long as the bytes it is told about, so a read past them would panic
    for truncated_bytes in 1..4
    {
        let captured = context.captured.borrow();
        reliable_endpoint_receive_packet( &mut receiver, &captured[0][..truncated_bytes as usize], truncated_bytes );
    }

    check!( reliable_endpoint_counters( &receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID] == 3 );
    check!( context.num_processed.get() == 0 );

    // the whole packet still arrives

    {
        let captured = context.captured.borrow();
        reliable_endpoint_receive_packet( &mut receiver, &captured[0][..whole_bytes as usize], whole_bytes );
    }
    check!( context.num_processed.get() == 1 );

    // now a fragmented packet

    context.num_captured.set( 0 );

    let large_packet = [0xCDu8; 1024];
    reliable_endpoint_send_packet( &mut sender, &large_packet, large_packet.len() as i32 );
    check!( context.num_captured.get() == 4 );

    // a fragment truncated inside its header is rejected

    for truncated_bytes in 1..RELIABLE_FRAGMENT_HEADER_BYTES
    {
        let captured = context.captured.borrow();
        reliable_endpoint_receive_packet( &mut receiver, &captured[1][..truncated_bytes as usize], truncated_bytes );
    }

    check!( reliable_endpoint_counters( &receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 0 );
    check!( reliable_endpoint_counters( &receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == ( RELIABLE_FRAGMENT_HEADER_BYTES - 1 ) as u64 );

    // a fragment that is not the last one must carry exactly fragment_size bytes, so a
    // truncated body is rejected too

    {
        let captured = context.captured.borrow();
        let captured_bytes = context.captured_bytes.borrow()[1] - 1;
        reliable_endpoint_receive_packet( &mut receiver, &captured[1][..captured_bytes as usize], captured_bytes );
    }
    check!( reliable_endpoint_counters( &receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 0 );
    check!( reliable_endpoint_counters( &receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID] == RELIABLE_FRAGMENT_HEADER_BYTES as u64 );
    check!( context.num_processed.get() == 1 );

    // the intact fragments reassemble

    for i in 0..context.num_captured.get() as usize
    {
        let captured = context.captured.borrow();
        let captured_bytes = context.captured_bytes.borrow()[i];
        reliable_endpoint_receive_packet( &mut receiver, &captured[i][..captured_bytes as usize], captured_bytes );
    }

    check!( reliable_endpoint_counters( &receiver )[RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED] == 4 );
    check!( context.num_processed.get() == 2 );

    reliable_endpoint_destroy( sender );
    reliable_endpoint_destroy( receiver );
}

// every function reliable.h declares is called at least once by the suite. this test names
// them all in one place so a new entry point cannot be added without being exercised

static test_surface_printf_calls: AtomicI32 = AtomicI32::new( 0 );

fn test_surface_printf_function( format: &str )
{
    let _ = format;
    test_surface_printf_calls.fetch_add( 1, Ordering::Relaxed );
}

fn test_public_api_surface()
{
    check!( reliable_init() == RELIABLE_OK );

    // port: reliable_assert_function is the Mutex holding the function; this reads it out and sets it back
    let assert_function: fn(&str, &str, &str, i32) = *reliable_assert_function.lock().unwrap_or_else( |e| e.into_inner() );
    reliable_set_assert_function( assert_function );

    reliable_set_printf_function( test_surface_printf_function );
    reliable_log_level( RELIABLE_LOG_LEVEL_NONE );

    let mut pair = test_pair_t::new();
    test_pair_configs( &mut pair );
    let pair = &pair;
    test_pair_create( pair, 100.0 );

    check!( reliable_endpoint_next_packet_sequence( pair.context.sender() ) == 0 );

    let packet = [0u8; 64];

    reliable_endpoint_send_packet( pair.context.sender(), &packet, packet.len() as i32 );
    reliable_endpoint_send_packet( pair.context.receiver(), &packet, packet.len() as i32 );

    reliable_endpoint_receive_packet( pair.context.sender(), &packet, packet.len() as i32 );

    reliable_endpoint_update( pair.context.sender(), 100.1 );

    let mut num_acks: i32 = 0;
    let acks = reliable_endpoint_get_acks( pair.context.sender(), &mut num_acks );
    // port: check( acks ) is dropped: a slice can't be NULL
    let _ = acks;
    check!( num_acks == 1 );
    reliable_endpoint_clear_acks( pair.context.sender() );
    reliable_endpoint_get_acks( pair.context.sender(), &mut num_acks );
    check!( num_acks == 0 );

    let _ = reliable_endpoint_rtt( pair.context.sender() );
    let _ = reliable_endpoint_rtt_min( pair.context.sender() );
    let _ = reliable_endpoint_rtt_max( pair.context.sender() );
    let _ = reliable_endpoint_rtt_avg( pair.context.sender() );
    let _ = reliable_endpoint_jitter_avg_vs_min_rtt( pair.context.sender() );
    let _ = reliable_endpoint_jitter_max_vs_min_rtt( pair.context.sender() );
    let _ = reliable_endpoint_jitter_stddev_vs_avg_rtt( pair.context.sender() );
    let _ = reliable_endpoint_packet_loss( pair.context.sender() );

    let mut sent_bandwidth: f32 = 0.0;
    let mut received_bandwidth: f32 = 0.0;
    let mut acked_bandwidth: f32 = 0.0;
    reliable_endpoint_bandwidth( pair.context.sender(), &mut sent_bandwidth, &mut received_bandwidth, &mut acked_bandwidth );

    check!( reliable_endpoint_counters( pair.context.sender() )[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT] == 1 );

    reliable_endpoint_reset( pair.context.sender() );
    check!( reliable_endpoint_next_packet_sequence( pair.context.sender() ) == 0 );

    // port: the packet the endpoint frees is a Vec (README: the matching *_free_packet takes the Vec<u8>)
    let owned: Vec<u8> = vec![ 0u8; 32 ];
    reliable_endpoint_free_packet( pair.context.sender(), owned );

    let mut name = [0u8; 8];
    let name_size = name.len();
    reliable_copy_string( &mut name, "abcdefghij", name_size );
    check!( &name == b"abcdefg\0" );

    let mut defaults = reliable_config_t::default();
    reliable_default_config( &mut defaults );
    check!( defaults.max_packet_size > 0 );

    test_pair_destroy( pair );

    // port: printf is the library's default printf function
    reliable_set_printf_function( default_printf_function );

    reliable_term();
    check!( reliable_init() == RELIABLE_OK );
}

macro_rules! RUN_TEST
{
    ( $test_function:ident ) =>
    {
        {
            print!( "{}\n", stringify!( $test_function ) );
            $test_function();
        }
    };
}

pub fn reliable_test()
{
    // while ( 1 )
    {
        RUN_TEST!( test_endian );
        RUN_TEST!( test_sequence_buffer );
        RUN_TEST!( test_generate_ack_bits );
        RUN_TEST!( test_packet_header );
        RUN_TEST!( test_acks );
        RUN_TEST!( test_acks_packet_loss );
        RUN_TEST!( test_duplicate_packets );
        RUN_TEST!( test_stale_packets );
        RUN_TEST!( test_ack_buffer_overflow );
        RUN_TEST!( test_packets );
        RUN_TEST!( test_large_packets );
        RUN_TEST!( test_sequence_buffer_rollover );
        RUN_TEST!( test_fragment_cleanup );
        RUN_TEST!( test_fragment_reassembly_alloc_failure );
        RUN_TEST!( test_fragment_reassembly_buffer_zeroed );
        RUN_TEST!( test_rtt );
        RUN_TEST!( test_endpoint_reset );
        RUN_TEST!( test_endpoint_reset_clears_stats );
        RUN_TEST!( test_rtt_min_large );
        RUN_TEST!( test_endpoint_create_invalid_config );
        RUN_TEST!( test_endpoint_create_allocation_failure );
        RUN_TEST!( test_endpoint_name_terminated );
        RUN_TEST!( test_config_name_bounded_in_rejection_log );
        RUN_TEST!( test_sequence_wrap );
        RUN_TEST!( test_fragment_counts );
        RUN_TEST!( test_truncated_packets );
        RUN_TEST!( test_public_api_surface );
    }
}
