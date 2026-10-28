/*
    netcode

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
    "netcode - Glenn Fiedler and Rowan Claude" in your product credits. The
    license doesn't require this credit. It's an official request, and honoring
    it is appreciated.
*/

/*
    Rust port of netcode/netcode.h + netcode/netcode.c (netcode 1.4.8).

    Port notes (see rust/README.md, "Conventions"):
      - The header comes first, then netcode.c in upstream order. Rust needs no prototypes, so the header's function
        declarations are not repeated: each function is defined where netcode.c defines it.
      - netcode_printf! takes a Rust format string; the function behind it, netcode_printf, takes the format_args!. The
        printf hook is fn( &str ) and receives the formatted text.
      - netcode_assert! is active in debug builds (cfg(debug_assertions), upstream's !NDEBUG) and calls the assert hook.
        As upstream, a hook that returns lets execution continue. Asserts that a pointer argument is not null are
        dropped: a Rust reference is never null.
      - A `uint8_t * buffer` walked by the read/write helpers (`uint8_t ** p`) is the slice plus a byte index into it,
        `netcode_write_uint32( buffer, &mut b, value )`, as the C# port does. `buffer - start` is `b - start`.
      - Packets are passed as `void *` upstream, with the packet type in the first byte. Here every packet struct
        implements the netcode_packet_t trait: packet_type() is that byte, and where C casts the pointer to a packet
        struct the port downcasts with as_any() / into_any().
      - Allocator callbacks stay in the configs, the packet queue and the network simulator, with the same defaulting,
        but packets and buffers are Box / Vec, as the C# port does. Box and Vec do not fail, so upstream's "could not
        allocate" branches have no Rust counterpart.
      - The sockets are std::net::UdpSocket (non-blocking). The socket is created with socket() and bound with bind()
        over a few lines of FFI, because SO_SNDBUF, SO_RCVBUF and IPV6_V6ONLY must be set before bind, which std
        cannot do. Send, receive, getsockname and non-blocking io use std.
      - The globals (init state, log level, printf and assert hooks) are a static mut, atomics and mutexes; netcode is
        single-threaded by design, as upstream.
*/

use crate::sodium::*;
use std::any::Any;
use std::ffi::c_void;
use std::net::{ Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket };
use std::sync::atomic::{ AtomicI32, AtomicUsize, Ordering };
use std::sync::Mutex;

// =====================================================================================================================
//      netcode.h
// =====================================================================================================================

pub const NETCODE_VERSION_FULL: &str = "1.4.8";
pub const NETCODE_VERSION_MAJOR: i32 = 1;
pub const NETCODE_VERSION_MINOR: i32 = 4;
pub const NETCODE_VERSION_PATCH: i32 = 8;

/*
    IMPORTANT: netcode is single-threaded by design and is not thread safe.

    The library uses global state (netcode_init/netcode_term, the log level, and the
    printf and assert hooks) and performs no internal synchronization. Call all netcode
    functions from the same thread, or provide your own locking around them. Each client
    and server object must only be updated from one thread at a time.
*/

// port: NETCODE_DEBUG / NETCODE_RELEASE follow cfg(debug_assertions), upstream's NDEBUG
#[cfg(debug_assertions)]
pub const NETCODE_DEBUG: i32 = 1;
#[cfg(not(debug_assertions))]
pub const NETCODE_RELEASE: i32 = 1;

// port: the list of little endian architecture macros is cfg(target_endian)
#[cfg(target_endian = "little")]
pub const NETCODE_LITTLE_ENDIAN: i32 = 1;
#[cfg(target_endian = "big")]
pub const NETCODE_BIG_ENDIAN: i32 = 1;

pub const NETCODE_PLATFORM_WINDOWS: i32 = 1;
pub const NETCODE_PLATFORM_MAC: i32 = 2;
pub const NETCODE_PLATFORM_UNIX: i32 = 3;

#[cfg(windows)]
pub const NETCODE_PLATFORM: i32 = NETCODE_PLATFORM_WINDOWS;
#[cfg(target_vendor = "apple")]
pub const NETCODE_PLATFORM: i32 = NETCODE_PLATFORM_MAC;
#[cfg(not(any(windows, target_vendor = "apple")))]
pub const NETCODE_PLATFORM: i32 = NETCODE_PLATFORM_UNIX;

pub const NETCODE_CONNECT_TOKEN_BYTES: i32 = 2048;
pub const NETCODE_KEY_BYTES: i32 = 32;
pub const NETCODE_MAC_BYTES: i32 = 16;
pub const NETCODE_USER_DATA_BYTES: i32 = 256;
pub const NETCODE_MAX_SERVERS_PER_CONNECT: i32 = 32;
pub const NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME: i32 = 30;

pub const NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED: i32 = -6;
pub const NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN: i32 = -5;
pub const NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT: i32 = -4;
pub const NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT: i32 = -3;
pub const NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT: i32 = -2;
pub const NETCODE_CLIENT_STATE_CONNECTION_DENIED: i32 = -1;
pub const NETCODE_CLIENT_STATE_DISCONNECTED: i32 = 0;
pub const NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST: i32 = 1;
pub const NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE: i32 = 2;
pub const NETCODE_CLIENT_STATE_CONNECTED: i32 = 3;

// The reason the client in a server slot was last disconnected. Tracked per-client slot:
// reset to NONE when the server starts and when a new client connects to the slot, and
// recorded before the connect_disconnect_callback fires, so it can be queried from inside
// that callback via netcode_server_client_disconnect_reason.
pub const NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE: i32 = 0;
pub const NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT: i32 = 1;
pub const NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT: i32 = 2;
pub const NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT: i32 = 3;

pub const NETCODE_CLIENT_CREATE_ERROR_NONE: i32 = 0;
pub const NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED: i32 = 1;
pub const NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED: i32 = 2;
pub const NETCODE_CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT: i32 = 3;
pub const NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED: i32 = 4;
pub const NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED: i32 = 5;
pub const NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED: i32 = 6;
pub const NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK: i32 = 7;

pub const NETCODE_SERVER_CREATE_ERROR_NONE: i32 = 0;
pub const NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED: i32 = 1;
pub const NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED: i32 = 2;
pub const NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED: i32 = 3;
pub const NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED: i32 = 4;
pub const NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED: i32 = 5;
pub const NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED: i32 = 6;
pub const NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED: i32 = 7;
pub const NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK: i32 = 8;

pub const NETCODE_MAX_CLIENTS: i32 = 256;
pub const NETCODE_MAX_PACKET_SIZE: i32 = 1200;

pub const NETCODE_MAX_ADDRESS_STRING_LENGTH: i32 = 256;

pub const NETCODE_LOG_LEVEL_NONE: i32 = 0;
pub const NETCODE_LOG_LEVEL_ERROR: i32 = 1;
pub const NETCODE_LOG_LEVEL_INFO: i32 = 2;
pub const NETCODE_LOG_LEVEL_DEBUG: i32 = 3;

pub const NETCODE_OK: i32 = 1;
pub const NETCODE_ERROR: i32 = 0;

// port: u8, the type of netcode_address_t::type that they are stored in and compared with
pub const NETCODE_ADDRESS_NONE: u8 = 0;
pub const NETCODE_ADDRESS_IPV4: u8 = 1;
pub const NETCODE_ADDRESS_IPV6: u8 = 2;

// port: NETCODE_CONST has no Rust meaning (`&` is const, `&mut` is not)

// port: int netcode_init(); void netcode_term(); are defined below

#[cfg(not(all(windows, target_env = "gnu")))]
pub const NETCODE_PACKET_TAGGING: i32 = 1;
// At least as of version 14.2.0, the Qwave library is not properly implemented
// in MingW-w64, so packet tagging is disabled by default.
#[cfg(all(windows, target_env = "gnu"))]
pub const NETCODE_PACKET_TAGGING: i32 = 0;

// port: void netcode_enable_packet_tagging(); is defined below

// port: the C union { uint8_t ipv4[4]; uint16_t ipv6[8]; } data. Rust keeps both members side by side; only the one
// named by type is meaningful, as upstream.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct netcode_address_data_t
{
    pub ipv4: [u8; 4],
    pub ipv6: [u16; 8],
}

#[derive(Clone, Copy, Default, Debug)]
pub struct netcode_address_t
{
    pub data: netcode_address_data_t,
    pub port: u16,
    pub r#type: u8,
}

// port: netcode_parse_address, netcode_address_to_string and netcode_address_equal are defined below

/*
    Writes the address into buffer in its printable form and returns buffer. The buffer must
    be at least NETCODE_MAX_ADDRESS_STRING_LENGTH bytes. The result is always null terminated,
    and is truncated to fit rather than overflowing the buffer.
*/

// port: C function pointers are Option<fn>: allocate_function is void * (*)(void*,size_t), free_function is
// void (*)(void*,void*). network_simulator is a non-owning pointer, as upstream (one simulator is shared by a server
// and its clients); null for none. Buffer parameters of the callbacks are slices.
#[derive(Clone, Copy)]
pub struct netcode_client_config_t
{
    pub allocator_context: *mut c_void,
    pub allocate_function: Option<fn( *mut c_void, usize ) -> *mut c_void>,
    pub free_function: Option<fn( *mut c_void, *mut c_void )>,
    pub network_simulator: *mut netcode_network_simulator_t,
    pub callback_context: *mut c_void,
    pub state_change_callback: Option<fn( *mut c_void, i32, i32 )>,
    pub send_loopback_packet_callback: Option<fn( *mut c_void, i32, &[u8], i32, u64 )>,
    pub override_send_and_receive: i32,
    pub send_packet_override: Option<fn( *mut c_void, &netcode_address_t, &[u8], i32 )>,
    pub receive_packet_override: Option<fn( *mut c_void, &mut netcode_address_t, &mut [u8], i32 ) -> i32>,
}

// port: the zeroed struct (C leaves it to netcode_default_client_config)
impl Default for netcode_client_config_t
{
    fn default() -> Self
    {
        netcode_client_config_t
        {
            allocator_context: std::ptr::null_mut(),
            allocate_function: None,
            free_function: None,
            network_simulator: std::ptr::null_mut(),
            callback_context: std::ptr::null_mut(),
            state_change_callback: None,
            send_loopback_packet_callback: None,
            override_send_and_receive: 0,
            send_packet_override: None,
            receive_packet_override: None,
        }
    }
}

// port: netcode_default_client_config ... netcode_generate_connect_token are defined below, where netcode.c defines them

#[derive(Clone, Copy)]
pub struct netcode_server_config_t
{
    pub protocol_id: u64,
    pub private_key: [u8; NETCODE_KEY_BYTES as usize],
    pub allocator_context: *mut c_void,
    pub allocate_function: Option<fn( *mut c_void, usize ) -> *mut c_void>,
    pub free_function: Option<fn( *mut c_void, *mut c_void )>,
    pub network_simulator: *mut netcode_network_simulator_t,
    pub callback_context: *mut c_void,
    pub connect_disconnect_callback: Option<fn( *mut c_void, i32, i32 )>,
    pub send_loopback_packet_callback: Option<fn( *mut c_void, i32, &[u8], i32, u64 )>,
    pub override_send_and_receive: i32,
    pub send_packet_override: Option<fn( *mut c_void, &netcode_address_t, &[u8], i32 )>,
    pub receive_packet_override: Option<fn( *mut c_void, &mut netcode_address_t, &mut [u8], i32 ) -> i32>,
    pub max_connect_token_lifetime: i32,
}

// port: the zeroed struct (C leaves it to netcode_default_server_config)
impl Default for netcode_server_config_t
{
    fn default() -> Self
    {
        netcode_server_config_t
        {
            protocol_id: 0,
            private_key: [0; NETCODE_KEY_BYTES as usize],
            allocator_context: std::ptr::null_mut(),
            allocate_function: None,
            free_function: None,
            network_simulator: std::ptr::null_mut(),
            callback_context: std::ptr::null_mut(),
            connect_disconnect_callback: None,
            send_loopback_packet_callback: None,
            override_send_and_receive: 0,
            send_packet_override: None,
            receive_packet_override: None,
            max_connect_token_lifetime: 0,
        }
    }
}

/*
    max_connect_token_lifetime is the longest lifetime in seconds that the backend issues
    connect tokens with, as passed to netcode_generate_connect_token. The server ignores any
    connection request whose connect token expire timestamp minus this lifetime is earlier
    than the time the server started, so a connect token that could have been issued before
    the server started cannot be presented after it. Set it to the lifetime your backend
    issues: a larger value rejects legitimate connect tokens until the difference has elapsed,
    and a smaller value lets connect tokens issued shortly before the server started through.
    A value of zero or less takes NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME instead.
*/

// port: netcode_default_server_config ... netcode_server_get_port are defined below, where netcode.c defines them

// port: netcode_log_level, netcode_set_printf_function and netcode_assert_function are defined below

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! netcode_assert {
    ( $condition:expr ) => {{
        if !( $condition )
        {
            // port: __FUNCTION__ is the type name of a local fn, less its own name
            fn __netcode_f() {}
            let name = ::core::any::type_name_of_val( &__netcode_f );
            let function = &name[..name.len() - "::__netcode_f".len()];
            $crate::netcode::netcode_assert_function_call( ::core::stringify!( $condition ), function, ::core::file!(), ::core::line!() as i32 );
        }
    }};
}

// port: in release the condition is not compiled, as upstream's ((void)0)
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! netcode_assert {
    ( $condition:expr ) => {{}};
}

/*
    The default assert handler prints the failed condition, breaks into the debugger and
    exits. A custom assert handler may return instead, in which case execution continues
    past the failed assert -- that is the caller's choice and their responsibility.
*/

// port: netcode_set_assert_function, netcode_random_bytes are defined below. netcode_sleep and netcode_time are
// defined below, where netcode.c defines them

// =====================================================================================================================
//      netcode.c
// =====================================================================================================================

// port: #include <sodium.h> is `use crate::sodium::*` above

pub const NETCODE_SOCKET_IPV6: i32 = 1;
pub const NETCODE_SOCKET_IPV4: i32 = 2;

pub const NETCODE_CONNECT_TOKEN_NONCE_BYTES: i32 = 24;
pub const NETCODE_CONNECT_TOKEN_PRIVATE_BYTES: i32 = 1024;
pub const NETCODE_CHALLENGE_TOKEN_BYTES: i32 = 300;
pub const NETCODE_VERSION_INFO_BYTES: i32 = 13;
pub const NETCODE_MAX_PACKET_BYTES: i32 = 1300;
pub const NETCODE_MAX_PAYLOAD_BYTES: i32 = 1200;
pub const NETCODE_PACKET_QUEUE_SIZE: i32 = 256;
pub const NETCODE_REPLAY_PROTECTION_BUFFER_SIZE: i32 = 256;
pub const NETCODE_CLIENT_MAX_RECEIVE_PACKETS: i32 = 64;
pub const NETCODE_SERVER_MAX_RECEIVE_PACKETS: i32 = 64 * NETCODE_MAX_CLIENTS;
pub const NETCODE_CLIENT_SOCKET_SNDBUF_SIZE: i32 = 4 * 1024 * 1024;
pub const NETCODE_CLIENT_SOCKET_RCVBUF_SIZE: i32 = 4 * 1024 * 1024;
pub const NETCODE_SERVER_SOCKET_SNDBUF_SIZE: i32 = 4 * 1024 * 1024;
pub const NETCODE_SERVER_SOCKET_RCVBUF_SIZE: i32 = 4 * 1024 * 1024;

// port: ( (uint8_t*) "NETCODE 1.02" ), with the string's terminating null (NETCODE_VERSION_INFO_BYTES)
pub const NETCODE_VERSION_INFO: &[u8; 13] = b"NETCODE 1.02\0";
pub const NETCODE_PACKET_SEND_RATE: f64 = 10.0;
pub const NETCODE_NUM_DISCONNECT_PACKETS: i32 = 10;

// port: the tests are always compiled (netcode_test, run by test.rs)
pub const NETCODE_ENABLE_TESTS: i32 = 1;

pub const NETCODE_ENABLE_LOGGING: i32 = 1;

// port: the NETCODE_NONCE_AUDIT build option is this const (upstream: NETCODE_ENABLE_NONCE_AUDIT, off by default)
pub const NETCODE_ENABLE_NONCE_AUDIT: i32 = 0;

// ------------------------------------------------------------------

#[cfg(not(all(windows, target_env = "gnu")))]
static netcode_packet_tagging_enabled: AtomicI32 = AtomicI32::new( 0 );

#[cfg(not(all(windows, target_env = "gnu")))]
pub fn netcode_enable_packet_tagging()
{
    netcode_packet_tagging_enabled.store( 1, Ordering::Relaxed );
}

#[cfg(all(windows, target_env = "gnu"))]
pub fn netcode_enable_packet_tagging() {}

// ------------------------------------------------------------------

fn netcode_default_assert_handler( condition: &str, function: &str, file: &str, line: i32 )
{
    print!( "assert failed: ( {} ), function {}, file {}, line {}\n", condition, function, file, line );
    // port: __builtin_trap() / __debugbreak(); exit( 1 )
    panic!( "assert failed: ( {} ), function {}, file {}, line {}", condition, function, file, line );
}

// port: upstream's printf; the hook receives the formatted text
fn printf( s: &str )
{
    print!( "{}", s );
}

static log_level: AtomicI32 = AtomicI32::new( 0 );
static printf_function: Mutex<fn( &str )> = Mutex::new( printf );
/// port: upstream's `void (*netcode_assert_function)(...)`, behind a mutex. netcode_assert! calls it through
/// netcode_assert_function_call.
pub static netcode_assert_function: Mutex<fn( &str, &str, &str, i32 )> = Mutex::new( netcode_default_assert_handler );

/// port: calls the current assert function (upstream calls the netcode_assert_function pointer directly)
pub fn netcode_assert_function_call( condition: &str, function: &str, file: &str, line: i32 )
{
    let function_ptr = *netcode_assert_function.lock().unwrap_or_else( |e| e.into_inner() );
    function_ptr( condition, function, file, line );
}

pub fn netcode_log_level( level: i32 )
{
    log_level.store( level, Ordering::Relaxed );
}

pub fn netcode_set_printf_function( function: fn( &str ) )
{
    // port: netcode_assert( function ) -- a Rust fn pointer is never null
    *printf_function.lock().unwrap_or_else( |e| e.into_inner() ) = function;
}

pub fn netcode_set_assert_function( function: fn( &str, &str, &str, i32 ) )
{
    *netcode_assert_function.lock().unwrap_or_else( |e| e.into_inner() ) = function;
}

#[macro_export]
macro_rules! netcode_printf {
    ( $level:expr, $($arg:tt)* ) => {
        $crate::netcode::netcode_printf( ( $level ) as i32, ::core::format_args!( $($arg)* ) )
    };
}

/// port: the function behind netcode_printf!; takes the format_args! in place of a printf format and varargs.
/// `#if NETCODE_ENABLE_LOGGING` is a const test.
pub fn netcode_printf( level: i32, args: std::fmt::Arguments )
{
    if NETCODE_ENABLE_LOGGING == 0
    {
        return;
    }
    if level > log_level.load( Ordering::Relaxed )
    {
        return;
    }
    // port: vsnprintf into char buffer[4*1024], truncated to fit
    let mut buffer = std::fmt::format( args );
    if buffer.len() > 4 * 1024 - 1
    {
        let mut end = 4 * 1024 - 1;
        while !buffer.is_char_boundary( end )
        {
            end -= 1;
        }
        buffer.truncate( end );
    }
    let function = *printf_function.lock().unwrap_or_else( |e| e.into_inner() );
    function( &buffer );
}

// port: malloc and free from the C runtime std links on every platform
mod netcode_crt
{
    use std::ffi::c_void;
    extern "C"
    {
        pub fn malloc( size: usize ) -> *mut c_void;
        pub fn free( p: *mut c_void );
    }
}

pub fn netcode_default_allocate_function( context: *mut c_void, bytes: usize ) -> *mut c_void
{
    let _ = context;
    unsafe { netcode_crt::malloc( bytes ) }
}

pub fn netcode_default_free_function( context: *mut c_void, pointer: *mut c_void )
{
    let _ = context;
    unsafe { netcode_crt::free( pointer ) }
}

// ------------------------------------------------------------------

// port: the platform headers (winsock2.h / sys/socket.h ...). Only the calls std cannot make are declared: socket,
// setsockopt and bind (plus WSAStartup / WSACleanup / WSAIoctl and qWAVE on Windows). Constants are each platform's.

#[cfg(windows)]
pub mod netcode_ffi
{
    use std::ffi::c_void;

    pub type SOCKET = usize;
    pub type socklen_t = i32;
    pub type netcode_raw_socket_t = SOCKET;

    pub const INVALID_SOCKET: SOCKET = !0;
    pub const NO_ERROR: i32 = 0;
    pub const AF_INET: i32 = 2;
    pub const AF_INET6: i32 = 23;
    pub const SOCK_DGRAM: i32 = 2;
    pub const IPPROTO_IP: i32 = 0;
    pub const IPPROTO_UDP: i32 = 17;
    pub const IPPROTO_IPV6: i32 = 41;
    pub const IPV6_V6ONLY: i32 = 27;
    pub const SOL_SOCKET: i32 = 0xffff;
    pub const SO_SNDBUF: i32 = 0x1001;
    pub const SO_RCVBUF: i32 = 0x1002;
    pub const IOC_IN: u32 = 0x80000000;
    pub const IOC_VENDOR: u32 = 0x18000000;

    #[allow(non_snake_case)]
    pub const fn _WSAIOW( x: u32, y: u32 ) -> u32
    {
        IOC_IN | x | y
    }

    pub const fn MAKEWORD( a: u8, b: u8 ) -> u16
    {
        ( a as u16 ) | ( ( b as u16 ) << 8 )
    }

    // port: opaque, at least as large as the real WSADATA on 32 and 64 bit
    #[repr(C, align(8))]
    pub struct WSADATA
    {
        pub data: [u8; 512],
    }

    #[link(name = "ws2_32")]
    extern "system"
    {
        pub fn WSAStartup( wVersionRequested: u16, lpWSAData: *mut WSADATA ) -> i32;
        pub fn WSACleanup() -> i32;
        pub fn socket( af: i32, r#type: i32, protocol: i32 ) -> SOCKET;
        pub fn setsockopt( s: SOCKET, level: i32, optname: i32, optval: *const c_void, optlen: i32 ) -> i32;
        pub fn bind( s: SOCKET, name: *const c_void, namelen: i32 ) -> i32;
        pub fn WSAIoctl( s: SOCKET, dwIoControlCode: u32, lpvInBuffer: *mut c_void, cbInBuffer: u32, lpvOutBuffer: *mut c_void, cbOutBuffer: u32,
                         lpcbBytesReturned: *mut u32, lpOverlapped: *mut c_void, lpCompletionRoutine: *mut c_void ) -> i32;
    }

    // qos2.h
    #[cfg(not(target_env = "gnu"))]
    pub mod qos
    {
        use std::ffi::c_void;

        pub type HANDLE = *mut c_void;
        pub type QOS_FLOWID = u32;
        pub type QOS_TRAFFIC_TYPE = i32;

        #[repr(C)]
        pub struct QOS_VERSION
        {
            pub MajorVersion: u16,
            pub MinorVersion: u16,
        }

        pub const QOSTrafficTypeAudioVideo: QOS_TRAFFIC_TYPE = 3;
        pub const QOS_NON_ADAPTIVE_FLOW: u32 = 0x00000002;

        #[link(name = "qwave")]
        extern "system"
        {
            pub fn QOSCreateHandle( Version: *const QOS_VERSION, QOSHandle: *mut HANDLE ) -> i32;
            pub fn QOSAddSocketToFlow( QOSHandle: HANDLE, Socket: super::SOCKET, DestAddr: *const c_void, TrafficType: QOS_TRAFFIC_TYPE, Flags: u32, FlowId: *mut QOS_FLOWID ) -> i32;
        }
    }
}

// port: the constants are those of Linux / Android (x86, arm, riscv, powerpc), Apple platforms and FreeBSD
#[cfg(unix)]
pub mod netcode_ffi
{
    use std::ffi::{ c_int, c_void };

    pub type socklen_t = u32;
    pub type netcode_raw_socket_t = c_int;

    pub const AF_INET: i32 = 2;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const AF_INET6: i32 = 10;
    #[cfg(target_vendor = "apple")]
    pub const AF_INET6: i32 = 30;
    #[cfg(target_os = "freebsd")]
    pub const AF_INET6: i32 = 28;
    pub const SOCK_DGRAM: i32 = 2;
    pub const IPPROTO_IP: i32 = 0;
    pub const IPPROTO_UDP: i32 = 17;
    pub const IPPROTO_IPV6: i32 = 41;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod values
    {
        pub const SOL_SOCKET: i32 = 1;
        pub const SO_SNDBUF: i32 = 7;
        pub const SO_RCVBUF: i32 = 8;
        pub const IPV6_V6ONLY: i32 = 26;
        pub const IP_TOS: i32 = 1;
        pub const IPV6_TCLASS: i32 = 67;
    }

    #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
    mod values
    {
        pub const SOL_SOCKET: i32 = 0xffff;
        pub const SO_SNDBUF: i32 = 0x1001;
        pub const SO_RCVBUF: i32 = 0x1002;
        pub const IPV6_V6ONLY: i32 = 27;
        pub const IP_TOS: i32 = 3;
        #[cfg(target_vendor = "apple")]
        pub const IPV6_TCLASS: i32 = 36;
        #[cfg(target_os = "freebsd")]
        pub const IPV6_TCLASS: i32 = 61;
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", target_os = "freebsd")))]
    compile_error!( "netcode - unknown platform!" );

    pub use values::*;

    // port: struct sockaddr starts with sa_len on the BSDs (and Apple platforms), before a one byte sa_family
    pub const SOCKADDR_HAS_LEN: bool = cfg!( any(target_vendor = "apple", target_os = "freebsd") );

    extern "C"
    {
        pub fn socket( domain: c_int, r#type: c_int, protocol: c_int ) -> c_int;
        pub fn setsockopt( socket: c_int, level: c_int, name: c_int, value: *const c_void, option_len: socklen_t ) -> c_int;
        pub fn bind( socket: c_int, address: *const c_void, address_len: socklen_t ) -> c_int;
    }
}

use netcode_ffi::socklen_t;

// port: struct sockaddr_storage, as bytes. netcode_address_to_sockaddr writes the platform's sockaddr_in /
// sockaddr_in6 layout into it for bind (and qWAVE); std hands received and local addresses back as SocketAddr.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct sockaddr_storage
{
    pub ss_data: [u8; 128],
}

impl Default for sockaddr_storage
{
    fn default() -> Self
    {
        sockaddr_storage { ss_data: [0; 128] }
    }
}

// port: writes ss_family (and ss_len on the BSDs) at the start of the sockaddr
fn netcode_sockaddr_set_family( sockaddr: &mut sockaddr_storage, family: i32, length: usize )
{
    #[cfg(unix)]
    if netcode_ffi::SOCKADDR_HAS_LEN
    {
        sockaddr.ss_data[0] = length as u8;
        sockaddr.ss_data[1] = family as u8;
        return;
    }
    let _ = length;
    sockaddr.ss_data[0..2].copy_from_slice( &( family as u16 ).to_ne_bytes() );
}

// port: htons / htonl
fn htons( value: u16 ) -> u16 { value.to_be() }
fn htonl( value: u32 ) -> u32 { value.to_be() }

// port: strlen of a null terminated string in a byte buffer (or the whole buffer when it has no null)
fn netcode_strlen( string: &[u8] ) -> usize
{
    string.iter().position( |&c| c == 0 ).unwrap_or( string.len() )
}

// port: a null terminated string in a byte buffer as &str. A string that is not UTF-8 is not a valid address or port
// either, so it reads as the empty string, which every parser here rejects.
fn netcode_cstr( string: &[u8] ) -> &str
{
    std::str::from_utf8( &string[..netcode_strlen( string )] ).unwrap_or( "" )
}

pub fn netcode_parse_port( string: &str, port: &mut u16 ) -> i32
{
    // the port must be all digits and fit in [0,65535]. anything else is an error,
    // rather than whatever atoi truncation used to produce.

    let string = string.as_bytes();

    if string.is_empty() || string[0] == b'\0'
    {
        return NETCODE_ERROR;
    }

    let mut value: i32 = 0;
    let mut i = 0;
    while i < string.len() && string[i] != b'\0'
    {
        if string[i] < b'0' || string[i] > b'9'
        {
            return NETCODE_ERROR;
        }
        value = value * 10 + ( string[i] - b'0' ) as i32;
        if value > 65535
        {
            return NETCODE_ERROR;
        }
        i += 1;
    }

    *port = value as u16;

    NETCODE_OK
}

pub fn netcode_parse_address( address_string_in: &str, address: &mut netcode_address_t ) -> i32
{
    *address = netcode_address_t::default();

    // first try to parse the string as an IPv6 address:
    // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
    // 2. otherwise try to parse as a raw IPv6 address using inet_pton

    let mut buffer = [0u8; NETCODE_MAX_ADDRESS_STRING_LENGTH as usize];

    // port: char * address_string = buffer; address_string is an index into buffer
    let mut address_string: usize = 0;
    // port: strncpy( address_string, address_string_in, NETCODE_MAX_ADDRESS_STRING_LENGTH - 1 )
    {
        let input = address_string_in.as_bytes();
        let mut i = 0;
        while i < input.len() && i < ( NETCODE_MAX_ADDRESS_STRING_LENGTH - 1 ) as usize && input[i] != b'\0'
        {
            buffer[i] = input[i];
            i += 1;
        }
    }
    buffer[( NETCODE_MAX_ADDRESS_STRING_LENGTH - 1 ) as usize] = b'\0';

    let mut address_string_length = netcode_strlen( &buffer[address_string..] ) as i32;

    if buffer[address_string] == b'['
    {
        let base_index = address_string_length - 1;

        for i in 0..6         // note: no need to search past 6 characters as ":65535" is longest possible port value
        {
            let index = base_index - i;
            if index < 3
            {
                break;
            }
            if buffer[index as usize] == b':' && buffer[( index - 1 ) as usize] == b']'
            {
                if netcode_parse_port( netcode_cstr( &buffer[( index + 1 ) as usize..] ), &mut address.port ) != NETCODE_OK
                {
                    return NETCODE_ERROR;
                }
                buffer[( index - 1 ) as usize] = b'\0';
                break;
            }
        }

        // if a port is omitted, it is assumed to be zero. strip the trailing ']' so "[addr]" parses as just the address

        if buffer[base_index as usize] == b']'
        {
            buffer[base_index as usize] = b'\0';
        }

        address_string += 1;
    }

    // port: inet_pton( AF_INET6 ) is Ipv6Addr's parser, which accepts the same text (no brackets, ports or scope ids)
    if let Ok( sockaddr6 ) = netcode_cstr( &buffer[address_string..] ).parse::<Ipv6Addr>()
    {
        address.r#type = NETCODE_ADDRESS_IPV6;
        // port: memcpy( ipv6_network_order, &sockaddr6 ) then ntohs: Ipv6Addr::segments() is already host order
        let ipv6_host_order = sockaddr6.segments();
        for i in 0..8
        {
            address.data.ipv6[i] = ipv6_host_order[i];
        }
        return NETCODE_OK;
    }

    // otherwise it's probably an IPv4 address:
    // 1. look for ":portnum", if found save the portnum and strip it out
    // 2. parse remaining ipv4 address via inet_pton

    address_string_length = netcode_strlen( &buffer[address_string..] ) as i32;
    let base_index = address_string_length - 1;
    for i in 0..6
    {
        let index = base_index - i;
        if index < 0
        {
            break;
        }
        if buffer[address_string + index as usize] == b':'
        {
            if netcode_parse_port( netcode_cstr( &buffer[address_string + ( index + 1 ) as usize..] ), &mut address.port ) != NETCODE_OK
            {
                return NETCODE_ERROR;
            }
            buffer[address_string + index as usize] = b'\0';
            break;
        }
    }

    // port: inet_pton( AF_INET ) is Ipv4Addr's parser: four dotted decimal octets, as inet_pton
    if let Ok( sockaddr4 ) = netcode_cstr( &buffer[address_string..] ).parse::<Ipv4Addr>()
    {
        address.r#type = NETCODE_ADDRESS_IPV4;
        // port: ntohl( sockaddr4.sin_addr.s_addr ): u32::from( Ipv4Addr ) is already host order
        let ipv4_host_order: u32 = u32::from( sockaddr4 );
        address.data.ipv4[0] = ( ( ipv4_host_order >> 24 ) & 0xFF ) as u8;
        address.data.ipv4[1] = ( ( ipv4_host_order >> 16 ) & 0xFF ) as u8;
        address.data.ipv4[2] = ( ( ipv4_host_order >> 8  ) & 0xFF ) as u8;
        address.data.ipv4[3] = ( ( ipv4_host_order       ) & 0xFF ) as u8;
        return NETCODE_OK;
    }

    NETCODE_ERROR
}

// port: returns the string in place of writing it into a char buffer[NETCODE_MAX_ADDRESS_STRING_LENGTH] (README.md,
// "Strings"). The text is never longer than NETCODE_MAX_ADDRESS_STRING_LENGTH - 1, so nothing is truncated.
pub fn netcode_address_to_string( address: &netcode_address_t ) -> String
{
    if address.r#type == NETCODE_ADDRESS_IPV6
    {
        // port: htons into ipv6_network_order, memcpy into sockaddr6 and inet_ntop( AF_INET6 ): Ipv6Addr's Display
        // writes the RFC 5952 form as inet_ntop does (except "::a.b.c.d" for IPv4 compatible addresses, which it
        // writes in hex)
        let sockaddr6 = Ipv6Addr::from( address.data.ipv6 );
        if address.port == 0
        {
            format!( "{}", sockaddr6 )
        }
        else
        {
            let address_string = format!( "{}", sockaddr6 );
            format!( "[{}]:{}", address_string, address.port )
        }
    }
    else if address.r#type == NETCODE_ADDRESS_IPV4
    {
        if address.port != 0
        {
            format!( "{}.{}.{}.{}:{}",
                address.data.ipv4[0],
                address.data.ipv4[1],
                address.data.ipv4[2],
                address.data.ipv4[3],
                address.port )
        }
        else
        {
            format!( "{}.{}.{}.{}",
                address.data.ipv4[0],
                address.data.ipv4[1],
                address.data.ipv4[2],
                address.data.ipv4[3] )
        }
    }
    else
    {
        format!( "{}", "NONE" )
    }
}

pub fn netcode_address_equal( a: &netcode_address_t, b: &netcode_address_t ) -> i32
{
    if a.r#type != b.r#type
    {
        return 0;
    }

    if a.port != b.port
    {
        return 0;
    }

    if a.r#type == NETCODE_ADDRESS_IPV4
    {
        for i in 0..4
        {
            if a.data.ipv4[i] != b.data.ipv4[i]
            {
                return 0;
            }
        }
    }
    else if a.r#type == NETCODE_ADDRESS_IPV6
    {
        for i in 0..8
        {
            if a.data.ipv6[i] != b.data.ipv6[i]
            {
                return 0;
            }
        }
    }
    else
    {
        return 0;
    }

    1
}

// ----------------------------------------------------------------

pub struct netcode_t
{
    pub initialized: i32,
}

// port: static mut, as upstream's static struct. netcode is single-threaded by design.
pub static mut netcode: netcode_t = netcode_t { initialized: 0 };

pub fn netcode_init() -> i32
{
    // reference counted so multiple subsystems in the same application can call
    // netcode_init and netcode_term independently

    unsafe
    {
        if netcode.initialized != 0
        {
            netcode.initialized += 1;
            return NETCODE_OK;
        }
    }

    #[cfg(windows)]
    {
        let mut WsaData = netcode_ffi::WSADATA { data: [0; 512] };
        if unsafe { netcode_ffi::WSAStartup( netcode_ffi::MAKEWORD( 2, 2 ), &mut WsaData ) } != netcode_ffi::NO_ERROR
        {
            return NETCODE_ERROR;
        }
    }

    if sodium_init() == -1
    {
        return NETCODE_ERROR;
    }

    unsafe { netcode.initialized = 1; }

    NETCODE_OK
}

pub fn netcode_term()
{
    netcode_assert!( unsafe { netcode.initialized } != 0 );

    unsafe
    {
        if netcode.initialized == 0
        {
            return;
        }

        netcode.initialized -= 1;

        if netcode.initialized != 0
        {
            return;
        }
    }

    #[cfg(windows)]
    unsafe
    {
        netcode_ffi::WSACleanup();
    }
}

// ----------------------------------------------------------------

// port: the socket handle (uint32_t on Windows, size_t elsewhere) is the std::net::UdpSocket that owns the socket.
// None is upstream's handle 0. Dropping it closes the socket.
pub type netcode_socket_handle_t = Option<UdpSocket>;

#[derive(Default, Debug)]
pub struct netcode_socket_t
{
    pub address: netcode_address_t,
    pub handle: netcode_socket_handle_t,
}

#[derive(Default, Debug)]
pub struct netcode_socket_holder_t
{
    pub ipv4: netcode_socket_t,
    pub ipv6: netcode_socket_t,
}

pub const NETCODE_SOCKET_ERROR_NONE: i32 = 0;
pub const NETCODE_SOCKET_ERROR_CREATE_FAILED: i32 = 1;
pub const NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED: i32 = 2;
pub const NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED: i32 = 3;
pub const NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED: i32 = 4;
pub const NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED: i32 = 5;
pub const NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED: i32 = 6;
pub const NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED: i32 = 7;
pub const NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED: i32 = 8;
pub const NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED: i32 = 9;
pub const NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED: i32 = 10;
pub const NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED: i32 = 11;

pub fn netcode_socket_destroy( socket: &mut netcode_socket_t )
{
    netcode_assert!( unsafe { netcode.initialized } != 0 );

    if socket.handle.is_some()
    {
        // port: close( socket->handle ) / closesocket( socket->handle ): dropping the UdpSocket closes it
        socket.handle = None;
    }
}

#[cfg(all(windows, not(target_env = "gnu")))]
pub fn netcode_set_socket_codepoint( socket: netcode_ffi::SOCKET, trafficType: netcode_ffi::qos::QOS_TRAFFIC_TYPE, flowId: netcode_ffi::qos::QOS_FLOWID, addr: &sockaddr_storage ) -> i32
{
    use netcode_ffi::qos::*;

    // IMPORTANT: closing the QOS handle removes all flows added on it, so we create one handle
    // on first use and share it across all sockets for the lifetime of the process.

    // port: static HANDLE qosHandle, as an atomic
    static qosHandle: AtomicUsize = AtomicUsize::new( 0 );
    if qosHandle.load( Ordering::Relaxed ) == 0
    {
        let QosVersion = QOS_VERSION { MajorVersion: 1, MinorVersion: 0 };
        let mut handle: HANDLE = std::ptr::null_mut();
        if unsafe { QOSCreateHandle( &QosVersion, &mut handle ) } == 0
        {
            qosHandle.store( 0, Ordering::Relaxed );
            // port: GetLastError()
            return std::io::Error::last_os_error().raw_os_error().unwrap_or( 0 );
        }
        qosHandle.store( handle as usize, Ordering::Relaxed );
    }
    let mut flowId = flowId;
    if unsafe { QOSAddSocketToFlow( qosHandle.load( Ordering::Relaxed ) as HANDLE, socket, addr.ss_data.as_ptr() as *const c_void, trafficType, QOS_NON_ADAPTIVE_FLOW, &mut flowId ) } == 0
    {
        return std::io::Error::last_os_error().raw_os_error().unwrap_or( 0 );
    }
    0
}

pub fn netcode_address_to_sockaddr( address: &netcode_address_t, sockaddr: &mut sockaddr_storage ) -> socklen_t
{
    netcode_assert!( address.r#type == NETCODE_ADDRESS_IPV4 || address.r#type == NETCODE_ADDRESS_IPV6 );

    *sockaddr = sockaddr_storage::default();

    // port: the fields of struct sockaddr_in6 / sockaddr_in are written at their offsets in sockaddr->ss_data

    if address.r#type == NETCODE_ADDRESS_IPV6
    {
        // struct sockaddr_in6: family, sin6_port (2), sin6_flowinfo (4), sin6_addr (8), sin6_scope_id (24). 28 bytes.
        netcode_sockaddr_set_family( sockaddr, netcode_ffi::AF_INET6, 28 );
        let mut ipv6_network_order = [0u16; 8];
        for i in 0..8
        {
            ipv6_network_order[i] = htons( address.data.ipv6[i] );
        }
        for i in 0..8
        {
            sockaddr.ss_data[8 + i * 2..8 + i * 2 + 2].copy_from_slice( &ipv6_network_order[i].to_ne_bytes() );
        }
        sockaddr.ss_data[2..4].copy_from_slice( &htons( address.port ).to_ne_bytes() );
        28
    }
    else
    {
        // struct sockaddr_in: family, sin_port (2), sin_addr (4), sin_zero (8). 16 bytes.
        netcode_sockaddr_set_family( sockaddr, netcode_ffi::AF_INET, 16 );
        let s_addr = htonl( ( ( address.data.ipv4[0] as u32 ) << 24 ) |
                            ( ( address.data.ipv4[1] as u32 ) << 16 ) |
                            ( ( address.data.ipv4[2] as u32 ) << 8  ) |
                            ( ( address.data.ipv4[3] as u32 )       ) );
        sockaddr.ss_data[4..8].copy_from_slice( &s_addr.to_ne_bytes() );
        sockaddr.ss_data[2..4].copy_from_slice( &htons( address.port ).to_ne_bytes() );
        16
    }
}

/// port addition: the std SocketAddr for an address, for UdpSocket::send_to (upstream passes the sockaddr from
/// netcode_address_to_sockaddr to sendto)
pub fn netcode_address_to_socket_addr( address: &netcode_address_t ) -> SocketAddr
{
    if address.r#type == NETCODE_ADDRESS_IPV6
    {
        SocketAddr::V6( SocketAddrV6::new( Ipv6Addr::from( address.data.ipv6 ), address.port, 0, 0 ) )
    }
    else
    {
        SocketAddr::V4( SocketAddrV4::new( Ipv4Addr::from( address.data.ipv4 ), address.port ) )
    }
}

// port: std hands back the sockaddr_storage of recvfrom and getsockname as a SocketAddr, which is always AF_INET6 or
// AF_INET, so upstream's NETCODE_ERROR return for any other family cannot happen
pub fn netcode_sockaddr_to_address( sockaddr: &SocketAddr, address: &mut netcode_address_t ) -> i32
{
    match sockaddr
    {
        SocketAddr::V6( addr_ipv6 ) =>
        {
            address.r#type = NETCODE_ADDRESS_IPV6;
            // port: memcpy from sin6_addr and ntohs: segments() is already host order
            let ipv6_host_order = addr_ipv6.ip().segments();
            for i in 0..8
            {
                address.data.ipv6[i] = ipv6_host_order[i];
            }
            address.port = addr_ipv6.port();
            NETCODE_OK
        }
        SocketAddr::V4( addr_ipv4 ) =>
        {
            address.r#type = NETCODE_ADDRESS_IPV4;
            let ipv4_host_order: u32 = u32::from( *addr_ipv4.ip() );
            address.data.ipv4[0] = ( ( ipv4_host_order >> 24 ) & 0xFF ) as u8;
            address.data.ipv4[1] = ( ( ipv4_host_order >> 16 ) & 0xFF ) as u8;
            address.data.ipv4[2] = ( ( ipv4_host_order >> 8  ) & 0xFF ) as u8;
            address.data.ipv4[3] = ( ( ipv4_host_order       ) & 0xFF ) as u8;
            address.port = addr_ipv4.port();
            NETCODE_OK
        }
    }
}

pub fn netcode_socket_create( s: &mut netcode_socket_t, address: &netcode_address_t, send_buffer_size: i32, receive_buffer_size: i32 ) -> i32
{
    use netcode_ffi::*;

    netcode_assert!( unsafe { netcode.initialized } != 0 );

    netcode_assert!( address.r#type != NETCODE_ADDRESS_NONE );

    s.address = *address;

    // create socket

    let handle: netcode_raw_socket_t = unsafe { socket( if address.r#type == NETCODE_ADDRESS_IPV6 { AF_INET6 } else { AF_INET }, SOCK_DGRAM, IPPROTO_UDP ) };

    #[cfg(windows)]
    let invalid = handle == INVALID_SOCKET;
    #[cfg(unix)]
    let invalid = handle == 0 || handle == -1;

    if invalid
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to create socket\n" );
        s.handle = None;
        return NETCODE_SOCKET_ERROR_CREATE_FAILED;
    }

    // port: from here on the UdpSocket owns the socket (and closes it in netcode_socket_destroy); `handle` stays the
    // raw socket for the setsockopt calls std cannot make
    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawSocket;
        s.handle = Some( unsafe { UdpSocket::from_raw_socket( handle as u64 ) } );
    }
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        s.handle = Some( unsafe { UdpSocket::from_raw_fd( handle ) } );
    }

    #[cfg(windows)]
    {
        // IMPORTANT: tell windows we don't want to receive any connection reset messages for this socket
        // If we don't do this, clients disconnecting hard will cause recvfrom on the server to repeatedly error out
        // due to ICMP disconnected packets, causing long periods where the server doesn't receive any packets from clients.

        let SIO_UDP_CONNRESET: u32 = _WSAIOW( IOC_VENDOR, 12 );
        let mut bNewBehavior: i32 = 0;      // BOOL FALSE
        let mut dwBytesReturned: u32 = 0;
        if unsafe { WSAIoctl( handle, SIO_UDP_CONNRESET, &mut bNewBehavior as *mut i32 as *mut c_void, std::mem::size_of::<i32>() as u32, std::ptr::null_mut(), 0, &mut dwBytesReturned, std::ptr::null_mut(), std::ptr::null_mut() ) } != 0
        {
            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to disable UDP CONNRESET (port unreachable) message reporting on socket\n" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED;
        }
    }

    // force IPv6 only if necessary

    if address.r#type == NETCODE_ADDRESS_IPV6
    {
        let yes: i32 = 1;
        if unsafe { setsockopt( handle, IPPROTO_IPV6, IPV6_V6ONLY, &yes as *const i32 as *const c_void, std::mem::size_of::<i32>() as socklen_t ) } != 0
        {
            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to set socket ipv6 only\n" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED;
        }
    }

    // increase socket send and receive buffer sizes. linux and windows clamp requests that
    // exceed the OS limit, but the BSDs reject them instead, so back off until accepted.

    {
        let mut size: i32 = send_buffer_size;
        while unsafe { setsockopt( handle, SOL_SOCKET, SO_SNDBUF, &size as *const i32 as *const c_void, std::mem::size_of::<i32>() as socklen_t ) } != 0
        {
            size /= 2;
            if size < 256 * 1024
            {
                netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to set socket send buffer size\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED;
            }
        }
        if size != send_buffer_size
        {
            netcode_printf!( NETCODE_LOG_LEVEL_INFO, "socket send buffer size reduced from {} to {}\n", send_buffer_size, size );
        }
    }

    {
        let mut size: i32 = receive_buffer_size;
        while unsafe { setsockopt( handle, SOL_SOCKET, SO_RCVBUF, &size as *const i32 as *const c_void, std::mem::size_of::<i32>() as socklen_t ) } != 0
        {
            size /= 2;
            if size < 256 * 1024
            {
                netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to set socket receive buffer size\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED;
            }
        }
        if size != receive_buffer_size
        {
            netcode_printf!( NETCODE_LOG_LEVEL_INFO, "socket receive buffer size reduced from {} to {}\n", receive_buffer_size, size );
        }
    }

    // bind to port

    {
        let mut socket_address = sockaddr_storage::default();
        let socket_address_length: socklen_t = netcode_address_to_sockaddr( address, &mut socket_address );

        if unsafe { bind( handle, socket_address.ss_data.as_ptr() as *const c_void, socket_address_length ) } < 0
        {
            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to bind socket ({})\n", if address.r#type == NETCODE_ADDRESS_IPV6 { "ipv6" } else { "ipv4" } );
            netcode_socket_destroy( s );
            return if address.r#type == NETCODE_ADDRESS_IPV6 { NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED } else { NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED };
        }
    }

    // if bound to port 0 find the actual port we got

    if address.port == 0
    {
        let mut bound_address = netcode_address_t::default();

        // port: getsockname is UdpSocket::local_addr
        let socket_address = s.handle.as_ref().unwrap().local_addr();

        let ok = match socket_address
        {
            Ok( socket_address ) => netcode_sockaddr_to_address( &socket_address, &mut bound_address ) == NETCODE_OK,
            Err( _ ) => false,
        };

        if !ok
        {
            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to get socket port ({})\n", if address.r#type == NETCODE_ADDRESS_IPV6 { "ipv6" } else { "ipv4" } );
            netcode_socket_destroy( s );
            return if address.r#type == NETCODE_ADDRESS_IPV6 { NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED } else { NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED };
        }

        s.address.port = bound_address.port;
    }

    // set non-blocking io

    // port: fcntl( O_NONBLOCK ) / ioctlsocket( FIONBIO ) is UdpSocket::set_nonblocking, which makes the same call
    if s.handle.as_ref().unwrap().set_nonblocking( true ).is_err()
    {
        netcode_socket_destroy( s );
        return NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED;
    }

    // tag packets as low latency

    // port: upstream's NETCODE_PLATFORM_MAC and NETCODE_PLATFORM_UNIX blocks are the same code (the constants differ,
    // see netcode_ffi), so they are one cfg(unix) block
    #[cfg(unix)]
    {
        if netcode_packet_tagging_enabled.load( Ordering::Relaxed ) != 0
        {
            if address.r#type == NETCODE_ADDRESS_IPV6
            {
                let tos: i32 = 46;
                if unsafe { setsockopt( handle, IPPROTO_IPV6, IPV6_TCLASS, &tos as *const i32 as *const c_void, std::mem::size_of::<i32>() as socklen_t ) } != 0
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to enable packet tagging (ipv6)\n" );
                    netcode_socket_destroy( s );
                    return NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED;
                }
            }
            else
            {
                let tos: i32 = 46;
                if unsafe { setsockopt( handle, IPPROTO_IP, IP_TOS, &tos as *const i32 as *const c_void, std::mem::size_of::<i32>() as socklen_t ) } != 0
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to enable packet tagging (ipv4)\n" );
                    netcode_socket_destroy( s );
                    return NETCODE_SOCKET_ERROR_ENABLE_PACKET_TAGGING_FAILED;
                }
            }
        }
    }

    #[cfg(all(windows, not(target_env = "gnu")))]
    {
        if netcode_packet_tagging_enabled.load( Ordering::Relaxed ) != 0
        {
            let mut addr = sockaddr_storage::default();
            netcode_sockaddr_set_family( &mut addr, if address.r#type == NETCODE_ADDRESS_IPV6 { AF_INET6 } else { AF_INET }, 0 );
            netcode_set_socket_codepoint( handle, netcode_ffi::qos::QOSTrafficTypeAudioVideo, 0, &addr );
        }
    }

    NETCODE_SOCKET_ERROR_NONE
}

pub fn netcode_socket_send_packet( socket: &netcode_socket_t, to: &netcode_address_t, packet_data: &[u8], packet_bytes: i32 )
{
    netcode_assert!( socket.handle.is_some() );
    netcode_assert!( to.r#type == NETCODE_ADDRESS_IPV6 || to.r#type == NETCODE_ADDRESS_IPV4 );
    netcode_assert!( packet_bytes > 0 );

    // port: netcode_address_to_sockaddr + sendto is UdpSocket::send_to, which takes the address as a SocketAddr
    let socket_address = netcode_address_to_socket_addr( to );

    if let Some( handle ) = socket.handle.as_ref()
    {
        let result = handle.send_to( &packet_data[..packet_bytes as usize], socket_address );

        let _ = result;
    }
}

pub fn netcode_socket_receive_packet( socket: &netcode_socket_t, from: &mut netcode_address_t, packet_data: &mut [u8], max_packet_size: i32 ) -> i32
{
    netcode_assert!( socket.handle.is_some() );
    netcode_assert!( max_packet_size > 0 );

    let handle = match socket.handle.as_ref()
    {
        Some( handle ) => handle,
        None => return 0,
    };

    // port: recvfrom is UdpSocket::recv_from, which returns the sockaddr_storage as a SocketAddr
    let result = handle.recv_from( &mut packet_data[..max_packet_size as usize] );

    // port: SOCKET_ERROR + WSAGetLastError() (windows) and result <= 0 + errno (unix) are the io::Error, whose
    // WouldBlock kind is WSAEWOULDBLOCK / EAGAIN
    let ( result, sockaddr_from ) = match result
    {
        Ok( result ) => result,
        Err( e ) =>
        {
            let error = e.raw_os_error().unwrap_or( 0 );

            if e.kind() == std::io::ErrorKind::WouldBlock
            {
                return 0;
            }

            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: recvfrom failed with error {}\n", error );

            return 0;
        }
    };

    // port: unix's result <= 0 also takes an empty datagram as no packet (there is no errno to report for it)
    #[cfg(unix)]
    if result == 0
    {
        return 0;
    }

    if netcode_sockaddr_to_address( &sockaddr_from, from ) != NETCODE_OK
    {
        netcode_assert!( false );
        return 0;
    }

    let bytes_read = result as i32;

    bytes_read
}

// ----------------------------------------------------------------

// port: uint8_t ** p is the buffer slice plus the index p into it

pub fn netcode_write_uint8( buffer: &mut [u8], p: &mut usize, value: u8 )
{
    buffer[*p] = value;
    *p += 1;
}

pub fn netcode_write_uint16( buffer: &mut [u8], p: &mut usize, value: u16 )
{
    buffer[*p] = ( value & 0xFF ) as u8;
    buffer[*p + 1] = ( value >> 8 ) as u8;
    *p += 2;
}

pub fn netcode_write_uint32( buffer: &mut [u8], p: &mut usize, value: u32 )
{
    buffer[*p] = ( value & 0xFF ) as u8;
    buffer[*p + 1] = ( ( value >> 8  ) & 0xFF ) as u8;
    buffer[*p + 2] = ( ( value >> 16 ) & 0xFF ) as u8;
    buffer[*p + 3] = ( value >> 24 ) as u8;
    *p += 4;
}

pub fn netcode_write_uint64( buffer: &mut [u8], p: &mut usize, value: u64 )
{
    buffer[*p] = ( value & 0xFF ) as u8;
    buffer[*p + 1] = ( ( value >> 8  ) & 0xFF ) as u8;
    buffer[*p + 2] = ( ( value >> 16 ) & 0xFF ) as u8;
    buffer[*p + 3] = ( ( value >> 24 ) & 0xFF ) as u8;
    buffer[*p + 4] = ( ( value >> 32 ) & 0xFF ) as u8;
    buffer[*p + 5] = ( ( value >> 40 ) & 0xFF ) as u8;
    buffer[*p + 6] = ( ( value >> 48 ) & 0xFF ) as u8;
    buffer[*p + 7] = ( value >> 56 ) as u8;
    *p += 8;
}

pub fn netcode_write_bytes( buffer: &mut [u8], p: &mut usize, byte_array: &[u8], num_bytes: i32 )
{
    for i in 0..num_bytes as usize
    {
        netcode_write_uint8( buffer, p, byte_array[i] );
    }
}

pub fn netcode_read_uint8( buffer: &[u8], p: &mut usize ) -> u8
{
    let value = buffer[*p];
    *p += 1;
    value
}

pub fn netcode_read_uint16( buffer: &[u8], p: &mut usize ) -> u16
{
    let mut value: u16;
    value = buffer[*p] as u16;
    value |= ( buffer[*p + 1] as u16 ) << 8;
    *p += 2;
    value
}

pub fn netcode_read_uint32( buffer: &[u8], p: &mut usize ) -> u32
{
    let mut value: u32;
    value  = buffer[*p] as u32;
    value |= ( buffer[*p + 1] as u32 ) << 8;
    value |= ( buffer[*p + 2] as u32 ) << 16;
    value |= ( buffer[*p + 3] as u32 ) << 24;
    *p += 4;
    value
}

pub fn netcode_read_uint64( buffer: &[u8], p: &mut usize ) -> u64
{
    let mut value: u64;
    value  = buffer[*p] as u64;
    value |= ( buffer[*p + 1] as u64 ) << 8;
    value |= ( buffer[*p + 2] as u64 ) << 16;
    value |= ( buffer[*p + 3] as u64 ) << 24;
    value |= ( buffer[*p + 4] as u64 ) << 32;
    value |= ( buffer[*p + 5] as u64 ) << 40;
    value |= ( buffer[*p + 6] as u64 ) << 48;
    value |= ( buffer[*p + 7] as u64 ) << 56;
    *p += 8;
    value
}

pub fn netcode_read_bytes( buffer: &[u8], p: &mut usize, byte_array: &mut [u8], num_bytes: i32 )
{
    for i in 0..num_bytes as usize
    {
        byte_array[i] = netcode_read_uint8( buffer, p );
    }
}

// ----------------------------------------------------------------

pub fn netcode_generate_key( key: &mut [u8] )
{
    randombytes_buf( key, NETCODE_KEY_BYTES as usize );
}

pub fn netcode_generate_nonce( nonce: &mut [u8] )
{
    randombytes_buf( nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize );
}

pub fn netcode_random_bytes( data: &mut [u8], bytes: i32 )
{
    netcode_assert!( bytes > 0 );
    randombytes_buf( data, bytes as usize );
}

// port: the message is encrypted and decrypted in place upstream (c and m are the same pointer). Rust slices cannot
// alias, so the input is copied to a temporary first and the output written over message. additional may be null
// upstream (None here).

pub fn netcode_encrypt_aead_bignonce( message: &mut [u8], message_length: u64,
                                      additional: Option<&[u8]>, additional_length: u64,
                                      nonce: &[u8],
                                      key: &[u8] ) -> i32
{
    let mut encrypted_length: u64 = 0;

    // port: in place
    let plaintext: Vec<u8> = message[..message_length as usize].to_vec();

    let result = crypto_aead_xchacha20poly1305_ietf_encrypt( &mut message[..message_length as usize + NETCODE_MAC_BYTES as usize], Some( &mut encrypted_length ),
                                                             &plaintext, message_length,
                                                             additional, additional_length,
                                                             None, nonce, key );

    if result != 0
    {
        return NETCODE_ERROR;
    }

    netcode_assert!( encrypted_length == message_length + NETCODE_MAC_BYTES as u64 );

    NETCODE_OK
}

pub fn netcode_decrypt_aead_bignonce( message: &mut [u8], message_length: u64,
                                      additional: Option<&[u8]>, additional_length: u64,
                                      nonce: &[u8],
                                      key: &[u8] ) -> i32
{
    let mut decrypted_length: u64 = 0;

    // port: in place
    let ciphertext: Vec<u8> = message[..message_length as usize].to_vec();

    let result = crypto_aead_xchacha20poly1305_ietf_decrypt( &mut message[..( message_length as usize ).saturating_sub( NETCODE_MAC_BYTES as usize )], Some( &mut decrypted_length ),
                                                             None,
                                                             &ciphertext, message_length,
                                                             additional, additional_length,
                                                             nonce, key );

    if result != 0
    {
        return NETCODE_ERROR;
    }

    netcode_assert!( decrypted_length == message_length - NETCODE_MAC_BYTES as u64 );

    NETCODE_OK
}

pub fn netcode_encrypt_aead( message: &mut [u8], message_length: u64,
                             additional: Option<&[u8]>, additional_length: u64,
                             nonce: &[u8],
                             key: &[u8] ) -> i32
{
    let mut encrypted_length: u64 = 0;

    // port: in place
    let plaintext: Vec<u8> = message[..message_length as usize].to_vec();

    let result = crypto_aead_chacha20poly1305_ietf_encrypt( &mut message[..message_length as usize + NETCODE_MAC_BYTES as usize], Some( &mut encrypted_length ),
                                                            &plaintext, message_length,
                                                            additional, additional_length,
                                                            None, nonce, key );

    if result != 0
    {
        return NETCODE_ERROR;
    }

    netcode_assert!( encrypted_length == message_length + NETCODE_MAC_BYTES as u64 );

    NETCODE_OK
}

pub fn netcode_decrypt_aead( message: &mut [u8], message_length: u64,
                             additional: Option<&[u8]>, additional_length: u64,
                             nonce: &[u8],
                             key: &[u8] ) -> i32
{
    let mut decrypted_length: u64 = 0;

    // port: in place
    let ciphertext: Vec<u8> = message[..message_length as usize].to_vec();

    let result = crypto_aead_chacha20poly1305_ietf_decrypt( &mut message[..( message_length as usize ).saturating_sub( NETCODE_MAC_BYTES as usize )], Some( &mut decrypted_length ),
                                                            None,
                                                            &ciphertext, message_length,
                                                            additional, additional_length,
                                                            nonce, key );

    if result != 0
    {
        return NETCODE_ERROR;
    }

    netcode_assert!( decrypted_length == message_length - NETCODE_MAC_BYTES as u64 );

    NETCODE_OK
}

// ----------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct netcode_connect_token_private_t
{
    pub client_id: u64,
    pub timeout_seconds: i32,
    pub num_server_addresses: i32,
    pub server_addresses: [netcode_address_t; NETCODE_MAX_SERVERS_PER_CONNECT as usize],
    pub client_to_server_key: [u8; NETCODE_KEY_BYTES as usize],
    pub server_to_client_key: [u8; NETCODE_KEY_BYTES as usize],
    pub user_data: [u8; NETCODE_USER_DATA_BYTES as usize],
}

// port: the zeroed struct
impl Default for netcode_connect_token_private_t
{
    fn default() -> Self
    {
        netcode_connect_token_private_t
        {
            client_id: 0,
            timeout_seconds: 0,
            num_server_addresses: 0,
            server_addresses: [netcode_address_t::default(); NETCODE_MAX_SERVERS_PER_CONNECT as usize],
            client_to_server_key: [0; NETCODE_KEY_BYTES as usize],
            server_to_client_key: [0; NETCODE_KEY_BYTES as usize],
            user_data: [0; NETCODE_USER_DATA_BYTES as usize],
        }
    }
}

// port: user_data may be null upstream (None here)
pub fn netcode_generate_connect_token_private( connect_token: &mut netcode_connect_token_private_t,
                                               client_id: u64,
                                               timeout_seconds: i32,
                                               num_server_addresses: i32,
                                               server_addresses: &[netcode_address_t],
                                               user_data: Option<&[u8]> )
{
    netcode_assert!( num_server_addresses > 0 );
    netcode_assert!( num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
    netcode_assert!( user_data.is_some() );

    connect_token.client_id = client_id;
    connect_token.timeout_seconds = timeout_seconds;
    connect_token.num_server_addresses = num_server_addresses;

    for i in 0..num_server_addresses as usize
    {
        connect_token.server_addresses[i] = server_addresses[i];
    }

    netcode_generate_key( &mut connect_token.client_to_server_key );
    netcode_generate_key( &mut connect_token.server_to_client_key );

    if let Some( user_data ) = user_data
    {
        connect_token.user_data.copy_from_slice( &user_data[..NETCODE_USER_DATA_BYTES as usize] );
    }
    else
    {
        connect_token.user_data = [0; NETCODE_USER_DATA_BYTES as usize];
    }
}

pub fn netcode_write_connect_token_private( connect_token: &netcode_connect_token_private_t, buffer: &mut [u8], buffer_length: i32 )
{
    netcode_assert!( connect_token.num_server_addresses > 0 );
    netcode_assert!( connect_token.num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
    netcode_assert!( buffer_length >= NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    let start: usize = 0;
    let mut b: usize = start;

    netcode_write_uint64( buffer, &mut b, connect_token.client_id );

    netcode_write_uint32( buffer, &mut b, connect_token.timeout_seconds as u32 );

    netcode_write_uint32( buffer, &mut b, connect_token.num_server_addresses as u32 );

    for i in 0..connect_token.num_server_addresses as usize
    {
        if connect_token.server_addresses[i].r#type == NETCODE_ADDRESS_IPV4
        {
            netcode_write_uint8( buffer, &mut b, NETCODE_ADDRESS_IPV4 );
            for j in 0..4
            {
                netcode_write_uint8( buffer, &mut b, connect_token.server_addresses[i].data.ipv4[j] );
            }
            netcode_write_uint16( buffer, &mut b, connect_token.server_addresses[i].port );
        }
        else if connect_token.server_addresses[i].r#type == NETCODE_ADDRESS_IPV6
        {
            netcode_write_uint8( buffer, &mut b, NETCODE_ADDRESS_IPV6 );
            for j in 0..8
            {
                netcode_write_uint16( buffer, &mut b, connect_token.server_addresses[i].data.ipv6[j] );
            }
            netcode_write_uint16( buffer, &mut b, connect_token.server_addresses[i].port );
        }
        else
        {
            netcode_assert!( false );
        }
    }

    netcode_write_bytes( buffer, &mut b, &connect_token.client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( buffer, &mut b, &connect_token.server_to_client_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( buffer, &mut b, &connect_token.user_data, NETCODE_USER_DATA_BYTES );

    netcode_assert!( ( b - start ) as i32 <= NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES );

    // port: memset( buffer, 0, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - ( buffer - start ) )
    buffer[b..start + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize].fill( 0 );
}

pub fn netcode_encrypt_connect_token_private( buffer: &mut [u8],
                                              buffer_length: i32,
                                              version_info: &[u8],
                                              protocol_id: u64,
                                              expire_timestamp: u64,
                                              nonce: &[u8],
                                              key: &[u8] ) -> i32
{
    netcode_assert!( buffer_length == NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    let mut additional_data = [0u8; ( NETCODE_VERSION_INFO_BYTES + 8 + 8 ) as usize];
    {
        let mut p: usize = 0;
        netcode_write_bytes( &mut additional_data, &mut p, version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &mut additional_data, &mut p, protocol_id );
        netcode_write_uint64( &mut additional_data, &mut p, expire_timestamp );
    }

    netcode_encrypt_aead_bignonce( buffer, ( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES ) as u64, Some( &additional_data ), additional_data.len() as u64, nonce, key )
}

pub fn netcode_decrypt_connect_token_private( buffer: &mut [u8],
                                              buffer_length: i32,
                                              version_info: &[u8],
                                              protocol_id: u64,
                                              expire_timestamp: u64,
                                              nonce: &[u8],
                                              key: &[u8] ) -> i32
{
    netcode_assert!( buffer_length == NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    let mut additional_data = [0u8; ( NETCODE_VERSION_INFO_BYTES + 8 + 8 ) as usize];
    {
        let mut p: usize = 0;
        netcode_write_bytes( &mut additional_data, &mut p, version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &mut additional_data, &mut p, protocol_id );
        netcode_write_uint64( &mut additional_data, &mut p, expire_timestamp );
    }
    netcode_decrypt_aead_bignonce( buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as u64, Some( &additional_data ), additional_data.len() as u64, nonce, key )
}

pub fn netcode_read_connect_token_private( buffer: &[u8], buffer_length: i32, connect_token: &mut netcode_connect_token_private_t ) -> i32
{
    if buffer_length < NETCODE_CONNECT_TOKEN_PRIVATE_BYTES
    {
        return NETCODE_ERROR;
    }

    let mut b: usize = 0;

    connect_token.client_id = netcode_read_uint64( buffer, &mut b );

    connect_token.timeout_seconds = netcode_read_uint32( buffer, &mut b ) as i32;

    connect_token.num_server_addresses = netcode_read_uint32( buffer, &mut b ) as i32;

    if connect_token.num_server_addresses <= 0
    {
        return NETCODE_ERROR;
    }

    if connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT
    {
        return NETCODE_ERROR;
    }

    for i in 0..connect_token.num_server_addresses as usize
    {
        connect_token.server_addresses[i].r#type = netcode_read_uint8( buffer, &mut b );

        if connect_token.server_addresses[i].r#type == NETCODE_ADDRESS_IPV4
        {
            for j in 0..4
            {
                connect_token.server_addresses[i].data.ipv4[j] = netcode_read_uint8( buffer, &mut b );
            }
            connect_token.server_addresses[i].port = netcode_read_uint16( buffer, &mut b );
        }
        else if connect_token.server_addresses[i].r#type == NETCODE_ADDRESS_IPV6
        {
            for j in 0..8
            {
                connect_token.server_addresses[i].data.ipv6[j] = netcode_read_uint16( buffer, &mut b );
            }
            connect_token.server_addresses[i].port = netcode_read_uint16( buffer, &mut b );
        }
        else
        {
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes( buffer, &mut b, &mut connect_token.client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( buffer, &mut b, &mut connect_token.server_to_client_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( buffer, &mut b, &mut connect_token.user_data, NETCODE_USER_DATA_BYTES );

    NETCODE_OK
}

// -----------------------------------------------

#[derive(Clone, Copy)]
pub struct netcode_challenge_token_t
{
    pub client_id: u64,
    pub user_data: [u8; NETCODE_USER_DATA_BYTES as usize],
}

// port: the zeroed struct
impl Default for netcode_challenge_token_t
{
    fn default() -> Self
    {
        netcode_challenge_token_t { client_id: 0, user_data: [0; NETCODE_USER_DATA_BYTES as usize] }
    }
}

pub fn netcode_write_challenge_token( challenge_token: &netcode_challenge_token_t, buffer: &mut [u8], buffer_length: i32 )
{
    netcode_assert!( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );

    buffer[..NETCODE_CHALLENGE_TOKEN_BYTES as usize].fill( 0 );

    let start: usize = 0;
    let mut b: usize = start;

    netcode_write_uint64( buffer, &mut b, challenge_token.client_id );

    netcode_write_bytes( buffer, &mut b, &challenge_token.user_data, NETCODE_USER_DATA_BYTES );

    netcode_assert!( ( b - start ) as i32 <= NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES );
}

pub fn netcode_encrypt_challenge_token( buffer: &mut [u8], buffer_length: i32, sequence: u64, key: &[u8] ) -> i32
{
    netcode_assert!( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );

    let mut nonce = [0u8; 12];
    {
        let mut p: usize = 0;
        netcode_write_uint32( &mut nonce, &mut p, 0 );
        netcode_write_uint64( &mut nonce, &mut p, sequence );
    }

    netcode_encrypt_aead( buffer, ( NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES ) as u64, None, 0, &nonce, key )
}

pub fn netcode_decrypt_challenge_token( buffer: &mut [u8], buffer_length: i32, sequence: u64, key: &[u8] ) -> i32
{
    netcode_assert!( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );

    let mut nonce = [0u8; 12];
    {
        let mut p: usize = 0;
        netcode_write_uint32( &mut nonce, &mut p, 0 );
        netcode_write_uint64( &mut nonce, &mut p, sequence );
    }

    netcode_decrypt_aead( buffer, NETCODE_CHALLENGE_TOKEN_BYTES as u64, None, 0, &nonce, key )
}

pub fn netcode_read_challenge_token( buffer: &[u8], buffer_length: i32, challenge_token: &mut netcode_challenge_token_t ) -> i32
{
    if buffer_length < NETCODE_CHALLENGE_TOKEN_BYTES
    {
        return NETCODE_ERROR;
    }

    let start: usize = 0;
    let mut b: usize = start;

    challenge_token.client_id = netcode_read_uint64( buffer, &mut b );

    netcode_read_bytes( buffer, &mut b, &mut challenge_token.user_data, NETCODE_USER_DATA_BYTES );

    netcode_assert!( ( b - start ) as i32 == 8 + NETCODE_USER_DATA_BYTES );

    NETCODE_OK
}

// ----------------------------------------------------------------

// port: u8, the type of the packet_type fields (index allowed_packets with `as usize`)
pub const NETCODE_CONNECTION_REQUEST_PACKET: u8 = 0;
pub const NETCODE_CONNECTION_DENIED_PACKET: u8 = 1;
pub const NETCODE_CONNECTION_CHALLENGE_PACKET: u8 = 2;
pub const NETCODE_CONNECTION_RESPONSE_PACKET: u8 = 3;
pub const NETCODE_CONNECTION_KEEP_ALIVE_PACKET: u8 = 4;
pub const NETCODE_CONNECTION_PAYLOAD_PACKET: u8 = 5;
pub const NETCODE_CONNECTION_DISCONNECT_PACKET: u8 = 6;
pub const NETCODE_CONNECTION_NUM_PACKETS: u8 = 7;

/// port: upstream passes packets as `void *` and reads the packet type from their first byte (every packet struct
/// starts with uint8_t packet_type), then casts to the struct for that type. Every packet struct implements this
/// trait: packet_type() is that first byte, and the casts are downcasts:
/// `packet.as_any().downcast_ref::<netcode_connection_keep_alive_packet_t>().unwrap()`, or for a Box,
/// `packet.into_any().downcast::<netcode_connection_payload_packet_t>().unwrap()`.
pub trait netcode_packet_t: Any
{
    fn packet_type( &self ) -> u8;
    fn as_any( &self ) -> &dyn Any;
    fn as_any_mut( &mut self ) -> &mut dyn Any;
    fn into_any( self: Box<Self> ) -> Box<dyn Any>;
}

macro_rules! netcode_impl_packet {
    ( $t:ty ) => {
        impl netcode_packet_t for $t
        {
            fn packet_type( &self ) -> u8 { self.packet_type }
            fn as_any( &self ) -> &dyn Any { self }
            fn as_any_mut( &mut self ) -> &mut dyn Any { self }
            fn into_any( self: Box<Self> ) -> Box<dyn Any> { self }
        }
    };
}

#[derive(Clone, Copy)]
pub struct netcode_connection_request_packet_t
{
    pub packet_type: u8,
    pub version_info: [u8; NETCODE_VERSION_INFO_BYTES as usize],
    pub protocol_id: u64,
    pub connect_token_expire_timestamp: u64,
    pub connect_token_nonce: [u8; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize],
    pub connect_token_data: [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize],
}

// port: the zeroed struct
impl Default for netcode_connection_request_packet_t
{
    fn default() -> Self
    {
        netcode_connection_request_packet_t
        {
            packet_type: 0,
            version_info: [0; NETCODE_VERSION_INFO_BYTES as usize],
            protocol_id: 0,
            connect_token_expire_timestamp: 0,
            connect_token_nonce: [0; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize],
            connect_token_data: [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize],
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct netcode_connection_denied_packet_t
{
    pub packet_type: u8,
}

#[derive(Clone, Copy)]
pub struct netcode_connection_challenge_packet_t
{
    pub packet_type: u8,
    pub challenge_token_sequence: u64,
    pub challenge_token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES as usize],
}

// port: the zeroed struct
impl Default for netcode_connection_challenge_packet_t
{
    fn default() -> Self
    {
        netcode_connection_challenge_packet_t { packet_type: 0, challenge_token_sequence: 0, challenge_token_data: [0; NETCODE_CHALLENGE_TOKEN_BYTES as usize] }
    }
}

#[derive(Clone, Copy)]
pub struct netcode_connection_response_packet_t
{
    pub packet_type: u8,
    pub challenge_token_sequence: u64,
    pub challenge_token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES as usize],
}

// port: the zeroed struct
impl Default for netcode_connection_response_packet_t
{
    fn default() -> Self
    {
        netcode_connection_response_packet_t { packet_type: 0, challenge_token_sequence: 0, challenge_token_data: [0; NETCODE_CHALLENGE_TOKEN_BYTES as usize] }
    }
}

#[derive(Clone, Copy, Default)]
pub struct netcode_connection_keep_alive_packet_t
{
    pub packet_type: u8,
    pub client_index: i32,
    pub max_clients: i32,
}

#[derive(Clone, Default)]
pub struct netcode_connection_payload_packet_t
{
    pub packet_type: u8,
    pub payload_bytes: u32,
    /* serialize's BitReader loads an 8-byte window from the current byte, so a
       read in the last payload byte reaches 7 past it. This array is the last
       member; sizeof(*packet)+payload_bytes is allocated, leaving 8 bytes
       behind the returned payload pointer. Do not shrink it. */
    // port: a Vec of payload_bytes bytes (the C struct allocates them past its end). It is the buffer
    // netcode_client_receive_packet / netcode_server_receive_packet hand out. Rust's reads are bounds checked, so
    // the 8 bytes of reader slack (and the netcode_payload_packet_tail_holds_reader_slack check) have no counterpart.
    pub payload_data: Vec<u8>,
}

#[derive(Clone, Copy, Default)]
pub struct netcode_connection_disconnect_packet_t
{
    pub packet_type: u8,
}

netcode_impl_packet!( netcode_connection_request_packet_t );
netcode_impl_packet!( netcode_connection_denied_packet_t );
netcode_impl_packet!( netcode_connection_challenge_packet_t );
netcode_impl_packet!( netcode_connection_response_packet_t );
netcode_impl_packet!( netcode_connection_keep_alive_packet_t );
netcode_impl_packet!( netcode_connection_payload_packet_t );
netcode_impl_packet!( netcode_connection_disconnect_packet_t );

pub fn netcode_create_payload_packet( payload_bytes: i32, allocator_context: *mut c_void, mut allocate_function: Option<fn( *mut c_void, usize ) -> *mut c_void> ) -> Option<Box<netcode_connection_payload_packet_t>>
{
    netcode_assert!( payload_bytes >= 0 );
    netcode_assert!( payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES );

    if allocate_function.is_none()
    {
        allocate_function = Some( netcode_default_allocate_function );
    }

    // port: allocate_function( allocator_context, sizeof( struct netcode_connection_payload_packet_t ) + payload_bytes )
    // is a Box and a Vec (see the port notes at the top), so the `if ( !packet ) return NULL;` cannot happen
    let _ = ( allocator_context, allocate_function );

    let packet = Box::new( netcode_connection_payload_packet_t
    {
        packet_type: NETCODE_CONNECTION_PAYLOAD_PACKET,
        payload_bytes: payload_bytes as u32,
        payload_data: vec![0u8; payload_bytes as usize],
    } );

    Some( packet )
}

#[derive(Clone, Copy, Default)]
pub struct netcode_context_t
{
    pub write_packet_key: [u8; NETCODE_KEY_BYTES as usize],
    pub read_packet_key: [u8; NETCODE_KEY_BYTES as usize],
}

pub fn netcode_sequence_number_bytes_required( sequence: u64 ) -> i32
{
    let mut i = 0;
    let mut mask: u64 = 0xFF00000000000000;
    while i < 7
    {
        if sequence & mask != 0
        {
            break;
        }
        mask >>= 8;
        i += 1;
    }
    8 - i
}

/*
    Test-only instrumentation, compiled in by the NETCODE_NONCE_AUDIT build option.

    Records the key and nonce of every packet netcode_write_packet encrypts and counts how
    many times a pair repeats. A repeated key and nonce pair under AEAD is what a connect
    token used for two sessions produces, so the whole test suite running with zero repeats
    is the property worth pinning. Not built into the library.
*/

// port: the functions are always compiled; netcode_write_packet only calls netcode_nonce_audit_write_packet when
// NETCODE_ENABLE_NONCE_AUDIT is set. The static arrays are allocated on first use, so they cost nothing otherwise.

pub const NETCODE_NONCE_AUDIT_MAX_RECORDS: i32 = 1 << 18;
pub const NETCODE_NONCE_AUDIT_HASH_SIZE: i32 = 1 << 19;
pub const NETCODE_NONCE_AUDIT_NONCE_BYTES: i32 = 12;

#[derive(Clone, Copy, Default)]
pub struct netcode_nonce_audit_record_t
{
    pub key: [u8; NETCODE_KEY_BYTES as usize],
    pub nonce: [u8; NETCODE_NONCE_AUDIT_NONCE_BYTES as usize],
}

// port: upstream's static netcode_nonce_audit_* variables, in one struct behind a mutex
pub struct netcode_nonce_audit_t
{
    pub netcode_nonce_audit_records: Vec<netcode_nonce_audit_record_t>,
    pub netcode_nonce_audit_hash: Vec<i32>,
    pub netcode_nonce_audit_hash_initialized: i32,
    pub netcode_nonce_audit_num_records: i32,
    pub netcode_nonce_audit_num_repeats: i32,
    pub netcode_nonce_audit_overflowed: i32,
}

static netcode_nonce_audit: Mutex<netcode_nonce_audit_t> = Mutex::new( netcode_nonce_audit_t
{
    netcode_nonce_audit_records: Vec::new(),
    netcode_nonce_audit_hash: Vec::new(),
    netcode_nonce_audit_hash_initialized: 0,
    netcode_nonce_audit_num_records: 0,
    netcode_nonce_audit_num_repeats: 0,
    netcode_nonce_audit_overflowed: 0,
} );

pub fn netcode_nonce_audit_write_packet( key: &[u8], nonce: &[u8] )
{
    let mut audit = netcode_nonce_audit.lock().unwrap_or_else( |e| e.into_inner() );
    let audit = &mut *audit;

    if audit.netcode_nonce_audit_hash_initialized == 0
    {
        // port: the static arrays are allocated here
        audit.netcode_nonce_audit_records = vec![netcode_nonce_audit_record_t::default(); NETCODE_NONCE_AUDIT_MAX_RECORDS as usize];
        audit.netcode_nonce_audit_hash = vec![0; NETCODE_NONCE_AUDIT_HASH_SIZE as usize];
        for i in 0..NETCODE_NONCE_AUDIT_HASH_SIZE as usize
        {
            audit.netcode_nonce_audit_hash[i] = -1;
        }
        audit.netcode_nonce_audit_hash_initialized = 1;
    }

    let mut hash: u64 = 0xCBF29CE484222325;
    for i in 0..NETCODE_KEY_BYTES as usize
    {
        hash ^= key[i] as u64;
        hash = hash.wrapping_mul( 0x00000100000001B3 );
    }
    for i in 0..NETCODE_NONCE_AUDIT_NONCE_BYTES as usize
    {
        hash ^= nonce[i] as u64;
        hash = hash.wrapping_mul( 0x00000100000001B3 );
    }

    let mut slot = ( hash & ( NETCODE_NONCE_AUDIT_HASH_SIZE - 1 ) as u64 ) as i32;

    while audit.netcode_nonce_audit_hash[slot as usize] != -1
    {
        let record = &audit.netcode_nonce_audit_records[audit.netcode_nonce_audit_hash[slot as usize] as usize];
        if record.key[..] == key[..NETCODE_KEY_BYTES as usize] && record.nonce[..] == nonce[..NETCODE_NONCE_AUDIT_NONCE_BYTES as usize]
        {
            audit.netcode_nonce_audit_num_repeats += 1;
            print!( "NONCE AUDIT: repeated key and nonce pair: key {:02x}{:02x}{:02x}{:02x}.. sequence {}\n",
                key[0], key[1], key[2], key[3], nonce[4] as i32 );
            return;
        }
        slot = ( slot + 1 ) & ( NETCODE_NONCE_AUDIT_HASH_SIZE - 1 );
    }

    if audit.netcode_nonce_audit_num_records == NETCODE_NONCE_AUDIT_MAX_RECORDS
    {
        audit.netcode_nonce_audit_overflowed = 1;
        return;
    }

    let record = &mut audit.netcode_nonce_audit_records[audit.netcode_nonce_audit_num_records as usize];
    record.key.copy_from_slice( &key[..NETCODE_KEY_BYTES as usize] );
    record.nonce.copy_from_slice( &nonce[..NETCODE_NONCE_AUDIT_NONCE_BYTES as usize] );
    audit.netcode_nonce_audit_hash[slot as usize] = audit.netcode_nonce_audit_num_records;
    audit.netcode_nonce_audit_num_records += 1;
}

pub fn netcode_nonce_audit_num_pairs() -> i32
{
    netcode_nonce_audit.lock().unwrap_or_else( |e| e.into_inner() ).netcode_nonce_audit_num_records
}

pub fn netcode_nonce_audit_repeats() -> i32
{
    netcode_nonce_audit.lock().unwrap_or_else( |e| e.into_inner() ).netcode_nonce_audit_num_repeats
}

pub fn netcode_nonce_audit_overflow() -> i32
{
    netcode_nonce_audit.lock().unwrap_or_else( |e| e.into_inner() ).netcode_nonce_audit_overflowed
}

pub fn netcode_write_packet( packet: &dyn netcode_packet_t, buffer: &mut [u8], buffer_length: i32, sequence: u64, write_packet_key: &[u8], protocol_id: u64 ) -> i32
{
    let packet_type: u8 = packet.packet_type();

    if packet_type == NETCODE_CONNECTION_REQUEST_PACKET
    {
        // connection request packet: first byte is zero

        netcode_assert!( buffer_length >= 1 + 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        let p = packet.as_any().downcast_ref::<netcode_connection_request_packet_t>().unwrap();

        let start: usize = 0;
        let mut b: usize = start;

        netcode_write_uint8( buffer, &mut b, NETCODE_CONNECTION_REQUEST_PACKET );
        netcode_write_bytes( buffer, &mut b, &p.version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( buffer, &mut b, p.protocol_id );
        netcode_write_uint64( buffer, &mut b, p.connect_token_expire_timestamp );
        netcode_write_bytes( buffer, &mut b, &p.connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        netcode_write_bytes( buffer, &mut b, &p.connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        netcode_assert!( ( b - start ) as i32 == 1 + 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        ( b - start ) as i32
    }
    else
    {
        // *** encrypted packets ***

        // write the prefix byte (this is a combination of the packet type and number of sequence bytes)

        let start: usize = 0;
        let mut b: usize = start;

        let sequence_bytes: u8 = netcode_sequence_number_bytes_required( sequence ) as u8;

        netcode_assert!( sequence_bytes >= 1 );
        netcode_assert!( sequence_bytes <= 8 );

        netcode_assert!( packet_type <= 0xF );

        let prefix_byte: u8 = packet_type | ( sequence_bytes << 4 );

        netcode_write_uint8( buffer, &mut b, prefix_byte );

        // write the variable length sequence number [1,8] bytes.

        let mut sequence_temp: u64 = sequence;

        for _i in 0..sequence_bytes
        {
            netcode_write_uint8( buffer, &mut b, ( sequence_temp & 0xFF ) as u8 );
            sequence_temp >>= 8;
        }

        // write packet data according to type. this data will be encrypted.

        let encrypted_start: usize = b;

        match packet_type
        {
            NETCODE_CONNECTION_DENIED_PACKET =>
            {
                // ...
            }

            NETCODE_CONNECTION_CHALLENGE_PACKET =>
            {
                let p = packet.as_any().downcast_ref::<netcode_connection_challenge_packet_t>().unwrap();
                netcode_write_uint64( buffer, &mut b, p.challenge_token_sequence );
                netcode_write_bytes( buffer, &mut b, &p.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
            }

            NETCODE_CONNECTION_RESPONSE_PACKET =>
            {
                let p = packet.as_any().downcast_ref::<netcode_connection_response_packet_t>().unwrap();
                netcode_write_uint64( buffer, &mut b, p.challenge_token_sequence );
                netcode_write_bytes( buffer, &mut b, &p.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
            }

            NETCODE_CONNECTION_KEEP_ALIVE_PACKET =>
            {
                let p = packet.as_any().downcast_ref::<netcode_connection_keep_alive_packet_t>().unwrap();
                netcode_write_uint32( buffer, &mut b, p.client_index as u32 );
                netcode_write_uint32( buffer, &mut b, p.max_clients as u32 );
            }

            NETCODE_CONNECTION_PAYLOAD_PACKET =>
            {
                let p = packet.as_any().downcast_ref::<netcode_connection_payload_packet_t>().unwrap();

                netcode_assert!( p.payload_bytes as i32 <= NETCODE_MAX_PAYLOAD_BYTES );

                netcode_write_bytes( buffer, &mut b, &p.payload_data, p.payload_bytes as i32 );
            }

            NETCODE_CONNECTION_DISCONNECT_PACKET =>
            {
                // ...
            }

            _ =>
            {
                netcode_assert!( false );
            }
        }

        netcode_assert!( ( b - start ) as i32 <= buffer_length - NETCODE_MAC_BYTES );

        let encrypted_finish: usize = b;

        // encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

        let mut additional_data = [0u8; ( NETCODE_VERSION_INFO_BYTES + 8 + 1 ) as usize];
        {
            let mut p: usize = 0;
            netcode_write_bytes( &mut additional_data, &mut p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
            netcode_write_uint64( &mut additional_data, &mut p, protocol_id );
            netcode_write_uint8( &mut additional_data, &mut p, prefix_byte );
        }

        let mut nonce = [0u8; 12];
        {
            let mut p: usize = 0;
            netcode_write_uint32( &mut nonce, &mut p, 0 );
            netcode_write_uint64( &mut nonce, &mut p, sequence );
        }

        if NETCODE_ENABLE_NONCE_AUDIT != 0
        {
            netcode_nonce_audit_write_packet( write_packet_key, &nonce );
        }

        if netcode_encrypt_aead( &mut buffer[encrypted_start..],
                                 ( encrypted_finish - encrypted_start ) as u64,
                                 Some( &additional_data ), additional_data.len() as u64,
                                 &nonce, write_packet_key ) != NETCODE_OK
        {
            return NETCODE_ERROR;
        }

        b += NETCODE_MAC_BYTES as usize;

        netcode_assert!( ( b - start ) as i32 <= buffer_length );

        ( b - start ) as i32
    }
}

#[derive(Clone, Copy)]
pub struct netcode_replay_protection_t
{
    pub most_recent_sequence: u64,
    pub received_packet: [u64; NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as usize],
}

// port: the zeroed struct (netcode_replay_protection_reset fills received_packet with 0xFF)
impl Default for netcode_replay_protection_t
{
    fn default() -> Self
    {
        netcode_replay_protection_t { most_recent_sequence: 0, received_packet: [0; NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as usize] }
    }
}

pub fn netcode_replay_protection_reset( replay_protection: &mut netcode_replay_protection_t )
{
    replay_protection.most_recent_sequence = 0;
    // port: memset( received_packet, 0xFF, sizeof( received_packet ) )
    replay_protection.received_packet = [u64::MAX; NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as usize];
}

pub fn netcode_replay_protection_already_received( replay_protection: &netcode_replay_protection_t, sequence: u64 ) -> i32
{
    // written so it cannot overflow: "sequence + BUFFER_SIZE <= most_recent" wraps for
    // sequence values near UINT64_MAX and falsely rejects them as replays

    if replay_protection.most_recent_sequence >= NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as u64 &&
         sequence <= replay_protection.most_recent_sequence - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as u64
    {
        return 1;
    }

    let index = ( sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as u64 ) as usize;

    if replay_protection.received_packet[index] == u64::MAX
    {
        return 0;
    }

    if replay_protection.received_packet[index] >= sequence
    {
        return 1;
    }

    0
}

pub fn netcode_replay_protection_advance_sequence( replay_protection: &mut netcode_replay_protection_t, sequence: u64 )
{
    if sequence > replay_protection.most_recent_sequence
    {
        replay_protection.most_recent_sequence = sequence;
    }

    let index = ( sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as u64 ) as usize;

    replay_protection.received_packet[index] = sequence;
}

// port: read_packet_key, private_key and replay_protection may be null upstream (None here). The buffer is decrypted
// in place, so it is &mut.
pub fn netcode_read_packet( buffer: &mut [u8],
                            buffer_length: i32,
                            sequence: &mut u64,
                            read_packet_key: Option<&[u8]>,
                            protocol_id: u64,
                            current_timestamp: u64,
                            min_connect_token_expire_timestamp: u64,
                            private_key: Option<&[u8]>,
                            allowed_packets: &[u8],
                            mut replay_protection: Option<&mut netcode_replay_protection_t>,
                            allocator_context: *mut c_void,
                            mut allocate_function: Option<fn( *mut c_void, usize ) -> *mut c_void> ) -> Option<Box<dyn netcode_packet_t>>
{
    *sequence = 0;

    if allocate_function.is_none()
    {
        allocate_function = Some( netcode_default_allocate_function );
    }

    if buffer_length < 1
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored packet. buffer length is less than 1\n" );
        return None;
    }

    let start: usize = 0;
    let mut b: usize = start;

    let prefix_byte: u8 = netcode_read_uint8( buffer, &mut b );

    if prefix_byte == NETCODE_CONNECTION_REQUEST_PACKET
    {
        // connection request packet: first byte is zero

        if allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET as usize] == 0
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. packet type is not allowed\n" );
            return None;
        }

        if buffer_length != 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. bad packet length (expected {}, got {})\n", 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, buffer_length );
            return None;
        }

        let private_key = match private_key
        {
            Some( private_key ) => private_key,
            None =>
            {
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. no private key\n" );
                return None;
            }
        };

        let mut version_info = [0u8; NETCODE_VERSION_INFO_BYTES as usize];
        netcode_read_bytes( buffer, &mut b, &mut version_info, NETCODE_VERSION_INFO_BYTES );
        if version_info[0]  != b'N' ||
           version_info[1]  != b'E' ||
           version_info[2]  != b'T' ||
           version_info[3]  != b'C' ||
           version_info[4]  != b'O' ||
           version_info[5]  != b'D' ||
           version_info[6]  != b'E' ||
           version_info[7]  != b' ' ||
           version_info[8]  != b'1' ||
           version_info[9]  != b'.' ||
           version_info[10] != b'0' ||
           version_info[11] != b'2' ||
           version_info[12] != b'\0'
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. bad version info\n" );
            return None;
        }

        let packet_protocol_id: u64 = netcode_read_uint64( buffer, &mut b );
        if packet_protocol_id != protocol_id
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. wrong protocol id. expected {:016x}, got {:016x}\n",
                protocol_id, packet_protocol_id );
            return None;
        }

        let packet_connect_token_expire_timestamp: u64 = netcode_read_uint64( buffer, &mut b );
        if packet_connect_token_expire_timestamp <= current_timestamp
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. connect token expired\n" );
            return None;
        }

        // a connect token that could have been issued before the server started is refused: its keys
        // were already used to encrypt packets under sequence numbers that start again from zero.

        if packet_connect_token_expire_timestamp < min_connect_token_expire_timestamp
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. connect token predates the server start\n" );
            return None;
        }

        let mut packet_connect_token_nonce = [0u8; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize];
        netcode_read_bytes( buffer, &mut b, &mut packet_connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );

        netcode_assert!( ( b - start ) as i32 == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES );

        if netcode_decrypt_connect_token_private( &mut buffer[b..],
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  &version_info,
                                                  protocol_id,
                                                  packet_connect_token_expire_timestamp,
                                                  &packet_connect_token_nonce,
                                                  private_key ) != NETCODE_OK
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection request packet. connect token failed to decrypt\n" );
            return None;
        }

        // port: allocate_function( allocator_context, sizeof( struct netcode_connection_request_packet_t ) ) is a Box,
        // which does not fail ("failed to allocate packet")
        let mut packet = Box::new( netcode_connection_request_packet_t::default() );

        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        packet.version_info = version_info;
        packet.protocol_id = packet_protocol_id;
        packet.connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
        packet.connect_token_nonce = packet_connect_token_nonce;
        netcode_read_bytes( buffer, &mut b, &mut packet.connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        netcode_assert!( ( b - start ) as i32 == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

        Some( packet )
    }
    else
    {
        // *** encrypted packets ***

        let read_packet_key = match read_packet_key
        {
            Some( read_packet_key ) => read_packet_key,
            None =>
            {
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. no read packet key for this address\n" );
                return None;
            }
        };

        if buffer_length < 1 + 1 + NETCODE_MAC_BYTES
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet is too small to be valid ({} bytes)\n", buffer_length );
            return None;
        }

        // extract the packet type and number of sequence bytes from the prefix byte

        let packet_type: i32 = ( prefix_byte & 0xF ) as i32;

        if packet_type >= NETCODE_CONNECTION_NUM_PACKETS as i32
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet type {} is invalid\n", packet_type );
            return None;
        }

        if allowed_packets[packet_type as usize] == 0
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. packet type {} is not allowed\n", packet_type );
            return None;
        }

        let sequence_bytes: i32 = ( prefix_byte >> 4 ) as i32;

        if sequence_bytes < 1 || sequence_bytes > 8
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. sequence bytes {} is out of range [1,8]\n", sequence_bytes );
            return None;
        }

        if buffer_length < 1 + sequence_bytes + NETCODE_MAC_BYTES
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. buffer is too small for sequence bytes + encryption mac\n" );
            return None;
        }

        // read variable length sequence number [1,8]

        for i in 0..sequence_bytes
        {
            let value: u8 = netcode_read_uint8( buffer, &mut b );
            *sequence |= ( value as u64 ) << ( 8 * i );
        }

        // ignore the packet if it has already been received

        if let Some( replay_protection ) = replay_protection.as_deref_mut()
        {
            if packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET as i32
            {
                if netcode_replay_protection_already_received( replay_protection, *sequence ) != 0
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored packet. sequence {:016x} already received (replay protection)\n", *sequence );
                    return None;
                }
            }
        }

        // decrypt the per-packet type data

        let mut additional_data = [0u8; ( NETCODE_VERSION_INFO_BYTES + 8 + 1 ) as usize];
        {
            let mut p: usize = 0;
            netcode_write_bytes( &mut additional_data, &mut p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
            netcode_write_uint64( &mut additional_data, &mut p, protocol_id );
            netcode_write_uint8( &mut additional_data, &mut p, prefix_byte );
        }

        let mut nonce = [0u8; 12];
        {
            let mut p: usize = 0;
            netcode_write_uint32( &mut nonce, &mut p, 0 );
            netcode_write_uint64( &mut nonce, &mut p, *sequence );
        }

        let encrypted_bytes: i32 = buffer_length - ( b - start ) as i32;

        if encrypted_bytes < NETCODE_MAC_BYTES
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. encrypted payload is too small\n" );
            return None;
        }

        if netcode_decrypt_aead( &mut buffer[b..], encrypted_bytes as u64, Some( &additional_data ), additional_data.len() as u64, &nonce, read_packet_key ) != NETCODE_OK
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored encrypted packet. failed to decrypt\n" );
            return None;
        }

        let decrypted_bytes: i32 = encrypted_bytes - NETCODE_MAC_BYTES;

        // update the latest replay protection sequence #

        if let Some( replay_protection ) = replay_protection.as_deref_mut()
        {
            if packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET as i32
            {
                netcode_replay_protection_advance_sequence( replay_protection, *sequence );
            }
        }

        // process the per-packet type data that was just decrypted

        // port: allocate_function( allocator_context, sizeof( struct ... ) ) is a Box below, which does not fail
        // ("could not allocate packet struct")

        match packet_type as u8
        {
            NETCODE_CONNECTION_DENIED_PACKET =>
            {
                if decrypted_bytes != 0
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection denied packet. decrypted packet data is wrong size\n" );
                    return None;
                }

                let mut packet = Box::new( netcode_connection_denied_packet_t::default() );

                packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

                Some( packet )
            }

            NETCODE_CONNECTION_CHALLENGE_PACKET =>
            {
                if decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection challenge packet. decrypted packet data is wrong size\n" );
                    return None;
                }

                let mut packet = Box::new( netcode_connection_challenge_packet_t::default() );

                packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
                packet.challenge_token_sequence = netcode_read_uint64( buffer, &mut b );
                netcode_read_bytes( buffer, &mut b, &mut packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

                Some( packet )
            }

            NETCODE_CONNECTION_RESPONSE_PACKET =>
            {
                if decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection response packet. decrypted packet data is wrong size\n" );
                    return None;
                }

                let mut packet = Box::new( netcode_connection_response_packet_t::default() );

                packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
                packet.challenge_token_sequence = netcode_read_uint64( buffer, &mut b );
                netcode_read_bytes( buffer, &mut b, &mut packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

                Some( packet )
            }

            NETCODE_CONNECTION_KEEP_ALIVE_PACKET =>
            {
                if decrypted_bytes != 8
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection keep alive packet. decrypted packet data is wrong size\n" );
                    return None;
                }

                let mut packet = Box::new( netcode_connection_keep_alive_packet_t::default() );

                packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
                packet.client_index = netcode_read_uint32( buffer, &mut b ) as i32;
                packet.max_clients = netcode_read_uint32( buffer, &mut b ) as i32;

                Some( packet )
            }

            NETCODE_CONNECTION_PAYLOAD_PACKET =>
            {
                if decrypted_bytes < 1
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too small\n" );
                    return None;
                }

                if decrypted_bytes > NETCODE_MAX_PAYLOAD_BYTES
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. payload is too large\n" );
                    return None;
                }

                let mut packet = match netcode_create_payload_packet( decrypted_bytes, allocator_context, allocate_function )
                {
                    Some( packet ) => packet,
                    None =>
                    {
                        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection payload packet. could not allocate packet struct\n" );
                        return None;
                    }
                };

                packet.payload_data[..decrypted_bytes as usize].copy_from_slice( &buffer[b..b + decrypted_bytes as usize] );

                Some( packet )
            }

            NETCODE_CONNECTION_DISCONNECT_PACKET =>
            {
                if decrypted_bytes != 0
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "ignored connection disconnect packet. decrypted packet data is wrong size\n" );
                    return None;
                }

                let mut packet = Box::new( netcode_connection_disconnect_packet_t::default() );

                packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

                Some( packet )
            }

            _ => None,
        }
    }
}

// ----------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct netcode_connect_token_t
{
    pub version_info: [u8; NETCODE_VERSION_INFO_BYTES as usize],
    pub protocol_id: u64,
    pub create_timestamp: u64,
    pub expire_timestamp: u64,
    pub nonce: [u8; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize],
    pub private_data: [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize],
    pub timeout_seconds: i32,
    pub num_server_addresses: i32,
    pub server_addresses: [netcode_address_t; NETCODE_MAX_SERVERS_PER_CONNECT as usize],
    pub client_to_server_key: [u8; NETCODE_KEY_BYTES as usize],
    pub server_to_client_key: [u8; NETCODE_KEY_BYTES as usize],
}

// port: the zeroed struct
impl Default for netcode_connect_token_t
{
    fn default() -> Self
    {
        netcode_connect_token_t
        {
            version_info: [0; NETCODE_VERSION_INFO_BYTES as usize],
            protocol_id: 0,
            create_timestamp: 0,
            expire_timestamp: 0,
            nonce: [0; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize],
            private_data: [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize],
            timeout_seconds: 0,
            num_server_addresses: 0,
            server_addresses: [netcode_address_t::default(); NETCODE_MAX_SERVERS_PER_CONNECT as usize],
            client_to_server_key: [0; NETCODE_KEY_BYTES as usize],
            server_to_client_key: [0; NETCODE_KEY_BYTES as usize],
        }
    }
}

pub fn netcode_write_connect_token( connect_token: &netcode_connect_token_t, buffer: &mut [u8], buffer_length: i32 )
{
    netcode_assert!( buffer_length >= NETCODE_CONNECT_TOKEN_BYTES );

    let start: usize = 0;
    let mut b: usize = start;

    netcode_write_bytes( buffer, &mut b, &connect_token.version_info, NETCODE_VERSION_INFO_BYTES );

    netcode_write_uint64( buffer, &mut b, connect_token.protocol_id );

    netcode_write_uint64( buffer, &mut b, connect_token.create_timestamp );

    netcode_write_uint64( buffer, &mut b, connect_token.expire_timestamp );

    netcode_write_bytes( buffer, &mut b, &connect_token.nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );

    netcode_write_bytes( buffer, &mut b, &connect_token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    netcode_write_uint32( buffer, &mut b, connect_token.timeout_seconds as u32 );

    netcode_write_uint32( buffer, &mut b, connect_token.num_server_addresses as u32 );

    for i in 0..connect_token.num_server_addresses as usize
    {
        if connect_token.server_addresses[i].r#type == NETCODE_ADDRESS_IPV4
        {
            netcode_write_uint8( buffer, &mut b, NETCODE_ADDRESS_IPV4 );
            for j in 0..4
            {
                netcode_write_uint8( buffer, &mut b, connect_token.server_addresses[i].data.ipv4[j] );
            }
            netcode_write_uint16( buffer, &mut b, connect_token.server_addresses[i].port );
        }
        else if connect_token.server_addresses[i].r#type == NETCODE_ADDRESS_IPV6
        {
            netcode_write_uint8( buffer, &mut b, NETCODE_ADDRESS_IPV6 );
            for j in 0..8
            {
                netcode_write_uint16( buffer, &mut b, connect_token.server_addresses[i].data.ipv6[j] );
            }
            netcode_write_uint16( buffer, &mut b, connect_token.server_addresses[i].port );
        }
        else
        {
            netcode_assert!( false );
        }
    }

    netcode_write_bytes( buffer, &mut b, &connect_token.client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( buffer, &mut b, &connect_token.server_to_client_key, NETCODE_KEY_BYTES );

    netcode_assert!( ( b - start ) as i32 <= NETCODE_CONNECT_TOKEN_BYTES );

    // port: memset( buffer, 0, NETCODE_CONNECT_TOKEN_BYTES - ( buffer - start ) )
    buffer[b..start + NETCODE_CONNECT_TOKEN_BYTES as usize].fill( 0 );
}

pub fn netcode_read_connect_token( buffer: &[u8], buffer_length: i32, connect_token: &mut netcode_connect_token_t ) -> i32
{
    if buffer_length != NETCODE_CONNECT_TOKEN_BYTES
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: read connect data has bad buffer length ({})\n", buffer_length );
        return NETCODE_ERROR;
    }

    let mut b: usize = 0;

    netcode_read_bytes( buffer, &mut b, &mut connect_token.version_info, NETCODE_VERSION_INFO_BYTES );
    if connect_token.version_info[0]  != b'N' ||
       connect_token.version_info[1]  != b'E' ||
       connect_token.version_info[2]  != b'T' ||
       connect_token.version_info[3]  != b'C' ||
       connect_token.version_info[4]  != b'O' ||
       connect_token.version_info[5]  != b'D' ||
       connect_token.version_info[6]  != b'E' ||
       connect_token.version_info[7]  != b' ' ||
       connect_token.version_info[8]  != b'1' ||
       connect_token.version_info[9]  != b'.' ||
       connect_token.version_info[10] != b'0' ||
       connect_token.version_info[11] != b'2' ||
       connect_token.version_info[12] != b'\0'
    {
        connect_token.version_info[12] = b'\0';
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: read connect data has bad version info (got {}, expected {})\n", String::from_utf8_lossy( &connect_token.version_info[..netcode_strlen( &connect_token.version_info )] ), netcode_cstr( NETCODE_VERSION_INFO ) );
        return NETCODE_ERROR;
    }

    connect_token.protocol_id = netcode_read_uint64( buffer, &mut b );

    connect_token.create_timestamp = netcode_read_uint64( buffer, &mut b );

    connect_token.expire_timestamp = netcode_read_uint64( buffer, &mut b );

    if connect_token.create_timestamp > connect_token.expire_timestamp
    {
        return NETCODE_ERROR;
    }

    netcode_read_bytes( buffer, &mut b, &mut connect_token.nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );

    netcode_read_bytes( buffer, &mut b, &mut connect_token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    connect_token.timeout_seconds = netcode_read_uint32( buffer, &mut b ) as i32;

    connect_token.num_server_addresses = netcode_read_uint32( buffer, &mut b ) as i32;

    if connect_token.num_server_addresses <= 0 || connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: read connect data has bad number of server addresses ({})\n", connect_token.num_server_addresses );
        return NETCODE_ERROR;
    }

    for i in 0..connect_token.num_server_addresses as usize
    {
        connect_token.server_addresses[i].r#type = netcode_read_uint8( buffer, &mut b );

        if connect_token.server_addresses[i].r#type == NETCODE_ADDRESS_IPV4
        {
            for j in 0..4
            {
                connect_token.server_addresses[i].data.ipv4[j] = netcode_read_uint8( buffer, &mut b );
            }
            connect_token.server_addresses[i].port = netcode_read_uint16( buffer, &mut b );
        }
        else if connect_token.server_addresses[i].r#type == NETCODE_ADDRESS_IPV6
        {
            for j in 0..8
            {
                connect_token.server_addresses[i].data.ipv6[j] = netcode_read_uint16( buffer, &mut b );
            }
            connect_token.server_addresses[i].port = netcode_read_uint16( buffer, &mut b );
        }
        else
        {
            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: read connect data has bad address type ({})\n", connect_token.server_addresses[i].r#type );
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes( buffer, &mut b, &mut connect_token.client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( buffer, &mut b, &mut connect_token.server_to_client_key, NETCODE_KEY_BYTES );

    NETCODE_OK
}

// ----------------------------------------------------------------

// port: packet_data holds the queued packets (void * upstream); a None slot is NULL. free_function is kept, but a
// queued packet is freed by dropping it.
pub struct netcode_packet_queue_t
{
    pub allocator_context: *mut c_void,
    pub allocate_function: Option<fn( *mut c_void, usize ) -> *mut c_void>,
    pub free_function: Option<fn( *mut c_void, *mut c_void )>,
    pub num_packets: i32,
    pub start_index: i32,
    pub packet_data: Vec<Option<Box<dyn netcode_packet_t>>>,
    pub packet_sequence: [u64; NETCODE_PACKET_QUEUE_SIZE as usize],
}

// port: the zeroed struct (the arrays are allocated here, at their fixed size)
impl Default for netcode_packet_queue_t
{
    fn default() -> Self
    {
        netcode_packet_queue_t
        {
            allocator_context: std::ptr::null_mut(),
            allocate_function: None,
            free_function: None,
            num_packets: 0,
            start_index: 0,
            packet_data: ( 0..NETCODE_PACKET_QUEUE_SIZE ).map( |_| None ).collect(),
            packet_sequence: [0; NETCODE_PACKET_QUEUE_SIZE as usize],
        }
    }
}

pub fn netcode_packet_queue_init( queue: &mut netcode_packet_queue_t,
                                  allocator_context: *mut c_void,
                                  mut allocate_function: Option<fn( *mut c_void, usize ) -> *mut c_void>,
                                  mut free_function: Option<fn( *mut c_void, *mut c_void )> )
{
    if allocate_function.is_none()
    {
        allocate_function = Some( netcode_default_allocate_function );
    }

    if free_function.is_none()
    {
        free_function = Some( netcode_default_free_function );
    }

    queue.allocator_context = allocator_context;
    queue.allocate_function = allocate_function;
    queue.free_function = free_function;
    queue.num_packets = 0;
    queue.start_index = 0;
    // port: memset( queue->packet_data, 0, sizeof( queue->packet_data ) )
    queue.packet_data = ( 0..NETCODE_PACKET_QUEUE_SIZE ).map( |_| None ).collect();
    queue.packet_sequence = [0; NETCODE_PACKET_QUEUE_SIZE as usize];
}

pub fn netcode_packet_queue_push( queue: &mut netcode_packet_queue_t, packet_data: Box<dyn netcode_packet_t>, packet_sequence: u64 ) -> i32
{
    if queue.num_packets == NETCODE_PACKET_QUEUE_SIZE
    {
        // port: queue->free_function( queue->allocator_context, packet_data ) -- the packet is dropped
        drop( packet_data );
        return 0;
    }
    let index = ( ( queue.start_index + queue.num_packets ) % NETCODE_PACKET_QUEUE_SIZE ) as usize;
    queue.packet_data[index] = Some( packet_data );
    queue.packet_sequence[index] = packet_sequence;
    queue.num_packets += 1;
    1
}

pub fn netcode_packet_queue_pop( queue: &mut netcode_packet_queue_t, packet_sequence: Option<&mut u64> ) -> Option<Box<dyn netcode_packet_t>>
{
    if queue.num_packets == 0
    {
        return None;
    }
    let packet = queue.packet_data[queue.start_index as usize].take();
    if let Some( packet_sequence ) = packet_sequence
    {
        *packet_sequence = queue.packet_sequence[queue.start_index as usize];
    }
    queue.start_index = ( queue.start_index + 1 ) % NETCODE_PACKET_QUEUE_SIZE;
    queue.num_packets -= 1;
    packet
}

pub fn netcode_packet_queue_clear( queue: &mut netcode_packet_queue_t )
{
    while queue.num_packets > 0
    {
        // port: queue->free_function( queue->allocator_context, netcode_packet_queue_pop( queue, NULL ) ) -- dropped
        drop( netcode_packet_queue_pop( queue, None ) );
    }
    queue.start_index = 0;
    for packet in queue.packet_data.iter_mut()
    {
        *packet = None;
    }
    queue.packet_sequence = [0; NETCODE_PACKET_QUEUE_SIZE as usize];
}

// ----------------------------------------------------------------

pub const NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES: i32 = NETCODE_MAX_CLIENTS * 256;
pub const NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS: i32 = NETCODE_MAX_CLIENTS * 64;
pub const NETCODE_NETWORK_SIMULATOR_RNG_SEED: u64 = 0x9E3779B97F4A7C15;

// port: packet_data is the packet's buffer (uint8_t * upstream); None is NULL
#[derive(Clone, Default)]
pub struct netcode_network_simulator_packet_entry_t
{
    pub from: netcode_address_t,
    pub to: netcode_address_t,
    pub delivery_time: f64,
    pub packet_data: Option<Vec<u8>>,
    pub packet_bytes: i32,
}

// port: the allocator callbacks are kept; packet buffers are Vecs, freed by dropping them
pub struct netcode_network_simulator_t
{
    pub allocator_context: *mut c_void,
    pub allocate_function: Option<fn( *mut c_void, usize ) -> *mut c_void>,
    pub free_function: Option<fn( *mut c_void, *mut c_void )>,
    pub latency_milliseconds: f32,
    pub jitter_milliseconds: f32,
    pub packet_loss_percent: f32,
    pub duplicate_packet_percent: f32,
    pub rng_state: u64,
    pub time: f64,
    pub current_index: i32,
    pub num_pending_receive_packets: i32,
    pub packet_entries: Vec<netcode_network_simulator_packet_entry_t>,
    pub pending_receive_packets: Vec<netcode_network_simulator_packet_entry_t>,
}

pub fn netcode_network_simulator_create( allocator_context: *mut c_void,
                                         mut allocate_function: Option<fn( *mut c_void, usize ) -> *mut c_void>,
                                         mut free_function: Option<fn( *mut c_void, *mut c_void )> ) -> Option<Box<netcode_network_simulator_t>>
{
    if allocate_function.is_none()
    {
        allocate_function = Some( netcode_default_allocate_function );
    }

    if free_function.is_none()
    {
        free_function = Some( netcode_default_free_function );
    }

    // port: allocate_function( allocator_context, sizeof( struct netcode_network_simulator_t ) ) and the memset are
    // the Box of the zeroed struct
    let mut network_simulator = Box::new( netcode_network_simulator_t
    {
        allocator_context: std::ptr::null_mut(),
        allocate_function: None,
        free_function: None,
        latency_milliseconds: 0.0,
        jitter_milliseconds: 0.0,
        packet_loss_percent: 0.0,
        duplicate_packet_percent: 0.0,
        rng_state: 0,
        time: 0.0,
        current_index: 0,
        num_pending_receive_packets: 0,
        packet_entries: vec![netcode_network_simulator_packet_entry_t::default(); NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES as usize],
        pending_receive_packets: vec![netcode_network_simulator_packet_entry_t::default(); NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS as usize],
    } );

    network_simulator.allocator_context = allocator_context;
    network_simulator.allocate_function = allocate_function;
    network_simulator.free_function = free_function;
    network_simulator.rng_state = NETCODE_NETWORK_SIMULATOR_RNG_SEED;

    Some( network_simulator )
}

pub fn netcode_network_simulator_reset( network_simulator: &mut netcode_network_simulator_t )
{
    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "network simulator reset\n" );

    for i in 0..NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES as usize
    {
        // port: free_function( packet_data ) and memset: the entry's buffer is dropped
        network_simulator.packet_entries[i] = netcode_network_simulator_packet_entry_t::default();
    }

    for i in 0..network_simulator.num_pending_receive_packets as usize
    {
        network_simulator.pending_receive_packets[i] = netcode_network_simulator_packet_entry_t::default();
    }

    network_simulator.current_index = 0;
    network_simulator.num_pending_receive_packets = 0;
    network_simulator.rng_state = NETCODE_NETWORK_SIMULATOR_RNG_SEED;
}

pub fn netcode_network_simulator_destroy( mut network_simulator: Box<netcode_network_simulator_t> )
{
    netcode_network_simulator_reset( &mut network_simulator );
    // port: free_function( allocator_context, network_simulator ) -- the Box is dropped
    drop( network_simulator );
}

pub fn netcode_network_simulator_random_uint64( network_simulator: &mut netcode_network_simulator_t ) -> u64
{
    // xorshift64*. self-contained and deterministic, unlike rand(): the simulator
    // produces the same loss, jitter and duplication sequence on every run, and
    // shares no state with the application or other simulator instances.

    let mut x: u64 = network_simulator.rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    network_simulator.rng_state = x;
    x.wrapping_mul( 0x2545F4914F6CDD1D )
}

pub fn netcode_network_simulator_random_float( network_simulator: &mut netcode_network_simulator_t, a: f32, b: f32 ) -> f32
{
    netcode_assert!( a < b );
    let random: f32 = ( netcode_network_simulator_random_uint64( network_simulator ) >> 40 ) as f32 / ( 1 << 24 ) as f32;
    a + random * ( b - a )
}

pub fn netcode_network_simulator_queue_packet( network_simulator: &mut netcode_network_simulator_t,
                                               from: &netcode_address_t,
                                               to: &netcode_address_t,
                                               packet_data: &[u8],
                                               packet_bytes: i32,
                                               delay: f32 )
{
    // allocate before touching the slot. if the allocator fails, drop this packet and leave
    // the entry already queued in that slot alone, rather than copying into null.

    // port: fix. the buffer is a Vec, but the allocator is still asked for (and handed back) packet_bytes, as
    // netcode_client_create does, so a failing allocator drops the packet as upstream (test_network_simulator_allocation_failure)

    let entry_packet_memory = ( network_simulator.allocate_function.unwrap() )( network_simulator.allocator_context, packet_bytes as usize );

    if entry_packet_memory.is_null()
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: network simulator could not allocate packet data\n" );
        return;
    }

    ( network_simulator.free_function.unwrap() )( network_simulator.allocator_context, entry_packet_memory );

    let mut entry_packet_data: Vec<u8> = vec![0u8; packet_bytes as usize];

    let current_index = network_simulator.current_index as usize;

    if network_simulator.packet_entries[current_index].packet_data.is_some()
    {
        // port: free_function -- the buffer is dropped
        network_simulator.packet_entries[current_index].packet_data = None;
    }

    entry_packet_data.copy_from_slice( &packet_data[..packet_bytes as usize] );

    network_simulator.packet_entries[current_index].from = *from;
    network_simulator.packet_entries[current_index].to = *to;
    network_simulator.packet_entries[current_index].packet_data = Some( entry_packet_data );
    network_simulator.packet_entries[current_index].packet_bytes = packet_bytes;
    network_simulator.packet_entries[current_index].delivery_time = network_simulator.time + delay as f64;
    network_simulator.current_index += 1;
    network_simulator.current_index %= NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES;
}

pub fn netcode_network_simulator_send_packet( network_simulator: &mut netcode_network_simulator_t,
                                              from: &netcode_address_t,
                                              to: &netcode_address_t,
                                              packet_data: &[u8],
                                              packet_bytes: i32 )
{
    netcode_assert!( from.r#type != 0 );
    netcode_assert!( to.r#type != 0 );
    netcode_assert!( packet_bytes > 0 );
    netcode_assert!( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    if netcode_network_simulator_random_float( network_simulator, 0.0, 100.0 ) <= network_simulator.packet_loss_percent
    {
        return;
    }

    let mut delay: f32 = network_simulator.latency_milliseconds / 1000.0;

    if network_simulator.jitter_milliseconds > 0.0
    {
        let jitter = network_simulator.jitter_milliseconds;
        delay += netcode_network_simulator_random_float( network_simulator, -jitter, jitter ) / 1000.0;
    }

    netcode_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, delay );

    if netcode_network_simulator_random_float( network_simulator, 0.0, 100.0 ) <= network_simulator.duplicate_packet_percent
    {
        let duplicate_delay = delay + netcode_network_simulator_random_float( network_simulator, 0.0, 1.0 );
        netcode_network_simulator_queue_packet( network_simulator, from, to, packet_data, packet_bytes, duplicate_delay );
    }
}

// port: uint8_t ** packet_data is a slice of buffer slots the received buffers are moved into; they belong to the
// caller, as upstream (dropping them is the free)
pub fn netcode_network_simulator_receive_packets( network_simulator: &mut netcode_network_simulator_t,
                                                  to: &netcode_address_t,
                                                  max_packets: i32,
                                                  packet_data: &mut [Option<Vec<u8>>],
                                                  packet_bytes: &mut [i32],
                                                  from: &mut [netcode_address_t] ) -> i32
{
    netcode_assert!( max_packets >= 0 );

    let mut num_packets: i32 = 0;

    for i in 0..network_simulator.num_pending_receive_packets as usize
    {
        if num_packets == max_packets
        {
            break;
        }

        if network_simulator.pending_receive_packets[i].packet_data.is_none()
        {
            continue;
        }

        if netcode_address_equal( &network_simulator.pending_receive_packets[i].to, to ) == 0
        {
            continue;
        }

        // port: the buffer moves to the caller, which is upstream's copy of the pointer followed by setting it NULL
        packet_data[num_packets as usize] = network_simulator.pending_receive_packets[i].packet_data.take();
        packet_bytes[num_packets as usize] = network_simulator.pending_receive_packets[i].packet_bytes;
        from[num_packets as usize] = network_simulator.pending_receive_packets[i].from;

        num_packets += 1;
    }

    netcode_assert!( num_packets <= max_packets );

    num_packets
}

pub fn netcode_network_simulator_update( network_simulator: &mut netcode_network_simulator_t, time: f64 )
{
    network_simulator.time = time;

    // discard any pending receive packets that are still in the buffer

    for i in 0..network_simulator.num_pending_receive_packets as usize
    {
        if network_simulator.pending_receive_packets[i].packet_data.is_some()
        {
            // port: free_function -- the buffer is dropped
            network_simulator.pending_receive_packets[i].packet_data = None;
        }
    }

    network_simulator.num_pending_receive_packets = 0;

    // walk across packet entries and move any that are ready to be received into the pending receive buffer

    for i in 0..NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES as usize
    {
        if network_simulator.packet_entries[i].packet_data.is_none()
        {
            continue;
        }

        if network_simulator.num_pending_receive_packets == NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS
        {
            break;
        }

        if network_simulator.packet_entries[i].packet_data.is_some() && network_simulator.packet_entries[i].delivery_time <= time
        {
            // port: the struct copy moves the buffer, then upstream sets the entry's pointer to NULL
            let entry = &mut network_simulator.packet_entries[i];
            let pending = netcode_network_simulator_packet_entry_t
            {
                from: entry.from,
                to: entry.to,
                delivery_time: entry.delivery_time,
                packet_data: entry.packet_data.take(),
                packet_bytes: entry.packet_bytes,
            };
            network_simulator.pending_receive_packets[network_simulator.num_pending_receive_packets as usize] = pending;
            network_simulator.num_pending_receive_packets += 1;
        }
    }
}

// ----------------------------------------------------------------

// shared by the client and server send paths: dispatch a written packet to the network
// simulator, the send override, or the socket matching the destination address family

// port: network_simulator is the config's non-owning pointer (null for none)
pub fn netcode_send_packet_to_address( network_simulator: *mut netcode_network_simulator_t,
                                       override_context: *mut c_void,
                                       send_packet_override: Option<fn( *mut c_void, &netcode_address_t, &[u8], i32 )>,
                                       socket_holder: &netcode_socket_holder_t,
                                       from: &netcode_address_t,
                                       to: &netcode_address_t,
                                       packet_data: &[u8],
                                       packet_bytes: i32 )
{
    if !network_simulator.is_null()
    {
        netcode_network_simulator_send_packet( unsafe { &mut *network_simulator }, from, to, packet_data, packet_bytes );
    }
    else if let Some( send_packet_override ) = send_packet_override
    {
        send_packet_override( override_context, to, packet_data, packet_bytes );
    }
    else if to.r#type == NETCODE_ADDRESS_IPV4
    {
        netcode_socket_send_packet( &socket_holder.ipv4, to, packet_data, packet_bytes );
    }
    else if to.r#type == NETCODE_ADDRESS_IPV6
    {
        netcode_socket_send_packet( &socket_holder.ipv6, to, packet_data, packet_bytes );
    }
}

// ----------------------------------------------------------------

pub fn netcode_client_state_name( client_state: i32 ) -> &'static str
{
    match client_state
    {
        NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED                  => "connect token expired",
        NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN                  => "invalid connect token",
        NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT                   => "connection timed out",
        NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT           => "connection request timed out",
        NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT          => "connection response timed out",
        NETCODE_CLIENT_STATE_CONNECTION_DENIED                      => "connection denied",
        NETCODE_CLIENT_STATE_DISCONNECTED                           => "disconnected",
        NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST             => "sending connection request",
        NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE            => "sending connection response",
        NETCODE_CLIENT_STATE_CONNECTED                              => "connected",
        _ =>
        {
            netcode_assert!( false );
            "???"
        }
    }
}


// port: netcode.c from netcode_default_client_config to the end of the library (before the tests). std/sodium
// items are named by full path here.

pub fn netcode_default_client_config( config: &mut netcode_client_config_t )
{
    config.allocator_context = std::ptr::null_mut();
    config.allocate_function = Some( netcode_default_allocate_function );
    config.free_function = Some( netcode_default_free_function );
    config.network_simulator = std::ptr::null_mut();
    config.callback_context = std::ptr::null_mut();
    config.state_change_callback = None;
    config.send_loopback_packet_callback = None;
    config.override_send_and_receive = 0;
    config.send_packet_override = None;
    config.receive_packet_override = None;
}

pub struct netcode_client_t
{
    pub config: netcode_client_config_t,
    pub state: i32,
    pub time: f64,
    pub connect_start_time: f64,
    pub last_packet_send_time: f64,
    pub last_packet_receive_time: f64,
    pub should_disconnect: i32,
    pub should_disconnect_state: i32,
    pub sequence: u64,
    pub client_index: i32,
    pub max_clients: i32,
    pub server_address_index: i32,
    pub address: netcode_address_t,
    pub server_address: netcode_address_t,
    pub connect_token: netcode_connect_token_t,
    pub socket_holder: netcode_socket_holder_t,
    pub context: netcode_context_t,
    pub replay_protection: netcode_replay_protection_t,
    pub packet_receive_queue: netcode_packet_queue_t,
    pub challenge_token_sequence: u64,
    pub challenge_token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES as usize],
    pub receive_packet_data: [Option<Vec<u8>>; NETCODE_CLIENT_MAX_RECEIVE_PACKETS as usize],
    pub receive_packet_bytes: [i32; NETCODE_CLIENT_MAX_RECEIVE_PACKETS as usize],
    pub receive_from: [netcode_address_t; NETCODE_CLIENT_MAX_RECEIVE_PACKETS as usize],
    pub loopback: i32,
}

// port: a C file static; an atomic (netcode is single threaded, so the ordering is irrelevant)
static client_create_error: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new( 0 );

pub fn netcode_client_create_error() -> i32
{
    return client_create_error.load( std::sync::atomic::Ordering::Relaxed );
}

fn netcode_set_client_create_error( error: i32 )
{
    // port: helper for the C assignment `client_create_error = ...`
    client_create_error.store( error, std::sync::atomic::Ordering::Relaxed );
}

pub fn netcode_client_socket_create( socket: &mut netcode_socket_t,
                                     address: &netcode_address_t,
                                     send_buffer_size: i32,
                                     receive_buffer_size: i32,
                                     config: &netcode_client_config_t ) -> i32
{
    if config.network_simulator.is_null()
    {
        if config.override_send_and_receive == 0
        {
            if netcode_socket_create( socket, address, send_buffer_size, receive_buffer_size ) != NETCODE_SOCKET_ERROR_NONE
            {
                netcode_set_client_create_error( if address.r#type == NETCODE_ADDRESS_IPV6 as u8 { NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED }
                                                 else { NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED } );
                return 0;
            }
        }
    }
    else
    {
        if address.port == 0
        {
            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: must bind to a specific port when using network simulator\n" );
            netcode_set_client_create_error( NETCODE_CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT );
            return 0;
        }
    }

    return 1;
}

pub fn netcode_client_create_dual( address1_string: &str,
                                   address2_string: Option<&str>,
                                   config: &netcode_client_config_t,
                                   time: f64 ) -> Option<Box<netcode_client_t>>
{
    netcode_assert!( unsafe { netcode.initialized } != 0 );

    netcode_set_client_create_error( NETCODE_CLIENT_CREATE_ERROR_NONE );

    // tolerate a zeroed config: default the allocator functions so a forgotten
    // netcode_default_client_config is an inconvenience, not a crash

    let mut config_copy: netcode_client_config_t = *config;
    if config_copy.allocate_function.is_none()
    {
        config_copy.allocate_function = Some( netcode_default_allocate_function );
    }
    if config_copy.free_function.is_none()
    {
        config_copy.free_function = Some( netcode_default_free_function );
    }
    let config = &config_copy;

    // the overrides are called on the update path with no null check. a missing one is a
    // configuration error, refused here rather than dereferenced on the first update.

    if config.override_send_and_receive != 0 && ( config.send_packet_override.is_none() || config.receive_packet_override.is_none() )
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: override_send_and_receive requires both send_packet_override and receive_packet_override\n" );
        netcode_set_client_create_error( NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );
        return None;
    }

    let mut address1 = netcode_address_t::default();
    let mut address2 = netcode_address_t::default();

    if netcode_parse_address( address1_string, &mut address1 ) != NETCODE_OK
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse client address\n" );
        netcode_set_client_create_error( NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED );
        return None;
    }

    if let Some( address2_string ) = address2_string
    {
        if netcode_parse_address( address2_string, &mut address2 ) != NETCODE_OK
        {
            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse client address2\n" );
            netcode_set_client_create_error( NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED );
            return None;
        }
    }

    let mut socket_ipv4 = netcode_socket_t::default();
    let mut socket_ipv6 = netcode_socket_t::default();

    if address1.r#type == NETCODE_ADDRESS_IPV4 as u8 || address2.r#type == NETCODE_ADDRESS_IPV4 as u8
    {
        let socket_address = if address1.r#type == NETCODE_ADDRESS_IPV4 as u8 { address1 } else { address2 };
        if netcode_client_socket_create( &mut socket_ipv4, &socket_address, NETCODE_CLIENT_SOCKET_SNDBUF_SIZE as i32, NETCODE_CLIENT_SOCKET_RCVBUF_SIZE as i32, config ) == 0
        {
            return None;
        }
    }

    if address1.r#type == NETCODE_ADDRESS_IPV6 as u8 || address2.r#type == NETCODE_ADDRESS_IPV6 as u8
    {
        let socket_address = if address1.r#type == NETCODE_ADDRESS_IPV6 as u8 { address1 } else { address2 };
        if netcode_client_socket_create( &mut socket_ipv6, &socket_address, NETCODE_CLIENT_SOCKET_SNDBUF_SIZE as i32, NETCODE_CLIENT_SOCKET_RCVBUF_SIZE as i32, config ) == 0
        {
            netcode_socket_destroy( &mut socket_ipv4 );
            return None;
        }
    }

    // port: the client lives in a Box, not in memory from allocate_function. The allocator is still asked for
    // (and handed back) the client's bytes, so a failing allocator reports NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED
    // as upstream does.

    let client_memory = ( config.allocate_function.unwrap() )( config.allocator_context, std::mem::size_of::<netcode_client_t>() );

    if client_memory.is_null()
    {
        netcode_socket_destroy( &mut socket_ipv4 );
        netcode_socket_destroy( &mut socket_ipv6 );
        netcode_set_client_create_error( NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED );
        return None;
    }

    ( config.free_function.unwrap() )( config.allocator_context, client_memory );

    let socket_address = if address1.r#type == NETCODE_ADDRESS_IPV4 as u8 { socket_ipv4.address } else { socket_ipv6.address };

    if config.network_simulator.is_null()
    {
        netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client started on port {}\n", socket_address.port );
    }
    else
    {
        netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client started on port {} (network simulator)\n", socket_address.port );
    }

    let mut client = Box::new( netcode_client_t
    {
        config: *config,
        socket_holder: netcode_socket_holder_t { ipv4: socket_ipv4, ipv6: socket_ipv6 },
        address: if !config.network_simulator.is_null() { address1 } else { socket_address },
        state: NETCODE_CLIENT_STATE_DISCONNECTED,
        time: time,
        connect_start_time: 0.0,
        last_packet_send_time: -1000.0,
        last_packet_receive_time: -1000.0,
        should_disconnect: 0,
        should_disconnect_state: NETCODE_CLIENT_STATE_DISCONNECTED,
        sequence: 0,
        client_index: 0,
        max_clients: 0,
        server_address_index: 0,
        challenge_token_sequence: 0,
        loopback: 0,
        server_address: netcode_address_t::default(),
        connect_token: netcode_connect_token_t::default(),
        context: netcode_context_t::default(),
        challenge_token_data: [0; NETCODE_CHALLENGE_TOKEN_BYTES as usize],
        replay_protection: netcode_replay_protection_t::default(),
        packet_receive_queue: netcode_packet_queue_t::default(),
        receive_packet_data: std::array::from_fn( |_| None ),
        receive_packet_bytes: [0; NETCODE_CLIENT_MAX_RECEIVE_PACKETS as usize],
        receive_from: [netcode_address_t::default(); NETCODE_CLIENT_MAX_RECEIVE_PACKETS as usize],
    } );

    netcode_packet_queue_init( &mut client.packet_receive_queue, config.allocator_context, config.allocate_function, config.free_function );

    netcode_replay_protection_reset( &mut client.replay_protection );

    return Some( client );
}

pub fn netcode_client_create( address: &str,
                              config: &netcode_client_config_t,
                              time: f64 ) -> Option<Box<netcode_client_t>>
{
    return netcode_client_create_dual( address, None, config, time );
}

pub fn netcode_client_destroy( mut client: Box<netcode_client_t> )
{
    if client.loopback == 0
    {
        netcode_client_disconnect( &mut client );
    }
    else
    {
        netcode_client_disconnect_loopback( &mut client );
    }
    netcode_socket_destroy( &mut client.socket_holder.ipv4 );
    netcode_socket_destroy( &mut client.socket_holder.ipv6 );
    netcode_packet_queue_clear( &mut client.packet_receive_queue );
    // port: free_function( allocator_context, client ) is dropping the Box
    drop( client );
}

pub fn netcode_client_set_state( client: &mut netcode_client_t, client_state: i32 )
{
    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client changed state from '{}' to '{}'\n",
        netcode_client_state_name( client.state ), netcode_client_state_name( client_state ) );

    if let Some( state_change_callback ) = client.config.state_change_callback
    {
        state_change_callback( client.config.callback_context, client.state, client_state );
    }

    client.state = client_state;
}

pub fn netcode_client_reset_before_next_connect( client: &mut netcode_client_t )
{
    client.connect_start_time = client.time;
    client.last_packet_send_time = client.time - 1.0f32 as f64;
    client.last_packet_receive_time = client.time;
    client.should_disconnect = 0;
    client.should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client.challenge_token_sequence = 0;

    client.challenge_token_data = [0; NETCODE_CHALLENGE_TOKEN_BYTES as usize];

    netcode_replay_protection_reset( &mut client.replay_protection );
}

pub fn netcode_client_reset_connection_data( client: &mut netcode_client_t, client_state: i32 )
{
    client.sequence = 0;
    client.loopback = 0;
    client.client_index = 0;
    client.max_clients = 0;
    client.connect_start_time = 0.0;
    client.server_address_index = 0;
    client.server_address = netcode_address_t::default();
    // port: sodium_memzero of the structs is assigning zeroed values
    client.connect_token = netcode_connect_token_t::default();
    client.context = netcode_context_t::default();

    netcode_client_set_state( client, client_state );

    netcode_client_reset_before_next_connect( client );

    netcode_packet_queue_clear( &mut client.packet_receive_queue );
}

pub fn netcode_client_connect( client: &mut netcode_client_t, connect_token: &[u8] )
{
    netcode_client_disconnect( client );

    if netcode_read_connect_token( connect_token, NETCODE_CONNECT_TOKEN_BYTES as i32, &mut client.connect_token ) != NETCODE_OK
    {
        netcode_client_set_state( client, NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN );
        return;
    }

    client.server_address_index = 0;
    client.server_address = client.connect_token.server_addresses[0];

    if client.connect_token.num_server_addresses == 1
    {
        netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connecting to server {}\n",
            netcode_address_to_string( &client.server_address ) );
    }
    else
    {
        netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connecting to server {} [{}/{}]\n",
            netcode_address_to_string( &client.server_address ), client.server_address_index + 1, client.connect_token.num_server_addresses );
    }

    client.context.read_packet_key.copy_from_slice( &client.connect_token.server_to_client_key[..NETCODE_KEY_BYTES as usize] );
    client.context.write_packet_key.copy_from_slice( &client.connect_token.client_to_server_key[..NETCODE_KEY_BYTES as usize] );

    netcode_client_reset_before_next_connect( client );

    netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );
}

pub fn netcode_client_process_packet_internal( client: &mut netcode_client_t, from: &netcode_address_t, packet: Box<dyn netcode_packet_t>, sequence: u64 )
{
    let packet_type: u8 = packet.packet_type();

    match packet_type
    {
        NETCODE_CONNECTION_DENIED_PACKET =>
        {
            if ( client.state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST ||
                 client.state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE )
                                                &&
                      netcode_address_equal( from, &client.server_address ) != 0
            {
                client.should_disconnect = 1;
                client.should_disconnect_state = NETCODE_CLIENT_STATE_CONNECTION_DENIED;
                client.last_packet_receive_time = client.time;
            }
        }

        NETCODE_CONNECTION_CHALLENGE_PACKET =>
        {
            if client.state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST && netcode_address_equal( from, &client.server_address ) != 0
            {
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client received connection challenge packet from server\n" );

                let p = packet.as_any().downcast_ref::<netcode_connection_challenge_packet_t>().unwrap();
                client.challenge_token_sequence = p.challenge_token_sequence;
                client.challenge_token_data.copy_from_slice( &p.challenge_token_data[..NETCODE_CHALLENGE_TOKEN_BYTES as usize] );
                client.last_packet_receive_time = client.time;

                netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE );
            }
        }

        NETCODE_CONNECTION_KEEP_ALIVE_PACKET =>
        {
            if netcode_address_equal( from, &client.server_address ) != 0
            {
                let p = packet.as_any().downcast_ref::<netcode_connection_keep_alive_packet_t>().unwrap();

                if client.state == NETCODE_CLIENT_STATE_CONNECTED
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n" );

                    client.last_packet_receive_time = client.time;
                }
                else if client.state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client received connection keep alive packet from server\n" );

                    client.last_packet_receive_time = client.time;
                    client.client_index = p.client_index;
                    client.max_clients = p.max_clients;

                    netcode_client_set_state( client, NETCODE_CLIENT_STATE_CONNECTED );

                    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connected to server\n" );
                }
            }
        }

        NETCODE_CONNECTION_PAYLOAD_PACKET =>
        {
            if client.state == NETCODE_CLIENT_STATE_CONNECTED && netcode_address_equal( from, &client.server_address ) != 0
            {
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client received connection payload packet from server\n" );

                netcode_packet_queue_push( &mut client.packet_receive_queue, packet, sequence );

                client.last_packet_receive_time = client.time;

                return;
            }
        }

        NETCODE_CONNECTION_DISCONNECT_PACKET =>
        {
            if client.state == NETCODE_CLIENT_STATE_CONNECTED && netcode_address_equal( from, &client.server_address ) != 0
            {
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client received disconnect packet from server\n" );

                client.should_disconnect = 1;
                client.should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
                client.last_packet_receive_time = client.time;
            }
        }

        _ => {}
    }

    // port: free_function( allocator_context, packet ) is the packet going out of scope here
}

pub fn netcode_client_process_packet( client: &mut netcode_client_t, from: &netcode_address_t, packet_data: &mut [u8], packet_bytes: i32 )
{
    let mut allowed_packets = [0u8; NETCODE_CONNECTION_NUM_PACKETS as usize];
    allowed_packets[NETCODE_CONNECTION_DENIED_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_CHALLENGE_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET as usize] = 1;

    let current_timestamp: u64 = netcode_ctime();

    let mut sequence: u64 = 0;

    let packet = netcode_read_packet( packet_data,
                                      packet_bytes,
                                      &mut sequence,
                                      Some( &client.context.read_packet_key[..] ),
                                      client.connect_token.protocol_id,
                                      current_timestamp,
                                      0,
                                      None,
                                      &allowed_packets,
                                      Some( &mut client.replay_protection ),
                                      client.config.allocator_context,
                                      client.config.allocate_function );

    let packet = match packet { Some( packet ) => packet, None => return };

    netcode_client_process_packet_internal( client, from, packet, sequence );
}

pub fn netcode_client_receive_packets( client: &mut netcode_client_t )
{
    netcode_assert!( client.loopback == 0 );

    if client.config.network_simulator.is_null()
    {
        // process packets received from socket

        loop
        {
            let mut from = netcode_address_t::default();
            let mut packet_data = [0u8; NETCODE_MAX_PACKET_BYTES as usize];
            let mut packet_bytes: i32 = 0;

            if client.config.override_send_and_receive != 0
            {
                packet_bytes = ( client.config.receive_packet_override.unwrap() )( client.config.callback_context, &mut from, &mut packet_data, NETCODE_MAX_PACKET_BYTES as i32 );
            }
            else if client.server_address.r#type == NETCODE_ADDRESS_IPV4 as u8
            {
                packet_bytes = netcode_socket_receive_packet( &client.socket_holder.ipv4, &mut from, &mut packet_data, NETCODE_MAX_PACKET_BYTES as i32 );
            }
            else if client.server_address.r#type == NETCODE_ADDRESS_IPV6 as u8
            {
                packet_bytes = netcode_socket_receive_packet( &client.socket_holder.ipv6, &mut from, &mut packet_data, NETCODE_MAX_PACKET_BYTES as i32 );
            }

            if packet_bytes == 0
            {
                break;
            }

            netcode_client_process_packet( client, &from, &mut packet_data, packet_bytes );
        }
    }
    else
    {
        // process packets received from network simulator

        let network_simulator = unsafe { &mut *client.config.network_simulator };

        let num_packets_received = netcode_network_simulator_receive_packets( network_simulator,
                                                                              &client.address,
                                                                              NETCODE_CLIENT_MAX_RECEIVE_PACKETS as i32,
                                                                              &mut client.receive_packet_data,
                                                                              &mut client.receive_packet_bytes,
                                                                              &mut client.receive_from );

        for i in 0..num_packets_received as usize
        {
            // port: the packet data is taken out of the client so it can be processed while the client is borrowed;
            // free_function( allocator_context, receive_packet_data[i] ) is dropping it at the end of the iteration
            let mut packet_data = client.receive_packet_data[i].take().unwrap_or_default();
            let from = client.receive_from[i];
            let packet_bytes = client.receive_packet_bytes[i];

            netcode_client_process_packet( client, &from, &mut packet_data, packet_bytes );
        }
    }
}

pub fn netcode_client_send_packet_to_server_internal( client: &mut netcode_client_t, packet: &dyn netcode_packet_t )
{
    netcode_assert!( client.loopback == 0 );

    let mut packet_data = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    let packet_bytes = netcode_write_packet( packet,
                                             &mut packet_data,
                                             NETCODE_MAX_PACKET_BYTES as i32,
                                             client.sequence,
                                             &client.context.write_packet_key,
                                             client.connect_token.protocol_id );
    client.sequence = client.sequence.wrapping_add( 1 );

    netcode_assert!( packet_bytes <= NETCODE_MAX_PACKET_BYTES as i32 );

    netcode_send_packet_to_address( client.config.network_simulator,
                                    client.config.callback_context,
                                    if client.config.override_send_and_receive != 0 { client.config.send_packet_override } else { None },
                                    &client.socket_holder,
                                    &client.address,
                                    &client.server_address,
                                    &packet_data,
                                    packet_bytes );

    client.last_packet_send_time = client.time;
}

pub fn netcode_client_send_packets( client: &mut netcode_client_t )
{
    netcode_assert!( client.loopback == 0 );

    match client.state
    {
        NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST =>
        {
            if client.last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE as f64 ) >= client.time
            {
                return;
            }

            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client sent connection request packet to server\n" );

            let mut packet = netcode_connection_request_packet_t
            {
                packet_type: NETCODE_CONNECTION_REQUEST_PACKET as u8,
                version_info: [0; NETCODE_VERSION_INFO_BYTES as usize],
                protocol_id: client.connect_token.protocol_id,
                connect_token_expire_timestamp: client.connect_token.expire_timestamp,
                connect_token_nonce: [0; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize],
                connect_token_data: [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize],
            };
            packet.version_info.copy_from_slice( &NETCODE_VERSION_INFO[..NETCODE_VERSION_INFO_BYTES as usize] );
            packet.connect_token_nonce.copy_from_slice( &client.connect_token.nonce[..NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize] );
            packet.connect_token_data.copy_from_slice( &client.connect_token.private_data[..NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize] );

            netcode_client_send_packet_to_server_internal( client, &packet );
        }

        NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE =>
        {
            if client.last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE as f64 ) >= client.time
            {
                return;
            }

            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client sent connection response packet to server\n" );

            let mut packet = netcode_connection_response_packet_t
            {
                packet_type: NETCODE_CONNECTION_RESPONSE_PACKET as u8,
                challenge_token_sequence: client.challenge_token_sequence,
                challenge_token_data: [0; NETCODE_CHALLENGE_TOKEN_BYTES as usize],
            };
            packet.challenge_token_data.copy_from_slice( &client.challenge_token_data );

            netcode_client_send_packet_to_server_internal( client, &packet );
        }

        NETCODE_CLIENT_STATE_CONNECTED =>
        {
            if client.last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE as f64 ) >= client.time
            {
                return;
            }

            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client sent connection keep alive packet to server\n" );

            let packet = netcode_connection_keep_alive_packet_t
            {
                packet_type: NETCODE_CONNECTION_KEEP_ALIVE_PACKET as u8,
                client_index: 0,
                max_clients: 0,
            };

            netcode_client_send_packet_to_server_internal( client, &packet );
        }

        _ => {}
    }
}

pub fn netcode_client_connect_to_next_server( client: &mut netcode_client_t ) -> i32
{
    if client.server_address_index + 1 >= client.connect_token.num_server_addresses
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client has no more servers to connect to\n" );
        return 0;
    }

    client.server_address_index += 1;
    client.server_address = client.connect_token.server_addresses[client.server_address_index as usize];

    netcode_client_reset_before_next_connect( client );

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connecting to next server {} [{}/{}]\n",
        netcode_address_to_string( &client.server_address ),
        client.server_address_index + 1,
        client.connect_token.num_server_addresses );

    netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );

    return 1;
}

pub fn netcode_client_update( client: &mut netcode_client_t, time: f64 )
{
    client.time = time;

    if client.loopback != 0
    {
        return;
    }

    netcode_client_receive_packets( client );

    netcode_client_send_packets( client );

    if client.state > NETCODE_CLIENT_STATE_DISCONNECTED && client.state < NETCODE_CLIENT_STATE_CONNECTED
    {
        let connect_token_expire_seconds: u64 = client.connect_token.expire_timestamp.wrapping_sub( client.connect_token.create_timestamp );
        if client.time - client.connect_start_time >= connect_token_expire_seconds as f64
        {
            netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connect failed. connect token expired\n" );
            netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED, 0 );
            return;
        }
    }

    if client.should_disconnect != 0
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client should disconnect -> {}\n", netcode_client_state_name( client.should_disconnect_state ) );
        if netcode_client_connect_to_next_server( client ) != 0
        {
            return;
        }
        let should_disconnect_state = client.should_disconnect_state;
        netcode_client_disconnect_internal( client, should_disconnect_state, 0 );
        return;
    }

    match client.state
    {
        NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST =>
        {
            if client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + ( client.connect_token.timeout_seconds as f64 ) < time
            {
                netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connect failed. connection request timed out\n" );
                if netcode_client_connect_to_next_server( client ) != 0
                {
                    return;
                }
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT, 0 );
                return;
            }
        }

        NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE =>
        {
            if client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + ( client.connect_token.timeout_seconds as f64 ) < time
            {
                netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connect failed. connection response timed out\n" );
                if netcode_client_connect_to_next_server( client ) != 0
                {
                    return;
                }
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT, 0 );
                return;
            }
        }

        NETCODE_CLIENT_STATE_CONNECTED =>
        {
            if client.connect_token.timeout_seconds > 0 && client.last_packet_receive_time + ( client.connect_token.timeout_seconds as f64 ) < time
            {
                netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connection timed out\n" );
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT, 0 );
                return;
            }
        }

        _ => {}
    }
}

pub fn netcode_client_next_packet_sequence( client: &mut netcode_client_t ) -> u64
{
    return client.sequence;
}

pub fn netcode_client_send_packet( client: &mut netcode_client_t, packet_data: &[u8], packet_bytes: i32 )
{
    netcode_assert!( packet_bytes > 0 );
    netcode_assert!( packet_bytes <= NETCODE_MAX_PACKET_SIZE as i32 );

    // zero byte payloads are not valid on the wire and would silently vanish at the receiver

    if packet_bytes <= 0 || packet_bytes > NETCODE_MAX_PACKET_SIZE as i32
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: payload packet size is out of range ({})\n", packet_bytes );
        return;
    }

    if client.state != NETCODE_CLIENT_STATE_CONNECTED
    {
        return;
    }

    if client.loopback == 0
    {
        // port: the C builds the payload packet in a stack buffer; here it is a payload packet value
        let packet = netcode_connection_payload_packet_t
        {
            packet_type: NETCODE_CONNECTION_PAYLOAD_PACKET as u8,
            payload_bytes: packet_bytes as u32,
            payload_data: packet_data[..packet_bytes as usize].to_vec(),
        };

        netcode_client_send_packet_to_server_internal( client, &packet );
    }
    else
    {
        let sequence = client.sequence;
        client.sequence = client.sequence.wrapping_add( 1 );
        ( client.config.send_loopback_packet_callback.unwrap() )( client.config.callback_context,
                                                                  client.client_index,
                                                                  packet_data,
                                                                  packet_bytes,
                                                                  sequence );
    }
}

pub fn netcode_client_receive_packet( client: &mut netcode_client_t, packet_bytes: &mut i32, packet_sequence: &mut u64 ) -> Option<Vec<u8>>
{
    let packet = netcode_packet_queue_pop( &mut client.packet_receive_queue, Some( packet_sequence ) );

    if let Some( packet ) = packet
    {
        netcode_assert!( packet.packet_type() == NETCODE_CONNECTION_PAYLOAD_PACKET as u8 );
        let packet = packet.into_any().downcast::<netcode_connection_payload_packet_t>().unwrap();
        *packet_bytes = packet.payload_bytes as i32;
        netcode_assert!( *packet_bytes >= 0 );
        netcode_assert!( *packet_bytes <= NETCODE_MAX_PAYLOAD_BYTES as i32 );
        // port: the payload is handed out as its own Vec (the packet's payload_data), not as a pointer into the packet
        return Some( packet.payload_data );
    }
    else
    {
        return None;
    }
}

pub fn netcode_client_free_packet( client: &mut netcode_client_t, packet: Vec<u8> )
{
    // port: free_function( allocator_context, packet - offset ) is dropping the Vec
    drop( packet );
}

pub fn netcode_client_disconnect( client: &mut netcode_client_t )
{
    netcode_assert!( client.loopback == 0 );
    netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_DISCONNECTED, 1 );
}

pub fn netcode_client_disconnect_internal( client: &mut netcode_client_t, destination_state: i32, send_disconnect_packets: i32 )
{
    netcode_assert!( client.loopback == 0 );
    netcode_assert!( destination_state <= NETCODE_CLIENT_STATE_DISCONNECTED );

    if client.state <= NETCODE_CLIENT_STATE_DISCONNECTED || client.state == destination_state
    {
        return;
    }

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client disconnected\n" );

    if client.loopback == 0 && send_disconnect_packets != 0 && client.state > NETCODE_CLIENT_STATE_DISCONNECTED
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client sent disconnect packets to server\n" );

        for i in 0..NETCODE_NUM_DISCONNECT_PACKETS as i32
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client sent disconnect packet {}\n", i );

            let packet = netcode_connection_disconnect_packet_t { packet_type: NETCODE_CONNECTION_DISCONNECT_PACKET as u8 };

            netcode_client_send_packet_to_server_internal( client, &packet );
        }
    }

    netcode_client_reset_connection_data( client, destination_state );
}

pub fn netcode_client_state( client: &mut netcode_client_t ) -> i32
{
    return client.state;
}

pub fn netcode_client_index( client: &mut netcode_client_t ) -> i32
{
    return client.client_index;
}

pub fn netcode_client_max_clients( client: &mut netcode_client_t ) -> i32
{
    return client.max_clients;
}

pub fn netcode_client_connect_loopback( client: &mut netcode_client_t, client_index: i32, max_clients: i32 )
{
    netcode_assert!( client.state <= NETCODE_CLIENT_STATE_DISCONNECTED );

    // a loopback client sends only through this callback. without it the first send would
    // call a null pointer, so refuse to enter loopback at all, in every build.

    netcode_assert!( client.config.send_loopback_packet_callback.is_some() );

    if client.config.send_loopback_packet_callback.is_none()
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: a loopback client requires send_loopback_packet_callback\n" );
        return;
    }

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "client connected to server via loopback as client {}\n", client_index );
    client.state = NETCODE_CLIENT_STATE_CONNECTED;
    client.client_index = client_index;
    client.max_clients = max_clients;
    client.loopback = 1;
}

pub fn netcode_client_disconnect_loopback( client: &mut netcode_client_t )
{
    netcode_assert!( client.loopback != 0 );
    netcode_client_reset_connection_data( client, NETCODE_CLIENT_STATE_DISCONNECTED );
}

pub fn netcode_client_loopback( client: &mut netcode_client_t ) -> i32
{
    return client.loopback;
}

pub fn netcode_client_process_loopback_packet( client: &mut netcode_client_t, packet_data: &[u8], packet_bytes: i32, packet_sequence: u64 )
{
    netcode_assert!( client.loopback != 0 );
    netcode_assert!( packet_bytes > 0 );
    netcode_assert!( packet_bytes <= NETCODE_MAX_PACKET_SIZE as i32 );

    if client.loopback == 0
    {
        return;
    }

    if packet_bytes <= 0 || packet_bytes > NETCODE_MAX_PACKET_SIZE as i32
    {
        return;
    }

    let mut packet = match netcode_create_payload_packet( packet_bytes, client.config.allocator_context, client.config.allocate_function )
    {
        Some( packet ) => packet,
        None => return,
    };
    packet.payload_data[..packet_bytes as usize].copy_from_slice( &packet_data[..packet_bytes as usize] );
    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "client processing loopback packet from server\n" );
    netcode_packet_queue_push( &mut client.packet_receive_queue, packet, packet_sequence );
}

pub fn netcode_client_get_port( client: &mut netcode_client_t ) -> u16
{
    return if client.address.r#type == NETCODE_ADDRESS_IPV4 as u8 { client.socket_holder.ipv4.address.port } else { client.socket_holder.ipv6.address.port };
}

pub fn netcode_client_server_address( client: &mut netcode_client_t ) -> &mut netcode_address_t
{
    return &mut client.server_address;
}

// ----------------------------------------------------------------

pub const NETCODE_MAX_ENCRYPTION_MAPPINGS: usize = NETCODE_MAX_CLIENTS as usize * 4;

// port: the arrays are heap allocated Vecs of NETCODE_MAX_ENCRYPTION_MAPPINGS entries (NETCODE_KEY_BYTES times that
// for the keys), so a server is never built on the stack. Default allocates them.
pub struct netcode_encryption_manager_t
{
    pub num_encryption_mappings: i32,
    pub timeout: Vec<i32>,
    pub expire_time: Vec<f64>,
    pub last_access_time: Vec<f64>,
    pub address: Vec<netcode_address_t>,
    pub client_index: Vec<i32>,
    pub connect_token_entry_index: Vec<i32>,
    pub send_key: Vec<u8>,
    pub receive_key: Vec<u8>,
}

impl Default for netcode_encryption_manager_t
{
    fn default() -> Self
    {
        netcode_encryption_manager_t
        {
            num_encryption_mappings: 0,
            timeout: vec![0; NETCODE_MAX_ENCRYPTION_MAPPINGS],
            expire_time: vec![0.0; NETCODE_MAX_ENCRYPTION_MAPPINGS],
            last_access_time: vec![0.0; NETCODE_MAX_ENCRYPTION_MAPPINGS],
            address: vec![netcode_address_t::default(); NETCODE_MAX_ENCRYPTION_MAPPINGS],
            client_index: vec![0; NETCODE_MAX_ENCRYPTION_MAPPINGS],
            connect_token_entry_index: vec![0; NETCODE_MAX_ENCRYPTION_MAPPINGS],
            send_key: vec![0; NETCODE_KEY_BYTES as usize * NETCODE_MAX_ENCRYPTION_MAPPINGS],
            receive_key: vec![0; NETCODE_KEY_BYTES as usize * NETCODE_MAX_ENCRYPTION_MAPPINGS],
        }
    }
}

pub fn netcode_encryption_manager_reset( encryption_manager: &mut netcode_encryption_manager_t )
{
    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "reset encryption manager\n" );

    encryption_manager.num_encryption_mappings = 0;

    for i in 0..NETCODE_MAX_ENCRYPTION_MAPPINGS
    {
        encryption_manager.client_index[i] = -1;
        encryption_manager.connect_token_entry_index[i] = -1;
        encryption_manager.expire_time[i] = -1.0;
        encryption_manager.last_access_time[i] = -1000.0;
        encryption_manager.address[i] = netcode_address_t::default();
    }

    encryption_manager.timeout.fill( 0 );
    let send_key_bytes = encryption_manager.send_key.len();
    crate::sodium::sodium_memzero( &mut encryption_manager.send_key, send_key_bytes );
    let receive_key_bytes = encryption_manager.receive_key.len();
    crate::sodium::sodium_memzero( &mut encryption_manager.receive_key, receive_key_bytes );
}

pub fn netcode_encryption_manager_entry_expired( encryption_manager: &netcode_encryption_manager_t, index: i32, time: f64 ) -> i32
{
    let index = index as usize;
    return ( ( encryption_manager.timeout[index] > 0 && ( encryption_manager.last_access_time[index] + encryption_manager.timeout[index] as f64 ) < time ) ||
             ( encryption_manager.expire_time[index] >= 0.0 && encryption_manager.expire_time[index] < time ) ) as i32;
}

pub fn netcode_encryption_manager_add_encryption_mapping( encryption_manager: &mut netcode_encryption_manager_t,
                                                          address: &netcode_address_t,
                                                          send_key: &[u8],
                                                          receive_key: &[u8],
                                                          time: f64,
                                                          expire_time: f64,
                                                          timeout: i32,
                                                          connect_token_entry_index: i32 ) -> i32
{
    let key_bytes = NETCODE_KEY_BYTES as usize;

    for i in 0..encryption_manager.num_encryption_mappings as usize
    {
        if netcode_address_equal( &encryption_manager.address[i], address ) != 0 && netcode_encryption_manager_entry_expired( encryption_manager, i as i32, time ) == 0
        {
            encryption_manager.timeout[i] = timeout;
            encryption_manager.expire_time[i] = expire_time;
            encryption_manager.last_access_time[i] = time;
            encryption_manager.connect_token_entry_index[i] = connect_token_entry_index;
            encryption_manager.send_key[i * key_bytes..( i + 1 ) * key_bytes].copy_from_slice( &send_key[..key_bytes] );
            encryption_manager.receive_key[i * key_bytes..( i + 1 ) * key_bytes].copy_from_slice( &receive_key[..key_bytes] );
            return 1;
        }
    }

    for i in 0..NETCODE_MAX_ENCRYPTION_MAPPINGS
    {
        if encryption_manager.address[i].r#type == NETCODE_ADDRESS_NONE as u8 ||
            ( netcode_encryption_manager_entry_expired( encryption_manager, i as i32, time ) != 0 && encryption_manager.client_index[i] == -1 )
        {
            encryption_manager.timeout[i] = timeout;
            encryption_manager.address[i] = *address;
            encryption_manager.expire_time[i] = expire_time;
            encryption_manager.last_access_time[i] = time;
            encryption_manager.connect_token_entry_index[i] = connect_token_entry_index;
            encryption_manager.send_key[i * key_bytes..( i + 1 ) * key_bytes].copy_from_slice( &send_key[..key_bytes] );
            encryption_manager.receive_key[i * key_bytes..( i + 1 ) * key_bytes].copy_from_slice( &receive_key[..key_bytes] );
            if i as i32 + 1 > encryption_manager.num_encryption_mappings
            {
                encryption_manager.num_encryption_mappings = i as i32 + 1;
            }
            return 1;
        }
    }

    return 0;
}

pub fn netcode_encryption_manager_remove_encryption_mapping( encryption_manager: &mut netcode_encryption_manager_t, address: &netcode_address_t, time: f64 ) -> i32
{
    let key_bytes = NETCODE_KEY_BYTES as usize;

    for i in 0..encryption_manager.num_encryption_mappings as usize
    {
        if netcode_address_equal( &encryption_manager.address[i], address ) != 0
        {
            encryption_manager.expire_time[i] = -1.0;
            encryption_manager.last_access_time[i] = -1000.0;
            encryption_manager.connect_token_entry_index[i] = -1;
            encryption_manager.address[i] = netcode_address_t::default();
            crate::sodium::sodium_memzero( &mut encryption_manager.send_key[i * key_bytes..( i + 1 ) * key_bytes], key_bytes );
            crate::sodium::sodium_memzero( &mut encryption_manager.receive_key[i * key_bytes..( i + 1 ) * key_bytes], key_bytes );

            if i as i32 + 1 == encryption_manager.num_encryption_mappings
            {
                let mut index: i32 = i as i32 - 1;
                while index >= 0
                {
                    if netcode_encryption_manager_entry_expired( encryption_manager, index, time ) == 0 || encryption_manager.client_index[index as usize] != -1
                    {
                        break;
                    }
                    encryption_manager.address[index as usize].r#type = NETCODE_ADDRESS_NONE as u8;
                    index -= 1;
                }
                encryption_manager.num_encryption_mappings = index + 1;
            }

            return 1;
        }
    }

    return 0;
}

pub fn netcode_encryption_manager_find_encryption_mapping( encryption_manager: &mut netcode_encryption_manager_t, address: &netcode_address_t, time: f64 ) -> i32
{
    for i in 0..encryption_manager.num_encryption_mappings as usize
    {
        if netcode_address_equal( &encryption_manager.address[i], address ) != 0 && netcode_encryption_manager_entry_expired( encryption_manager, i as i32, time ) == 0
        {
            encryption_manager.last_access_time[i] = time;
            return i as i32;
        }
    }
    return -1;
}

pub fn netcode_encryption_manager_touch( encryption_manager: &mut netcode_encryption_manager_t, index: i32, address: &netcode_address_t, time: f64 ) -> i32
{
    netcode_assert!( index >= 0 );
    netcode_assert!( index < encryption_manager.num_encryption_mappings );
    if netcode_address_equal( &encryption_manager.address[index as usize], address ) == 0
    {
        return 0;
    }
    encryption_manager.last_access_time[index as usize] = time;
    return 1;
}

pub fn netcode_encryption_manager_set_expire_time( encryption_manager: &mut netcode_encryption_manager_t, index: i32, expire_time: f64 )
{
    netcode_assert!( index >= 0 );
    netcode_assert!( index < encryption_manager.num_encryption_mappings );
    encryption_manager.expire_time[index as usize] = expire_time;
}


pub fn netcode_encryption_manager_get_send_key( encryption_manager: &netcode_encryption_manager_t, index: i32 ) -> Option<&[u8]>
{
    if index == -1
    {
        return None;
    }
    netcode_assert!( index >= 0 );
    netcode_assert!( index < encryption_manager.num_encryption_mappings );
    let key_bytes = NETCODE_KEY_BYTES as usize;
    let index = index as usize;
    return Some( &encryption_manager.send_key[index * key_bytes..( index + 1 ) * key_bytes] );
}

pub fn netcode_encryption_manager_get_receive_key( encryption_manager: &netcode_encryption_manager_t, index: i32 ) -> Option<&[u8]>
{
    if index == -1
    {
        return None;
    }
    netcode_assert!( index >= 0 );
    netcode_assert!( index < encryption_manager.num_encryption_mappings );
    let key_bytes = NETCODE_KEY_BYTES as usize;
    let index = index as usize;
    return Some( &encryption_manager.receive_key[index * key_bytes..( index + 1 ) * key_bytes] );
}

pub fn netcode_encryption_manager_get_timeout( encryption_manager: &netcode_encryption_manager_t, index: i32 ) -> i32
{
    if index == -1
    {
        return 0;
    }
    netcode_assert!( index >= 0 );
    netcode_assert!( index < encryption_manager.num_encryption_mappings );
    return encryption_manager.timeout[index as usize];
}

pub fn netcode_encryption_manager_get_connect_token_entry_index( encryption_manager: &netcode_encryption_manager_t, index: i32 ) -> i32
{
    if index == -1
    {
        return -1;
    }
    netcode_assert!( index >= 0 );
    netcode_assert!( index < encryption_manager.num_encryption_mappings );
    return encryption_manager.connect_token_entry_index[index as usize];
}

// ----------------------------------------------------------------

pub const NETCODE_MAX_CONNECT_TOKEN_ENTRIES: usize = NETCODE_MAX_CLIENTS as usize * 8;

pub const NETCODE_CONNECT_TOKEN_ENTRY_FREE: i32 = 0;
pub const NETCODE_CONNECT_TOKEN_ENTRY_PENDING: i32 = 1;
pub const NETCODE_CONNECT_TOKEN_ENTRY_CONSUMED: i32 = 2;

pub const NETCODE_CONNECT_TOKEN_ENTRY_REFUSED: i32 = -1;
pub const NETCODE_CONNECT_TOKEN_HISTORY_FULL: i32 = -2;

#[derive(Clone, Copy, Default)]
pub struct netcode_connect_token_entry_t
{
    pub state: i32,
    pub time: f64,                      // server time the entry was created. never refreshed afterwards
    pub expire_timestamp: u64,          // when the connect token expires, and with it this entry
    pub mac: [u8; NETCODE_MAC_BYTES as usize],
    pub address: netcode_address_t,
}

pub fn netcode_connect_token_entries_reset( connect_token_entries: &mut [netcode_connect_token_entry_t] )
{
    for i in 0..NETCODE_MAX_CONNECT_TOKEN_ENTRIES
    {
        connect_token_entries[i].state = NETCODE_CONNECT_TOKEN_ENTRY_FREE;
        connect_token_entries[i].time = -1000.0;
        connect_token_entries[i].expire_timestamp = 0;
        connect_token_entries[i].mac = [0; NETCODE_MAC_BYTES as usize];
        connect_token_entries[i].address = netcode_address_t::default();
    }
}

/*
    Returns the index of the entry that admits this connection request, or one of
    NETCODE_CONNECT_TOKEN_ENTRY_REFUSED and NETCODE_CONNECT_TOKEN_HISTORY_FULL.

    An entry is created pending the first time a connect token is seen, and becomes consumed
    when the client that presented it is installed in a client slot. A pending entry admits
    a retransmitted connection request from the address that created it, so a handshake that
    loses a packet still completes. A consumed entry admits nothing, whatever the address, so
    the keys inside a connect token encrypt exactly one session.

    An entry lives until its connect token expires. A history whose entries all hold unexpired
    connect tokens refuses a new connect token instead of evicting one, because evicting is
    how a flood of connect tokens would reopen a token that has already been used.
*/

pub fn netcode_connect_token_entries_find_or_add( connect_token_entries: &mut [netcode_connect_token_entry_t],
                                                  address: &netcode_address_t,
                                                  mac: &[u8],
                                                  expire_timestamp: u64,
                                                  current_timestamp: u64,
                                                  time: f64 ) -> i32
{
    let mac_bytes = NETCODE_MAC_BYTES as usize;

    // find the matching entry for the token mac and the first entry free to take a new token.
    // constant time worst case. This is intentional!

    let mut matching_token_index: i32 = -1;
    let mut free_token_index: i32 = -1;

    for i in 0..NETCODE_MAX_CONNECT_TOKEN_ENTRIES
    {
        if connect_token_entries[i].state != NETCODE_CONNECT_TOKEN_ENTRY_FREE &&
             mac[..mac_bytes] == connect_token_entries[i].mac[..mac_bytes]
        {
            matching_token_index = i as i32;
        }

        if free_token_index == -1 &&
             ( connect_token_entries[i].state == NETCODE_CONNECT_TOKEN_ENTRY_FREE ||
               connect_token_entries[i].expire_timestamp <= current_timestamp )
        {
            free_token_index = i as i32;
        }
    }

    // if no entry is found with the mac, this is a new connect token

    if matching_token_index == -1
    {
        if free_token_index == -1
        {
            return NETCODE_CONNECT_TOKEN_HISTORY_FULL;
        }

        let entry = &mut connect_token_entries[free_token_index as usize];
        entry.state = NETCODE_CONNECT_TOKEN_ENTRY_PENDING;
        entry.time = time;
        entry.expire_timestamp = expire_timestamp;
        entry.address = *address;
        entry.mac.copy_from_slice( &mac[..mac_bytes] );
        return free_token_index;
    }

    // a pending entry admits the address that created it, and nothing else. a consumed entry admits nothing.
    // the entry time is set when the entry is created and is never refreshed.

    netcode_assert!( matching_token_index >= 0 );
    netcode_assert!( ( matching_token_index as usize ) < NETCODE_MAX_CONNECT_TOKEN_ENTRIES );

    if connect_token_entries[matching_token_index as usize].state == NETCODE_CONNECT_TOKEN_ENTRY_PENDING &&
         netcode_address_equal( &connect_token_entries[matching_token_index as usize].address, address ) != 0
    {
        return matching_token_index;
    }

    return NETCODE_CONNECT_TOKEN_ENTRY_REFUSED;
}

pub fn netcode_connect_token_entries_consume( connect_token_entries: &mut [netcode_connect_token_entry_t], index: i32 )
{
    netcode_assert!( index >= 0 );
    netcode_assert!( ( index as usize ) < NETCODE_MAX_CONNECT_TOKEN_ENTRIES );

    connect_token_entries[index as usize].state = NETCODE_CONNECT_TOKEN_ENTRY_CONSUMED;
}

pub type netcode_fnv_t = u64;

pub fn netcode_fnv_init( fnv: &mut netcode_fnv_t )
{
    *fnv = 0xCBF29CE484222325;
}

pub fn netcode_fnv_write( fnv: &mut netcode_fnv_t, data: &[u8], size: usize )
{
    for i in 0..size
    {
        *fnv ^= data[i] as u64;
        *fnv = fnv.wrapping_mul( 0x00000100000001B3 );
    }
}

pub fn netcode_fnv_finalize( fnv: &mut netcode_fnv_t ) -> u64
{
    return *fnv;
}

pub fn netcode_hash_string( string: &str ) -> u64
{
    let mut fnv: netcode_fnv_t = 0;
    netcode_fnv_init( &mut fnv );
    netcode_fnv_write( &mut fnv, string.as_bytes(), string.len() );
    return netcode_fnv_finalize( &mut fnv );
}

pub fn netcode_hash_data( data: &[u8], size: usize ) -> u64
{
    let mut fnv: netcode_fnv_t = 0;
    netcode_fnv_init( &mut fnv );
    netcode_fnv_write( &mut fnv, data, size );
    return netcode_fnv_finalize( &mut fnv );
}

// ----------------------------------------------------------------

pub const NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS: u32 = 1;
pub const NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS: u32 = 1 << 1;

pub fn netcode_default_server_config( config: &mut netcode_server_config_t )
{
    config.max_connect_token_lifetime = NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME as i32;
    config.allocator_context = std::ptr::null_mut();
    config.allocate_function = Some( netcode_default_allocate_function );
    config.free_function = Some( netcode_default_free_function );
    config.network_simulator = std::ptr::null_mut();
    config.callback_context = std::ptr::null_mut();
    config.connect_disconnect_callback = None;
    config.send_loopback_packet_callback = None;
    config.override_send_and_receive = 0;
    config.send_packet_override = None;
    config.receive_packet_override = None;
}

// port: the per-client arrays of large entries and the per-receive arrays are heap allocated Vecs with the upstream
// lengths, so a server is never built on the stack
pub struct netcode_server_t
{
    pub config: netcode_server_config_t,
    pub socket_holder: netcode_socket_holder_t,
    pub address: netcode_address_t,
    pub address2: netcode_address_t,
    pub flags: u32,
    pub time: f64,
    pub running: i32,
    pub max_clients: i32,
    pub num_connected_clients: i32,
    pub global_sequence: u64,
    pub challenge_sequence: u64,
    pub min_connect_token_expire_timestamp: u64,
    pub challenge_key: [u8; NETCODE_KEY_BYTES as usize],
    pub client_connected: [i32; NETCODE_MAX_CLIENTS as usize],
    pub client_timeout: [i32; NETCODE_MAX_CLIENTS as usize],
    pub client_loopback: [i32; NETCODE_MAX_CLIENTS as usize],
    pub client_confirmed: [i32; NETCODE_MAX_CLIENTS as usize],
    pub client_disconnect_reason: [i32; NETCODE_MAX_CLIENTS as usize],
    pub client_encryption_index: [i32; NETCODE_MAX_CLIENTS as usize],
    pub client_id: [u64; NETCODE_MAX_CLIENTS as usize],
    pub client_sequence: [u64; NETCODE_MAX_CLIENTS as usize],
    pub client_last_packet_send_time: [f64; NETCODE_MAX_CLIENTS as usize],
    pub client_last_packet_receive_time: [f64; NETCODE_MAX_CLIENTS as usize],
    pub client_user_data: Vec<[u8; NETCODE_USER_DATA_BYTES as usize]>,
    pub client_replay_protection: Vec<netcode_replay_protection_t>,
    pub client_packet_queue: Vec<netcode_packet_queue_t>,
    pub client_address: [netcode_address_t; NETCODE_MAX_CLIENTS as usize],
    pub connect_token_entries: Vec<netcode_connect_token_entry_t>,
    pub encryption_manager: netcode_encryption_manager_t,
    pub receive_packet_data: Vec<Option<Vec<u8>>>,
    pub receive_packet_bytes: Vec<i32>,
    pub receive_from: Vec<netcode_address_t>,
}

// port: a C file static; an atomic (netcode is single threaded, so the ordering is irrelevant)
static server_create_error: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new( 0 );

pub fn netcode_server_create_error() -> i32
{
    return server_create_error.load( std::sync::atomic::Ordering::Relaxed );
}

fn netcode_set_server_create_error( error: i32 )
{
    // port: helper for the C assignment `server_create_error = ...`
    server_create_error.store( error, std::sync::atomic::Ordering::Relaxed );
}

pub fn netcode_server_socket_create( socket: &mut netcode_socket_t,
                                     address: &netcode_address_t,
                                     send_buffer_size: i32,
                                     receive_buffer_size: i32,
                                     config: &netcode_server_config_t ) -> i32
{
    if config.network_simulator.is_null()
    {
        if config.override_send_and_receive == 0
        {
            let socket_error = netcode_socket_create( socket, address, send_buffer_size, receive_buffer_size );

            if socket_error != NETCODE_SOCKET_ERROR_NONE
            {
                // report bind failures separately: a port already in use is the common
                // operational failure for dedicated servers, and callers want to react
                // to it differently than to a socket that could not be created at all

                if socket_error == NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED || socket_error == NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED
                {
                    netcode_set_server_create_error( if address.r#type == NETCODE_ADDRESS_IPV6 as u8 { NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED }
                                                     else { NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED } );
                }
                else
                {
                    netcode_set_server_create_error( if address.r#type == NETCODE_ADDRESS_IPV6 as u8 { NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED }
                                                     else { NETCODE_SERVER_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED } );
                }
                return 0;
            }
        }
    }

    return 1;
}

pub fn netcode_server_create_dual( server_address1_string: &str, server_address2_string: Option<&str>, config: &netcode_server_config_t, time: f64 ) -> Option<Box<netcode_server_t>>
{
    netcode_assert!( unsafe { netcode.initialized } != 0 );

    netcode_set_server_create_error( NETCODE_SERVER_CREATE_ERROR_NONE );

    // tolerate a zeroed config: default the allocator functions so a forgotten
    // netcode_default_server_config is an inconvenience, not a crash

    let mut config_copy: netcode_server_config_t = *config;
    if config_copy.allocate_function.is_none()
    {
        config_copy.allocate_function = Some( netcode_default_allocate_function );
    }
    if config_copy.free_function.is_none()
    {
        config_copy.free_function = Some( netcode_default_free_function );
    }
    if config_copy.max_connect_token_lifetime <= 0
    {
        config_copy.max_connect_token_lifetime = NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME as i32;
    }
    let config = &config_copy;

    // the overrides are called on the update path with no null check. a missing one is a
    // configuration error, refused here rather than dereferenced on the first update.

    if config.override_send_and_receive != 0 && ( config.send_packet_override.is_none() || config.receive_packet_override.is_none() )
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: override_send_and_receive requires both send_packet_override and receive_packet_override\n" );
        netcode_set_server_create_error( NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );
        return None;
    }

    let mut server_address1 = netcode_address_t::default();
    let mut server_address2 = netcode_address_t::default();

    if netcode_parse_address( server_address1_string, &mut server_address1 ) != NETCODE_OK
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse server public address\n" );
        netcode_set_server_create_error( NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED );
        return None;
    }

    if let Some( server_address2_string ) = server_address2_string
    {
        if netcode_parse_address( server_address2_string, &mut server_address2 ) != NETCODE_OK
        {
            netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: failed to parse server public address2\n" );
            netcode_set_server_create_error( NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED );
            return None;
        }
    }

    let mut bind_address_ipv4 = netcode_address_t::default();
    let mut bind_address_ipv6 = netcode_address_t::default();

    let mut socket_ipv4 = netcode_socket_t::default();
    let mut socket_ipv6 = netcode_socket_t::default();

    if server_address1.r#type == NETCODE_ADDRESS_IPV4 as u8 || server_address2.r#type == NETCODE_ADDRESS_IPV4 as u8
    {
        bind_address_ipv4.r#type = NETCODE_ADDRESS_IPV4 as u8;
        bind_address_ipv4.port = if server_address1.r#type == NETCODE_ADDRESS_IPV4 as u8 { server_address1.port } else { server_address2.port };

        if netcode_server_socket_create( &mut socket_ipv4, &bind_address_ipv4, NETCODE_SERVER_SOCKET_SNDBUF_SIZE as i32, NETCODE_SERVER_SOCKET_RCVBUF_SIZE as i32, config ) == 0
        {
            return None;
        }
    }

    if server_address1.r#type == NETCODE_ADDRESS_IPV6 as u8 || server_address2.r#type == NETCODE_ADDRESS_IPV6 as u8
    {
        bind_address_ipv6.r#type = NETCODE_ADDRESS_IPV6 as u8;
        bind_address_ipv6.port = if server_address1.r#type == NETCODE_ADDRESS_IPV6 as u8 { server_address1.port } else { server_address2.port };

        if netcode_server_socket_create( &mut socket_ipv6, &bind_address_ipv6, NETCODE_SERVER_SOCKET_SNDBUF_SIZE as i32, NETCODE_SERVER_SOCKET_RCVBUF_SIZE as i32, config ) == 0
        {
            netcode_socket_destroy( &mut socket_ipv4 );
            return None;
        }
    }

    // port: the server lives in a Box, not in memory from allocate_function. The allocator is still asked for
    // (and handed back) the server's bytes, so a failing allocator reports NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED
    // as upstream does.

    let server_memory = ( config.allocate_function.unwrap() )( config.allocator_context, std::mem::size_of::<netcode_server_t>() );
    if server_memory.is_null()
    {
        netcode_socket_destroy( &mut socket_ipv4 );
        netcode_socket_destroy( &mut socket_ipv6 );
        netcode_set_server_create_error( NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED );
        return None;
    }

    ( config.free_function.unwrap() )( config.allocator_context, server_memory );

    if config.network_simulator.is_null()
    {
        netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server listening on {}\n", server_address1_string );
    }
    else
    {
        netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server listening on {} (network simulator)\n", server_address1_string );
    }

    // port: memset( server, 0 ) and the assignments after it are the struct literal

    let mut server = Box::new( netcode_server_t
    {
        config: *config,
        socket_holder: netcode_socket_holder_t { ipv4: socket_ipv4, ipv6: socket_ipv6 },
        address: server_address1,
        address2: server_address2,
        flags: 0,
        time: time,
        running: 0,
        max_clients: 0,
        num_connected_clients: 0,
        global_sequence: 1u64 << 63,
        challenge_sequence: 0,
        min_connect_token_expire_timestamp: 0,
        challenge_key: [0; NETCODE_KEY_BYTES as usize],
        client_connected: [0; NETCODE_MAX_CLIENTS as usize],
        client_timeout: [0; NETCODE_MAX_CLIENTS as usize],
        client_loopback: [0; NETCODE_MAX_CLIENTS as usize],
        client_confirmed: [0; NETCODE_MAX_CLIENTS as usize],
        client_disconnect_reason: [0; NETCODE_MAX_CLIENTS as usize],
        client_encryption_index: [0; NETCODE_MAX_CLIENTS as usize],
        client_id: [0; NETCODE_MAX_CLIENTS as usize],
        client_sequence: [0; NETCODE_MAX_CLIENTS as usize],
        client_last_packet_send_time: [0.0; NETCODE_MAX_CLIENTS as usize],
        client_last_packet_receive_time: [0.0; NETCODE_MAX_CLIENTS as usize],
        client_user_data: vec![[0; NETCODE_USER_DATA_BYTES as usize]; NETCODE_MAX_CLIENTS as usize],
        client_replay_protection: ( 0..NETCODE_MAX_CLIENTS as usize ).map( |_| netcode_replay_protection_t::default() ).collect(),
        client_packet_queue: ( 0..NETCODE_MAX_CLIENTS as usize ).map( |_| netcode_packet_queue_t::default() ).collect(),
        client_address: [netcode_address_t::default(); NETCODE_MAX_CLIENTS as usize],
        connect_token_entries: vec![netcode_connect_token_entry_t::default(); NETCODE_MAX_CONNECT_TOKEN_ENTRIES],
        encryption_manager: netcode_encryption_manager_t::default(),
        receive_packet_data: ( 0..NETCODE_SERVER_MAX_RECEIVE_PACKETS as usize ).map( |_| None ).collect(),
        receive_packet_bytes: vec![0; NETCODE_SERVER_MAX_RECEIVE_PACKETS as usize],
        receive_from: vec![netcode_address_t::default(); NETCODE_SERVER_MAX_RECEIVE_PACKETS as usize],
    } );

    for i in 0..NETCODE_MAX_CLIENTS as usize
    {
        server.client_encryption_index[i] = -1;
    }

    netcode_connect_token_entries_reset( &mut server.connect_token_entries );

    netcode_encryption_manager_reset( &mut server.encryption_manager );

    for i in 0..NETCODE_MAX_CLIENTS as usize
    {
        netcode_replay_protection_reset( &mut server.client_replay_protection[i] );
    }

    return Some( server );
}

pub fn netcode_server_create( server_address_string: &str, config: &netcode_server_config_t, time: f64 ) -> Option<Box<netcode_server_t>>
{
    return netcode_server_create_dual( server_address_string, None, config, time );
}

pub fn netcode_server_destroy( mut server: Box<netcode_server_t> )
{
    netcode_server_stop( &mut server );

    netcode_socket_destroy( &mut server.socket_holder.ipv4 );
    netcode_socket_destroy( &mut server.socket_holder.ipv6 );

    crate::sodium::sodium_memzero( &mut server.config.private_key, NETCODE_KEY_BYTES as usize );

    // port: free_function( allocator_context, server ) is dropping the Box
    drop( server );
}

pub fn netcode_server_start( server: &mut netcode_server_t, max_clients: i32 )
{
    netcode_assert!( max_clients > 0 );
    netcode_assert!( max_clients <= NETCODE_MAX_CLIENTS as i32 );

    // the per-client arrays are sized NETCODE_MAX_CLIENTS. an out of range value here
    // must not get through in release builds where asserts compile out

    if max_clients <= 0 || max_clients > NETCODE_MAX_CLIENTS as i32
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: max clients must be in [1,{}], got {}\n", NETCODE_MAX_CLIENTS, max_clients );
        return;
    }

    if server.running != 0
    {
        netcode_server_stop( server );
    }

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server started with {} client slots\n", max_clients );

    server.running = 1;
    server.max_clients = max_clients;
    server.num_connected_clients = 0;
    server.challenge_sequence = 0;
    netcode_generate_key( &mut server.challenge_key );

    // a connect token issued before this server started carries keys that already encrypted
    // packets at sequence numbers this run starts again from. the earliest expire timestamp a
    // connect token issued after the start can carry is the start time plus the maximum
    // lifetime the backend issues, so anything earlier than that is refused.

    server.min_connect_token_expire_timestamp = netcode_ctime().wrapping_add( server.config.max_connect_token_lifetime as u64 );

    // global packets (challenge, denied) encrypt with the same per-token server to client
    // keys as per-client packets, whose sequences start at zero, so the global sequence
    // lives in the top half of the sequence space to keep AEAD nonces disjoint under a
    // shared key. netcode_server_stop zeroes it, so it must be re-seeded on every start,
    // not just in netcode_server_create -- otherwise a stopped and restarted server would
    // reuse nonces between global and per-client packets.

    server.global_sequence = 1u64 << 63;

    for i in 0..server.max_clients as usize
    {
        netcode_packet_queue_init( &mut server.client_packet_queue[i], server.config.allocator_context, server.config.allocate_function, server.config.free_function );
    }

    for i in 0..NETCODE_MAX_CLIENTS as usize
    {
        server.client_disconnect_reason[i] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    }
}

pub fn netcode_server_send_global_packet( server: &mut netcode_server_t, packet: &dyn netcode_packet_t, to: &netcode_address_t, packet_key: &[u8] )
{
    let mut packet_data = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    let packet_bytes = netcode_write_packet( packet, &mut packet_data, NETCODE_MAX_PACKET_BYTES as i32, server.global_sequence, packet_key, server.config.protocol_id );

    netcode_assert!( packet_bytes <= NETCODE_MAX_PACKET_BYTES as i32 );

    netcode_send_packet_to_address( server.config.network_simulator,
                                    server.config.callback_context,
                                    if server.config.override_send_and_receive != 0 { server.config.send_packet_override } else { None },
                                    &server.socket_holder,
                                    &server.address,
                                    to,
                                    &packet_data,
                                    packet_bytes );

    server.global_sequence = server.global_sequence.wrapping_add( 1 );
}

pub fn netcode_server_send_client_packet( server: &mut netcode_server_t, packet: &dyn netcode_packet_t, client_index: i32 )
{
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    netcode_assert!( server.client_connected[client_index as usize] != 0 );
    netcode_assert!( server.client_loopback[client_index as usize] == 0 );

    let ci = client_index as usize;

    let mut packet_data = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    if netcode_encryption_manager_touch( &mut server.encryption_manager,
                                         server.client_encryption_index[ci],
                                         &server.client_address[ci],
                                         server.time ) == 0
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: encryption mapping is out of date for client {}\n", client_index );
        return;
    }

    // port: the key is never NULL here: the touch above succeeded, so the index is a live mapping
    let packet_key = netcode_encryption_manager_get_send_key( &server.encryption_manager, server.client_encryption_index[ci] );

    let packet_bytes = netcode_write_packet( packet, &mut packet_data, NETCODE_MAX_PACKET_BYTES as i32, server.client_sequence[ci], packet_key.unwrap(), server.config.protocol_id );

    netcode_assert!( packet_bytes <= NETCODE_MAX_PACKET_BYTES as i32 );

    netcode_send_packet_to_address( server.config.network_simulator,
                                    server.config.callback_context,
                                    if server.config.override_send_and_receive != 0 { server.config.send_packet_override } else { None },
                                    &server.socket_holder,
                                    &server.address,
                                    &server.client_address[ci],
                                    &packet_data,
                                    packet_bytes );

    server.client_sequence[ci] = server.client_sequence[ci].wrapping_add( 1 );

    server.client_last_packet_send_time[ci] = server.time;
}

pub fn netcode_server_reset_client_slot( server: &mut netcode_server_t, client_index: i32 )
{
    let ci = client_index as usize;

    netcode_packet_queue_clear( &mut server.client_packet_queue[ci] );

    server.client_connected[ci] = 0;
    server.client_loopback[ci] = 0;
    server.client_confirmed[ci] = 0;
    server.client_id[ci] = 0;
    server.client_sequence[ci] = 0;
    server.client_last_packet_send_time[ci] = 0.0;
    server.client_last_packet_receive_time[ci] = 0.0;
    server.client_address[ci] = netcode_address_t::default();
    server.client_encryption_index[ci] = -1;
    server.client_user_data[ci] = [0; NETCODE_USER_DATA_BYTES as usize];

    server.num_connected_clients -= 1;

    netcode_assert!( server.num_connected_clients >= 0 );
}

pub fn netcode_server_disconnect_client_internal( server: &mut netcode_server_t, client_index: i32, send_disconnect_packets: i32, disconnect_reason: i32 )
{
    netcode_assert!( server.running != 0 );
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    netcode_assert!( server.client_connected[client_index as usize] != 0 );
    netcode_assert!( server.client_loopback[client_index as usize] == 0 );
    netcode_assert!( server.encryption_manager.client_index[server.client_encryption_index[client_index as usize] as usize] == client_index );

    let ci = client_index as usize;

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server disconnected client {}\n", client_index );

    // record why before the callback fires, so the reason can be queried from inside the callback

    server.client_disconnect_reason[ci] = disconnect_reason;

    if let Some( connect_disconnect_callback ) = server.config.connect_disconnect_callback
    {
        connect_disconnect_callback( server.config.callback_context, client_index, 0 );
    }

    if send_disconnect_packets != 0
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server sent disconnect packets to client {}\n", client_index );

        for i in 0..NETCODE_NUM_DISCONNECT_PACKETS as i32
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server sent disconnect packet {}\n", i );

            let packet = netcode_connection_disconnect_packet_t { packet_type: NETCODE_CONNECTION_DISCONNECT_PACKET as u8 };

            netcode_server_send_client_packet( server, &packet, client_index );
        }
    }

    netcode_replay_protection_reset( &mut server.client_replay_protection[ci] );

    server.encryption_manager.client_index[server.client_encryption_index[ci] as usize] = -1;

    let client_address = server.client_address[ci];
    let time = server.time;
    netcode_encryption_manager_remove_encryption_mapping( &mut server.encryption_manager, &client_address, time );

    netcode_server_reset_client_slot( server, client_index );
}

pub fn netcode_server_disconnect_client( server: &mut netcode_server_t, client_index: i32 )
{
    if server.running == 0
    {
        return;
    }

    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );

    if client_index < 0 || client_index >= server.max_clients
    {
        return;
    }

    netcode_assert!( server.client_loopback[client_index as usize] == 0 );

    if server.client_connected[client_index as usize] == 0
    {
        return;
    }

    if server.client_loopback[client_index as usize] != 0
    {
        return;
    }

    netcode_server_disconnect_client_internal( server, client_index, 1, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );
}

pub fn netcode_server_disconnect_all_clients( server: &mut netcode_server_t )
{
    if server.running == 0
    {
        return;
    }

    for i in 0..server.max_clients
    {
        if server.client_connected[i as usize] != 0 && server.client_loopback[i as usize] == 0
        {
            netcode_server_disconnect_client_internal( server, i, 1, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );
        }
    }
}

pub fn netcode_server_stop( server: &mut netcode_server_t )
{
    if server.running == 0
    {
        return;
    }

    netcode_server_disconnect_all_clients( server );

    // loopback clients are not disconnected above, but they must not survive a server stop

    for i in 0..server.max_clients
    {
        if server.client_connected[i as usize] != 0 && server.client_loopback[i as usize] != 0
        {
            netcode_server_disconnect_loopback_client( server, i );
        }
    }

    server.running = 0;
    server.max_clients = 0;
    server.num_connected_clients = 0;

    server.global_sequence = 0;
    server.challenge_sequence = 0;
    crate::sodium::sodium_memzero( &mut server.challenge_key, NETCODE_KEY_BYTES as usize );

    netcode_connect_token_entries_reset( &mut server.connect_token_entries );

    netcode_encryption_manager_reset( &mut server.encryption_manager );

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server stopped\n" );
}

pub fn netcode_server_find_client_index_by_id( server: &mut netcode_server_t, client_id: u64 ) -> i32
{
    for i in 0..server.max_clients
    {
        if server.client_connected[i as usize] != 0 && server.client_id[i as usize] == client_id
        {
            return i;
        }
    }

    return -1;
}

pub fn netcode_server_find_client_index_by_address( server: &mut netcode_server_t, address: &netcode_address_t ) -> i32
{
    for i in 0..server.max_clients
    {
        if server.client_connected[i as usize] != 0 && netcode_address_equal( &server.client_address[i as usize], address ) != 0
        {
            return i;
        }
    }

    return -1;
}

pub fn netcode_server_process_connection_request_packet( server: &mut netcode_server_t,
                                                         from: &netcode_address_t,
                                                         packet: &mut netcode_connection_request_packet_t,
                                                         current_timestamp: u64 )
{
    let mut connect_token_private = netcode_connect_token_private_t::default();
    if netcode_read_connect_token_private( &packet.connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as i32, &mut connect_token_private ) != NETCODE_OK
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. failed to read connect token\n" );
        return;
    }

    let mut found_server_address = 0;
    for i in 0..connect_token_private.num_server_addresses as usize
    {
        if netcode_address_equal( &server.address, &connect_token_private.server_addresses[i] ) != 0
        {
            found_server_address = 1;
        }
        if server.address2.r#type != NETCODE_ADDRESS_NONE as u8 && netcode_address_equal( &server.address2, &connect_token_private.server_addresses[i] ) != 0
        {
            found_server_address = 1;
        }
    }
    if found_server_address == 0
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. server address not in connect token whitelist\n" );
        return;
    }

    if netcode_server_find_client_index_by_address( server, from ) != -1
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. a client with this address is already connected\n" );
        return;
    }

    if netcode_server_find_client_index_by_id( server, connect_token_private.client_id ) != -1
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. a client with this id is already connected\n" );
        return;
    }

    let connect_token_entry_index = netcode_connect_token_entries_find_or_add( &mut server.connect_token_entries,
                                                                               from,
                                                                               &packet.connect_token_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize - NETCODE_MAC_BYTES as usize..],
                                                                               packet.connect_token_expire_timestamp,
                                                                               current_timestamp,
                                                                               server.time );

    if connect_token_entry_index == NETCODE_CONNECT_TOKEN_HISTORY_FULL
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. connect token history is full\n" );
        return;
    }

    if connect_token_entry_index == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. connect token has already been used\n" );
        return;
    }

    if server.num_connected_clients == server.max_clients
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server denied connection request. server is full\n" );

        let p = netcode_connection_denied_packet_t { packet_type: NETCODE_CONNECTION_DENIED_PACKET as u8 };

        netcode_server_send_global_packet( server, &p, from, &connect_token_private.server_to_client_key );

        return;
    }

    let expire_time: f64 = if connect_token_private.timeout_seconds >= 0 { server.time + connect_token_private.timeout_seconds as f64 } else { -1.0 };

    if netcode_encryption_manager_add_encryption_mapping( &mut server.encryption_manager,
                                                          from,
                                                          &connect_token_private.server_to_client_key,
                                                          &connect_token_private.client_to_server_key,
                                                          server.time,
                                                          expire_time,
                                                          connect_token_private.timeout_seconds,
                                                          connect_token_entry_index ) == 0
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. failed to add encryption mapping\n" );
        return;
    }

    let mut challenge_token = netcode_challenge_token_t::default();
    challenge_token.client_id = connect_token_private.client_id;
    challenge_token.user_data.copy_from_slice( &connect_token_private.user_data[..NETCODE_USER_DATA_BYTES as usize] );

    let mut challenge_packet = netcode_connection_challenge_packet_t
    {
        packet_type: NETCODE_CONNECTION_CHALLENGE_PACKET as u8,
        challenge_token_sequence: server.challenge_sequence,
        challenge_token_data: [0; NETCODE_CHALLENGE_TOKEN_BYTES as usize],
    };
    netcode_write_challenge_token( &challenge_token, &mut challenge_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES as i32 );
    if netcode_encrypt_challenge_token( &mut challenge_packet.challenge_token_data,
                                        NETCODE_CHALLENGE_TOKEN_BYTES as i32,
                                        server.challenge_sequence,
                                        &server.challenge_key ) != NETCODE_OK
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection request. failed to encrypt challenge token\n" );
        return;
    }

    server.challenge_sequence = server.challenge_sequence.wrapping_add( 1 );

    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server sent connection challenge packet\n" );

    netcode_server_send_global_packet( server, &challenge_packet, from, &connect_token_private.server_to_client_key );
}

pub fn netcode_server_find_free_client_index( server: &mut netcode_server_t ) -> i32
{
    for i in 0..server.max_clients
    {
        if server.client_connected[i as usize] == 0
        {
            return i;
        }
    }

    return -1;
}

pub fn netcode_server_connect_client( server: &mut netcode_server_t,
                                      client_index: i32,
                                      address: &netcode_address_t,
                                      client_id: u64,
                                      encryption_index: i32,
                                      timeout_seconds: i32,
                                      user_data: &[u8] )
{
    netcode_assert!( server.running != 0 );
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    netcode_assert!( encryption_index != -1 );
    netcode_assert!( server.encryption_manager.client_index[encryption_index as usize] == -1 );

    let ci = client_index as usize;

    server.num_connected_clients += 1;

    netcode_assert!( server.num_connected_clients <= server.max_clients );

    netcode_assert!( server.client_connected[ci] == 0 );

    netcode_encryption_manager_set_expire_time( &mut server.encryption_manager, encryption_index, -1.0 );

    server.encryption_manager.client_index[encryption_index as usize] = client_index;

    server.client_connected[ci] = 1;
    server.client_timeout[ci] = timeout_seconds;
    server.client_encryption_index[ci] = encryption_index;
    server.client_id[ci] = client_id;
    server.client_sequence[ci] = 0;
    server.client_address[ci] = *address;
    server.client_disconnect_reason[ci] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;

    netcode_assert!( netcode_server_find_client_index_by_id( server, client_id ) == client_index );
    netcode_assert!( netcode_server_find_client_index_by_address( server, address ) == client_index );

    server.client_last_packet_send_time[ci] = server.time;
    server.client_last_packet_receive_time[ci] = server.time;
    server.client_user_data[ci].copy_from_slice( &user_data[..NETCODE_USER_DATA_BYTES as usize] );

    // the connect token that got this client here is spent: its history entry admits nothing from now on

    let connect_token_entry_index = netcode_encryption_manager_get_connect_token_entry_index( &server.encryption_manager, encryption_index );
    if connect_token_entry_index >= 0
    {
        netcode_connect_token_entries_consume( &mut server.connect_token_entries, connect_token_entry_index );
    }

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server accepted client {} {:016x} in slot {}\n",
        netcode_address_to_string( address ), client_id, client_index );

    let packet = netcode_connection_keep_alive_packet_t
    {
        packet_type: NETCODE_CONNECTION_KEEP_ALIVE_PACKET as u8,
        client_index: client_index,
        max_clients: server.max_clients,
    };

    netcode_server_send_client_packet( server, &packet, client_index );

    if let Some( connect_disconnect_callback ) = server.config.connect_disconnect_callback
    {
        connect_disconnect_callback( server.config.callback_context, client_index, 1 );
    }
}

pub fn netcode_server_process_connection_response_packet( server: &mut netcode_server_t,
                                                          from: &netcode_address_t,
                                                          packet: &mut netcode_connection_response_packet_t,
                                                          encryption_index: i32 )
{
    if netcode_decrypt_challenge_token( &mut packet.challenge_token_data,
                                        NETCODE_CHALLENGE_TOKEN_BYTES as i32,
                                        packet.challenge_token_sequence,
                                        &server.challenge_key ) != NETCODE_OK
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. failed to decrypt challenge token\n" );
        return;
    }

    let mut challenge_token = netcode_challenge_token_t::default();
    if netcode_read_challenge_token( &packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES as i32, &mut challenge_token ) != NETCODE_OK
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. failed to read challenge token\n" );
        return;
    }

    // port: the send key is copied out of the encryption manager, because the C pointer into it cannot be held across
    // the calls below that take the whole server
    let packet_send_key: Option<[u8; NETCODE_KEY_BYTES as usize]> = netcode_encryption_manager_get_send_key( &server.encryption_manager, encryption_index )
        .map( |key| { let mut copy = [0u8; NETCODE_KEY_BYTES as usize]; copy.copy_from_slice( &key[..NETCODE_KEY_BYTES as usize] ); copy } );

    let packet_send_key = match packet_send_key
    {
        Some( packet_send_key ) => packet_send_key,
        None =>
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. no packet send key\n" );
            return;
        }
    };

    if netcode_server_find_client_index_by_address( server, from ) != -1
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. a client with this address is already connected\n" );
        return;
    }

    if netcode_server_find_client_index_by_id( server, challenge_token.client_id ) != -1
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server ignored connection response. a client with this id is already connected\n" );
        return;
    }

    if server.num_connected_clients == server.max_clients
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server denied connection response. server is full\n" );

        let p = netcode_connection_denied_packet_t { packet_type: NETCODE_CONNECTION_DENIED_PACKET as u8 };

        netcode_server_send_global_packet( server, &p, from, &packet_send_key );

        return;
    }

    let client_index = netcode_server_find_free_client_index( server );

    netcode_assert!( client_index != -1 );

    let timeout_seconds = netcode_encryption_manager_get_timeout( &server.encryption_manager, encryption_index );

    netcode_server_connect_client( server, client_index, from, challenge_token.client_id, encryption_index, timeout_seconds, &challenge_token.user_data );
}

pub fn netcode_server_process_packet_internal( server: &mut netcode_server_t,
                                               from: &netcode_address_t,
                                               mut packet: Box<dyn netcode_packet_t>,
                                               sequence: u64,
                                               current_timestamp: u64,
                                               encryption_index: i32,
                                               client_index: i32 )
{
    let packet_type: u8 = packet.packet_type();

    match packet_type
    {
        NETCODE_CONNECTION_REQUEST_PACKET =>
        {
            if ( server.flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS ) == 0
            {
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server received connection request from {}\n", netcode_address_to_string( from ) );
                netcode_server_process_connection_request_packet( server, from, packet.as_any_mut().downcast_mut::<netcode_connection_request_packet_t>().unwrap(), current_timestamp );
            }
        }

        NETCODE_CONNECTION_RESPONSE_PACKET =>
        {
            if ( server.flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS ) == 0
            {
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server received connection response from {}\n", netcode_address_to_string( from ) );
                netcode_server_process_connection_response_packet( server, from, packet.as_any_mut().downcast_mut::<netcode_connection_response_packet_t>().unwrap(), encryption_index );
            }
        }

        NETCODE_CONNECTION_KEEP_ALIVE_PACKET =>
        {
            if client_index != -1
            {
                let ci = client_index as usize;
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server received connection keep alive packet from client {}\n", client_index );
                server.client_last_packet_receive_time[ci] = server.time;
                if server.client_confirmed[ci] == 0
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server confirmed connection with client {}\n", client_index );
                    server.client_confirmed[ci] = 1;
                }
            }
        }

        NETCODE_CONNECTION_PAYLOAD_PACKET =>
        {
            if client_index != -1
            {
                let ci = client_index as usize;
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server received connection payload packet from client {}\n", client_index );
                server.client_last_packet_receive_time[ci] = server.time;
                if server.client_confirmed[ci] == 0
                {
                    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server confirmed connection with client {}\n", client_index );
                    server.client_confirmed[ci] = 1;
                }
                netcode_packet_queue_push( &mut server.client_packet_queue[ci], packet, sequence );
                return;
            }
        }

        NETCODE_CONNECTION_DISCONNECT_PACKET =>
        {
            if client_index != -1
            {
                netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server received disconnect packet from client {}\n", client_index );
                netcode_server_disconnect_client_internal( server, client_index, 0, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT );
            }
        }

        _ => {}
    }

    // port: free_function( allocator_context, packet ) is the packet going out of scope here
}

pub fn netcode_server_process_packet( server: &mut netcode_server_t, from: &netcode_address_t, packet_data: &mut [u8], packet_bytes: i32 )
{
    let mut allowed_packets = [0u8; NETCODE_CONNECTION_NUM_PACKETS as usize];
    allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_RESPONSE_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET as usize] = 1;

    let current_timestamp: u64 = netcode_ctime();

    netcode_server_read_and_process_packet( server, from, packet_data, packet_bytes, current_timestamp, &allowed_packets );
}

pub fn netcode_server_read_and_process_packet( server: &mut netcode_server_t,
                                               from: &netcode_address_t,
                                               packet_data: &mut [u8],
                                               packet_bytes: i32,
                                               current_timestamp: u64,
                                               allowed_packets: &[u8] )
{
    if server.running == 0
    {
        return;
    }

    if packet_bytes <= 1
    {
        return;
    }

    let mut sequence: u64 = 0;

    let mut encryption_index: i32 = -1;
    let client_index = netcode_server_find_client_index_by_address( server, from );
    if client_index != -1
    {
        netcode_assert!( client_index >= 0 );
        netcode_assert!( client_index < server.max_clients );
        encryption_index = server.client_encryption_index[client_index as usize];
    }
    else
    {
        let time = server.time;
        encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut server.encryption_manager, from, time );
    }

    let read_packet_key = netcode_encryption_manager_get_receive_key( &server.encryption_manager, encryption_index );

    if read_packet_key.is_none() && packet_data[0] != 0
    {
        netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server could not process packet because no encryption mapping exists for {}\n", netcode_address_to_string( from ) );
        return;
    }

    let packet = netcode_read_packet( packet_data,
                                      packet_bytes,
                                      &mut sequence,
                                      read_packet_key,
                                      server.config.protocol_id,
                                      current_timestamp,
                                      server.min_connect_token_expire_timestamp,
                                      Some( &server.config.private_key[..] ),
                                      allowed_packets,
                                      if client_index != -1 { Some( &mut server.client_replay_protection[client_index as usize] ) } else { None },
                                      server.config.allocator_context,
                                      server.config.allocate_function );

    let packet = match packet { Some( packet ) => packet, None => return };

    netcode_server_process_packet_internal( server, from, packet, sequence, current_timestamp, encryption_index, client_index );
}

pub fn netcode_server_receive_packets( server: &mut netcode_server_t )
{
    let mut allowed_packets = [0u8; NETCODE_CONNECTION_NUM_PACKETS as usize];
    allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_RESPONSE_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET as usize] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET as usize] = 1;

    let current_timestamp: u64 = netcode_ctime();

    if server.config.network_simulator.is_null()
    {
        // process packets received from socket

        loop
        {
            let mut from = netcode_address_t::default();

            let mut packet_data = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

            let mut packet_bytes: i32 = 0;

            if server.config.override_send_and_receive != 0
            {
                packet_bytes = ( server.config.receive_packet_override.unwrap() )( server.config.callback_context, &mut from, &mut packet_data, NETCODE_MAX_PACKET_BYTES as i32 );
            }
            else
            {
                // port: handle != 0 is handle.is_some()
                if server.socket_holder.ipv4.handle.is_some()
                {
                    packet_bytes = netcode_socket_receive_packet( &server.socket_holder.ipv4, &mut from, &mut packet_data, NETCODE_MAX_PACKET_BYTES as i32 );
                }

                if packet_bytes == 0 && server.socket_holder.ipv6.handle.is_some()
                {
                    packet_bytes = netcode_socket_receive_packet( &server.socket_holder.ipv6, &mut from, &mut packet_data, NETCODE_MAX_PACKET_BYTES as i32 );
                }
            }

            if packet_bytes == 0
            {
                break;
            }

            netcode_server_read_and_process_packet( server, &from, &mut packet_data, packet_bytes, current_timestamp, &allowed_packets );
        }
    }
    else
    {
        // process packets received from network simulator

        let network_simulator = unsafe { &mut *server.config.network_simulator };

        let num_packets_received = netcode_network_simulator_receive_packets( network_simulator,
                                                                              &server.address,
                                                                              NETCODE_SERVER_MAX_RECEIVE_PACKETS as i32,
                                                                              &mut server.receive_packet_data,
                                                                              &mut server.receive_packet_bytes,
                                                                              &mut server.receive_from );

        for i in 0..num_packets_received as usize
        {
            // port: the packet data is taken out of the server so it can be processed while the server is borrowed;
            // free_function( allocator_context, receive_packet_data[i] ) is dropping it at the end of the iteration
            let mut packet_data = server.receive_packet_data[i].take().unwrap_or_default();
            let from = server.receive_from[i];
            let packet_bytes = server.receive_packet_bytes[i];

            netcode_server_read_and_process_packet( server,
                                                    &from,
                                                    &mut packet_data,
                                                    packet_bytes,
                                                    current_timestamp,
                                                    &allowed_packets );
        }
    }
}

pub fn netcode_server_send_packets( server: &mut netcode_server_t )
{
    if server.running == 0
    {
        return;
    }

    for i in 0..server.max_clients
    {
        let ci = i as usize;
        if server.client_connected[ci] != 0 && server.client_loopback[ci] == 0 &&
             ( server.client_last_packet_send_time[ci] + ( 1.0 / NETCODE_PACKET_SEND_RATE as f64 ) <= server.time )
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server sent connection keep alive packet to client {}\n", i );
            let packet = netcode_connection_keep_alive_packet_t
            {
                packet_type: NETCODE_CONNECTION_KEEP_ALIVE_PACKET as u8,
                client_index: i,
                max_clients: server.max_clients,
            };
            netcode_server_send_client_packet( server, &packet, i );
        }
    }
}

pub fn netcode_server_check_for_timeouts( server: &mut netcode_server_t )
{
    if server.running == 0
    {
        return;
    }

    for i in 0..server.max_clients
    {
        let ci = i as usize;

        if server.client_connected[ci] == 0
        {
            continue;
        }

        if server.client_timeout[ci] <= 0
        {
            continue;
        }

        if server.client_loopback[ci] != 0
        {
            continue;
        }

        if ( server.time - server.client_last_packet_receive_time[ci] ) >= 1.0f32 as f64
        {
            netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server has not received a packet from client {} for {:.2} seconds\n", i, server.time - server.client_last_packet_receive_time[ci] );
        }

        if server.client_last_packet_receive_time[ci] + server.client_timeout[ci] as f64 <= server.time
        {
            netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server timed out client {}\n", i );
            netcode_server_disconnect_client_internal( server, i, 0, NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT );
        }
    }
}

pub fn netcode_server_client_connected( server: &mut netcode_server_t, client_index: i32 ) -> i32
{
    if server.running == 0
    {
        return 0;
    }

    if client_index < 0 || client_index >= server.max_clients
    {
        return 0;
    }

    return server.client_connected[client_index as usize];
}

pub fn netcode_server_client_disconnect_reason( server: &mut netcode_server_t, client_index: i32 ) -> i32
{
    if server.running == 0
    {
        return NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    }

    if client_index < 0 || client_index >= server.max_clients
    {
        return NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    }

    return server.client_disconnect_reason[client_index as usize];
}

pub fn netcode_server_client_id( server: &mut netcode_server_t, client_index: i32 ) -> u64
{
    if server.running == 0
    {
        return 0;
    }

    if client_index < 0 || client_index >= server.max_clients
    {
        return 0;
    }

    return server.client_id[client_index as usize];
}

pub fn netcode_server_client_address( server: &mut netcode_server_t, client_index: i32 ) -> Option<&mut netcode_address_t>
{
    if server.running == 0
    {
        return None;
    }

    if client_index < 0 || client_index >= server.max_clients
    {
        return None;
    }

    return Some( &mut server.client_address[client_index as usize] );
}

pub fn netcode_server_next_packet_sequence( server: &mut netcode_server_t, client_index: i32 ) -> u64
{
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    if server.running == 0
    {
        return 0;
    }
    if client_index < 0 || client_index >= server.max_clients
    {
        return 0;
    }
    if server.client_connected[client_index as usize] == 0
    {
        return 0;
    }
    return server.client_sequence[client_index as usize];
}

pub fn netcode_server_send_packet( server: &mut netcode_server_t, client_index: i32, packet_data: &[u8], packet_bytes: i32 )
{
    netcode_assert!( packet_bytes > 0 );
    netcode_assert!( packet_bytes <= NETCODE_MAX_PACKET_SIZE as i32 );

    // zero byte payloads are not valid on the wire and would silently vanish at the receiver

    if packet_bytes <= 0 || packet_bytes > NETCODE_MAX_PACKET_SIZE as i32
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: payload packet size is out of range ({})\n", packet_bytes );
        return;
    }

    if server.running == 0
    {
        return;
    }

    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );

    if client_index < 0 || client_index >= server.max_clients
    {
        return;
    }

    let ci = client_index as usize;

    if server.client_connected[ci] == 0
    {
        return;
    }

    if server.client_loopback[ci] == 0
    {
        // port: the C builds the payload packet in a stack buffer; here it is a payload packet value
        let packet = netcode_connection_payload_packet_t
        {
            packet_type: NETCODE_CONNECTION_PAYLOAD_PACKET as u8,
            payload_bytes: packet_bytes as u32,
            payload_data: packet_data[..packet_bytes as usize].to_vec(),
        };

        if server.client_confirmed[ci] == 0
        {
            let keep_alive_packet = netcode_connection_keep_alive_packet_t
            {
                packet_type: NETCODE_CONNECTION_KEEP_ALIVE_PACKET as u8,
                client_index: client_index,
                max_clients: server.max_clients,
            };
            netcode_server_send_client_packet( server, &keep_alive_packet, client_index );
        }

        netcode_server_send_client_packet( server, &packet, client_index );
    }
    else
    {
        netcode_assert!( server.config.send_loopback_packet_callback.is_some() );

        let sequence = server.client_sequence[ci];
        server.client_sequence[ci] = server.client_sequence[ci].wrapping_add( 1 );

        ( server.config.send_loopback_packet_callback.unwrap() )( server.config.callback_context,
                                                                  client_index,
                                                                  packet_data,
                                                                  packet_bytes,
                                                                  sequence );

        server.client_last_packet_send_time[ci] = server.time;
    }
}

pub fn netcode_server_receive_packet( server: &mut netcode_server_t, client_index: i32, packet_bytes: &mut i32, packet_sequence: &mut u64 ) -> Option<Vec<u8>>
{
    netcode_assert!( client_index >= 0 );

    if server.running == 0
    {
        return None;
    }

    netcode_assert!( client_index < server.max_clients );

    if client_index < 0 || client_index >= server.max_clients
    {
        return None;
    }

    if server.client_connected[client_index as usize] == 0
    {
        return None;
    }

    let packet = netcode_packet_queue_pop( &mut server.client_packet_queue[client_index as usize], Some( packet_sequence ) );

    if let Some( packet ) = packet
    {
        netcode_assert!( packet.packet_type() == NETCODE_CONNECTION_PAYLOAD_PACKET as u8 );
        let packet = packet.into_any().downcast::<netcode_connection_payload_packet_t>().unwrap();
        *packet_bytes = packet.payload_bytes as i32;
        netcode_assert!( *packet_bytes >= 0 );
        netcode_assert!( *packet_bytes <= NETCODE_MAX_PAYLOAD_BYTES as i32 );
        // port: the payload is handed out as its own Vec (the packet's payload_data), not as a pointer into the packet
        return Some( packet.payload_data );
    }
    else
    {
        return None;
    }
}

pub fn netcode_server_free_packet( server: &mut netcode_server_t, packet: Vec<u8> )
{
    // port: free_function( allocator_context, packet - offset ) is dropping the Vec
    drop( packet );
}

pub fn netcode_server_num_connected_clients( server: &mut netcode_server_t ) -> i32
{
    return server.num_connected_clients;
}

pub fn netcode_server_client_user_data( server: &mut netcode_server_t, client_index: i32 ) -> Option<&mut [u8]>
{
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    if server.running == 0
    {
        return None;
    }
    if client_index < 0 || client_index >= server.max_clients
    {
        return None;
    }
    return Some( &mut server.client_user_data[client_index as usize][..] );
}

pub fn netcode_server_running( server: &mut netcode_server_t ) -> i32
{
    return server.running;
}

pub fn netcode_server_max_clients( server: &mut netcode_server_t ) -> i32
{
    return server.max_clients;
}

pub fn netcode_server_update( server: &mut netcode_server_t, time: f64 )
{
    server.time = time;
    netcode_server_receive_packets( server );
    netcode_server_send_packets( server );
    netcode_server_check_for_timeouts( server );
}

pub fn netcode_server_connect_loopback_client( server: &mut netcode_server_t, client_index: i32, client_id: u64, user_data: Option<&[u8]> )
{
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    netcode_assert!( server.running != 0 );

    // the server sends to a loopback client only through this callback. without it the
    // first send would call a null pointer, so refuse the slot at all, in every build.

    netcode_assert!( server.config.send_loopback_packet_callback.is_some() );

    if server.config.send_loopback_packet_callback.is_none()
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: a loopback client requires send_loopback_packet_callback\n" );
        return;
    }

    if server.running == 0
    {
        return;
    }

    if client_index < 0 || client_index >= server.max_clients
    {
        return;
    }

    let ci = client_index as usize;

    netcode_assert!( server.client_connected[ci] == 0 );

    if server.client_connected[ci] != 0
    {
        return;
    }

    server.num_connected_clients += 1;

    netcode_assert!( server.num_connected_clients <= server.max_clients );

    server.client_loopback[ci] = 1;
    server.client_connected[ci] = 1;
    server.client_confirmed[ci] = 1;
    server.client_encryption_index[ci] = -1;
    server.client_id[ci] = client_id;
    server.client_sequence[ci] = 0;
    server.client_disconnect_reason[ci] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    server.client_address[ci] = netcode_address_t::default();
    server.client_last_packet_send_time[ci] = server.time;
    server.client_last_packet_receive_time[ci] = server.time;

    if let Some( user_data ) = user_data
    {
        server.client_user_data[ci].copy_from_slice( &user_data[..NETCODE_USER_DATA_BYTES as usize] );
    }
    else
    {
        server.client_user_data[ci] = [0; NETCODE_USER_DATA_BYTES as usize];
    }

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server connected loopback client {:016x} in slot {}\n", client_id, client_index );

    if let Some( connect_disconnect_callback ) = server.config.connect_disconnect_callback
    {
        connect_disconnect_callback( server.config.callback_context, client_index, 1 );
    }
}

pub fn netcode_server_disconnect_loopback_client( server: &mut netcode_server_t, client_index: i32 )
{
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    netcode_assert!( server.running != 0 );

    if server.running == 0
    {
        return;
    }

    if client_index < 0 || client_index >= server.max_clients
    {
        return;
    }

    let ci = client_index as usize;

    netcode_assert!( server.client_connected[ci] != 0 );
    netcode_assert!( server.client_loopback[ci] != 0 );

    if server.client_connected[ci] == 0 || server.client_loopback[ci] == 0
    {
        return;
    }

    netcode_printf!( NETCODE_LOG_LEVEL_INFO, "server disconnected loopback client {}\n", client_index );

    server.client_disconnect_reason[ci] = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT;

    if let Some( connect_disconnect_callback ) = server.config.connect_disconnect_callback
    {
        connect_disconnect_callback( server.config.callback_context, client_index, 0 );
    }

    netcode_server_reset_client_slot( server, client_index );
}

pub fn netcode_server_client_loopback( server: &mut netcode_server_t, client_index: i32 ) -> i32
{
    netcode_assert!( server.running != 0 );
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    if server.running == 0
    {
        return 0;
    }
    if client_index < 0 || client_index >= server.max_clients
    {
        return 0;
    }
    return server.client_loopback[client_index as usize];
}

pub fn netcode_server_process_loopback_packet( server: &mut netcode_server_t, client_index: i32, packet_data: &[u8], packet_bytes: i32, packet_sequence: u64 )
{
    netcode_assert!( client_index >= 0 );
    netcode_assert!( client_index < server.max_clients );
    netcode_assert!( packet_bytes > 0 );
    netcode_assert!( packet_bytes <= NETCODE_MAX_PACKET_SIZE as i32 );
    netcode_assert!( server.running != 0 );

    if server.running == 0
    {
        return;
    }

    if client_index < 0 || client_index >= server.max_clients
    {
        return;
    }

    let ci = client_index as usize;

    netcode_assert!( server.client_connected[ci] != 0 );
    netcode_assert!( server.client_loopback[ci] != 0 );

    if server.client_connected[ci] == 0 || server.client_loopback[ci] == 0
    {
        return;
    }

    if packet_bytes <= 0 || packet_bytes > NETCODE_MAX_PACKET_SIZE as i32
    {
        return;
    }

    let mut packet = match netcode_create_payload_packet( packet_bytes, server.config.allocator_context, server.config.allocate_function )
    {
        Some( packet ) => packet,
        None => return,
    };

    packet.payload_data[..packet_bytes as usize].copy_from_slice( &packet_data[..packet_bytes as usize] );

    netcode_printf!( NETCODE_LOG_LEVEL_DEBUG, "server processing loopback packet from client {}\n", client_index );

    server.client_last_packet_receive_time[ci] = server.time;

    netcode_packet_queue_push( &mut server.client_packet_queue[ci], packet, packet_sequence );
}

pub fn netcode_server_get_port( server: &mut netcode_server_t ) -> u16
{
    return if server.address.r#type == NETCODE_ADDRESS_IPV4 as u8 { server.socket_holder.ipv4.address.port } else { server.socket_holder.ipv6.address.port };
}

// ----------------------------------------------------------------

pub fn netcode_generate_connect_token( num_server_addresses: i32,
                                       public_server_addresses: &[&str],
                                       internal_server_addresses: &[&str],
                                       expire_seconds: i32,
                                       timeout_seconds: i32,
                                       client_id: u64,
                                       protocol_id: u64,
                                       private_key: &[u8],
                                       user_data: &[u8],
                                       output_buffer: &mut [u8] ) -> i32
{
    netcode_assert!( num_server_addresses > 0 );
    netcode_assert!( num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT as i32 );

    // the parsed address arrays below are sized NETCODE_MAX_SERVERS_PER_CONNECT. an out of
    // range value here must not get through in release builds where asserts compile out.
    // every other public entry point already does this; this one was missed

    if num_server_addresses <= 0 || num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT as i32
    {
        netcode_printf!( NETCODE_LOG_LEVEL_ERROR, "error: number of server addresses must be in [1,{}], got {}\n", NETCODE_MAX_SERVERS_PER_CONNECT, num_server_addresses );
        return NETCODE_ERROR;
    }

    // parse public server addresses

    let mut parsed_public_server_addresses = [netcode_address_t::default(); NETCODE_MAX_SERVERS_PER_CONNECT as usize];
    for i in 0..num_server_addresses as usize
    {
        if netcode_parse_address( public_server_addresses[i], &mut parsed_public_server_addresses[i] ) != NETCODE_OK
        {
            return NETCODE_ERROR;
        }
    }

    // parse internal server addresses

    let mut parsed_internal_server_addresses = [netcode_address_t::default(); NETCODE_MAX_SERVERS_PER_CONNECT as usize];
    for i in 0..num_server_addresses as usize
    {
        if netcode_parse_address( internal_server_addresses[i], &mut parsed_internal_server_addresses[i] ) != NETCODE_OK
        {
            return NETCODE_ERROR;
        }
    }

    // generate a connect token

    let mut nonce = [0u8; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize];
    netcode_generate_nonce( &mut nonce );

    let mut connect_token_private = netcode_connect_token_private_t::default();
    netcode_generate_connect_token_private( &mut connect_token_private, client_id, timeout_seconds, num_server_addresses, &parsed_internal_server_addresses, Some( user_data ) );

    // write it to a buffer

    let mut connect_token_data = [0u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize];
    netcode_write_connect_token_private( &connect_token_private, &mut connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as i32 );

    // encrypt the buffer

    let create_timestamp: u64 = netcode_ctime();
    let expire_timestamp: u64 = if expire_seconds >= 0 { create_timestamp.wrapping_add( expire_seconds as u64 ) } else { 0xFFFFFFFFFFFFFFFF };
    if netcode_encrypt_connect_token_private( &mut connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as i32, &NETCODE_VERSION_INFO[..], protocol_id, expire_timestamp, &nonce, private_key ) != NETCODE_OK
    {
        return NETCODE_ERROR;
    }

    // wrap a connect token around the private connect token data

    let mut connect_token = netcode_connect_token_t::default();
    connect_token.version_info.copy_from_slice( &NETCODE_VERSION_INFO[..NETCODE_VERSION_INFO_BYTES as usize] );
    connect_token.protocol_id = protocol_id;
    connect_token.create_timestamp = create_timestamp;
    connect_token.expire_timestamp = expire_timestamp;
    connect_token.nonce.copy_from_slice( &nonce );
    connect_token.private_data.copy_from_slice( &connect_token_data );
    connect_token.num_server_addresses = num_server_addresses;
    for i in 0..num_server_addresses as usize
    {
        connect_token.server_addresses[i] = parsed_public_server_addresses[i];
    }
    connect_token.client_to_server_key.copy_from_slice( &connect_token_private.client_to_server_key[..NETCODE_KEY_BYTES as usize] );
    connect_token.server_to_client_key.copy_from_slice( &connect_token_private.server_to_client_key[..NETCODE_KEY_BYTES as usize] );
    connect_token.timeout_seconds = timeout_seconds;

    // write the connect token to the output buffer

    netcode_write_connect_token( &connect_token, output_buffer, NETCODE_CONNECT_TOKEN_BYTES as i32 );

    return NETCODE_OK;
}

// ---------------------------------------------------------------

// port: C's time( NULL ), the wall clock in whole seconds since the epoch, used for connect token timestamps
pub fn netcode_ctime() -> u64
{
    return match std::time::SystemTime::now().duration_since( std::time::UNIX_EPOCH )
    {
        Ok( duration ) => duration.as_secs(),
        Err( _ ) => 0,
    };
}

// port: upstream's per-platform clocks (mach_absolute_time, clock_gettime( CLOCK_MONOTONIC_RAW ), QueryPerformanceCounter)
// are all std::time::Instant, a monotonic clock on every platform. The start is taken on the first call, which
// returns 0.0, as upstream. The per-platform sleeps are kept.

static netcode_time_start: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

// port: <time.h>'s nanosleep, called directly and not through std::thread::sleep, which makes no system call at all
// for a zero duration. Upstream's netcode_sleep( 0.0 ) is a real nanosleep, which gives up the CPU (Linux pads it
// with the timer slack): tests that pump client and server over real sockets in a tight loop depend on that to let
// the kernel deliver their loopback packets, which Linux does asynchronously, between frames.
#[cfg(unix)]
mod netcode_time_ffi
{
    use std::ffi::{ c_int, c_long };

    // port: time_t is a long on Linux / Android, Apple platforms and FreeBSD
    #[repr(C)]
    pub struct timespec
    {
        pub tv_sec: c_long,
        pub tv_nsec: c_long,
    }

    extern "C"
    {
        pub fn nanosleep( req: *const timespec, rem: *mut timespec ) -> c_int;
    }
}

#[cfg(target_os = "macos")]
// MacOS
pub fn netcode_sleep( time: f64 )
{
    let mut ts = netcode_time_ffi::timespec { tv_sec: 0, tv_nsec: 0 };
    ts.tv_sec = time as std::ffi::c_long;
    ts.tv_nsec = ( ( time - ( ts.tv_sec as f64 ) ) * 1000000000.0 ) as std::ffi::c_long;
    unsafe { netcode_time_ffi::nanosleep( &ts, std::ptr::null_mut() ); }
}

#[cfg(all(unix, not(target_os = "macos")))]
// linux and other unix systems (openbsd, freebsd etc.)
pub fn netcode_sleep( time: f64 )
{
    let mut ts = netcode_time_ffi::timespec { tv_sec: 0, tv_nsec: 0 };
    ts.tv_sec = time as std::ffi::c_long;
    ts.tv_nsec = ( ( time - ( ts.tv_sec as f64 ) ) * 1000000000.0 ) as std::ffi::c_long;
    unsafe { netcode_time_ffi::nanosleep( &ts, std::ptr::null_mut() ); }
}

#[cfg(windows)]
// windows
pub fn netcode_sleep( time: f64 )
{
    // port: Sleep( (int) ( time * 1000 ) ) is std::thread::sleep, which calls Sleep( 0 ) for a zero duration as
    // upstream does. A negative time is skipped (upstream passes it to Sleep as a huge DWORD).
    let milliseconds = ( time * 1000.0 ) as i32;
    if milliseconds >= 0
    {
        std::thread::sleep( std::time::Duration::from_millis( milliseconds as u64 ) );
    }
}

pub fn netcode_time() -> f64
{
    match netcode_time_start.get()
    {
        Some( start ) => return start.elapsed().as_secs_f64(),
        None =>
        {
            let _ = netcode_time_start.set( std::time::Instant::now() );
            return 0.0;
        }
    }
}

// ---------------------------------------------------------------


// =====================================================================================================================
//      netcode.c tests (first half)
// =====================================================================================================================

// port: netcode.c from `#if NETCODE_ENABLE_TESTS` up to test_client_server_ipv4_socket_connect. In the same module as the library, so it uses the library's items directly; std items are named by full path.
// The tests are always compiled (NETCODE_ENABLE_TESTS is 1). Packets and buffers upstream frees with free() are
// dropped here (`// port: free`).

fn check_handler( condition: &str,
                  function: &str,
                  file: &str,
                  line: i32 )
{
    print!( "check failed: ( {} ), function {}, file {}, line {}\n", condition, function, file, line );
    // port: __builtin_trap() / __debugbreak() under NETCODE_DEBUG; the process exits with 1 in every build
    std::process::exit( 1 );
}

// port: a local macro (not exported); __FUNCTION__ is the type name of a local fn, less its own name
macro_rules! check {
    ( $condition:expr ) => {{
        if !( $condition )
        {
            fn __check_f() {}
            let name = ::core::any::type_name_of_val( &__check_f );
            let function = &name[..name.len() - "::__check_f".len()];
            check_handler( ::core::stringify!( $condition ), function, ::core::file!(), ::core::line!() as i32 );
        }
    }};
}

fn test_crypto_aead_vectors()
{
    // Known-answer test for the two AEAD primitives netcode relies on, exercising
    // whichever implementation the running CPU selects (reference / SSSE3 / AVX2 for
    // ChaCha20, donna / SSE2 for Poly1305). Expected ciphertext was generated from
    // libsodium reference output and is unchanged across 1.0.20 -> 1.0.22. Do not
    // edit these arrays by hand: a golden failure here means the vendored crypto no
    // longer agrees with upstream, which would break every other netcode
    // implementation on the wire.
    //
    // Declared static on purpose. yojimbo vendors this file and compiles it with
    // NETCODE_ENABLE_TESTS=1 while defining its own test_crypto_aead_vectors in
    // test.cpp; internal linkage keeps the two from colliding.

    // port: the Rust sodium port has only the reference ChaCha20 and Poly1305 implementations (no SIMD variants)

    static kat_key: [u8; 32] = [
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
        0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
        0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
    ];
    static kat_ad: [u8; 12] = [
        0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,
    ];
    static kat_msg: [u8; 58] = [
        0x79,0x6f,0x6a,0x69,0x6d,0x62,0x6f,0x20,0x76,0x65,0x6e,0x64,0x6f,0x72,0x65,0x64,0x20,0x6c,0x69,0x62,
        0x73,0x6f,0x64,0x69,0x75,0x6d,0x20,0x41,0x45,0x41,0x44,0x20,0x6b,0x6e,0x6f,0x77,0x6e,0x2d,0x61,0x6e,
        0x73,0x77,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,0x76,0x65,0x63,0x74,0x6f,0x72,0x21,0x21,
    ];
    static kat_npub_ietf: [u8; 12] = [
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,
    ];
    static kat_ct_ietf: [u8; 74] = [
        0xd5,0xae,0xb1,0x85,0x15,0x8b,0x07,0xb3,0x01,0x15,0xf0,0x59,
        0xb4,0x4e,0x9d,0x45,0x91,0x58,0xab,0xff,0xaf,0xbd,0x81,0x4f,
        0xbf,0x52,0xc2,0x4c,0xa1,0x5e,0x60,0x5f,0x58,0x63,0x31,0x96,
        0xda,0x90,0x07,0x63,0xb9,0x0c,0x21,0x46,0xf2,0xe4,0x65,0x96,
        0x7a,0x81,0x7f,0xa2,0x5d,0xd1,0x79,0xf6,0x9b,0x18,0x5d,0xe0,
        0xb6,0x57,0x93,0xbe,0x8c,0xb5,0xa9,0x75,0x98,0xa4,0x6f,0xd5,
        0xbe,0x9d,
    ];
    static kat_npub_xchacha: [u8; 24] = [
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
        0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    ];
    static kat_ct_xchacha: [u8; 74] = [
        0x2b,0x24,0x83,0x2a,0x6c,0x9e,0x21,0x02,0x2a,0x14,0x32,0x56,
        0x4b,0x27,0x37,0x92,0x24,0x40,0xa9,0x92,0xd3,0x53,0xa7,0xa5,
        0x64,0xd3,0x8e,0x0c,0x75,0x79,0x75,0x3f,0xca,0x82,0xfa,0x85,
        0xf0,0xa6,0xac,0x08,0x9a,0x25,0xf1,0x8f,0x42,0x20,0x70,0x8e,
        0x38,0x25,0xd1,0x08,0x45,0x81,0x75,0x18,0xe4,0xd1,0x88,0xbd,
        0x92,0xfa,0x84,0xdc,0xd6,0xa3,0x9a,0x67,0x52,0x91,0x62,0xf4,
        0x86,0x7b,
    ];

    let mut c = [0u8; 128];
    let mut m = [0u8; 128];
    let mut clen: u64 = 0;
    let mut mlen: u64 = 0;

    // ChaCha20-Poly1305 (IETF) -- the construction netcode uses on the wire

    check!( crypto_aead_chacha20poly1305_ietf_encrypt( &mut c, Some( &mut clen ), &kat_msg, kat_msg.len() as u64, Some( &kat_ad ), kat_ad.len() as u64, None, &kat_npub_ietf, &kat_key ) == 0 );
    check!( clen == kat_ct_ietf.len() as u64 );
    check!( c[..clen as usize] == kat_ct_ietf[..clen as usize] );
    check!( crypto_aead_chacha20poly1305_ietf_decrypt( &mut m, Some( &mut mlen ), None, &c, clen, Some( &kat_ad ), kat_ad.len() as u64, &kat_npub_ietf, &kat_key ) == 0 );
    check!( mlen == kat_msg.len() as u64 );
    check!( m[..mlen as usize] == kat_msg[..mlen as usize] );

    // a tampered tag must be rejected. this is the path ACQUIRE_FENCE guards: the
    // plaintext must not be produced before authentication has completed.

    c[0] ^= 0x01;
    check!( crypto_aead_chacha20poly1305_ietf_decrypt( &mut m, Some( &mut mlen ), None, &c, clen, Some( &kat_ad ), kat_ad.len() as u64, &kat_npub_ietf, &kat_key ) != 0 );

    // XChaCha20-Poly1305

    check!( crypto_aead_xchacha20poly1305_ietf_encrypt( &mut c, Some( &mut clen ), &kat_msg, kat_msg.len() as u64, Some( &kat_ad ), kat_ad.len() as u64, None, &kat_npub_xchacha, &kat_key ) == 0 );
    check!( clen == kat_ct_xchacha.len() as u64 );
    check!( c[..clen as usize] == kat_ct_xchacha[..clen as usize] );
    check!( crypto_aead_xchacha20poly1305_ietf_decrypt( &mut m, Some( &mut mlen ), None, &c, clen, Some( &kat_ad ), kat_ad.len() as u64, &kat_npub_xchacha, &kat_key ) == 0 );
    check!( mlen == kat_msg.len() as u64 );
    check!( m[..mlen as usize] == kat_msg[..mlen as usize] );
    c[0] ^= 0x01;
    check!( crypto_aead_xchacha20poly1305_ietf_decrypt( &mut m, Some( &mut mlen ), None, &c, clen, Some( &kat_ad ), kat_ad.len() as u64, &kat_npub_xchacha, &kat_key ) != 0 );

    // the constant-time comparison that checks the Poly1305 tag. libsodium 1.0.21
    // hardened crypto_verify_n against the compiler optimising it into something
    // branchy; these assertions pin its contract.

    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    for i in 0..64
    {
        a[i] = i as u8;
        b[i] = i as u8;
    }
    check!( crypto_verify_16( &a, &b ) == 0 );
    check!( crypto_verify_32( &a, &b ) == 0 );
    check!( crypto_verify_64( &a, &b ) == 0 );
    for i in 0..8
    {
        b[0] = ( a[0] ^ ( 1u32 << i ) as u8 ) as u8;
        check!( crypto_verify_16( &a, &b ) == -1 );
        check!( crypto_verify_32( &a, &b ) == -1 );
        check!( crypto_verify_64( &a, &b ) == -1 );
    }
    b[0] = a[0];
    b[63] = ( a[63] ^ 0x80 ) as u8;
    check!( crypto_verify_64( &a, &b ) == -1 );
}

// port: upstream queues malloc'd buffers of the given size (the queue holds void *). The Rust queue holds packets, so
// the test queues payload packets carrying a buffer of that size, and compares their addresses as upstream compares
// the pointers.
fn test_queue_packet( bytes: usize ) -> Box<dyn netcode_packet_t>
{
    Box::new( netcode_connection_payload_packet_t { packet_type: NETCODE_CONNECTION_PAYLOAD_PACKET, payload_bytes: bytes as u32, payload_data: vec![0u8; bytes] } )
}

// port: the address of a queued packet, for the pointer comparisons
fn test_queue_packet_address( packet: &dyn netcode_packet_t ) -> *const u8
{
    packet as *const dyn netcode_packet_t as *const u8
}

fn test_queue()
{
    let mut queue = netcode_packet_queue_t::default();

    netcode_packet_queue_init( &mut queue, std::ptr::null_mut(), None, None );

    check!( queue.num_packets == 0 );
    check!( queue.start_index == 0 );

    // attempting to pop a packet off an empty queue should return NULL

    check!( netcode_packet_queue_pop( &mut queue, None ).is_none() );

    // add some packets to the queue and make sure they pop off in the correct order
    {
        const NUM_PACKETS: usize = 100;

        let mut packets: [*const u8; NUM_PACKETS] = [std::ptr::null(); NUM_PACKETS];

        for i in 0..NUM_PACKETS
        {
            let packet = test_queue_packet( ( i + 1 ) * 256 );
            packets[i] = test_queue_packet_address( &*packet );
            check!( netcode_packet_queue_push( &mut queue, packet, i as u64 ) == 1 );
        }

        check!( queue.num_packets == NUM_PACKETS as i32 );

        for i in 0..NUM_PACKETS
        {
            let mut sequence: u64 = 0;
            let packet = netcode_packet_queue_pop( &mut queue, Some( &mut sequence ) );
            check!( sequence == i as u64 );
            check!( packet.as_ref().map( |p| test_queue_packet_address( &**p ) ) == Some( packets[i] ) );
            // port: free( packet )
            drop( packet );
        }
    }

    // after all entries are popped off, the queue is empty, so calls to pop should return NULL

    check!( queue.num_packets == 0 );

    check!( netcode_packet_queue_pop( &mut queue, None ).is_none() );

    // test that the packet queue can be filled to max capacity

    let mut packets: [*const u8; NETCODE_PACKET_QUEUE_SIZE as usize] = [std::ptr::null(); NETCODE_PACKET_QUEUE_SIZE as usize];

    for i in 0..NETCODE_PACKET_QUEUE_SIZE as usize
    {
        let packet = test_queue_packet( i * 256 );
        packets[i] = test_queue_packet_address( &*packet );
        check!( netcode_packet_queue_push( &mut queue, packet, i as u64 ) == 1 );
    }

    check!( queue.num_packets == NETCODE_PACKET_QUEUE_SIZE );

    // when the queue is full, attempting to push a packet should fail and return 0

    check!( netcode_packet_queue_push( &mut queue, test_queue_packet( 100 ), 0 ) == 0 );

    // make sure all packets pop off in the correct order

    for i in 0..NETCODE_PACKET_QUEUE_SIZE as usize
    {
        let mut sequence: u64 = 0;
        let packet = netcode_packet_queue_pop( &mut queue, Some( &mut sequence ) );
        check!( sequence == i as u64 );
        check!( packet.as_ref().map( |p| test_queue_packet_address( &**p ) ) == Some( packets[i] ) );
        // port: free( packet )
        drop( packet );
    }

    // add some packets again

    for i in 0..NETCODE_PACKET_QUEUE_SIZE as usize
    {
        let packet = test_queue_packet( i * 256 );
        packets[i] = test_queue_packet_address( &*packet );
        check!( netcode_packet_queue_push( &mut queue, packet, i as u64 ) == 1 );
    }

    // clear the queue and make sure that all packets are freed

    netcode_packet_queue_clear( &mut queue );

    check!( queue.start_index == 0 );
    check!( queue.num_packets == 0 );
    for i in 0..NETCODE_PACKET_QUEUE_SIZE as usize
    {
        check!( queue.packet_data[i].is_none() );
    }
}

fn test_endian()
{
    let value: u32 = 0x11223344;

    // port: char * bytes = (char*) &value
    let bytes: [u8; 4] = value.to_ne_bytes();

    // port: #if NETCODE_LITTLE_ENDIAN is cfg(target_endian)
    #[cfg(target_endian = "little")]
    {
        check!( bytes[0] == 0x44 );
        check!( bytes[1] == 0x33 );
        check!( bytes[2] == 0x22 );
        check!( bytes[3] == 0x11 );
    }

    #[cfg(not(target_endian = "little"))]
    {
        check!( bytes[3] == 0x44 );
        check!( bytes[2] == 0x33 );
        check!( bytes[1] == 0x22 );
        check!( bytes[0] == 0x11 );
    }
}

fn test_sequence()
{
    check!( netcode_sequence_number_bytes_required( 0 ) == 1 );
    check!( netcode_sequence_number_bytes_required( 0x11 ) == 1 );
    check!( netcode_sequence_number_bytes_required( 0x1122 ) == 2 );
    check!( netcode_sequence_number_bytes_required( 0x112233 ) == 3 );
    check!( netcode_sequence_number_bytes_required( 0x11223344 ) == 4 );
    check!( netcode_sequence_number_bytes_required( 0x1122334455 ) == 5 );
    check!( netcode_sequence_number_bytes_required( 0x112233445566 ) == 6 );
    check!( netcode_sequence_number_bytes_required( 0x11223344556677 ) == 7 );
    check!( netcode_sequence_number_bytes_required( 0x1122334455667788 ) == 8 );
}

fn test_address()
{
    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "[", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "[]", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "[]:", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( ":", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "1", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "12", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "123", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "1234", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "1234.0.12313.0000", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "1234.0.12313.0000.0.0.0.0.0", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( ".", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "..", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "...", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "....", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( ".....", &mut address ) == NETCODE_ERROR );
    }

    // ports must be all digits in [0,65535]. out of range and non-numeric ports must not silently truncate

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "127.0.0.1:65535", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV4 );
        check!( address.port == 65535 );
        check!( netcode_parse_address( "[::1]:65535", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 65535 );
        check!( netcode_parse_address( "127.0.0.1:65536", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "127.0.0.1:99999", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "127.0.0.1:", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "127.0.0.1:40k", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "[::1]:65536", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "[::1]:", &mut address ) == NETCODE_ERROR );
        check!( netcode_parse_address( "[::1]:40k", &mut address ) == NETCODE_ERROR );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "107.77.207.77", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV4 );
        check!( address.port == 0 );
        check!( address.data.ipv4[0] == 107 );
        check!( address.data.ipv4[1] == 77 );
        check!( address.data.ipv4[2] == 207 );
        check!( address.data.ipv4[3] == 77 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "127.0.0.1", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV4 );
        check!( address.port == 0 );
        check!( address.data.ipv4[0] == 127 );
        check!( address.data.ipv4[1] == 0 );
        check!( address.data.ipv4[2] == 0 );
        check!( address.data.ipv4[3] == 1 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "107.77.207.77:40000", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV4 );
        check!( address.port == 40000 );
        check!( address.data.ipv4[0] == 107 );
        check!( address.data.ipv4[1] == 77 );
        check!( address.data.ipv4[2] == 207 );
        check!( address.data.ipv4[3] == 77 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "127.0.0.1:40000", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV4 );
        check!( address.port == 40000 );
        check!( address.data.ipv4[0] == 127 );
        check!( address.data.ipv4[1] == 0 );
        check!( address.data.ipv4[2] == 0 );
        check!( address.data.ipv4[3] == 1 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "fe80::202:b3ff:fe1e:8329", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 0 );
        check!( address.data.ipv6[0] == 0xfe80 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0202 );
        check!( address.data.ipv6[5] == 0xb3ff );
        check!( address.data.ipv6[6] == 0xfe1e );
        check!( address.data.ipv6[7] == 0x8329 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "::", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 0 );
        check!( address.data.ipv6[0] == 0x0000 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0000 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "::1", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 0 );
        check!( address.data.ipv6[0] == 0x0000 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0001 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "::0", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 0 );
        check!( address.data.ipv6[0] == 0x0000 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0000 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "[::1]", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 0 );
        check!( address.data.ipv6[0] == 0x0000 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0001 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "[::0]", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 0 );
        check!( address.data.ipv6[0] == 0x0000 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0000 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "[fe80::1]", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 0 );
        check!( address.data.ipv6[0] == 0xfe80 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0001 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "[fe80::202:b3ff:fe1e:8329]:40000", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 40000 );
        check!( address.data.ipv6[0] == 0xfe80 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0202 );
        check!( address.data.ipv6[5] == 0xb3ff );
        check!( address.data.ipv6[6] == 0xfe1e );
        check!( address.data.ipv6[7] == 0x8329 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "[::]:40000", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 40000 );
        check!( address.data.ipv6[0] == 0x0000 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0000 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "[::1]:5", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 5 );
        check!( address.data.ipv6[0] == 0x0000 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0001 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "[fe80::1]:5", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 5 );
        check!( address.data.ipv6[0] == 0xfe80 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0001 );
    }

    {
        let mut address = netcode_address_t::default();
        check!( netcode_parse_address( "[::1]:40000", &mut address ) == NETCODE_OK );
        check!( address.r#type == NETCODE_ADDRESS_IPV6 );
        check!( address.port == 40000 );
        check!( address.data.ipv6[0] == 0x0000 );
        check!( address.data.ipv6[1] == 0x0000 );
        check!( address.data.ipv6[2] == 0x0000 );
        check!( address.data.ipv6[3] == 0x0000 );
        check!( address.data.ipv6[4] == 0x0000 );
        check!( address.data.ipv6[5] == 0x0000 );
        check!( address.data.ipv6[6] == 0x0000 );
        check!( address.data.ipv6[7] == 0x0001 );
    }
}

const TEST_PROTOCOL_ID: u64 = 0x1122334455667788;
const TEST_CLIENT_ID: u64 = 0x1;
const TEST_SERVER_PORT: u16 = 40000;
const TEST_CONNECT_TOKEN_EXPIRY: i32 = 30;
const TEST_TIMEOUT_SECONDS: i32 = 15;

// port: static ints the assert handlers bump are atomics
static test_oor_asserts_fired: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new( 0 );

fn test_oor_assert_handler( condition: &str, function: &str, file: &str, line: i32 )
{
    let _ = ( condition, function, file, line );
    test_oor_asserts_fired.fetch_add( 1, std::sync::atomic::Ordering::Relaxed );
    // deliberately RETURNS. netcode.h documents that a custom handler may do this and
    // execution continues past the failed assert -- which is the only way to reach the
    // release-build code path from a test binary that has asserts compiled in.
}

fn test_generate_connect_token_out_of_range()
{
    // netcode_generate_connect_token parses into arrays sized NETCODE_MAX_SERVERS_PER_CONNECT.
    // The bounds used to be assert-only, so -DNDEBUG release builds -- which is what ships,
    // and what Debian packages -- wrote past a stack array. Every other public entry point
    // already paired its asserts with a runtime check; this one was missed.
    //
    // The asserts fire first by design, so this installs a handler that returns in order to
    // reach the runtime check underneath them. Without the fix, execution continues into the
    // parse loop and writes out of bounds instead of returning NETCODE_ERROR.

    let private_key = [0u8; NETCODE_KEY_BYTES as usize];
    let user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    // port: the memsets are the zero initializers above

    // port: &server_address (a one element array of strings) is a one element slice
    let server_address: [&str; 1] = [ "127.0.0.1:40000" ];

    test_oor_asserts_fired.store( 0, std::sync::atomic::Ordering::Relaxed );
    netcode_set_assert_function( test_oor_assert_handler );

    check!( netcode_generate_connect_token( 0, &server_address, &server_address, 30, 5, 1000, TEST_PROTOCOL_ID, &private_key, &user_data, &mut connect_token ) == NETCODE_ERROR );
    check!( netcode_generate_connect_token( -1, &server_address, &server_address, 30, 5, 1000, TEST_PROTOCOL_ID, &private_key, &user_data, &mut connect_token ) == NETCODE_ERROR );
    check!( netcode_generate_connect_token( NETCODE_MAX_SERVERS_PER_CONNECT + 1, &server_address, &server_address, 30, 5, 1000, TEST_PROTOCOL_ID, &private_key, &user_data, &mut connect_token ) == NETCODE_ERROR );

    // In a DEBUG build the asserts must still have fired -- they are the caller's debug aid
    // and this test must not silently prove they were removed. In a RELEASE build they are
    // compiled to ((void)0) by design, so requiring them there would fail the very
    // configuration this fix exists for. That asymmetry IS the point of the fix.

    // port: #ifndef NDEBUG is cfg(debug_assertions)
    #[cfg(debug_assertions)]
    {
        check!( test_oor_asserts_fired.load( std::sync::atomic::Ordering::Relaxed ) > 0 );
    }

    // restore the DEFAULT handler, not NULL: netcode_assert calls the pointer with no null
    // guard, so NULL would turn the next failing assert anywhere in the suite into a crash

    netcode_set_assert_function( netcode_default_assert_handler );

    // and an in-range call still succeeds, so the guard cannot pass by rejecting everything

    check!( netcode_generate_connect_token( 1, &server_address, &server_address, 30, 5, 1000, TEST_PROTOCOL_ID, &private_key, &user_data, &mut connect_token ) == NETCODE_OK );
}

fn test_connect_token()
{
    // generate a connect token

    let mut server_address = netcode_address_t::default();
    server_address.r#type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    let mut input_token = netcode_connect_token_private_t::default();

    netcode_generate_connect_token_private( &mut input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, std::slice::from_ref( &server_address ), Some( &user_data ) );

    check!( input_token.client_id == TEST_CLIENT_ID );
    check!( input_token.num_server_addresses == 1 );
    check!( input_token.user_data[..] == user_data[..] );
    check!( netcode_address_equal( &input_token.server_addresses[0], &server_address ) != 0 );

    // write it to a buffer

    let mut buffer = [0u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize];

    netcode_write_connect_token_private( &input_token, &mut buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    // encrypt the buffer

    // port: time( NULL ) is netcode_ctime()
    let expire_timestamp: u64 = netcode_ctime() + 30;
    let mut nonce = [0u8; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize];
    netcode_generate_nonce( &mut nonce );
    let mut key = [0u8; NETCODE_KEY_BYTES as usize];
    netcode_generate_key( &mut key );

    check!( netcode_encrypt_connect_token_private( &mut buffer,
                                                   NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                   NETCODE_VERSION_INFO,
                                                   TEST_PROTOCOL_ID,
                                                   expire_timestamp,
                                                   &nonce,
                                                   &key ) == NETCODE_OK );

    // decrypt the buffer

    check!( netcode_decrypt_connect_token_private( &mut buffer,
                                                   NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                   NETCODE_VERSION_INFO,
                                                   TEST_PROTOCOL_ID,
                                                   expire_timestamp,
                                                   &nonce,
                                                   &key ) == NETCODE_OK );

    // read the connect token back in

    let mut output_token = netcode_connect_token_private_t::default();

    check!( netcode_read_connect_token_private( &buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, &mut output_token ) == NETCODE_OK );

    // make sure that everything matches the original connect token

    check!( output_token.client_id == input_token.client_id );
    check!( output_token.timeout_seconds == input_token.timeout_seconds );
    check!( output_token.num_server_addresses == input_token.num_server_addresses );
    check!( netcode_address_equal( &output_token.server_addresses[0], &input_token.server_addresses[0] ) != 0 );
    check!( output_token.client_to_server_key[..] == input_token.client_to_server_key[..] );
    check!( output_token.server_to_client_key[..] == input_token.server_to_client_key[..] );
    check!( output_token.user_data[..] == input_token.user_data[..] );
}

fn test_challenge_token()
{
    // additional data is NULL, 0. CMakeLists.txt keeps sodium's UBSan exemption as alignment only, so this path guards #186.

    let mut input_token = netcode_challenge_token_t::default();

    input_token.client_id = TEST_CLIENT_ID;
    netcode_random_bytes( &mut input_token.user_data, NETCODE_USER_DATA_BYTES );

    // write it to a buffer

    let mut buffer = [0u8; NETCODE_CHALLENGE_TOKEN_BYTES as usize];

    netcode_write_challenge_token( &input_token, &mut buffer, NETCODE_CHALLENGE_TOKEN_BYTES );

    // encrypt the buffer

    let sequence: u64 = 1000;
    let mut key = [0u8; NETCODE_KEY_BYTES as usize];
    netcode_generate_key( &mut key );

    check!( netcode_encrypt_challenge_token( &mut buffer, NETCODE_CHALLENGE_TOKEN_BYTES, sequence, &key ) == NETCODE_OK );

    // decrypt the buffer

    check!( netcode_decrypt_challenge_token( &mut buffer, NETCODE_CHALLENGE_TOKEN_BYTES, sequence, &key ) == NETCODE_OK );

    // read the challenge token back in

    let mut output_token = netcode_challenge_token_t::default();

    check!( netcode_read_challenge_token( &buffer, NETCODE_CHALLENGE_TOKEN_BYTES, &mut output_token ) == NETCODE_OK );

    // make sure that everything matches the original challenge token

    check!( output_token.client_id == input_token.client_id );
    check!( output_token.user_data[..] == input_token.user_data[..] );
}

// port: the cast of netcode_read_packet's void * to the packet struct is a downcast
fn test_packet_as<T: 'static>( packet: &Option<Box<dyn netcode_packet_t>> ) -> &T
{
    packet.as_ref().unwrap().as_any().downcast_ref::<T>().unwrap()
}

fn test_connection_request_packet()
{
    // generate a connect token

    let mut server_address = netcode_address_t::default();
    server_address.r#type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    let mut input_token = netcode_connect_token_private_t::default();

    netcode_generate_connect_token_private( &mut input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, std::slice::from_ref( &server_address ), Some( &user_data ) );

    check!( input_token.client_id == TEST_CLIENT_ID );
    check!( input_token.num_server_addresses == 1 );
    check!( input_token.user_data[..] == user_data[..] );
    check!( netcode_address_equal( &input_token.server_addresses[0], &server_address ) != 0 );

    // write the conect token to a buffer (non-encrypted)

    let mut connect_token_data = [0u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize];

    netcode_write_connect_token_private( &input_token, &mut connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

    let mut encrypted_connect_token_data = [0u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize];

    encrypted_connect_token_data.copy_from_slice( &connect_token_data );

    let connect_token_expire_timestamp: u64 = netcode_ctime() + 30;
    let mut connect_token_nonce = [0u8; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize];
    netcode_generate_nonce( &mut connect_token_nonce );
    let mut connect_token_key = [0u8; NETCODE_KEY_BYTES as usize];
    netcode_generate_key( &mut connect_token_key );

    check!( netcode_encrypt_connect_token_private( &mut encrypted_connect_token_data,
                                                   NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                   NETCODE_VERSION_INFO,
                                                   TEST_PROTOCOL_ID,
                                                   connect_token_expire_timestamp,
                                                   &connect_token_nonce,
                                                   &connect_token_key ) == NETCODE_OK );

    // setup a connection request packet wrapping the encrypted connect token

    let mut input_packet = netcode_connection_request_packet_t::default();

    input_packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    input_packet.version_info.copy_from_slice( &NETCODE_VERSION_INFO[..NETCODE_VERSION_INFO_BYTES as usize] );
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
    input_packet.connect_token_nonce.copy_from_slice( &connect_token_nonce );
    input_packet.connect_token_data.copy_from_slice( &encrypted_connect_token_data );

    // write the connection request packet to a buffer

    // port: sizeof( buffer ) is written out at the write call (the slice is mutably borrowed there)
    let mut buffer = [0u8; 2048];

    let mut packet_key = [0u8; NETCODE_KEY_BYTES as usize];

    netcode_generate_key( &mut packet_key );

    let bytes_written = netcode_write_packet( &input_packet, &mut buffer, 2048, 1000, &packet_key, TEST_PROTOCOL_ID );

    check!( bytes_written > 0 );

    // read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

    let mut sequence: u64 = 1000;

    let allowed_packets = [1u8; NETCODE_CONNECTION_NUM_PACKETS as usize];

    let output_packet_data = netcode_read_packet( &mut buffer, bytes_written, &mut sequence, Some( &packet_key ), TEST_PROTOCOL_ID, netcode_ctime(), 0, Some( &connect_token_key ), &allowed_packets, None, std::ptr::null_mut(), None );

    check!( output_packet_data.is_some() );

    let output_packet = test_packet_as::<netcode_connection_request_packet_t>( &output_packet_data );

    // make sure the read packet matches what was written

    check!( output_packet.packet_type == NETCODE_CONNECTION_REQUEST_PACKET );
    check!( output_packet.version_info[..] == input_packet.version_info[..] );
    check!( output_packet.protocol_id == input_packet.protocol_id );
    check!( output_packet.connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp );
    check!( output_packet.connect_token_nonce[..] == input_packet.connect_token_nonce[..] );
    check!( output_packet.connect_token_data[..( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES ) as usize] == connect_token_data[..( NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES ) as usize] );

    // port: free( output_packet )
    drop( output_packet_data );
}

pub fn test_connection_denied_packet()
{
    // setup a connection denied packet

    let mut input_packet = netcode_connection_denied_packet_t::default();

    input_packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

    // write the packet to a buffer

    // port: sizeof( buffer ) is NETCODE_MAX_PACKET_BYTES at the write call
    let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    let mut packet_key = [0u8; NETCODE_KEY_BYTES as usize];

    netcode_generate_key( &mut packet_key );

    let bytes_written = netcode_write_packet( &input_packet, &mut buffer, NETCODE_MAX_PACKET_BYTES, 1000, &packet_key, TEST_PROTOCOL_ID );

    check!( bytes_written > 0 );

    // read the packet back in from the buffer

    let mut sequence: u64 = 0;

    let allowed_packet_types = [1u8; NETCODE_CONNECTION_NUM_PACKETS as usize];

    let output_packet_data = netcode_read_packet( &mut buffer, bytes_written, &mut sequence, Some( &packet_key ), TEST_PROTOCOL_ID, netcode_ctime(), 0, None, &allowed_packet_types, None, std::ptr::null_mut(), None );

    check!( output_packet_data.is_some() );

    let output_packet = test_packet_as::<netcode_connection_denied_packet_t>( &output_packet_data );

    // make sure the read packet matches what was written

    check!( output_packet.packet_type == NETCODE_CONNECTION_DENIED_PACKET );

    // port: free( output_packet )
    drop( output_packet_data );
}

pub fn test_connection_challenge_packet()
{
    // setup a connection challenge packet

    let mut input_packet = netcode_connection_challenge_packet_t::default();

    input_packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes( &mut input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

    // write the packet to a buffer

    // port: sizeof( buffer ) is NETCODE_MAX_PACKET_BYTES at the write call
    let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    let mut packet_key = [0u8; NETCODE_KEY_BYTES as usize];

    netcode_generate_key( &mut packet_key );

    let bytes_written = netcode_write_packet( &input_packet, &mut buffer, NETCODE_MAX_PACKET_BYTES, 1000, &packet_key, TEST_PROTOCOL_ID );

    check!( bytes_written > 0 );

    // read the packet back in from the buffer

    let mut sequence: u64 = 0;

    let allowed_packet_types = [1u8; NETCODE_CONNECTION_NUM_PACKETS as usize];

    let output_packet_data = netcode_read_packet( &mut buffer, bytes_written, &mut sequence, Some( &packet_key ), TEST_PROTOCOL_ID, netcode_ctime(), 0, None, &allowed_packet_types, None, std::ptr::null_mut(), None );

    check!( output_packet_data.is_some() );

    let output_packet = test_packet_as::<netcode_connection_challenge_packet_t>( &output_packet_data );

    // make sure the read packet packet matches what was written

    check!( output_packet.packet_type == NETCODE_CONNECTION_CHALLENGE_PACKET );
    check!( output_packet.challenge_token_sequence == input_packet.challenge_token_sequence );
    check!( output_packet.challenge_token_data[..] == input_packet.challenge_token_data[..] );

    // port: free( output_packet )
    drop( output_packet_data );
}

pub fn test_connection_response_packet()
{
    // setup a connection response packet

    let mut input_packet = netcode_connection_response_packet_t::default();

    input_packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes( &mut input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

    // write the packet to a buffer

    // port: sizeof( buffer ) is NETCODE_MAX_PACKET_BYTES at the write call
    let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    let mut packet_key = [0u8; NETCODE_KEY_BYTES as usize];

    netcode_generate_key( &mut packet_key );

    let bytes_written = netcode_write_packet( &input_packet, &mut buffer, NETCODE_MAX_PACKET_BYTES, 1000, &packet_key, TEST_PROTOCOL_ID );

    check!( bytes_written > 0 );

    // read the packet back in from the buffer

    let mut sequence: u64 = 0;

    let allowed_packet_types = [1u8; NETCODE_CONNECTION_NUM_PACKETS as usize];

    let output_packet_data = netcode_read_packet( &mut buffer, bytes_written, &mut sequence, Some( &packet_key ), TEST_PROTOCOL_ID, netcode_ctime(), 0, None, &allowed_packet_types, None, std::ptr::null_mut(), None );

    check!( output_packet_data.is_some() );

    let output_packet = test_packet_as::<netcode_connection_response_packet_t>( &output_packet_data );

    // make sure the read packet matches what was written

    check!( output_packet.packet_type == NETCODE_CONNECTION_RESPONSE_PACKET );
    check!( output_packet.challenge_token_sequence == input_packet.challenge_token_sequence );
    check!( output_packet.challenge_token_data[..] == input_packet.challenge_token_data[..] );

    // port: free( output_packet )
    drop( output_packet_data );
}

pub fn test_connection_keep_alive_packet()
{
    // setup a connection keep alive packet

    let mut input_packet = netcode_connection_keep_alive_packet_t::default();

    input_packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
    input_packet.client_index = 10;
    input_packet.max_clients = 16;

    // write the packet to a buffer

    // port: sizeof( buffer ) is NETCODE_MAX_PACKET_BYTES at the write call
    let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    let mut packet_key = [0u8; NETCODE_KEY_BYTES as usize];

    netcode_generate_key( &mut packet_key );

    let bytes_written = netcode_write_packet( &input_packet, &mut buffer, NETCODE_MAX_PACKET_BYTES, 1000, &packet_key, TEST_PROTOCOL_ID );

    check!( bytes_written > 0 );

    // read the packet back in from the buffer

    let mut sequence: u64 = 0;

    let allowed_packet_types = [1u8; NETCODE_CONNECTION_NUM_PACKETS as usize];

    let output_packet_data = netcode_read_packet( &mut buffer, bytes_written, &mut sequence, Some( &packet_key ), TEST_PROTOCOL_ID, netcode_ctime(), 0, None, &allowed_packet_types, None, std::ptr::null_mut(), None );

    check!( output_packet_data.is_some() );

    let output_packet = test_packet_as::<netcode_connection_keep_alive_packet_t>( &output_packet_data );

    // make sure the read packet matches what was written

    check!( output_packet.packet_type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET );
    check!( output_packet.client_index == input_packet.client_index );
    check!( output_packet.max_clients == input_packet.max_clients );

    // port: free( output_packet )
    drop( output_packet_data );
}

pub fn test_connection_payload_packet()
{
    // setup a connection payload packet

    let mut input_packet = netcode_create_payload_packet( NETCODE_MAX_PAYLOAD_BYTES, std::ptr::null_mut(), None ).unwrap();

    check!( input_packet.packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
    check!( input_packet.payload_bytes == NETCODE_MAX_PAYLOAD_BYTES as u32 );

    netcode_random_bytes( &mut input_packet.payload_data, NETCODE_MAX_PAYLOAD_BYTES );

    // write the packet to a buffer

    // port: sizeof( buffer ) is NETCODE_MAX_PACKET_BYTES at the write call
    let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    let mut packet_key = [0u8; NETCODE_KEY_BYTES as usize];

    netcode_generate_key( &mut packet_key );

    let bytes_written = netcode_write_packet( &*input_packet, &mut buffer, NETCODE_MAX_PACKET_BYTES, 1000, &packet_key, TEST_PROTOCOL_ID );

    check!( bytes_written > 0 );

    // read the packet back in from the buffer

    let mut sequence: u64 = 0;

    let allowed_packet_types = [1u8; NETCODE_CONNECTION_NUM_PACKETS as usize];

    let output_packet_data = netcode_read_packet( &mut buffer, bytes_written, &mut sequence, Some( &packet_key ), TEST_PROTOCOL_ID, netcode_ctime(), 0, None, &allowed_packet_types, None, std::ptr::null_mut(), None );

    check!( output_packet_data.is_some() );

    let output_packet = test_packet_as::<netcode_connection_payload_packet_t>( &output_packet_data );

    // make sure the read packet matches what was written

    check!( output_packet.packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
    check!( output_packet.payload_bytes == input_packet.payload_bytes );
    check!( output_packet.payload_data[..NETCODE_MAX_PAYLOAD_BYTES as usize] == input_packet.payload_data[..NETCODE_MAX_PAYLOAD_BYTES as usize] );

    // port: free( input_packet ); free( output_packet )
    drop( input_packet );
    drop( output_packet_data );
}

pub fn test_connection_disconnect_packet()
{
    // setup a connection disconnect packet

    let mut input_packet = netcode_connection_disconnect_packet_t::default();

    input_packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

    // write the packet to a buffer

    // port: sizeof( buffer ) is NETCODE_MAX_PACKET_BYTES at the write call
    let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES as usize];

    let mut packet_key = [0u8; NETCODE_KEY_BYTES as usize];

    netcode_generate_key( &mut packet_key );

    let bytes_written = netcode_write_packet( &input_packet, &mut buffer, NETCODE_MAX_PACKET_BYTES, 1000, &packet_key, TEST_PROTOCOL_ID );

    check!( bytes_written > 0 );

    // read the packet back in from the buffer

    let mut sequence: u64 = 0;

    let allowed_packet_types = [1u8; NETCODE_CONNECTION_NUM_PACKETS as usize];

    let output_packet_data = netcode_read_packet( &mut buffer, bytes_written, &mut sequence, Some( &packet_key ), TEST_PROTOCOL_ID, netcode_ctime(), 0, None, &allowed_packet_types, None, std::ptr::null_mut(), None );

    check!( output_packet_data.is_some() );

    let output_packet = test_packet_as::<netcode_connection_disconnect_packet_t>( &output_packet_data );

    // make sure the read packet matches what was written

    check!( output_packet.packet_type == NETCODE_CONNECTION_DISCONNECT_PACKET );

    // port: free( output_packet )
    drop( output_packet_data );
}

pub fn test_connect_token_public()
{
    // generate a private connect token

    let mut server_address = netcode_address_t::default();
    server_address.r#type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    let mut connect_token_private = netcode_connect_token_private_t::default();

    netcode_generate_connect_token_private( &mut connect_token_private, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, std::slice::from_ref( &server_address ), Some( &user_data ) );

    check!( connect_token_private.client_id == TEST_CLIENT_ID );
    check!( connect_token_private.num_server_addresses == 1 );
    check!( connect_token_private.user_data[..] == user_data[..] );
    check!( netcode_address_equal( &connect_token_private.server_addresses[0], &server_address ) != 0 );

    // write it to a buffer

    let mut connect_token_private_data = [0u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES as usize];
    netcode_write_connect_token_private( &connect_token_private, &mut connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    // encrypt the buffer

    let create_timestamp: u64 = netcode_ctime();
    let expire_timestamp: u64 = create_timestamp + 30;
    let mut connect_token_nonce = [0u8; NETCODE_CONNECT_TOKEN_NONCE_BYTES as usize];
    netcode_generate_nonce( &mut connect_token_nonce );
    let mut key = [0u8; NETCODE_KEY_BYTES as usize];
    netcode_generate_key( &mut key );
    check!( netcode_encrypt_connect_token_private( &mut connect_token_private_data,
                                                   NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                   NETCODE_VERSION_INFO,
                                                   TEST_PROTOCOL_ID,
                                                   expire_timestamp,
                                                   &connect_token_nonce,
                                                   &key ) == 1 );

    // wrap a public connect token around the private connect token data

    // port: the memset is the zeroed default
    let mut input_connect_token = netcode_connect_token_t::default();
    input_connect_token.version_info.copy_from_slice( &NETCODE_VERSION_INFO[..NETCODE_VERSION_INFO_BYTES as usize] );
    input_connect_token.protocol_id = TEST_PROTOCOL_ID;
    input_connect_token.create_timestamp = create_timestamp;
    input_connect_token.expire_timestamp = expire_timestamp;
    input_connect_token.nonce.copy_from_slice( &connect_token_nonce );
    input_connect_token.private_data.copy_from_slice( &connect_token_private_data );
    input_connect_token.num_server_addresses = 1;
    input_connect_token.server_addresses[0] = server_address;
    input_connect_token.client_to_server_key.copy_from_slice( &connect_token_private.client_to_server_key );
    input_connect_token.server_to_client_key.copy_from_slice( &connect_token_private.server_to_client_key );
    input_connect_token.timeout_seconds = TEST_TIMEOUT_SECONDS as i32;

    // write the connect token to a buffer

    let mut buffer = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
    netcode_write_connect_token( &input_connect_token, &mut buffer, NETCODE_CONNECT_TOKEN_BYTES );

    // read the buffer back in

    let mut output_connect_token = netcode_connect_token_t::default();
    check!( netcode_read_connect_token( &buffer, NETCODE_CONNECT_TOKEN_BYTES, &mut output_connect_token ) == 1 );

    // make sure the public connect token matches what was written

    check!( output_connect_token.version_info[..] == input_connect_token.version_info[..] );
    check!( output_connect_token.protocol_id == input_connect_token.protocol_id );
    check!( output_connect_token.create_timestamp == input_connect_token.create_timestamp );
    check!( output_connect_token.expire_timestamp == input_connect_token.expire_timestamp );
    check!( output_connect_token.nonce[..] == input_connect_token.nonce[..] );
    check!( output_connect_token.private_data[..] == input_connect_token.private_data[..] );
    check!( output_connect_token.num_server_addresses == input_connect_token.num_server_addresses );
    check!( netcode_address_equal( &output_connect_token.server_addresses[0], &input_connect_token.server_addresses[0] ) != 0 );
    check!( output_connect_token.client_to_server_key[..] == input_connect_token.client_to_server_key[..] );
    check!( output_connect_token.server_to_client_key[..] == input_connect_token.server_to_client_key[..] );
    check!( output_connect_token.timeout_seconds == input_connect_token.timeout_seconds );
}

pub fn test_encryption_manager()
{
    let mut encryption_manager = netcode_encryption_manager_t::default();

    netcode_encryption_manager_reset( &mut encryption_manager );

    let mut time: f64 = 100.0;

    // generate some test encryption mappings

    #[derive(Clone, Copy, Default)]
    struct encryption_mapping_t
    {
        address: netcode_address_t,
        send_key: [u8; NETCODE_KEY_BYTES as usize],
        receive_key: [u8; NETCODE_KEY_BYTES as usize],
    }

    const NUM_ENCRYPTION_MAPPINGS: usize = 5;

    // port: the memset is the zeroed default
    let mut encryption_mapping = [encryption_mapping_t::default(); NUM_ENCRYPTION_MAPPINGS];
    for i in 0..NUM_ENCRYPTION_MAPPINGS
    {
        encryption_mapping[i].address.r#type = NETCODE_ADDRESS_IPV6;
        encryption_mapping[i].address.data.ipv6[7] = 1;
        encryption_mapping[i].address.port = ( 20000 + i ) as u16;
        netcode_generate_key( &mut encryption_mapping[i].send_key );
        netcode_generate_key( &mut encryption_mapping[i].receive_key );
    }

    // add the encryption mappings to the manager and make sure they can be looked up by address

    for i in 0..NUM_ENCRYPTION_MAPPINGS
    {
        let mut encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[i].address, time );

        check!( encryption_index == -1 );

        check!( netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index ).is_none() );
        check!( netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index ).is_none() );

        check!( netcode_encryption_manager_add_encryption_mapping( &mut encryption_manager,
                                                                   &encryption_mapping[i].address,
                                                                   &encryption_mapping[i].send_key,
                                                                   &encryption_mapping[i].receive_key,
                                                                   time,
                                                                   -1.0,
                                                                   TEST_TIMEOUT_SECONDS,
                                                                   -1 ) != 0 );

        encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[i].address, time );

        let send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        let receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check!( send_key.is_some() );
        check!( receive_key.is_some() );

        check!( send_key.unwrap()[..NETCODE_KEY_BYTES as usize] == encryption_mapping[i].send_key[..] );
        check!( receive_key.unwrap()[..NETCODE_KEY_BYTES as usize] == encryption_mapping[i].receive_key[..] );
    }

    // removing an encryption mapping that doesn't exist should return 0
    {
        let mut address = netcode_address_t::default();
        address.r#type = NETCODE_ADDRESS_IPV6;
        address.data.ipv6[7] = 1;
        address.port = 50000;

        check!( netcode_encryption_manager_remove_encryption_mapping( &mut encryption_manager, &address, time ) == 0 );
    }

    // remove the first and last encryption mappings

    check!( netcode_encryption_manager_remove_encryption_mapping( &mut encryption_manager, &encryption_mapping[0].address, time ) == 1 );

    check!( netcode_encryption_manager_remove_encryption_mapping( &mut encryption_manager, &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address, time ) == 1 );

    // make sure the encryption mappings that were removed can no longer be looked up by address

    for i in 0..NUM_ENCRYPTION_MAPPINGS
    {
        let encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[i].address, time );

        let send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        let receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        if i != 0 && i != NUM_ENCRYPTION_MAPPINGS - 1
        {
            check!( send_key.is_some() );
            check!( receive_key.is_some() );

            check!( send_key.unwrap()[..NETCODE_KEY_BYTES as usize] == encryption_mapping[i].send_key[..] );
            check!( receive_key.unwrap()[..NETCODE_KEY_BYTES as usize] == encryption_mapping[i].receive_key[..] );
        }
        else
        {
            check!( send_key.is_none() );
            check!( receive_key.is_none() );
        }
    }

    // add the encryption mappings back in

    check!( netcode_encryption_manager_add_encryption_mapping( &mut encryption_manager,
                                                               &encryption_mapping[0].address,
                                                               &encryption_mapping[0].send_key,
                                                               &encryption_mapping[0].receive_key,
                                                               time,
                                                               -1.0,
                                                               TEST_TIMEOUT_SECONDS,
                                                               -1 ) != 0 );

    check!( netcode_encryption_manager_add_encryption_mapping( &mut encryption_manager,
                                                               &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address,
                                                               &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].send_key,
                                                               &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].receive_key,
                                                               time,
                                                               -1.0,
                                                               TEST_TIMEOUT_SECONDS,
                                                               -1 ) != 0 );

    // all encryption mappings should be able to be looked up by address again

    for i in 0..NUM_ENCRYPTION_MAPPINGS
    {
        let encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[i].address, time );

        let send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        let receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check!( send_key.is_some() );
        check!( receive_key.is_some() );

        check!( send_key.unwrap()[..NETCODE_KEY_BYTES as usize] == encryption_mapping[i].send_key[..] );
        check!( receive_key.unwrap()[..NETCODE_KEY_BYTES as usize] == encryption_mapping[i].receive_key[..] );
    }

    // check that encryption mappings time out properly

    time += ( TEST_TIMEOUT_SECONDS * 2 ) as f64;

    for i in 0..NUM_ENCRYPTION_MAPPINGS
    {
        let encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[i].address, time );

        let send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        let receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check!( send_key.is_none() );
        check!( receive_key.is_none() );
    }

    // add the same encryption mappings after timeout

    for i in 0..NUM_ENCRYPTION_MAPPINGS
    {
        let mut encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[i].address, time );

        check!( encryption_index == -1 );

        check!( netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index ).is_none() );
        check!( netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index ).is_none() );

        check!( netcode_encryption_manager_add_encryption_mapping( &mut encryption_manager,
                                                                   &encryption_mapping[i].address,
                                                                   &encryption_mapping[i].send_key,
                                                                   &encryption_mapping[i].receive_key,
                                                                   time,
                                                                   -1.0,
                                                                   TEST_TIMEOUT_SECONDS,
                                                                   -1 ) != 0 );

        encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[i].address, time );

        let send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        let receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check!( send_key.is_some() );
        check!( receive_key.is_some() );

        check!( send_key.unwrap()[..NETCODE_KEY_BYTES as usize] == encryption_mapping[i].send_key[..] );
        check!( receive_key.unwrap()[..NETCODE_KEY_BYTES as usize] == encryption_mapping[i].receive_key[..] );
    }

    // reset the encryption mapping and verify that all encryption mappings have been removed

    netcode_encryption_manager_reset( &mut encryption_manager );

    for i in 0..NUM_ENCRYPTION_MAPPINGS
    {
        let encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[i].address, time );

        let send_key = netcode_encryption_manager_get_send_key( &encryption_manager, encryption_index );
        let receive_key = netcode_encryption_manager_get_receive_key( &encryption_manager, encryption_index );

        check!( send_key.is_none() );
        check!( receive_key.is_none() );
    }

    // test the expire time for encryption mapping works as expected

    check!( netcode_encryption_manager_add_encryption_mapping( &mut encryption_manager,
                                                               &encryption_mapping[0].address,
                                                               &encryption_mapping[0].send_key,
                                                               &encryption_mapping[0].receive_key,
                                                               time,
                                                               time + 1.0,
                                                               TEST_TIMEOUT_SECONDS,
                                                               -1 ) != 0 );

    let encryption_index = netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[0].address, time );

    check!( encryption_index != -1 );

    // port: time + 1.1f promotes the float 1.1f to double
    check!( netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[0].address, time + 1.1f32 as f64 ) == -1 );

    netcode_encryption_manager_set_expire_time( &mut encryption_manager, encryption_index, -1.0 );

    check!( netcode_encryption_manager_find_encryption_mapping( &mut encryption_manager, &encryption_mapping[0].address, time ) == encryption_index );
}

pub fn test_replay_protection()
{
    let mut replay_protection = netcode_replay_protection_t::default();

    for i in 0..2
    {
        netcode_replay_protection_reset( &mut replay_protection );

        check!( replay_protection.most_recent_sequence == 0 );

        // the first time we receive packets, they should not be already received

        const MAX_SEQUENCE: u64 = ( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE * 4 ) as u64;

        let mut sequence: u64 = 0;
        while sequence < MAX_SEQUENCE
        {
            check!( netcode_replay_protection_already_received( &replay_protection, sequence ) == 0 );
            netcode_replay_protection_advance_sequence( &mut replay_protection, sequence );
            sequence += 1;
        }

        // old packets outside buffer should be considered already received

        check!( netcode_replay_protection_already_received( &replay_protection, 0 ) == 1 );

        // packets received a second time should be flagged already received

        sequence = MAX_SEQUENCE - 10;
        while sequence < MAX_SEQUENCE
        {
            check!( netcode_replay_protection_already_received( &replay_protection, sequence ) == 1 );
            sequence += 1;
        }

        // jumping ahead to a much higher sequence should be considered not already received

        check!( netcode_replay_protection_already_received( &replay_protection, MAX_SEQUENCE + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as u64 ) == 0 );

        // old packets should be considered already received

        sequence = 0;
        while sequence < MAX_SEQUENCE
        {
            check!( netcode_replay_protection_already_received( &replay_protection, sequence ) == 1 );
            sequence += 1;
        }
    }

    // sequence numbers near UINT64_MAX must not be falsely rejected as replays.
    // "sequence + buffer size" overflowed in the already received check and treated
    // the top of the sequence space as ancient packets. found by fuzz_read_packet.

    netcode_replay_protection_reset( &mut replay_protection );

    check!( netcode_replay_protection_already_received( &replay_protection, u64::MAX - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as u64 ) == 0 );
    netcode_replay_protection_advance_sequence( &mut replay_protection, u64::MAX - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as u64 );

    check!( netcode_replay_protection_already_received( &replay_protection, u64::MAX - 1 ) == 0 );
    netcode_replay_protection_advance_sequence( &mut replay_protection, u64::MAX - 1 );

    // and a replayed packet up there is still caught

    check!( netcode_replay_protection_already_received( &replay_protection, u64::MAX - 1 ) == 1 );

    // while packets that fell out of the window are rejected as before

    check!( netcode_replay_protection_already_received( &replay_protection, u64::MAX - 1 - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE as u64 ) == 1 );
}

static num_ignored_asserts: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new( 0 );

fn test_runtime_guards_assert_handler( condition: &str, function: &str, file: &str, line: i32 )
{
    let _ = condition;
    let _ = function;
    let _ = file;
    let _ = line;
    num_ignored_asserts.fetch_add( 1, std::sync::atomic::Ordering::Relaxed );
}

pub fn test_runtime_guards()
{
    // out of range arguments to public entry points must not crash or corrupt memory in
    // release builds, where asserts compile out. install an assert handler that continues
    // instead of aborting so this test also runs in debug builds.

    netcode_set_assert_function( test_runtime_guards_assert_handler );

    // no private key needed: nothing in this test decrypts anything

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;

    let server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

    check!( server.is_some() );

    let mut server = server.unwrap();

    // starting with an out of range number of clients must not start the server

    netcode_server_start( &mut server, 0 );
    check!( netcode_server_running( &mut server ) == 0 );

    netcode_server_start( &mut server, -1 );
    check!( netcode_server_running( &mut server ) == 0 );

    netcode_server_start( &mut server, NETCODE_MAX_CLIENTS + 1 );
    check!( netcode_server_running( &mut server ) == 0 );

    netcode_server_start( &mut server, 1 );
    check!( netcode_server_running( &mut server ) != 0 );
    check!( netcode_server_max_clients( &mut server ) == 1 );

    // out of range client indices must return cleanly. max clients is 1, so 1 is out of range

    check!( netcode_server_client_user_data( &mut server, -1 ).is_none() );
    check!( netcode_server_client_user_data( &mut server, 1 ).is_none() );
    check!( netcode_server_client_user_data( &mut server, NETCODE_MAX_CLIENTS ).is_none() );

    check!( netcode_server_next_packet_sequence( &mut server, -1 ) == 0 );
    check!( netcode_server_next_packet_sequence( &mut server, 1 ) == 0 );

    check!( netcode_server_client_loopback( &mut server, -1 ) == 0 );
    check!( netcode_server_client_loopback( &mut server, 1 ) == 0 );

    let mut packet_bytes: i32 = 0;
    let mut packet_sequence: u64 = 0;
    check!( netcode_server_receive_packet( &mut server, -1, &mut packet_bytes, &mut packet_sequence ).is_none() );
    check!( netcode_server_receive_packet( &mut server, 1, &mut packet_bytes, &mut packet_sequence ).is_none() );

    let payload = [0u8; NETCODE_MAX_PACKET_SIZE as usize];

    netcode_server_send_packet( &mut server, -1, &payload, NETCODE_MAX_PACKET_SIZE );
    netcode_server_send_packet( &mut server, 1, &payload, NETCODE_MAX_PACKET_SIZE );

    netcode_server_disconnect_client( &mut server, -1 );
    netcode_server_disconnect_client( &mut server, 1 );

    netcode_server_connect_loopback_client( &mut server, -1, 1, None );
    netcode_server_connect_loopback_client( &mut server, 1, 1, None );

    netcode_server_disconnect_loopback_client( &mut server, -1 );
    netcode_server_disconnect_loopback_client( &mut server, 1 );

    netcode_server_process_loopback_packet( &mut server, -1, &payload, NETCODE_MAX_PACKET_SIZE, 0 );
    netcode_server_process_loopback_packet( &mut server, 1, &payload, NETCODE_MAX_PACKET_SIZE, 0 );

    // none of the above may have connected anybody or torn anything down

    check!( netcode_server_running( &mut server ) != 0 );
    check!( netcode_server_num_connected_clients( &mut server ) == 0 );

    netcode_server_destroy( server );

    netcode_set_assert_function( netcode_default_assert_handler );
}

pub fn test_init_and_defaults()
{
    // netcode_init is reference counted, so multiple subsystems in the same
    // application can call netcode_init and netcode_term independently.
    // the test runner has already called netcode_init once.

    check!( unsafe { netcode.initialized } == 1 );
    check!( netcode_init() == NETCODE_OK );
    check!( unsafe { netcode.initialized } == 2 );
    netcode_term();
    check!( unsafe { netcode.initialized } == 1 );

    // a zeroed config must give working defaults instead of crashing on a NULL allocator

    {
        // port: the memset is the zeroed default
        let client_config = netcode_client_config_t::default();

        // port 0 asks the OS for an ephemeral port. This test only checks that a zeroed
        // config yields working defaults -- it never connects -- so a fixed port buys
        // nothing and makes the test fail whenever anything else on the machine happens
        // to hold that port. Observed on a windows CI runner, 2026-07-26.
        let client = netcode_client_create( "127.0.0.1:0", &client_config, 0.0 );

        check!( client.is_some() );

        netcode_client_destroy( client.unwrap() );
    }

    {
        let server_config = netcode_server_config_t::default();

        // ephemeral here too, and for the same reason: nothing connects to this server.
        let server = netcode_server_create( "127.0.0.1:0", &server_config, 0.0 );

        check!( server.is_some() );

        netcode_server_destroy( server.unwrap() );
    }
}

fn test_failing_allocate_function( context: *mut std::ffi::c_void, bytes: usize ) -> *mut std::ffi::c_void
{
    let _ = context;
    let _ = bytes;
    std::ptr::null_mut()
}

static test_simulator_allocations_fail: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new( 0 );

fn test_toggle_allocate_function( context: *mut std::ffi::c_void, bytes: usize ) -> *mut std::ffi::c_void
{
    let _ = context;
    if test_simulator_allocations_fail.load( std::sync::atomic::Ordering::Relaxed ) != 0
    {
        return std::ptr::null_mut();
    }
    // port: malloc
    unsafe { netcode_crt::malloc( bytes ) }
}

fn test_toggle_free_function( context: *mut std::ffi::c_void, pointer: *mut std::ffi::c_void )
{
    let _ = context;
    // port: free
    unsafe { netcode_crt::free( pointer ) }
}

fn test_override_send_packet( context: *mut std::ffi::c_void, to: &netcode_address_t, packet_data: &[u8], packet_bytes: i32 )
{
    let _ = context;
    let _ = to;
    let _ = packet_data;
    let _ = packet_bytes;
}

fn test_override_receive_packet( context: *mut std::ffi::c_void, from: &mut netcode_address_t, packet_data: &mut [u8], max_packet_bytes: i32 ) -> i32
{
    let _ = context;
    let _ = from;
    let _ = packet_data;
    let _ = max_packet_bytes;
    0
}

pub fn test_client_create_error()
{
    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );

    // successful create leaves the create error as NONE

    {
        let client = netcode_client_create( "0.0.0.0:50000", &client_config, 0.0 );

        check!( client.is_some() );
        check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_NONE );

        netcode_client_destroy( client.unwrap() );
    }

    // bad first address

    check!( netcode_client_create( "not an address", &client_config, 0.0 ).is_none() );
    check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED );

    // bad second address

    check!( netcode_client_create_dual( "0.0.0.0:50000", Some( "not an address" ), &client_config, 0.0 ).is_none() );
    check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_PARSE_ADDRESS2_FAILED );

    // the network simulator requires binding to a specific port

    {
        let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

        let mut simulator_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut simulator_config );
        simulator_config.network_simulator = &mut *network_simulator;

        check!( netcode_client_create( "0.0.0.0", &simulator_config, 0.0 ).is_none() );
        check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_SIMULATOR_REQUIRES_PORT );

        netcode_network_simulator_destroy( network_simulator );
    }

    // binding a second client to a port already in use fails at socket creation (ipv4)

    {
        let first_client = netcode_client_create( "127.0.0.1:50000", &client_config, 0.0 );

        check!( first_client.is_some() );

        check!( netcode_client_create( "127.0.0.1:50000", &client_config, 0.0 ).is_none() );
        check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED );

        netcode_client_destroy( first_client.unwrap() );
    }

    // and the same over ipv6 reports the ipv6 error

    {
        let first_client = netcode_client_create( "[::1]:50000", &client_config, 0.0 );

        check!( first_client.is_some() );

        check!( netcode_client_create( "[::1]:50000", &client_config, 0.0 ).is_none() );
        check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED );

        netcode_client_destroy( first_client.unwrap() );
    }

    // client struct allocation failure

    {
        let mut failing_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut failing_config );
        failing_config.allocate_function = Some( test_failing_allocate_function );

        check!( netcode_client_create( "0.0.0.0:50000", &failing_config, 0.0 ).is_none() );
        check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED );
    }

    // override_send_and_receive with either override callback missing is refused at create time,
    // rather than calling a null pointer on the first update

    {
        let mut override_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut override_config );
        override_config.override_send_and_receive = 1;
        override_config.send_packet_override = Some( test_override_send_packet );

        check!( netcode_client_create( "0.0.0.0:50000", &override_config, 0.0 ).is_none() );
        check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );

        override_config.send_packet_override = None;
        override_config.receive_packet_override = Some( test_override_receive_packet );

        check!( netcode_client_create( "0.0.0.0:50000", &override_config, 0.0 ).is_none() );
        check!( netcode_client_create_error() == NETCODE_CLIENT_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );
    }
}

pub fn test_server_create_error()
{
    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );

    // successful create leaves the create error as NONE

    {
        let server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

        check!( server.is_some() );
        check!( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_NONE );

        netcode_server_destroy( server.unwrap() );
    }

    // bad first address

    check!( netcode_server_create( "not an address", &server_config, 0.0 ).is_none() );
    check!( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED );

    // bad second address

    check!( netcode_server_create_dual( "127.0.0.1:40000", Some( "not an address" ), &server_config, 0.0 ).is_none() );
    check!( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_PARSE_ADDRESS2_FAILED );

    // a port already in use is reported as a bind failure, distinct from other socket errors (ipv4)

    {
        let first_server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

        check!( first_server.is_some() );

        check!( netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 ).is_none() );
        check!( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED );

        netcode_server_destroy( first_server.unwrap() );
    }

    // and the same over ipv6 reports the ipv6 bind error

    {
        let first_server = netcode_server_create( "[::1]:40000", &server_config, 0.0 );

        check!( first_server.is_some() );

        check!( netcode_server_create( "[::1]:40000", &server_config, 0.0 ).is_none() );
        check!( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED );

        netcode_server_destroy( first_server.unwrap() );
    }

    // server struct allocation failure

    {
        let mut failing_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut failing_config );
        failing_config.allocate_function = Some( test_failing_allocate_function );

        check!( netcode_server_create( "127.0.0.1:40000", &failing_config, 0.0 ).is_none() );
        check!( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED );
    }

    // override_send_and_receive with either override callback missing is refused at create time,
    // rather than calling a null pointer on the first update

    {
        let mut override_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut override_config );
        override_config.override_send_and_receive = 1;
        override_config.send_packet_override = Some( test_override_send_packet );

        check!( netcode_server_create( "127.0.0.1:40000", &override_config, 0.0 ).is_none() );
        check!( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );

        override_config.send_packet_override = None;
        override_config.receive_packet_override = Some( test_override_receive_packet );

        check!( netcode_server_create( "127.0.0.1:40000", &override_config, 0.0 ).is_none() );
        check!( netcode_server_create_error() == NETCODE_SERVER_CREATE_ERROR_MISSING_OVERRIDE_CALLBACK );
    }
}

pub fn test_network_simulator_allocation_failure()
{
    // a failed allocation in the simulator must drop the packet, not memcpy into null

    let network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), Some( test_toggle_allocate_function ), Some( test_toggle_free_function ) );

    check!( network_simulator.is_some() );

    let mut network_simulator = network_simulator.unwrap();

    let mut from = netcode_address_t::default();
    let mut to = netcode_address_t::default();

    check!( netcode_parse_address( "127.0.0.1:50000", &mut from ) == NETCODE_OK );
    check!( netcode_parse_address( "127.0.0.1:50001", &mut to ) == NETCODE_OK );

    let mut packet_data = [0u8; 256];
    for i in 0..256
    {
        packet_data[i] = i as u8;
    }

    test_simulator_allocations_fail.store( 1, std::sync::atomic::Ordering::Relaxed );

    netcode_network_simulator_send_packet( &mut network_simulator, &from, &to, &packet_data, packet_data.len() as i32 );

    test_simulator_allocations_fail.store( 0, std::sync::atomic::Ordering::Relaxed );

    netcode_network_simulator_update( &mut network_simulator, 0.0 );

    let mut receive_packet_data: [Option<Vec<u8>>; 16] = std::array::from_fn( |_| None );
    let mut receive_packet_bytes = [0i32; 16];
    let mut receive_from = [netcode_address_t::default(); 16];

    check!( netcode_network_simulator_receive_packets( &mut network_simulator, &to, 16, &mut receive_packet_data, &mut receive_packet_bytes, &mut receive_from ) == 0 );

    // and the simulator still works once the allocator recovers

    netcode_network_simulator_send_packet( &mut network_simulator, &from, &to, &packet_data, packet_data.len() as i32 );

    netcode_network_simulator_update( &mut network_simulator, 0.0 );

    check!( netcode_network_simulator_receive_packets( &mut network_simulator, &to, 16, &mut receive_packet_data, &mut receive_packet_bytes, &mut receive_from ) == 1 );

    // a received packet buffer belongs to the caller, so free it before the simulator goes

    // port: test_toggle_free_function( NULL, receive_packet_data[0] ) -- the buffer is a Vec, freed by dropping it
    drop( receive_packet_data[0].take() );

    netcode_network_simulator_destroy( network_simulator );
}

pub fn test_network_simulator_determinism()
{
    // the network simulator has its own seeded rng, so two simulators given
    // identical inputs must drop, delay and duplicate identically

    const DETERMINISM_NUM_PACKETS: i32 = 100;
    const DETERMINISM_MAX_RECEIVE: usize = 256;

    let simulator_a = netcode_network_simulator_create( std::ptr::null_mut(), None, None );
    let simulator_b = netcode_network_simulator_create( std::ptr::null_mut(), None, None );

    check!( simulator_a.is_some() );
    check!( simulator_b.is_some() );

    let mut simulator_a = simulator_a.unwrap();
    let mut simulator_b = simulator_b.unwrap();

    simulator_a.latency_milliseconds = 100.0;
    simulator_a.jitter_milliseconds = 50.0;
    simulator_a.packet_loss_percent = 25.0;
    simulator_a.duplicate_packet_percent = 25.0;

    simulator_b.latency_milliseconds = 100.0;
    simulator_b.jitter_milliseconds = 50.0;
    simulator_b.packet_loss_percent = 25.0;
    simulator_b.duplicate_packet_percent = 25.0;

    let mut from = netcode_address_t::default();
    let mut to = netcode_address_t::default();
    check!( netcode_parse_address( "127.0.0.1:40000", &mut from ) == NETCODE_OK );
    check!( netcode_parse_address( "127.0.0.1:50000", &mut to ) == NETCODE_OK );

    let mut packet_data = [0u8; 256];
    for i in 0..DETERMINISM_NUM_PACKETS
    {
        for j in 0..packet_data.len() as i32
        {
            packet_data[j as usize] = ( i + j ) as u8;
        }
        netcode_network_simulator_send_packet( &mut simulator_a, &from, &to, &packet_data, packet_data.len() as i32 );
        netcode_network_simulator_send_packet( &mut simulator_b, &from, &to, &packet_data, packet_data.len() as i32 );
    }

    let mut total_received: i32 = 0;

    let mut time: f64 = 0.0;
    while time < 2.0
    {
        netcode_network_simulator_update( &mut simulator_a, time );
        netcode_network_simulator_update( &mut simulator_b, time );

        let mut packet_data_a: Vec<Option<Vec<u8>>> = ( 0..DETERMINISM_MAX_RECEIVE ).map( |_| None ).collect();
        let mut packet_data_b: Vec<Option<Vec<u8>>> = ( 0..DETERMINISM_MAX_RECEIVE ).map( |_| None ).collect();
        let mut packet_bytes_a = [0i32; DETERMINISM_MAX_RECEIVE];
        let mut packet_bytes_b = [0i32; DETERMINISM_MAX_RECEIVE];
        let mut from_a = [netcode_address_t::default(); DETERMINISM_MAX_RECEIVE];
        let mut from_b = [netcode_address_t::default(); DETERMINISM_MAX_RECEIVE];

        let num_packets_a = netcode_network_simulator_receive_packets( &mut simulator_a, &to, DETERMINISM_MAX_RECEIVE as i32, &mut packet_data_a, &mut packet_bytes_a, &mut from_a );
        let num_packets_b = netcode_network_simulator_receive_packets( &mut simulator_b, &to, DETERMINISM_MAX_RECEIVE as i32, &mut packet_data_b, &mut packet_bytes_b, &mut from_b );

        check!( num_packets_a == num_packets_b );

        for i in 0..num_packets_a as usize
        {
            check!( packet_bytes_a[i] == packet_bytes_b[i] );
            check!( packet_data_a[i].as_ref().unwrap()[..packet_bytes_a[i] as usize] == packet_data_b[i].as_ref().unwrap()[..packet_bytes_a[i] as usize] );
            // port: free( packet_data_a[i] ); free( packet_data_b[i] )
            drop( packet_data_a[i].take() );
            drop( packet_data_b[i].take() );
        }

        total_received += num_packets_a;

        time += 0.01;
    }

    check!( total_received > 0 );

    netcode_network_simulator_destroy( simulator_a );
    netcode_network_simulator_destroy( simulator_b );
}

pub fn test_client_create()
{
    // port: socket handle != 0 is handle.is_some()

    {
        let mut client_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut client_config );

        let client = netcode_client_create( "127.0.0.1:40000", &client_config, 0.0 );

        let mut test_address = netcode_address_t::default();
        netcode_parse_address( "127.0.0.1:40000", &mut test_address );

        check!( client.is_some() );
        let client = client.unwrap();
        check!( client.socket_holder.ipv4.handle.is_some() );
        check!( client.socket_holder.ipv6.handle.is_none() );
        check!( netcode_address_equal( &client.address, &test_address ) != 0 );

        netcode_client_destroy( client );
    }

    {
        let mut client_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut client_config );

        let client = netcode_client_create( "[::]:50000", &client_config, 0.0 );

        let mut test_address = netcode_address_t::default();
        netcode_parse_address( "[::]:50000", &mut test_address );

        check!( client.is_some() );
        let client = client.unwrap();
        check!( client.socket_holder.ipv4.handle.is_none() );
        check!( client.socket_holder.ipv6.handle.is_some() );
        check!( netcode_address_equal( &client.address, &test_address ) != 0 );

        netcode_client_destroy( client );
    }

    {
        let mut client_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut client_config );

        let client = netcode_client_create_dual( "127.0.0.1:40000", Some( "[::]:50000" ), &client_config, 0.0 );

        let mut test_address = netcode_address_t::default();
        netcode_parse_address( "127.0.0.1:40000", &mut test_address );

        check!( client.is_some() );
        let client = client.unwrap();
        check!( client.socket_holder.ipv4.handle.is_some() );
        check!( client.socket_holder.ipv6.handle.is_some() );
        check!( netcode_address_equal( &client.address, &test_address ) != 0 );

        netcode_client_destroy( client );
    }

    {
        let mut client_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut client_config );

        let client = netcode_client_create_dual( "[::]:50000", Some( "127.0.0.1:40000" ), &client_config, 0.0 );

        let mut test_address = netcode_address_t::default();
        netcode_parse_address( "[::]:50000", &mut test_address );

        check!( client.is_some() );
        let client = client.unwrap();
        check!( client.socket_holder.ipv4.handle.is_some() );
        check!( client.socket_holder.ipv6.handle.is_some() );
        check!( netcode_address_equal( &client.address, &test_address ) != 0 );

        netcode_client_destroy( client );
    }
}

pub fn test_server_create()
{
    {
        let mut server_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut server_config );

        let server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

        let mut test_address = netcode_address_t::default();
        netcode_parse_address( "127.0.0.1:40000", &mut test_address );

        check!( server.is_some() );
        let server = server.unwrap();
        check!( server.socket_holder.ipv4.handle.is_some() );
        check!( server.socket_holder.ipv6.handle.is_none() );
        check!( netcode_address_equal( &server.address, &test_address ) != 0 );

        netcode_server_destroy( server );
    }

    {
        let mut server_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut server_config );

        let server = netcode_server_create( "[::1]:50000", &server_config, 0.0 );

        let mut test_address = netcode_address_t::default();
        netcode_parse_address( "[::1]:50000", &mut test_address );

        check!( server.is_some() );
        let server = server.unwrap();
        check!( server.socket_holder.ipv4.handle.is_none() );
        check!( server.socket_holder.ipv6.handle.is_some() );
        check!( netcode_address_equal( &server.address, &test_address ) != 0 );

        netcode_server_destroy( server );
    }

    {
        let mut server_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut server_config );

        let server = netcode_server_create_dual( "127.0.0.1:40000", Some( "[::1]:50000" ), &server_config, 0.0 );

        let mut test_address = netcode_address_t::default();
        netcode_parse_address( "127.0.0.1:40000", &mut test_address );

        check!( server.is_some() );
        let server = server.unwrap();
        check!( server.socket_holder.ipv4.handle.is_some() );
        check!( server.socket_holder.ipv6.handle.is_some() );
        check!( netcode_address_equal( &server.address, &test_address ) != 0 );

        netcode_server_destroy( server );
    }

    {
        let mut server_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut server_config );

        let server = netcode_server_create_dual( "[::1]:50000", Some( "127.0.0.1:40000" ), &server_config, 0.0 );

        let mut test_address = netcode_address_t::default();
        netcode_parse_address( "[::1]:50000", &mut test_address );

        check!( server.is_some() );
        let server = server.unwrap();
        check!( server.socket_holder.ipv4.handle.is_some() );
        check!( server.socket_holder.ipv6.handle.is_some() );
        check!( netcode_address_equal( &server.address, &test_address ) != 0 );

        netcode_server_destroy( server );
    }
}

pub fn test_server_restart_global_sequence()
{
    // global packets (challenge, denied) share per-token server to client keys with
    // per-client packets, so the global sequence must stay in the top half of the
    // sequence space or a stopped and restarted server reuses AEAD nonces. regression
    // test: netcode_server_stop zeroes the global sequence, start must re-seed it.

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );

    let server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

    check!( server.is_some() );
    let mut server = server.unwrap();
    check!( server.global_sequence == 1u64 << 63 );

    netcode_server_start( &mut server, 1 );

    check!( server.global_sequence == 1u64 << 63 );

    server.global_sequence += 1000;        // as if the server had sent some global packets

    netcode_server_stop( &mut server );

    netcode_server_start( &mut server, 1 );

    check!( server.global_sequence == 1u64 << 63 );

    netcode_server_destroy( server );
}

// port: upstream's file static is named private_key. A Rust static cannot share its name with the library's
// `private_key` parameters and locals in this module (E0530: they cannot shadow a static), so it is test_private_key.
static test_private_key: [u8; NETCODE_KEY_BYTES as usize] = [ 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
                                                              0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
                                                              0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
                                                              0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 ];

// port: netcode_random_bytes( (uint8_t*) &client_id, 8 )
fn test_random_client_id() -> u64
{
    let mut client_id_bytes = [0u8; 8];
    netcode_random_bytes( &mut client_id_bytes, 8 );
    u64::from_ne_bytes( client_id_bytes )
}

pub fn test_client_server_connect()
{
    // port: the simulator is shared through raw pointers by the client and server configs, as upstream, so the test
    // holds it as a raw pointer too (Box::into_raw / Box::from_raw around its lifetime)
    let network_simulator: *mut netcode_network_simulator_t = Box::into_raw( netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap() );

    unsafe
    {
        ( *network_simulator ).latency_milliseconds = 250.0;
        ( *network_simulator ).jitter_milliseconds = 250.0;
        ( *network_simulator ).packet_loss_percent = 5.0;
        ( *network_simulator ).duplicate_packet_percent = 10.0;
    }

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: [&str; 1] = [ "[::1]:40000" ];

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let client_id: u64 = test_random_client_id();

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( unsafe { &mut *network_simulator }, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    let mut server_num_packets_received: i32 = 0;
    let mut client_num_packets_received: i32 = 0;

    let mut packet_data = [0u8; NETCODE_MAX_PACKET_SIZE as usize];
    for i in 0..NETCODE_MAX_PACKET_SIZE as usize
    {
        packet_data[i] = i as u8;
    }

    loop
    {
        netcode_network_simulator_update( unsafe { &mut *network_simulator }, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        netcode_client_send_packet( &mut client, &packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_server_send_packet( &mut server, 0, &packet_data, NETCODE_MAX_PACKET_SIZE );

        loop
        {
            let mut packet_bytes: i32 = 0;
            let mut packet_sequence: u64 = 0;
            let packet = netcode_client_receive_packet( &mut client, &mut packet_bytes, &mut packet_sequence );
            let Some( packet ) = packet else { break; };
            let _ = packet_sequence;
            netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
            client_num_packets_received += 1;
            netcode_client_free_packet( &mut client, packet );
        }

        loop
        {
            let mut packet_bytes: i32 = 0;
            let mut packet_sequence: u64 = 0;
            let packet = netcode_server_receive_packet( &mut server, 0, &mut packet_bytes, &mut packet_sequence );
            let Some( packet ) = packet else { break; };
            let _ = packet_sequence;
            netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
            server_num_packets_received += 1;
            netcode_server_free_packet( &mut server, packet );
        }

        if client_num_packets_received >= 10 && server_num_packets_received >= 10
        {
            if netcode_server_client_connected( &mut server, 0 ) != 0
            {
                netcode_server_disconnect_client( &mut server, 0 );
            }
        }

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( client_num_packets_received >= 10 && server_num_packets_received >= 10 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( unsafe { Box::from_raw( network_simulator ) } );
}

// port: the NULL second addresses are None
pub fn client_server_socket_connect_to( client_address: &str, client_address2: Option<&str>, server_address: &str, server_address2: Option<&str>, connect_address: &str )
{
    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );

    let client = netcode_client_create_dual( client_address, client_address2, &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.private_key.copy_from_slice( &test_private_key );

    let server = netcode_server_create_dual( server_address, server_address2, &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let client_id: u64 = test_random_client_id();

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    // port: &connect_address (a one element array of strings) is a one element slice
    let connect_address: [&str; 1] = [ connect_address ];

    check!( netcode_generate_connect_token( 1, &connect_address, &connect_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        // this test runs over real sockets while advancing virtual time, so it must yield
        // real time each iteration or the virtual timeouts can expire before the OS delivers
        // a single loopback packet

        netcode_sleep( 0.01 );

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );
}

pub fn client_server_socket_connect( client_address: &str, client_address2: Option<&str>, server_address: &str, server_address2: Option<&str> )
{
    client_server_socket_connect_to( client_address, client_address2, server_address, server_address2, server_address );
}

// port: netcode.c tests, the second half: test_client_server_ipv4_socket_connect through netcode_test and the end of
// the file. In the same module as the library and the first half, so it uses the library
// and the first half's test helpers (check!, test_private_key, TEST_*, client_server_socket_connect, test_random_client_id,
// ...) directly.
//
// port: a network simulator is created as a Box and handed to the client and server configs as the non-owning raw pointer they hold.

fn test_client_server_ipv4_socket_connect()
{
    client_server_socket_connect( "0.0.0.0:50000", None              , "127.0.0.1:40000", None                );
    client_server_socket_connect( "0.0.0.0:50000", None              , "127.0.0.1:40000", Some( "[::1]:40000" ) );
    client_server_socket_connect( "0.0.0.0:50000", Some( "[::]:50000" ), "127.0.0.1:40000", None                );
    client_server_socket_connect( "0.0.0.0:50000", Some( "[::]:50000" ), "127.0.0.1:40000", Some( "[::1]:40000" ) );
}

fn test_client_server_ipv6_socket_connect()
{
    client_server_socket_connect( "[::]:50000"   , None              , "[::1]:40000", None                    );
    client_server_socket_connect( "[::]:50000"   , None              , "[::1]:40000", Some( "127.0.0.1:40000" ) );
    client_server_socket_connect( "0.0.0.0:50000", Some( "[::]:50000" ), "[::1]:40000", None                    );
    client_server_socket_connect( "0.0.0.0:50000", Some( "[::]:50000" ), "[::1]:40000", Some( "127.0.0.1:40000" ) );
}

fn test_client_server_dual_socket_connect()
{
    // dual stack client connects to dual stack server over ipv4

    client_server_socket_connect( "0.0.0.0:50000", Some( "[::]:50000" ), "127.0.0.1:40000", Some( "[::1]:40000" ) );

    // dual stack client connects to dual stack server over ipv6

    client_server_socket_connect( "0.0.0.0:50000", Some( "[::]:50000" ), "[::1]:40000", Some( "127.0.0.1:40000" ) );

    // dual stack client connects to the second address of a dual stack server (ipv6, then ipv4)

    client_server_socket_connect_to( "0.0.0.0:50000", Some( "[::]:50000" ), "127.0.0.1:40000", Some( "[::1]:40000" ), "[::1]:40000" );

    client_server_socket_connect_to( "0.0.0.0:50000", Some( "[::]:50000" ), "[::1]:40000", Some( "127.0.0.1:40000" ), "127.0.0.1:40000" );
}

fn test_client_server_keep_alive()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    // connect client to server

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    // pump the client and server long enough that they would timeout without keep alive packets

    let num_iterations: i32 = ( ( 1.25f32 * TEST_TIMEOUT_SECONDS as f32 ) as f64 / delta_time ) as i32 + 1;

    for _i in 0..num_iterations
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_server_multiple_clients()
{
    const NUM_START_STOP_ITERATIONS: usize = 3;

    let max_clients: [i32; NUM_START_STOP_ITERATIONS] = [ 2, 32, 5 ];

    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    for i in 0..NUM_START_STOP_ITERATIONS
    {
        // start the server with max # of clients for this iteration

        netcode_server_start( &mut server, max_clients[i] );

        // create # of client objects for this iteration and connect to server

        // port: the malloc'd array of client pointers is a Vec of boxes (it cannot fail, so there is no check)
        let mut client: Vec<Box<netcode_client_t>> = Vec::with_capacity( max_clients[i] as usize );

        for j in 0..max_clients[i] as usize
        {
            let client_address = format!( "[::]:{}", 50000 + j as i32 );

            let mut client_config = netcode_client_config_t::default();
            netcode_default_client_config( &mut client_config );
            client_config.network_simulator = &mut *network_simulator;

            let new_client = netcode_client_create( &client_address, &client_config, time );

            check!( new_client.is_some() );
            client.push( new_client.unwrap() );

            let mut client_id: u64 = j as u64;
            client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

            let server_address: &str = "[::1]:40000";

            let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

            let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
            netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

            check!( netcode_generate_connect_token( 1,
                                                    &[server_address],
                                                    &[server_address],
                                                    TEST_CONNECT_TOKEN_EXPIRY as i32,
                                                    TEST_TIMEOUT_SECONDS as i32,
                                                    client_id,
                                                    TEST_PROTOCOL_ID,
                                                    &test_private_key,
                                                    &user_data,
                                                    &mut connect_token ) != 0 );

            netcode_client_connect( &mut client[j], &connect_token );
        }

        // make sure all clients can connect

        loop
        {
            netcode_network_simulator_update( &mut network_simulator, time );

            for j in 0..max_clients[i] as usize
            {
                netcode_client_update( &mut client[j], time );
            }

            netcode_server_update( &mut server, time );

            let mut num_connected_clients = 0;

            for j in 0..max_clients[i] as usize
            {
                if netcode_client_state( &mut client[j] ) <= NETCODE_CLIENT_STATE_DISCONNECTED
                {
                    break;
                }

                if netcode_client_state( &mut client[j] ) == NETCODE_CLIENT_STATE_CONNECTED
                {
                    num_connected_clients += 1;
                }
            }

            if num_connected_clients == max_clients[i]
            {
                break;
            }

            time += delta_time;
        }

        check!( netcode_server_num_connected_clients( &mut server ) == max_clients[i] );

        for j in 0..max_clients[i] as usize
        {
            check!( netcode_client_state( &mut client[j] ) == NETCODE_CLIENT_STATE_CONNECTED );
            check!( netcode_server_client_connected( &mut server, j as i32 ) == 1 );
        }

        // make sure all clients can exchange packets with the server

        let mut server_num_packets_received: Vec<i32> = vec![ 0; max_clients[i] as usize ];
        let mut client_num_packets_received: Vec<i32> = vec![ 0; max_clients[i] as usize ];

        let mut packet_data = [0u8; NETCODE_MAX_PACKET_SIZE as usize];
        for j in 0..NETCODE_MAX_PACKET_SIZE as usize
        {
            packet_data[j] = j as u8;
        }

        loop
        {
            netcode_network_simulator_update( &mut network_simulator, time );

            for j in 0..max_clients[i] as usize
            {
                netcode_client_update( &mut client[j], time );
            }

            netcode_server_update( &mut server, time );

            for j in 0..max_clients[i] as usize
            {
                netcode_client_send_packet( &mut client[j], &packet_data, NETCODE_MAX_PACKET_SIZE );
            }

            for j in 0..max_clients[i] as usize
            {
                netcode_server_send_packet( &mut server, j as i32, &packet_data, NETCODE_MAX_PACKET_SIZE );
            }

            for j in 0..max_clients[i] as usize
            {
                loop
                {
                    let mut packet_bytes: i32 = 0;
                    let mut packet_sequence: u64 = 0;
                    let packet = netcode_client_receive_packet( &mut client[j], &mut packet_bytes, &mut packet_sequence );
                    let Some( packet ) = packet else { break; };
                    netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                    netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                    client_num_packets_received[j] += 1;
                    netcode_client_free_packet( &mut client[j], packet );
                }
            }

            for j in 0..max_clients[i] as usize
            {
                loop
                {
                    let mut packet_bytes: i32 = 0;
                    let mut packet_sequence: u64 = 0;
                    let packet = netcode_server_receive_packet( &mut server, j as i32, &mut packet_bytes, &mut packet_sequence );
                    let Some( packet ) = packet else { break; };
                    netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                    netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                    server_num_packets_received[j] += 1;
                    netcode_server_free_packet( &mut server, packet );
                }
            }

            let mut num_clients_ready = 0;

            for j in 0..max_clients[i] as usize
            {
                if client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1
                {
                    num_clients_ready += 1;
                }
            }

            if num_clients_ready == max_clients[i]
            {
                break;
            }

            for j in 0..max_clients[i] as usize
            {
                if netcode_client_state( &mut client[j] ) <= NETCODE_CLIENT_STATE_DISCONNECTED
                {
                    break;
                }
            }

            time += delta_time;
        }

        let mut num_clients_ready = 0;

        for j in 0..max_clients[i] as usize
        {
            if client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1
            {
                num_clients_ready += 1;
            }
        }

        check!( num_clients_ready == max_clients[i] );

        drop( server_num_packets_received );
        drop( client_num_packets_received );

        netcode_network_simulator_reset( &mut network_simulator );

        for client_j in client.drain( .. )
        {
            netcode_client_destroy( client_j );
        }

        drop( client );

        netcode_server_stop( &mut server );
    }

    netcode_server_destroy( server );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_server_multiple_servers()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: [&str; 3] = [ "10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000" ];

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 3, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    let mut server_num_packets_received = 0;
    let mut client_num_packets_received = 0;

    let mut packet_data = [0u8; NETCODE_MAX_PACKET_SIZE as usize];
    for i in 0..NETCODE_MAX_PACKET_SIZE as usize
    {
        packet_data[i] = i as u8;
    }

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        netcode_client_send_packet( &mut client, &packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_server_send_packet( &mut server, 0, &packet_data, NETCODE_MAX_PACKET_SIZE );

        loop
        {
            let mut packet_bytes: i32 = 0;
            let mut packet_sequence: u64 = 0;
            let packet = netcode_client_receive_packet( &mut client, &mut packet_bytes, &mut packet_sequence );
            let Some( packet ) = packet else { break; };
            netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
            client_num_packets_received += 1;
            netcode_client_free_packet( &mut client, packet );
        }

        loop
        {
            let mut packet_bytes: i32 = 0;
            let mut packet_sequence: u64 = 0;
            let packet = netcode_server_receive_packet( &mut server, 0, &mut packet_bytes, &mut packet_sequence );
            let Some( packet ) = packet else { break; };
            netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
            server_num_packets_received += 1;
            netcode_server_free_packet( &mut server, packet );
        }

        if client_num_packets_received >= 10 && server_num_packets_received >= 10
        {
            if netcode_server_client_connected( &mut server, 0 ) != 0
            {
                netcode_server_disconnect_client( &mut server, 0 );
            }
        }

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( client_num_packets_received >= 10 && server_num_packets_received >= 10 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_error_connect_token_expired()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let time: f64 = 0.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], 0, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    netcode_client_update( &mut client, time );

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_error_invalid_connect_token()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let time: f64 = 0.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
    netcode_random_bytes( &mut connect_token, NETCODE_CONNECT_TOKEN_BYTES );

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    netcode_client_connect( &mut client, &connect_token );

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_error_connection_timed_out()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    // connect a client to the server

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    // now disable updating the server and verify that the client times out

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_error_connection_response_timeout()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    server.flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS;

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_error_connection_request_timeout()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 60.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    server.flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS;

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_error_connection_denied()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    // start a server and connect one client

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    // now attempt to connect a second client. the connection should be denied.

    let client2 = netcode_client_create( "[::]:50001", &client_config, time );

    check!( client2.is_some() );
    let mut client2 = client2.unwrap();

    let mut connect_token2 = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id2: u64 = 0;
    client_id2 = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id2, 8 )

    let mut user_data2 = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data2, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id2, TEST_PROTOCOL_ID, &test_private_key, &user_data2, &mut connect_token2 ) != 0 );

    netcode_client_connect( &mut client2, &connect_token2 );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_client_update( &mut client2, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client2 ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_state( &mut client2 ) == NETCODE_CLIENT_STATE_CONNECTION_DENIED );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_client_destroy( client2 );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_side_disconnect()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    // start a server and connect one client

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    // disconnect client side and verify that the server sees that client disconnect cleanly, rather than timing out.

    netcode_client_disconnect( &mut client );

    for _i in 0..10
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_server_client_connected( &mut server, 0 ) == 0
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_server_client_connected( &mut server, 0 ) == 0 );
    check!( netcode_server_num_connected_clients( &mut server ) == 0 );
    check!( netcode_server_client_disconnect_reason( &mut server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_CLIENT_DISCONNECT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_server_side_disconnect()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    // start a server and connect one client

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    // disconnect server side and verify that the client disconnects cleanly, rather than timing out.

    netcode_server_disconnect_client( &mut server, 0 );

    for _i in 0..10
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_DISCONNECTED );
    check!( netcode_server_client_connected( &mut server, 0 ) == 0 );
    check!( netcode_server_num_connected_clients( &mut server ) == 0 );
    check!( netcode_server_client_disconnect_reason( &mut server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_server_client_disconnect_reason()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    // start a server and connect one client

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    // no disconnect has happened yet, so the client slot reason is none

    check!( netcode_server_client_disconnect_reason( &mut server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_client_disconnect_reason( &mut server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    // stop updating the client so it goes silent. the server should time it out
    // and record that as the disconnect reason, distinct from a clean disconnect

    for _i in 0..200
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_server_update( &mut server, time );

        if netcode_server_client_connected( &mut server, 0 ) == 0
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_server_client_connected( &mut server, 0 ) == 0 );
    check!( netcode_server_num_connected_clients( &mut server ) == 0 );
    check!( netcode_server_client_disconnect_reason( &mut server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT );

    // reconnect. a new client connecting to the slot clears the reason back to none

    netcode_client_disconnect( &mut client );

    // catch the client's internal clock up to the current time before reconnecting, since it
    // was deliberately not updated above. otherwise the first update after connect sees the
    // whole timeout leg as elapsed time and immediately times out the connection request.
    netcode_client_update( &mut client, time );

    netcode_network_simulator_reset( &mut network_simulator );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_client_disconnect_reason( &mut server, 0 ) == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_client_reconnect()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    // start a server and connect one client

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    // disconnect client on the server-side and wait until client sees the disconnect

    netcode_network_simulator_reset( &mut network_simulator );

    netcode_server_disconnect_client( &mut server, 0 );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_DISCONNECTED );
    check!( netcode_server_client_connected( &mut server, 0 ) == 0 );
    check!( netcode_server_num_connected_clients( &mut server ) == 0 );

    // now reconnect the client and verify they connect

    netcode_network_simulator_reset( &mut network_simulator );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_connect_token_entries()
{
    let mut connect_token_entries = vec![ netcode_connect_token_entry_t::default(); NETCODE_MAX_CONNECT_TOKEN_ENTRIES ];

    netcode_connect_token_entries_reset( &mut connect_token_entries );

    let mut address_a = netcode_address_t::default();
    let mut address_b = netcode_address_t::default();

    check!( netcode_parse_address( "[::1]:50000", &mut address_a ) == NETCODE_OK );
    check!( netcode_parse_address( "[::1]:50001", &mut address_b ) == NETCODE_OK );

    let current_timestamp: u64 = 1000;
    let expire_timestamp: u64 = current_timestamp + 30;

    let mut mac = [0u8; NETCODE_MAC_BYTES as usize];

    // a connect token the history has not seen creates a pending entry

    mac[0] = 1;

    let index = netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_a, &mac, expire_timestamp, current_timestamp, 100.0 );

    check!( index >= 0 );
    check!( connect_token_entries[index as usize].state == NETCODE_CONNECT_TOKEN_ENTRY_PENDING );
    check!( connect_token_entries[index as usize].time == 100.0 );

    // a pending entry admits a retransmitted connection request from the address that created it,
    // and the entry time is not refreshed

    check!( netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_a, &mac, expire_timestamp, current_timestamp, 200.0 ) == index );
    check!( connect_token_entries[index as usize].time == 100.0 );

    // a pending entry refuses every other address

    check!( netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_b, &mac, expire_timestamp, current_timestamp, 200.0 ) == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED );

    // a consumed entry admits nothing, including the address that used the connect token

    netcode_connect_token_entries_consume( &mut connect_token_entries, index );

    check!( connect_token_entries[index as usize].state == NETCODE_CONNECT_TOKEN_ENTRY_CONSUMED );
    check!( netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_a, &mac, expire_timestamp, current_timestamp, 300.0 ) == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED );
    check!( netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_b, &mac, expire_timestamp, current_timestamp, 300.0 ) == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED );

    // a history whose entries all hold unexpired connect tokens refuses a new connect token
    // instead of evicting one

    for i in 1..NETCODE_MAX_CONNECT_TOKEN_ENTRIES
    {
        mac = [0u8; NETCODE_MAC_BYTES as usize];
        mac[0] = ( i + 1 ) as u8;
        mac[1] = ( ( i + 1 ) >> 8 ) as u8;
        check!( netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_a, &mac, expire_timestamp, current_timestamp, 400.0 ) >= 0 );
    }

    mac = [0u8; NETCODE_MAC_BYTES as usize];
    mac[0] = 0xFF;
    mac[1] = 0xFF;

    check!( netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_a, &mac, expire_timestamp, current_timestamp, 500.0 ) == NETCODE_CONNECT_TOKEN_HISTORY_FULL );

    // the consumed entry is still refusing its connect token, and was not evicted by the flood

    mac = [0u8; NETCODE_MAC_BYTES as usize];
    mac[0] = 1;

    check!( netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_a, &mac, expire_timestamp, current_timestamp, 500.0 ) == NETCODE_CONNECT_TOKEN_ENTRY_REFUSED );

    // entries live until their connect token expires. once they have, the history takes new connect tokens again

    mac = [0u8; NETCODE_MAC_BYTES as usize];
    mac[0] = 0xFF;
    mac[1] = 0xFF;

    check!( netcode_connect_token_entries_find_or_add( &mut connect_token_entries, &address_a, &mac, expire_timestamp, expire_timestamp, 600.0 ) >= 0 );
}

/*
    A client and a server wired directly to each other through the send and receive overrides.
    Packets are handed straight to the other side, so the handshake is exercised with no sockets,
    no network simulator and no randomness at all. The wire can drop the first packets the server
    sends, which is what makes the client retransmit its connection request, and it keeps a copy
    of the first payload packet the client sends so it can be replayed later.
*/

// port: upstream's send overrides call netcode_server_process_packet / netcode_client_process_packet on the other
// side directly. That re-enters the side that is sending (the server answers a connection request inside the
// client's send, and that answer is processed by the client while netcode_client_update still holds it), which is
// two live &mut to one object in Rust. So each send override queues the packet for the other side instead, and that
// side's receive override hands it over on its next receive: the same packets, in the same order, through the same
// process path, delivered on the receiver's next update rather than inside the sender's call.
struct test_wire_t
{
    client: *mut netcode_client_t,
    server: *mut netcode_server_t,
    client_address: netcode_address_t,
    server_address: netcode_address_t,
    shutting_down: i32,
    drop_server_packets: i32,
    num_connection_requests: i32,
    payload_packet: [u8; NETCODE_MAX_PACKET_BYTES as usize],
    payload_packet_bytes: i32,
    // port: the packets on the wire to each side (see above)
    packets_to_server: std::collections::VecDeque<Vec<u8>>,
    packets_to_client: std::collections::VecDeque<Vec<u8>>,
}

// port: memset( &test_wire, 0, sizeof( test_wire ) )
const fn test_wire_zeroed() -> test_wire_t
{
    const ZERO_ADDRESS: netcode_address_t = netcode_address_t { data: netcode_address_data_t { ipv4: [0; 4], ipv6: [0; 8] }, port: 0, r#type: 0 };
    test_wire_t
    {
        client: std::ptr::null_mut(),
        server: std::ptr::null_mut(),
        client_address: ZERO_ADDRESS,
        server_address: ZERO_ADDRESS,
        shutting_down: 0,
        drop_server_packets: 0,
        num_connection_requests: 0,
        payload_packet: [0; NETCODE_MAX_PACKET_BYTES as usize],
        payload_packet_bytes: 0,
        packets_to_server: std::collections::VecDeque::new(),
        packets_to_client: std::collections::VecDeque::new(),
    }
}

// port: a C file static, `static mut` as upstream. The tests are single threaded, and the overrides touch only the
// wire's own fields, never the client or server it points to.
static mut test_wire: test_wire_t = test_wire_zeroed();

fn test_wire_client_send_packet( context: *mut c_void, to: &netcode_address_t, packet_data: &[u8], packet_bytes: i32 )
{
    unsafe
    {
        // the wire is down once either end is being destroyed. the disconnect packets they send
        // on the way out have nowhere to go, exactly as an application shutting down would find

        if test_wire.shutting_down != 0
        {
            return;
        }

        if packet_data[0] == NETCODE_CONNECTION_REQUEST_PACKET
        {
            test_wire.num_connection_requests += 1;
        }

        if ( packet_data[0] & 0xF ) == NETCODE_CONNECTION_PAYLOAD_PACKET && test_wire.payload_packet_bytes == 0
        {
            test_wire.payload_packet[..packet_bytes as usize].copy_from_slice( &packet_data[..packet_bytes as usize] );
            test_wire.payload_packet_bytes = packet_bytes;
        }

        // port: netcode_server_process_packet( test_wire.server, &test_wire.client_address, packet_data, packet_bytes ),
        // on the server's next receive (see test_wire_t)
        test_wire.packets_to_server.push_back( packet_data[..packet_bytes as usize].to_vec() );
    }
}

fn test_wire_server_send_packet( context: *mut c_void, to: &netcode_address_t, packet_data: &[u8], packet_bytes: i32 )
{
    unsafe
    {
        if test_wire.shutting_down != 0
        {
            return;
        }

        if test_wire.drop_server_packets > 0
        {
            test_wire.drop_server_packets -= 1;
            return;
        }

        // port: netcode_client_process_packet( test_wire.client, &test_wire.server_address, packet_data, packet_bytes ),
        // on the client's next receive (see test_wire_t)
        test_wire.packets_to_client.push_back( packet_data[..packet_bytes as usize].to_vec() );
    }
}

// port: upstream has one receive override that returns 0. Here each side's receive hands over the packets queued
// for it, from the other side's address
fn test_wire_client_receive_packet( context: *mut c_void, from: &mut netcode_address_t, packet_data: &mut [u8], max_packet_bytes: i32 ) -> i32
{
    unsafe
    {
        let Some( packet ) = test_wire.packets_to_client.pop_front() else { return 0; };
        netcode_assert!( packet.len() <= max_packet_bytes as usize );
        *from = test_wire.server_address;
        packet_data[..packet.len()].copy_from_slice( &packet );
        return packet.len() as i32;
    }
}

fn test_wire_server_receive_packet( context: *mut c_void, from: &mut netcode_address_t, packet_data: &mut [u8], max_packet_bytes: i32 ) -> i32
{
    unsafe
    {
        let Some( packet ) = test_wire.packets_to_server.pop_front() else { return 0; };
        netcode_assert!( packet.len() <= max_packet_bytes as usize );
        *from = test_wire.client_address;
        packet_data[..packet.len()].copy_from_slice( &packet );
        return packet.len() as i32;
    }
}

fn test_wire_create( drop_server_packets: i32 )
{
    unsafe
    {
        test_wire = test_wire_zeroed();

        test_wire.drop_server_packets = drop_server_packets;

        check!( netcode_parse_address( "[::1]:50000", &mut test_wire.client_address ) == NETCODE_OK );
        check!( netcode_parse_address( "[::1]:40000", &mut test_wire.server_address ) == NETCODE_OK );

        let mut client_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut client_config );
        client_config.override_send_and_receive = 1;
        client_config.send_packet_override = Some( test_wire_client_send_packet );
        client_config.receive_packet_override = Some( test_wire_client_receive_packet );

        let client = netcode_client_create( "[::1]:50000", &client_config, 0.0 );

        check!( client.is_some() );
        // port: the wire holds the client and server as raw pointers (Box::into_raw), freed in test_wire_destroy
        test_wire.client = Box::into_raw( client.unwrap() );

        let mut server_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut server_config );
        server_config.protocol_id = TEST_PROTOCOL_ID;
        server_config.override_send_and_receive = 1;
        server_config.send_packet_override = Some( test_wire_server_send_packet );
        server_config.receive_packet_override = Some( test_wire_server_receive_packet );
        server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

        let server = netcode_server_create( "[::1]:40000", &server_config, 0.0 );

        check!( server.is_some() );
        test_wire.server = Box::into_raw( server.unwrap() );

        netcode_server_start( &mut *test_wire.server, 1 );
    }
}

fn test_wire_destroy()
{
    unsafe
    {
        test_wire.shutting_down = 1;
        netcode_server_destroy( Box::from_raw( test_wire.server ) );
        netcode_client_destroy( Box::from_raw( test_wire.client ) );
        test_wire = test_wire_zeroed();
    }
}

fn test_wire_connect_client( connect_token: &[u8], time: &mut f64, delta_time: f64 )
{
    unsafe
    {
        netcode_client_connect( &mut *test_wire.client, connect_token );

        loop
        {
            netcode_client_update( &mut *test_wire.client, *time );

            netcode_server_update( &mut *test_wire.server, *time );

            if netcode_client_state( &mut *test_wire.client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
            {
                break;
            }

            if netcode_client_state( &mut *test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED
            {
                break;
            }

            *time += delta_time;
        }
    }
}

fn test_wire_generate_connect_token( connect_token: &mut [u8], client_id: u64, expire_seconds: i32 )
{
    let server_address: &str = "[::1]:40000";

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], expire_seconds, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, connect_token ) != 0 );
}

fn test_client_server_connection_request_retransmission()
{
    // the first three packets the server sends are dropped, so the client retransmits its
    // connection request into a handshake the server already has a pending history entry for

    test_wire_create( 3 );

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
    test_wire_generate_connect_token( &mut connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY as i32 );

    test_wire_connect_client( &connect_token, &mut time, delta_time );

    unsafe
    {
        check!( netcode_client_state( &mut *test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );
        check!( netcode_server_client_connected( &mut *test_wire.server, 0 ) == 1 );
        check!( netcode_server_num_connected_clients( &mut *test_wire.server ) == 1 );
        check!( test_wire.num_connection_requests >= 4 );
    }

    test_wire_destroy();
}

fn test_client_server_replay_across_sessions()
{
    test_wire_create( 0 );

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    // connect a first session and keep a copy of a payload packet the client sends in it

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
    test_wire_generate_connect_token( &mut connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY as i32 );

    test_wire_connect_client( &connect_token, &mut time, delta_time );

    unsafe
    {
        check!( netcode_client_state( &mut *test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );

        let mut payload = [0u8; NETCODE_MAX_PACKET_SIZE as usize];
        for i in 0..NETCODE_MAX_PACKET_SIZE as usize
        {
            payload[i] = i as u8;
        }

        netcode_client_send_packet( &mut *test_wire.client, &payload, NETCODE_MAX_PACKET_SIZE );

        check!( test_wire.payload_packet_bytes > 0 );

        // disconnect, then connect a second session with a new connect token

        netcode_server_disconnect_client( &mut *test_wire.server, 0 );

        while netcode_client_state( &mut *test_wire.client ) > NETCODE_CLIENT_STATE_DISCONNECTED
        {
            netcode_client_update( &mut *test_wire.client, time );
            netcode_server_update( &mut *test_wire.server, time );
            time += delta_time;
        }
    }

    let mut second_connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
    test_wire_generate_connect_token( &mut second_connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY as i32 );

    test_wire_connect_client( &second_connect_token, &mut time, delta_time );

    unsafe
    {
        check!( netcode_client_state( &mut *test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );

        // drain anything the second session has delivered so far

        loop
        {
            let mut packet_bytes: i32 = 0;
            let mut packet_sequence: u64 = 0;
            let packet = netcode_server_receive_packet( &mut *test_wire.server, 0, &mut packet_bytes, &mut packet_sequence );
            let Some( packet ) = packet else { break; };
            netcode_server_free_packet( &mut *test_wire.server, packet );
        }

        // the datagram from the first session is refused by the second

        let payload_packet_bytes = test_wire.payload_packet_bytes;
        netcode_server_process_packet( &mut *test_wire.server, &test_wire.client_address, &mut test_wire.payload_packet, payload_packet_bytes );

        let mut packet_bytes: i32 = 0;
        let mut packet_sequence: u64 = 0;

        check!( netcode_server_receive_packet( &mut *test_wire.server, 0, &mut packet_bytes, &mut packet_sequence ).is_none() );
    }

    test_wire_destroy();
}

fn test_client_reconnect_with_used_connect_token()
{
    test_wire_create( 0 );

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
    test_wire_generate_connect_token( &mut connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY as i32 );

    test_wire_connect_client( &connect_token, &mut time, delta_time );

    unsafe
    {
        check!( netcode_client_state( &mut *test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );
        check!( netcode_server_num_connected_clients( &mut *test_wire.server ) == 1 );

        // disconnect the client server side and wait until the client sees it

        netcode_server_disconnect_client( &mut *test_wire.server, 0 );

        while netcode_client_state( &mut *test_wire.client ) > NETCODE_CLIENT_STATE_DISCONNECTED
        {
            netcode_client_update( &mut *test_wire.client, time );
            netcode_server_update( &mut *test_wire.server, time );
            time += delta_time;
        }

        check!( netcode_server_num_connected_clients( &mut *test_wire.server ) == 0 );
    }

    // the connect token is spent. presenting it again, from the same address that used it,
    // connects nothing: the client runs out of connection request retries instead

    test_wire_connect_client( &connect_token, &mut time, delta_time );

    unsafe
    {
        check!( netcode_client_state( &mut *test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );
        check!( netcode_server_num_connected_clients( &mut *test_wire.server ) == 0 );
    }

    test_wire_destroy();
}

fn test_client_error_connect_token_predates_server_start()
{
    test_wire_create( 0 );

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    // a connect token with a shorter lifetime than the server's configured maximum expires
    // earlier than any connect token the backend could have issued after the server started,
    // which is exactly the shape of a connect token issued before it started

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
    test_wire_generate_connect_token( &mut connect_token, TEST_CLIENT_ID, NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME - 10 );

    test_wire_connect_client( &connect_token, &mut time, delta_time );

    unsafe
    {
        check!( netcode_client_state( &mut *test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT );
        check!( netcode_server_num_connected_clients( &mut *test_wire.server ) == 0 );
    }

    // a connect token with the full lifetime connects

    test_wire_generate_connect_token( &mut connect_token, TEST_CLIENT_ID, TEST_CONNECT_TOKEN_EXPIRY as i32 );

    test_wire_connect_client( &connect_token, &mut time, delta_time );

    unsafe
    {
        check!( netcode_client_state( &mut *test_wire.client ) == NETCODE_CLIENT_STATE_CONNECTED );
        check!( netcode_server_num_connected_clients( &mut *test_wire.server ) == 1 );
    }

    test_wire_destroy();
}

// port: #if NETCODE_ENABLE_NONCE_AUDIT -- always compiled; netcode_test runs it when the const is set
fn test_nonce_audit()
{
    // every packet every test above encrypted was recorded by key and nonce. a repeat is a
    // connect token encrypting two sessions, which is what the connect token lifecycle prevents

    print!( "\n    {} key and nonce pairs recorded\n    ", netcode_nonce_audit_num_pairs() );

    check!( netcode_nonce_audit_num_pairs() > 0 );
    check!( netcode_nonce_audit_overflow() == 0 );
    check!( netcode_nonce_audit_repeats() == 0 );
}

// port: the context holds the client and server as raw pointers, as upstream
struct test_loopback_context_t
{
    client: *mut netcode_client_t,
    server: *mut netcode_server_t,
    num_loopback_packets_sent_to_client: i32,
    num_loopback_packets_sent_to_server: i32,
}

fn client_send_loopback_packet_callback( _context: *mut c_void, client_index: i32, packet_data: &[u8], packet_bytes: i32, packet_sequence: u64 )
{
    check!( !_context.is_null() );
    check!( client_index == 0 );
    // port: check( packet_data ) -- a slice is never null
    check!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
    for i in 0..packet_bytes as usize
    {
        check!( packet_data[i] == i as u8 );
    }
    let context = unsafe { &mut *( _context as *mut test_loopback_context_t ) };
    context.num_loopback_packets_sent_to_server += 1;
    netcode_server_process_loopback_packet( unsafe { &mut *context.server }, client_index, packet_data, packet_bytes, packet_sequence );
}

fn server_send_loopback_packet_callback( _context: *mut c_void, client_index: i32, packet_data: &[u8], packet_bytes: i32, packet_sequence: u64 )
{
    check!( !_context.is_null() );
    check!( client_index == 0 );
    // port: check( packet_data ) -- a slice is never null
    check!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
    for i in 0..packet_bytes as usize
    {
        check!( packet_data[i] == i as u8 );
    }
    let context = unsafe { &mut *( _context as *mut test_loopback_context_t ) };
    context.num_loopback_packets_sent_to_client += 1;
    netcode_client_process_loopback_packet( unsafe { &mut *context.client }, packet_data, packet_bytes, packet_sequence );
}

fn test_disable_timeout()
{
    let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

    network_simulator.latency_milliseconds = 250.0;
    network_simulator.jitter_milliseconds = 250.0;
    network_simulator.packet_loss_percent = 5.0;
    network_simulator.duplicate_packet_percent = 10.0;

    let mut time: f64 = 0.0;
    let delta_time: f64 = 1.0 / 10.0;

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );
    client_config.network_simulator = &mut *network_simulator;

    let client = netcode_client_create( "[::]:50000", &client_config, time );

    check!( client.is_some() );
    let mut client = client.unwrap();

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = &mut *network_simulator;
    server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

    let server = netcode_server_create( "[::1]:40000", &server_config, time );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    let server_address: &str = "[::1]:40000";

    let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

    let mut client_id: u64 = 0;
    client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

    let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
    netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

    check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, -1, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

    netcode_client_connect( &mut client, &connect_token );

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        if netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED
        {
            break;
        }

        time += delta_time;
    }

    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_CONNECTED );
    check!( netcode_client_index( &mut client ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 1 );
    check!( netcode_server_num_connected_clients( &mut server ) == 1 );

    let mut server_num_packets_received = 0;
    let mut client_num_packets_received = 0;

    let mut packet_data = [0u8; NETCODE_MAX_PACKET_SIZE as usize];
    for i in 0..NETCODE_MAX_PACKET_SIZE as usize
    {
        packet_data[i] = i as u8;
    }

    loop
    {
        netcode_network_simulator_update( &mut network_simulator, time );

        netcode_client_update( &mut client, time );

        netcode_server_update( &mut server, time );

        netcode_client_send_packet( &mut client, &packet_data, NETCODE_MAX_PACKET_SIZE );

        netcode_server_send_packet( &mut server, 0, &packet_data, NETCODE_MAX_PACKET_SIZE );

        loop
        {
            let mut packet_bytes: i32 = 0;
            let mut packet_sequence: u64 = 0;
            let packet = netcode_client_receive_packet( &mut client, &mut packet_bytes, &mut packet_sequence );
            let Some( packet ) = packet else { break; };
            netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
            client_num_packets_received += 1;
            netcode_client_free_packet( &mut client, packet );
        }

        loop
        {
            let mut packet_bytes: i32 = 0;
            let mut packet_sequence: u64 = 0;
            let packet = netcode_server_receive_packet( &mut server, 0, &mut packet_bytes, &mut packet_sequence );
            let Some( packet ) = packet else { break; };
            netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
            netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
            server_num_packets_received += 1;
            netcode_server_free_packet( &mut server, packet );
        }

        if client_num_packets_received >= 10 && server_num_packets_received >= 10
        {
            if netcode_server_client_connected( &mut server, 0 ) != 0
            {
                netcode_server_disconnect_client( &mut server, 0 );
            }
        }

        if netcode_client_state( &mut client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
        {
            break;
        }

        time += 1000.0;        // normally this would timeout the client
    }

    check!( client_num_packets_received >= 10 && server_num_packets_received >= 10 );

    netcode_server_destroy( server );

    netcode_client_destroy( client );

    netcode_network_simulator_destroy( network_simulator );
}

fn test_loopback()
{
    // port: the context, client and server live behind raw pointers (Box::into_raw) for the whole test, because the
    // loopback callbacks reach them through the context while the test also calls them
    let context: *mut test_loopback_context_t = Box::into_raw( Box::new( test_loopback_context_t
    {
        client: std::ptr::null_mut(),
        server: std::ptr::null_mut(),
        num_loopback_packets_sent_to_client: 0,
        num_loopback_packets_sent_to_server: 0,
    } ) );

    unsafe
    {
        let mut network_simulator = netcode_network_simulator_create( std::ptr::null_mut(), None, None ).unwrap();

        network_simulator.latency_milliseconds = 250.0;
        network_simulator.jitter_milliseconds = 250.0;
        network_simulator.packet_loss_percent = 5.0;
        network_simulator.duplicate_packet_percent = 10.0;

        let mut time: f64 = 0.0;
        let delta_time: f64 = 1.0 / 10.0;

        // start the server

        let mut server_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut server_config );
        server_config.protocol_id = TEST_PROTOCOL_ID;
        server_config.network_simulator = &mut *network_simulator;
        server_config.callback_context = context as *mut c_void;
        server_config.send_loopback_packet_callback = Some( server_send_loopback_packet_callback );
        server_config.private_key.copy_from_slice( &test_private_key[..NETCODE_KEY_BYTES as usize] );

        let server = netcode_server_create( "[::1]:40000", &server_config, time );

        check!( server.is_some() );
        let server: *mut netcode_server_t = Box::into_raw( server.unwrap() );

        let max_clients: i32 = 2;

        netcode_server_start( &mut *server, max_clients );

        ( *context ).server = server;

        // connect a loopback client in slot 0

        let mut client_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut client_config );
        client_config.callback_context = context as *mut c_void;
        client_config.send_loopback_packet_callback = Some( client_send_loopback_packet_callback );
        client_config.network_simulator = &mut *network_simulator;

        let loopback_client = netcode_client_create( "[::]:50000", &client_config, time );
        check!( loopback_client.is_some() );
        let loopback_client: *mut netcode_client_t = Box::into_raw( loopback_client.unwrap() );
        netcode_client_connect_loopback( &mut *loopback_client, 0, max_clients );
        ( *context ).client = loopback_client;

        check!( netcode_client_index( &mut *loopback_client ) == 0 );
        check!( netcode_client_loopback( &mut *loopback_client ) == 1 );
        check!( netcode_client_max_clients( &mut *loopback_client ) == max_clients );
        check!( netcode_client_state( &mut *loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

        let mut client_id: u64 = 0;
        client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )
        netcode_server_connect_loopback_client( &mut *server, 0, client_id, None );

        check!( netcode_server_client_loopback( &mut *server, 0 ) == 1 );
        check!( netcode_server_client_connected( &mut *server, 0 ) == 1 );
        check!( netcode_server_num_connected_clients( &mut *server ) == 1 );

        // connect a regular client in the other slot

        let regular_client = netcode_client_create( "[::]:50001", &client_config, time );

        check!( regular_client.is_some() );
        let regular_client: *mut netcode_client_t = Box::into_raw( regular_client.unwrap() );

        let server_address: &str = "[::1]:40000";

        let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
        client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

        let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
        netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

        check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

        netcode_client_connect( &mut *regular_client, &connect_token );

        loop
        {
            netcode_network_simulator_update( &mut network_simulator, time );

            netcode_client_update( &mut *regular_client, time );

            netcode_server_update( &mut *server, time );

            if netcode_client_state( &mut *regular_client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
            {
                break;
            }

            if netcode_client_state( &mut *regular_client ) == NETCODE_CLIENT_STATE_CONNECTED
            {
                break;
            }

            time += delta_time;
        }

        check!( netcode_client_state( &mut *regular_client ) == NETCODE_CLIENT_STATE_CONNECTED );
        check!( netcode_client_index( &mut *regular_client ) == 1 );
        check!( netcode_server_client_connected( &mut *server, 0 ) == 1 );
        check!( netcode_server_client_connected( &mut *server, 1 ) == 1 );
        check!( netcode_server_client_loopback( &mut *server, 0 ) == 1 );
        check!( netcode_server_client_loopback( &mut *server, 1 ) == 0 );
        check!( netcode_server_num_connected_clients( &mut *server ) == 2 );

        // test that we can exchange packets for the regular client and the loopback client

        let mut loopback_client_num_packets_received = 0;
        let mut loopback_server_num_packets_received = 0;
        let mut regular_server_num_packets_received = 0;
        let mut regular_client_num_packets_received = 0;

        let mut packet_data = [0u8; NETCODE_MAX_PACKET_SIZE as usize];
        for i in 0..NETCODE_MAX_PACKET_SIZE as usize
        {
            packet_data[i] = i as u8;
        }

        loop
        {
            netcode_network_simulator_update( &mut network_simulator, time );

            netcode_client_update( &mut *regular_client, time );

            netcode_server_update( &mut *server, time );

            netcode_client_send_packet( &mut *loopback_client, &packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_client_send_packet( &mut *regular_client, &packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_server_send_packet( &mut *server, 0, &packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_server_send_packet( &mut *server, 1, &packet_data, NETCODE_MAX_PACKET_SIZE );

            loop
            {
                let mut packet_bytes: i32 = 0;
                let mut packet_sequence: u64 = 0;
                let packet = netcode_client_receive_packet( &mut *loopback_client, &mut packet_bytes, &mut packet_sequence );
                let Some( packet ) = packet else { break; };
                netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                loopback_client_num_packets_received += 1;
                netcode_client_free_packet( &mut *loopback_client, packet );
            }

            loop
            {
                let mut packet_bytes: i32 = 0;
                let mut packet_sequence: u64 = 0;
                let packet = netcode_client_receive_packet( &mut *regular_client, &mut packet_bytes, &mut packet_sequence );
                let Some( packet ) = packet else { break; };
                netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                regular_client_num_packets_received += 1;
                netcode_client_free_packet( &mut *regular_client, packet );
            }

            loop
            {
                let mut packet_bytes: i32 = 0;
                let mut packet_sequence: u64 = 0;
                let packet = netcode_server_receive_packet( &mut *server, 0, &mut packet_bytes, &mut packet_sequence );
                let Some( packet ) = packet else { break; };
                netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                loopback_server_num_packets_received += 1;
                netcode_server_free_packet( &mut *server, packet );
            }

            loop
            {
                let mut packet_bytes: i32 = 0;
                let mut packet_sequence: u64 = 0;
                let packet = netcode_server_receive_packet( &mut *server, 1, &mut packet_bytes, &mut packet_sequence );
                let Some( packet ) = packet else { break; };
                netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                regular_server_num_packets_received += 1;
                netcode_server_free_packet( &mut *server, packet );
            }

            if loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
               regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10
            {
                break;
            }

            if netcode_client_state( &mut *regular_client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
            {
                break;
            }

            time += delta_time;
        }

        check!( loopback_client_num_packets_received >= 10 );
        check!( loopback_server_num_packets_received >= 10 );
        check!( regular_client_num_packets_received >= 10 );
        check!( regular_server_num_packets_received >= 10 );
        check!( ( *context ).num_loopback_packets_sent_to_client >= 10 );
        check!( ( *context ).num_loopback_packets_sent_to_server >= 10 );

        // verify that we can disconnect the loopback client

        check!( netcode_server_client_loopback( &mut *server, 0 ) == 1 );
        check!( netcode_server_client_connected( &mut *server, 0 ) == 1 );
        check!( netcode_server_num_connected_clients( &mut *server ) == 2 );

        netcode_server_disconnect_loopback_client( &mut *server, 0 );

        check!( netcode_server_client_loopback( &mut *server, 0 ) == 0 );
        check!( netcode_server_client_connected( &mut *server, 0 ) == 0 );
        check!( netcode_server_num_connected_clients( &mut *server ) == 1 );

        netcode_client_disconnect_loopback( &mut *loopback_client );

        check!( netcode_client_state( &mut *loopback_client ) == NETCODE_CLIENT_STATE_DISCONNECTED );

        // verify that we can reconnect the loopback client

        client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )
        netcode_server_connect_loopback_client( &mut *server, 0, client_id, None );

        check!( netcode_server_client_loopback( &mut *server, 0 ) == 1 );
        check!( netcode_server_client_loopback( &mut *server, 1 ) == 0 );
        check!( netcode_server_client_connected( &mut *server, 0 ) == 1 );
        check!( netcode_server_client_connected( &mut *server, 1 ) == 1 );
        check!( netcode_server_num_connected_clients( &mut *server ) == 2 );

        netcode_client_connect_loopback( &mut *loopback_client, 0, max_clients );

        check!( netcode_client_index( &mut *loopback_client ) == 0 );
        check!( netcode_client_loopback( &mut *loopback_client ) == 1 );
        check!( netcode_client_max_clients( &mut *loopback_client ) == max_clients );
        check!( netcode_client_state( &mut *loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

        // verify that we can exchange packets for both regular and loopback client post reconnect

        loopback_server_num_packets_received = 0;
        loopback_client_num_packets_received = 0;
        regular_server_num_packets_received = 0;
        regular_client_num_packets_received = 0;
        ( *context ).num_loopback_packets_sent_to_client = 0;
        ( *context ).num_loopback_packets_sent_to_server = 0;

        loop
        {
            netcode_network_simulator_update( &mut network_simulator, time );

            netcode_client_update( &mut *regular_client, time );

            netcode_server_update( &mut *server, time );

            netcode_client_send_packet( &mut *loopback_client, &packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_client_send_packet( &mut *regular_client, &packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_server_send_packet( &mut *server, 0, &packet_data, NETCODE_MAX_PACKET_SIZE );

            netcode_server_send_packet( &mut *server, 1, &packet_data, NETCODE_MAX_PACKET_SIZE );

            loop
            {
                let mut packet_bytes: i32 = 0;
                let mut packet_sequence: u64 = 0;
                let packet = netcode_client_receive_packet( &mut *loopback_client, &mut packet_bytes, &mut packet_sequence );
                let Some( packet ) = packet else { break; };
                netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                loopback_client_num_packets_received += 1;
                netcode_client_free_packet( &mut *loopback_client, packet );
            }

            loop
            {
                let mut packet_bytes: i32 = 0;
                let mut packet_sequence: u64 = 0;
                let packet = netcode_client_receive_packet( &mut *regular_client, &mut packet_bytes, &mut packet_sequence );
                let Some( packet ) = packet else { break; };
                netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                regular_client_num_packets_received += 1;
                netcode_client_free_packet( &mut *regular_client, packet );
            }

            loop
            {
                let mut packet_bytes: i32 = 0;
                let mut packet_sequence: u64 = 0;
                let packet = netcode_server_receive_packet( &mut *server, 0, &mut packet_bytes, &mut packet_sequence );
                let Some( packet ) = packet else { break; };
                netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                loopback_server_num_packets_received += 1;
                netcode_server_free_packet( &mut *server, packet );
            }

            loop
            {
                let mut packet_bytes: i32 = 0;
                let mut packet_sequence: u64 = 0;
                let packet = netcode_server_receive_packet( &mut *server, 1, &mut packet_bytes, &mut packet_sequence );
                let Some( packet ) = packet else { break; };
                netcode_assert!( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                netcode_assert!( packet[..NETCODE_MAX_PACKET_SIZE as usize] == packet_data[..] );
                regular_server_num_packets_received += 1;
                netcode_server_free_packet( &mut *server, packet );
            }

            if loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
               regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10
            {
                break;
            }

            if netcode_client_state( &mut *regular_client ) <= NETCODE_CLIENT_STATE_DISCONNECTED
            {
                break;
            }

            time += delta_time;
        }

        check!( loopback_client_num_packets_received >= 10 );
        check!( loopback_server_num_packets_received >= 10 );
        check!( regular_client_num_packets_received >= 10 );
        check!( regular_server_num_packets_received >= 10 );
        check!( ( *context ).num_loopback_packets_sent_to_client >= 10 );
        check!( ( *context ).num_loopback_packets_sent_to_server >= 10 );

        // verify the regular client times out but loopback client doesn't

        time += 100000.0;

        netcode_server_update( &mut *server, time );

        check!( netcode_server_client_connected( &mut *server, 0 ) == 1 );
        check!( netcode_server_client_connected( &mut *server, 1 ) == 0 );

        netcode_client_update( &mut *loopback_client, time );

        check!( netcode_client_state( &mut *loopback_client ) == NETCODE_CLIENT_STATE_CONNECTED );

        // verify that disconnect all clients leaves loopback clients alone

        netcode_server_disconnect_all_clients( &mut *server );

        check!( netcode_server_client_connected( &mut *server, 0 ) == 1 );
        check!( netcode_server_client_connected( &mut *server, 1 ) == 0 );
        check!( netcode_server_client_loopback( &mut *server, 0 ) == 1 );

        // clean up

        netcode_client_destroy( Box::from_raw( regular_client ) );

        netcode_client_destroy( Box::from_raw( loopback_client ) );

        netcode_server_destroy( Box::from_raw( server ) );

        netcode_network_simulator_destroy( network_simulator );

        drop( Box::from_raw( context ) );
    }
}

// port: #if NETCODE_PACKET_TAGGING -- always compiled; netcode_test runs it when the const is set
fn test_packet_tagging()
{
    // IMPORTANT: Packet tagging is off by default because it doesn't play well with some older home routers
    // See https://learn.microsoft.com/en-us/gaming/gdk/_content/gc/networking/overviews/qos-packet-tagging
    // However, I really recommend providing players with a way to turn it on, since it can significantly reduce
    // jitter playing over Wi-Fi.

    netcode_enable_packet_tagging();

    {
        let server_address: &str = "127.0.0.1:40000";

        let mut server_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut server_config );

        let server = netcode_server_create( server_address, &server_config, 0.0 );

        check!( server.is_some() );
        let server = server.unwrap();

        let mut client_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut client_config );

        let client = netcode_client_create( "127.0.0.1:50000", &client_config, 0.0 );

        check!( client.is_some() );
        let mut client = client.unwrap();

        let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

        let mut client_id: u64 = 0;
        client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

        let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
        netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

        check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

        netcode_client_connect( &mut client, &connect_token );

        netcode_client_destroy( client );

        netcode_server_destroy( server );
    }

    {
        let server_address: &str = "[::1]:40000";

        let mut server_config = netcode_server_config_t::default();
        netcode_default_server_config( &mut server_config );

        let server = netcode_server_create( server_address, &server_config, 0.0 );

        check!( server.is_some() );
        let server = server.unwrap();

        let mut client_config = netcode_client_config_t::default();
        netcode_default_client_config( &mut client_config );

        let client = netcode_client_create( "[::1]:50000", &client_config, 0.0 );

        check!( client.is_some() );
        let mut client = client.unwrap();

        let mut connect_token = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];

        let mut client_id: u64 = 0;
        client_id = test_random_client_id(); // port: netcode_random_bytes( (uint8_t*) &client_id, 8 )

        let mut user_data = [0u8; NETCODE_USER_DATA_BYTES as usize];
        netcode_random_bytes( &mut user_data, NETCODE_USER_DATA_BYTES );

        check!( netcode_generate_connect_token( 1, &[server_address], &[server_address], TEST_CONNECT_TOKEN_EXPIRY as i32, TEST_TIMEOUT_SECONDS as i32, client_id, TEST_PROTOCOL_ID, &test_private_key, &user_data, &mut connect_token ) != 0 );

        netcode_client_connect( &mut client, &connect_token );

        netcode_client_destroy( client );

        netcode_server_destroy( server );
    }
}

fn test_loopback_callback_required()
{
    // entering loopback with send_loopback_packet_callback unset would call a null pointer
    // on the next send. both sides must refuse to enter loopback instead. the guard asserts
    // as well as returning, so install the handler that continues to run this in debug.

    netcode_set_assert_function( test_runtime_guards_assert_handler );

    let mut client_config = netcode_client_config_t::default();
    netcode_default_client_config( &mut client_config );

    let client = netcode_client_create( "0.0.0.0:50000", &client_config, 0.0 );

    check!( client.is_some() );
    let mut client = client.unwrap();

    netcode_client_connect_loopback( &mut client, 0, 1 );

    check!( netcode_client_loopback( &mut client ) == 0 );
    check!( netcode_client_state( &mut client ) == NETCODE_CLIENT_STATE_DISCONNECTED );

    let payload = [0u8; NETCODE_MAX_PACKET_SIZE as usize];

    netcode_client_send_packet( &mut client, &payload, NETCODE_MAX_PACKET_SIZE );

    netcode_client_destroy( client );

    let mut server_config = netcode_server_config_t::default();
    netcode_default_server_config( &mut server_config );

    let server = netcode_server_create( "127.0.0.1:40000", &server_config, 0.0 );

    check!( server.is_some() );
    let mut server = server.unwrap();

    netcode_server_start( &mut server, 1 );

    netcode_server_connect_loopback_client( &mut server, 0, 1, None );

    check!( netcode_server_client_loopback( &mut server, 0 ) == 0 );
    check!( netcode_server_client_connected( &mut server, 0 ) == 0 );
    check!( netcode_server_num_connected_clients( &mut server ) == 0 );

    netcode_server_send_packet( &mut server, 0, &payload, NETCODE_MAX_PACKET_SIZE );

    netcode_server_destroy( server );

    netcode_set_assert_function( netcode_default_assert_handler );
}

macro_rules! RUN_TEST {
    ( $test_function:ident ) => {
        {
            print!( "{}\n", stringify!( $test_function ) );
            $test_function();
        }
    };
}

pub fn netcode_test()
{
    //while ( 1 )
    {
        RUN_TEST!( test_crypto_aead_vectors );
        RUN_TEST!( test_queue );
        RUN_TEST!( test_endian );
        RUN_TEST!( test_address );
        RUN_TEST!( test_sequence );
        RUN_TEST!( test_connect_token );
        RUN_TEST!( test_generate_connect_token_out_of_range );
        RUN_TEST!( test_challenge_token );
        RUN_TEST!( test_connection_request_packet );
        RUN_TEST!( test_connection_denied_packet );
        RUN_TEST!( test_connection_challenge_packet );
        RUN_TEST!( test_connection_response_packet );
        RUN_TEST!( test_connection_keep_alive_packet );
        RUN_TEST!( test_connection_payload_packet );
        RUN_TEST!( test_connection_disconnect_packet );
        RUN_TEST!( test_connect_token_public );
        RUN_TEST!( test_encryption_manager );
        RUN_TEST!( test_replay_protection );
        RUN_TEST!( test_runtime_guards );
        RUN_TEST!( test_init_and_defaults );
        RUN_TEST!( test_client_create_error );
        RUN_TEST!( test_server_create_error );
        RUN_TEST!( test_network_simulator_determinism );
        RUN_TEST!( test_network_simulator_allocation_failure );
        RUN_TEST!( test_client_create );
        RUN_TEST!( test_server_create );
        RUN_TEST!( test_server_restart_global_sequence );
        RUN_TEST!( test_client_server_connect );
        RUN_TEST!( test_client_server_ipv4_socket_connect );
        RUN_TEST!( test_client_server_ipv6_socket_connect );
        RUN_TEST!( test_client_server_dual_socket_connect );
        RUN_TEST!( test_client_server_keep_alive );
        RUN_TEST!( test_client_server_multiple_clients );
        RUN_TEST!( test_client_server_multiple_servers );
        RUN_TEST!( test_client_error_connect_token_expired );
        RUN_TEST!( test_client_error_invalid_connect_token );
        RUN_TEST!( test_client_error_connection_timed_out );
        RUN_TEST!( test_client_error_connection_response_timeout );
        RUN_TEST!( test_client_error_connection_request_timeout );
        RUN_TEST!( test_client_error_connection_denied );
        RUN_TEST!( test_client_side_disconnect );
        RUN_TEST!( test_server_side_disconnect );
        RUN_TEST!( test_server_client_disconnect_reason );
        RUN_TEST!( test_client_reconnect );
        RUN_TEST!( test_connect_token_entries );
        RUN_TEST!( test_client_server_connection_request_retransmission );
        RUN_TEST!( test_client_server_replay_across_sessions );
        RUN_TEST!( test_client_reconnect_with_used_connect_token );
        RUN_TEST!( test_client_error_connect_token_predates_server_start );
        RUN_TEST!( test_disable_timeout );
        RUN_TEST!( test_loopback );
        RUN_TEST!( test_loopback_callback_required );
        // port: #if NETCODE_PACKET_TAGGING / #if NETCODE_ENABLE_NONCE_AUDIT are const tests
        if NETCODE_PACKET_TAGGING != 0
        {
            RUN_TEST!( test_packet_tagging );
        }
        if NETCODE_ENABLE_NONCE_AUDIT != 0
        {
            RUN_TEST!( test_nonce_audit );
        }
    }
}
