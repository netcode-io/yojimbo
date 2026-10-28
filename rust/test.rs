/*
    Yojimbo Unit Tests.

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

// port: the program keeps upstream's names (README, "Names")
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_imports, unused_unsafe, unused_comparisons, unreachable_code, static_mut_refs)]
#![allow(clippy::all)]

// port: #include "yojimbo.h", "shared.h", "serialize.h" and <sodium.h> are the crate (serialize and sodium are
// modules of it, reached as yojimbo::serialize / yojimbo::sodium; serialize is also re-exported at the crate root)
use yojimbo::*;
use std::ffi::c_void;

#[path = "shared.rs"]
mod shared;
use shared::*;

// For netcode_generate_connect_token: one test mints a single connect token and keeps it,
// which is what a matchmaker does and what Client::InsecureConnect deliberately will not do.
// Present in both configurations, unlike sodium.h.
use yojimbo::netcode::*;

fn CheckHandler( condition: &str,
                 function: &str,
                 file: &str,
                 line: i32 )
{
    println!( "check failed: ( {} ), function {}, file {}, line {}", condition, function, file, line );
    // port: __builtin_trap() / __debugbreak() in debug builds is an abort
    #[cfg(debug_assertions)]
    {
        std::process::abort();
    }
    std::process::exit( 1 );
}

// port: __FUNCTION__, the name of the enclosing function
macro_rules! function_name {
    () => {{
        fn __f() {}
        fn __type_name_of<T>( _: T ) -> &'static str { std::any::type_name::<T>() }
        let name = __type_name_of( __f );
        let name = &name[..name.len() - 5];
        match name.rfind( "::" ) { Some( i ) => &name[i + 2..], None => name }
    }};
}

macro_rules! check {
    ( $condition:expr ) => {
        if !( $condition )
        {
            CheckHandler( stringify!( $condition ), function_name!(), file!(), line!() as i32 );
        }
    };
}

// port: the C library's malloc / free, for the tests that work on raw memory. A 16 byte header in front of the block
// holds its size, as DefaultAllocator does, so free can hand std::alloc::dealloc the layout back.
const MallocHeaderBytes: usize = 16;

fn malloc( size: usize ) -> *mut u8
{
    let layout = match std::alloc::Layout::from_size_align( size + MallocHeaderBytes, MallocHeaderBytes )
    {
        Ok( layout ) => layout,
        Err( _ ) => return std::ptr::null_mut(),
    };
    let block = unsafe { std::alloc::alloc( layout ) };
    if block.is_null()
    {
        return std::ptr::null_mut();
    }
    unsafe
    {
        ( block as *mut usize ).write( size );
        block.add( MallocHeaderBytes )
    }
}

fn free( p: *mut u8 )
{
    if p.is_null()
    {
        return;
    }
    unsafe
    {
        let block = p.sub( MallocHeaderBytes );
        let size = ( block as *mut usize ).read();
        std::alloc::dealloc( block, std::alloc::Layout::from_size_align_unchecked( size + MallocHeaderBytes, MallocHeaderBytes ) );
    }
}

// port: the C library's rand() / srand() are yojimbo_rand() / yojimbo_srand(), the generator behind yojimbo_random_int
// (see yojimbo_utils.rs), so one seed reproduces a run
fn rand() -> i32
{
    yojimbo_rand()
}

fn srand( seed: u32 )
{
    yojimbo_srand( seed );
}

// Allocator used by the allocation-failure tests. Delegates to malloc/free, tracks the number of
// outstanding blocks so leaks are observable, and can be "armed" to start returning NULL after a
// given number of successful allocations (to force a failure at a specific point).
pub struct ArmableAllocator
{
    pub base: AllocatorBase,
    m_allocsUntilFail: i32,
    m_outstanding: i32,
}

impl ArmableAllocator
{
    pub fn new() -> ArmableAllocator { ArmableAllocator { base: AllocatorBase::new(), m_allocsUntilFail: -1, m_outstanding: 0 } }
    pub fn Arm( &mut self, allocsUntilFail: i32 ) { self.m_allocsUntilFail = allocsUntilFail; }
    pub fn Disarm( &mut self ) { self.m_allocsUntilFail = -1; }
    pub fn GetOutstanding( &self ) -> i32 { self.m_outstanding }
}

impl Allocator for ArmableAllocator
{
    fn Allocate( &mut self, size: usize, file: &'static str, line: u32 ) -> *mut u8
    {
        if self.m_allocsUntilFail == 0
        {
            self.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return std::ptr::null_mut();
        }
        if self.m_allocsUntilFail > 0
        {
            self.m_allocsUntilFail -= 1;
        }
        let p = malloc( size );
        if p.is_null()
        {
            self.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return std::ptr::null_mut();
        }
        self.m_outstanding += 1;
        self.TrackAlloc( p, size, file, line );
        p
    }

    fn Free( &mut self, p: *mut u8, file: &'static str, line: u32 )
    {
        if p.is_null()
        {
            return;
        }
        self.m_outstanding -= 1;
        self.TrackFree( p, file, line );
        free( p );
    }

    fn base( &self ) -> &AllocatorBase { &self.base }

    fn base_mut( &mut self ) -> &mut AllocatorBase { &mut self.base }
}

fn test_queue()
{
    const QueueSize: i32 = 1024;

    let mut queue: Queue<i32> = Queue::new( GetDefaultAllocator(), QueueSize );

    check!( queue.IsEmpty() );
    check!( !queue.IsFull() );
    check!( queue.GetNumEntries() == 0 );
    check!( queue.GetSize() == QueueSize );

    let NumEntries: i32 = 100;

    for i in 0..NumEntries
    {
        queue.Push( i );
    }

    check!( !queue.IsEmpty() );
    check!( !queue.IsFull() );
    check!( queue.GetNumEntries() == NumEntries );
    check!( queue.GetSize() == QueueSize );

    for i in 0..NumEntries
    {
        check!( queue[i] == i );
    }

    for i in 0..NumEntries
    {
        check!( queue.Pop() == i );
    }

    check!( queue.IsEmpty() );
    check!( !queue.IsFull() );
    check!( queue.GetNumEntries() == 0 );
    check!( queue.GetSize() == QueueSize );

    for i in 0..QueueSize
    {
        queue.Push( i );
    }

    check!( !queue.IsEmpty() );
    check!( queue.IsFull() );
    check!( queue.GetNumEntries() == QueueSize );
    check!( queue.GetSize() == QueueSize );

    queue.Clear();

    check!( queue.IsEmpty() );
    check!( !queue.IsFull() );
    check!( queue.GetNumEntries() == 0 );
    check!( queue.GetSize() == QueueSize );
}

fn parse_address( string: &str ) -> bool
{
    let address = Address::from_string( string );
    address.IsValid()
}

fn test_address_classification()
{
    // These predicates had NO coverage at all, which is how they drifted: IsMulticast,
    // IsLinkLocal and IsSiteLocal compared the first 16-bit group for exact equality
    // instead of masking the prefix. Because IsGlobalUnicast is the negation of the other
    // three, a missed classification did not return false -- it returned TRUE, so ff02::1
    // (all nodes) reported as global unicast.

    // multicast is ff00::/8 -- the whole range, not just the group ff00

    check!( Address::from_string( "ff00::1" ).IsMulticast() );
    check!( Address::from_string( "ff02::1" ).IsMulticast() );            // all nodes: the common one
    check!( Address::from_string( "ff05::1:3" ).IsMulticast() );
    check!( Address::from_string( "ffff::1" ).IsMulticast() );
    check!( !Address::from_string( "ff02::1" ).IsGlobalUnicast() );
    check!( !Address::from_string( "ff05::1:3" ).IsGlobalUnicast() );

    // link local is fe80::/10, so fe80 through febf

    check!( Address::from_string( "fe80::1" ).IsLinkLocal() );
    check!( Address::from_string( "febf::1" ).IsLinkLocal() );
    check!( !Address::from_string( "febf::1" ).IsGlobalUnicast() );
    check!( !Address::from_string( "fec0::1" ).IsLinkLocal() );           // fec0 is site local, not link local

    // site local is fec0::/10, so fec0 through feff

    check!( Address::from_string( "fec0::1" ).IsSiteLocal() );
    check!( Address::from_string( "feff::1" ).IsSiteLocal() );
    check!( !Address::from_string( "fe80::1" ).IsSiteLocal() );

    // and the boundaries below the ranges must NOT be classified

    check!( !Address::from_string( "fe7f::1" ).IsLinkLocal() );
    check!( !Address::from_string( "fe7f::1" ).IsSiteLocal() );
    check!( Address::from_string( "fe7f::1" ).IsGlobalUnicast() );
    check!( !Address::from_string( "feff::1" ).IsGlobalUnicast() );

    // genuine global unicast still classifies, so the fix cannot pass by returning false

    check!( Address::from_string( "2001:4860:4860::8888" ).IsGlobalUnicast() );
    check!( !Address::from_string( "2001:4860:4860::8888" ).IsMulticast() );
    check!( !Address::from_string( "2001:4860:4860::8888" ).IsLoopback() );

    // loopback is unchanged, and is excluded from global unicast

    check!( Address::from_string( "::1" ).IsLoopback() );
    check!( !Address::from_string( "::1" ).IsGlobalUnicast() );
    check!( Address::from_string( "127.0.0.1" ).IsLoopback() );

    // IPv4 is never any of the IPv6 classifications

    check!( !Address::from_string( "127.0.0.1" ).IsMulticast() );
    check!( !Address::from_string( "10.0.0.1" ).IsGlobalUnicast() );
    check!( !Address::from_string( "224.0.0.1" ).IsMulticast() );
}

// YJ-11: Address::Parse used strtol with no end pointer and treated everything past a closing
// bracket as unread. strtol stops at the first character it cannot use and reports what it read,
// so "127.0.0.1:40k" parsed as port 40, an empty port as 0, and a port with more digits than a
// long saturated instead of failing; "[::1" skipped the missing bracket and "[::1]junk" had the
// junk truncated away. Address::Parse documents that an unparseable address is cleared to
// ADDRESS_NONE, so each of these must be invalid.
fn test_address_malformed_port()
{
    // trailing junk after the digits
    check!( parse_address( "127.0.0.1:40k" ) == false );
    check!( parse_address( "127.0.0.1:40 " ) == false );
    check!( parse_address( "127.0.0.1:4.0" ) == false );
    check!( parse_address( "[::1]:40k" ) == false );

    // no digits at all
    check!( parse_address( "127.0.0.1:" ) == false );
    check!( parse_address( "[::1]:" ) == false );

    // a sign or leading whitespace is not a port
    check!( parse_address( "127.0.0.1:+40" ) == false );
    check!( parse_address( "127.0.0.1:-1" ) == false );
    check!( parse_address( "[::1]:+40" ) == false );
    check!( parse_address( "[::1]: 40" ) == false );

    // out of range, including more digits than fit in the parser's own integer
    check!( parse_address( "127.0.0.1:65536" ) == false );
    check!( parse_address( "127.0.0.1:99999" ) == false );
    check!( parse_address( "127.0.0.1:99999999999999999999999" ) == false );
    check!( parse_address( "[::1]:65536" ) == false );
    check!( parse_address( "[::1]:99999999999999999999999" ) == false );

    // bracket syntax is exact
    check!( parse_address( "[::1" ) == false );
    check!( parse_address( "[::1]junk" ) == false );
    check!( parse_address( "[::1]]" ) == false );
    check!( parse_address( "[::1]40000" ) == false );

    // ...and the forms that were always valid still are, with the port they say
    {
        let address = Address::from_string( "127.0.0.1:65535" );
        check!( address.IsValid() );
        check!( address.GetPort() == 65535 );
    }
    {
        let address = Address::from_string( "127.0.0.1:0" );
        check!( address.IsValid() );
        check!( address.GetPort() == 0 );
    }
    {
        let address = Address::from_string( "[::1]:40000" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 40000 );
    }
    {
        let address = Address::from_string( "[::1]" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
    }
}

fn test_address()
{
    check!( parse_address( "" ) == false );
    check!( parse_address( "[" ) == false );
    check!( parse_address( "[]" ) == false );
    check!( parse_address( "[]:" ) == false );
    check!( parse_address( ":" ) == false );
    check!( parse_address( "1" ) == false );
    check!( parse_address( "12" ) == false );
    check!( parse_address( "123" ) == false );
    check!( parse_address( "1234" ) == false );
    check!( parse_address( "1234.0.12313.0000" ) == false );
    check!( parse_address( "1234.0.12313.0000.0.0.0.0.0" ) == false );
    check!( parse_address( "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131" ) == false );
    check!( parse_address( "." ) == false );
    check!( parse_address( ".." ) == false );
    check!( parse_address( "..." ) == false );
    check!( parse_address( "...." ) == false );
    check!( parse_address( "....." ) == false );

    {
        let address = Address::from_string( "107.77.207.77" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV4 );
        check!( address.GetPort() == 0 );
        check!( address.GetAddress4()[0] == 107 );
        check!( address.GetAddress4()[1] == 77 );
        check!( address.GetAddress4()[2] == 207 );
        check!( address.GetAddress4()[3] == 77 );
        check!( !address.IsLoopback() );
    }

    {
        let address = Address::from_string( "127.0.0.1" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV4 );
        check!( address.GetPort() == 0 );
        check!( address.GetAddress4()[0] == 127 );
        check!( address.GetAddress4()[1] == 0 );
        check!( address.GetAddress4()[2] == 0 );
        check!( address.GetAddress4()[3] == 1 );
        check!( address.IsLoopback() );
    }

    {
        let address = Address::from_string( "107.77.207.77:40000" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV4 );
        check!( address.GetPort() == 40000 );
        check!( address.GetAddress4()[0] == 107 );
        check!( address.GetAddress4()[1] == 77 );
        check!( address.GetAddress4()[2] == 207 );
        check!( address.GetAddress4()[3] == 77 );
        check!( !address.IsLoopback() );
    }

    {
        let address = Address::from_string( "127.0.0.1:40000" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV4 );
        check!( address.GetPort() == 40000 );
        check!( address.GetAddress4()[0] == 127 );
        check!( address.GetAddress4()[1] == 0 );
        check!( address.GetAddress4()[2] == 0 );
        check!( address.GetAddress4()[3] == 1 );
        check!( address.IsLoopback() );
    }

    {
        let address = Address::from_string( "fe80::202:b3ff:fe1e:8329" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
        check!( address.GetAddress6()[0] == 0xfe80 );
        check!( address.GetAddress6()[1] == 0x0000 );
        check!( address.GetAddress6()[2] == 0x0000 );
        check!( address.GetAddress6()[3] == 0x0000 );
        check!( address.GetAddress6()[4] == 0x0202 );
        check!( address.GetAddress6()[5] == 0xb3ff );
        check!( address.GetAddress6()[6] == 0xfe1e );
        check!( address.GetAddress6()[7] == 0x8329 );
        check!( !address.IsLoopback() );
    }

    {
        let address = Address::from_string( "::" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
        check!( address.GetAddress6()[0] == 0x0000 );
        check!( address.GetAddress6()[1] == 0x0000 );
        check!( address.GetAddress6()[2] == 0x0000 );
        check!( address.GetAddress6()[3] == 0x0000 );
        check!( address.GetAddress6()[4] == 0x0000 );
        check!( address.GetAddress6()[5] == 0x0000 );
        check!( address.GetAddress6()[6] == 0x0000 );
        check!( address.GetAddress6()[7] == 0x0000 );
        check!( !address.IsLoopback() );
    }

    {
        let address = Address::from_string( "::1" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
        check!( address.GetAddress6()[0] == 0x0000 );
        check!( address.GetAddress6()[1] == 0x0000 );
        check!( address.GetAddress6()[2] == 0x0000 );
        check!( address.GetAddress6()[3] == 0x0000 );
        check!( address.GetAddress6()[4] == 0x0000 );
        check!( address.GetAddress6()[5] == 0x0000 );
        check!( address.GetAddress6()[6] == 0x0000 );
        check!( address.GetAddress6()[7] == 0x0001 );
        check!( address.IsLoopback() );
    }

    {
        let address = Address::from_string( "[fe80::202:b3ff:fe1e:8329]:40000" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 40000 );
        check!( address.GetAddress6()[0] == 0xfe80 );
        check!( address.GetAddress6()[1] == 0x0000 );
        check!( address.GetAddress6()[2] == 0x0000 );
        check!( address.GetAddress6()[3] == 0x0000 );
        check!( address.GetAddress6()[4] == 0x0202 );
        check!( address.GetAddress6()[5] == 0xb3ff );
        check!( address.GetAddress6()[6] == 0xfe1e );
        check!( address.GetAddress6()[7] == 0x8329 );
        check!( !address.IsLoopback() );
    }

    {
        let address = Address::from_string( "[::]:40000" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 40000 );
        check!( address.GetAddress6()[0] == 0x0000 );
        check!( address.GetAddress6()[1] == 0x0000 );
        check!( address.GetAddress6()[2] == 0x0000 );
        check!( address.GetAddress6()[3] == 0x0000 );
        check!( address.GetAddress6()[4] == 0x0000 );
        check!( address.GetAddress6()[5] == 0x0000 );
        check!( address.GetAddress6()[6] == 0x0000 );
        check!( address.GetAddress6()[7] == 0x0000 );
        check!( !address.IsLoopback() );
    }

    {
        let address = Address::from_string( "[::1]:40000" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 40000 );
        check!( address.GetAddress6()[0] == 0x0000 );
        check!( address.GetAddress6()[1] == 0x0000 );
        check!( address.GetAddress6()[2] == 0x0000 );
        check!( address.GetAddress6()[3] == 0x0000 );
        check!( address.GetAddress6()[4] == 0x0000 );
        check!( address.GetAddress6()[5] == 0x0000 );
        check!( address.GetAddress6()[6] == 0x0000 );
        check!( address.GetAddress6()[7] == 0x0001 );
        check!( address.IsLoopback() );
    }

    // Regression: bracketed IPv6 with no port. Scanning for ':' from the end used to misparse
    // a colon inside the address as a port separator, leaving the address unparseable.
    {
        let address = Address::from_string( "[::1]" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
        check!( address.GetAddress6()[0] == 0x0000 );
        check!( address.GetAddress6()[1] == 0x0000 );
        check!( address.GetAddress6()[2] == 0x0000 );
        check!( address.GetAddress6()[3] == 0x0000 );
        check!( address.GetAddress6()[4] == 0x0000 );
        check!( address.GetAddress6()[5] == 0x0000 );
        check!( address.GetAddress6()[6] == 0x0000 );
        check!( address.GetAddress6()[7] == 0x0001 );
        check!( address.IsLoopback() );
    }

    {
        let address = Address::from_string( "[::]" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
        for i in 0..8
        {
            check!( address.GetAddress6()[i] == 0x0000 );
        }
        check!( !address.IsLoopback() );
    }

    {
        let address = Address::from_string( "[fe80::202:b3ff:fe1e:8329]" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
        check!( address.GetAddress6()[0] == 0xfe80 );
        check!( address.GetAddress6()[1] == 0x0000 );
        check!( address.GetAddress6()[2] == 0x0000 );
        check!( address.GetAddress6()[3] == 0x0000 );
        check!( address.GetAddress6()[4] == 0x0202 );
        check!( address.GetAddress6()[5] == 0xb3ff );
        check!( address.GetAddress6()[6] == 0xfe1e );
        check!( address.GetAddress6()[7] == 0x8329 );
        check!( !address.IsLoopback() );
    }

    // port: char buffer[MaxAddressLength] is gone: Address::ToString returns a String (README, "Strings"), so the
    // strcmp checks compare strings

    {
        let address6: [u16; 8] = [ 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 ];

        let address = Address::from_ipv6( address6[0], address6[1], address6[2], address6[2],
                                          address6[4], address6[5], address6[6], address6[7], 0 );

        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );

        for i in 0..8
        {
            check!( address6[i] == address.GetAddress6()[i] );
        }

        check!( address.ToString() == "fe80::202:b3ff:fe1e:8329" );
    }

    {
        let address6: [u16; 8] = [ 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 ];

        let address = Address::from_ipv6_array( &address6, 0 );

        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );

        for i in 0..8
        {
            check!( address6[i] == address.GetAddress6()[i] );
        }

        check!( address.ToString() == "fe80::202:b3ff:fe1e:8329" );
    }

    {
        let address6: [u16; 8] = [ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001 ];

        let address = Address::from_ipv6_array( &address6, 0 );

        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );

        for i in 0..8
        {
            check!( address6[i] == address.GetAddress6()[i] );
        }

        check!( address.ToString() == "::1" );
    }

    {
        let address6: [u16; 8] = [ 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 ];

        let address = Address::from_ipv6( address6[0], address6[1], address6[2], address6[2],
                                          address6[4], address6[5], address6[6], address6[7], 65535 );

        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 65535 );

        for i in 0..8
        {
            check!( address6[i] == address.GetAddress6()[i] );
        }

        check!( address.ToString() == "[fe80::202:b3ff:fe1e:8329]:65535" );
    }

    {
        let address6: [u16; 8] = [ 0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329 ];

        let address = Address::from_ipv6_array( &address6, 65535 );

        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 65535 );

        for i in 0..8
        {
            check!( address6[i] == address.GetAddress6()[i] );
        }

        check!( address.ToString() == "[fe80::202:b3ff:fe1e:8329]:65535" );
    }

    {
        let address6: [u16; 8] = [ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001 ];

        let address = Address::from_ipv6_array( &address6, 65535 );

        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 65535 );

        for i in 0..8
        {
            check!( address6[i] == address.GetAddress6()[i] );
        }

        check!( address.ToString() == "[::1]:65535" );
    }

    {
        let address = Address::from_string( "fe80::202:b3ff:fe1e:8329" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
        check!( address.ToString() == "fe80::202:b3ff:fe1e:8329" );
    }

    {
        let address = Address::from_string( "::1" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 0 );
        check!( address.ToString() == "::1" );
    }

    {
        let address = Address::from_string( "[fe80::202:b3ff:fe1e:8329]:65535" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 65535 );
        check!( address.ToString() == "[fe80::202:b3ff:fe1e:8329]:65535" );
    }

    {
        let address = Address::from_string( "[::1]:65535" );
        check!( address.IsValid() );
        check!( address.GetType() == ADDRESS_IPV6 );
        check!( address.GetPort() == 65535 );
        check!( address.ToString() == "[::1]:65535" );
    }
}

fn test_network_simulator_drains_all_slots()
{
    // Regression: ReceivePackets used to scan only the first min(numEntries, maxPackets) ring
    // slots. Packets are stored across the whole ring (at m_currentIndex), so when a caller
    // passes maxPackets < numEntries, any packet held in a tail slot was never drained. It must
    // scan the entire ring and only cap how many packets it returns per call.

    const NumEntries: i32 = 4;

    let mut sim = NetworkSimulator::new( GetDefaultAllocator(), NumEntries, 0.0 );

    // Negative loss/duplicate rates make those RNG checks impossible to fire (random_float is
    // always >= 0), so sends are fully deterministic, and they mark the simulator active.
    sim.SetPacketLoss( -1.0 );
    sim.SetDuplicates( -1.0 );

    let mut payload = [0u8; 8];
    for i in 0..NumEntries
    {
        payload.fill( i as u8 );
        sim.SendPacket( i, &payload, payload.len() as i32 );    // fills ring slots 0..NumEntries-1, "to" == slot
    }

    sim.AdvanceTime( 1.0 );     // past every delivery time (latency 0)

    // Drain with maxPackets (2) smaller than the ring (4). Everything must come out across calls,
    // including packets in the tail slots that the old code stranded.
    let mut seen = [false; NumEntries as usize];
    let mut totalReceived = 0;

    for iter in 0..NumEntries + 2
    {
        let mut packetData: [*mut u8; 2] = [std::ptr::null_mut(); 2];
        let mut packetBytes = [0i32; 2];
        let mut to = [0i32; 2];
        let n = sim.ReceivePackets( 2, &mut packetData, &mut packetBytes, Some( &mut to ) );
        check!( n <= 2 );        // never returns more than maxPackets
        for i in 0..n as usize
        {
            check!( to[i] >= 0 && to[i] < NumEntries );
            check!( !seen[to[i] as usize] );      // no packet delivered twice
            check!( packetBytes[i] == payload.len() as i32 );
            seen[to[i] as usize] = true;
            totalReceived += 1;
            YOJIMBO_FREE!( sim.GetAllocator(), packetData[i] );
        }
    }

    check!( totalReceived == NumEntries );
    for i in 0..NumEntries as usize
    {
        check!( seen[i] );       // tail slots (index >= maxPackets) were drained too
    }
}

fn test_bit_array()
{
    const Size: i32 = 300;

    let mut bit_array = BitArray::new( GetDefaultAllocator(), Size );

    // verify initial conditions

    check!( bit_array.GetSize() == Size );

    for i in 0..Size
    {
        check!( bit_array.GetBit( i ) == 0 );
    }

    // set every third bit and verify correct bits are set on read

    for i in 0..Size
    {
        if ( i % 3 ) == 0
        {
            bit_array.SetBit( i );
        }
    }

    for i in 0..Size
    {
        if ( i % 3 ) == 0
        {
            check!( bit_array.GetBit( i ) == 1 );
        }
        else
        {
            check!( bit_array.GetBit( i ) == 0 );
        }
    }

    // now clear every third bit to zero and verify all bits are zero

    for i in 0..Size
    {
        if ( i % 3 ) == 0
        {
            bit_array.ClearBit( i );
        }
    }

    for i in 0..Size
    {
        check!( bit_array.GetBit( i ) == 0 );
    }

    // now set some more bits

    for i in 0..Size
    {
        if ( i % 10 ) == 0
        {
            bit_array.SetBit( i );
        }
    }

    for i in 0..Size
    {
        if ( i % 10 ) == 0
        {
            check!( bit_array.GetBit( i ) == 1 );
        }
        else
        {
            check!( bit_array.GetBit( i ) == 0 );
        }
    }

    // clear and verify all bits are zero

    bit_array.Clear();

    for i in 0..Size
    {
        check!( bit_array.GetBit( i ) == 0 );
    }
}

struct TestSequenceData
{
    sequence: u16,
}

impl TestSequenceData
{
    // port: explicit TestSequenceData( uint16_t _sequence )
    fn new( _sequence: u16 ) -> TestSequenceData { TestSequenceData { sequence: _sequence } }
}

// port: TestSequenceData() : sequence(0xFFFF) {}
impl Default for TestSequenceData
{
    fn default() -> TestSequenceData { TestSequenceData { sequence: 0xFFFF } }
}

fn test_sequence_buffer()
{
    const Size: i32 = 256;

    let mut sequence_buffer: SequenceBuffer<TestSequenceData> = SequenceBuffer::new( GetDefaultAllocator(), Size );

    for i in 0..Size
    {
        check!( sequence_buffer.Find( i as u16 ).is_null() );
    }

    for i in 0..=Size*4
    {
        let entry: *mut TestSequenceData = sequence_buffer.Insert( i as u16, false );
        unsafe { ( *entry ).sequence = i as u16; }
        check!( sequence_buffer.GetSequence() as i32 == i + 1 );
    }

    for i in 0..=Size
    {
        let entry: *mut TestSequenceData = sequence_buffer.Insert( i as u16, false );
        check!( entry.is_null() );
    }

    let mut index: i32 = Size * 4;
    for i in 0..Size
    {
        let entry: *mut TestSequenceData = sequence_buffer.Find( index as u16 );
        check!( !entry.is_null() );
        check!( unsafe { ( *entry ).sequence } as u32 == index as u32 );
        index -= 1;
    }

    for i in 0..=Size
    {
        let entry: *mut TestSequenceData = sequence_buffer.Insert( i as u16, true );
        check!( !entry.is_null() );
        unsafe { ( *entry ).sequence = i as u16; }
        check!( sequence_buffer.GetSequence() as i32 == i + 1 );
    }

    sequence_buffer.Reset();

    check!( sequence_buffer.GetSequence() == 0 );

    for i in 0..Size
    {
        check!( sequence_buffer.Find( i as u16 ).is_null() );
    }
}

fn test_allocator_tlsf()
{
    const NumBlocks: i32 = 256;
    const BlockSize: i32 = 1024;
    const MemorySize: i32 = NumBlocks * BlockSize;

    let memory: *mut u8 = malloc( MemorySize as usize );

    let mut allocator = TLSF_Allocator::new( memory, MemorySize as usize );

    let mut blockData: [*mut u8; NumBlocks as usize] = [std::ptr::null_mut(); NumBlocks as usize];

    let mut stopIndex: i32 = 0;

    for i in 0..NumBlocks
    {
        blockData[i as usize] = YOJIMBO_ALLOCATE!( &mut allocator, BlockSize );

        if blockData[i as usize].is_null()
        {
            check!( allocator.GetErrorLevel() == ALLOCATOR_ERROR_OUT_OF_MEMORY );
            allocator.ClearError();
            check!( allocator.GetErrorLevel() == ALLOCATOR_ERROR_NONE );
            stopIndex = i;
            break;
        }

        check!( !blockData[i as usize].is_null() );
        check!( allocator.GetErrorLevel() == ALLOCATOR_ERROR_NONE );

        unsafe { std::ptr::write_bytes( blockData[i as usize], ( i + 10 ) as u8, BlockSize as usize ); }
    }

    check!( stopIndex > NumBlocks / 2 );

    for i in 0..NumBlocks - 1
    {
        if !blockData[i as usize].is_null()
        {
            for j in 0..BlockSize as usize
            {
                check!( unsafe { *blockData[i as usize].add( j ) } == ( i + 10 ) as u8 );
            }
        }

        YOJIMBO_FREE!( &mut allocator, blockData[i as usize] );
    }

    free( memory );
}

// port: Rust has no default arguments; callers pass upstream's defaults deltaTime = 0.1f, packetLossPercent = 90
fn PumpConnectionUpdate( connectionConfig: &ConnectionConfig, time: &mut f64, sender: &mut Connection, receiver: &mut Connection, senderSequence: &mut u16, receiverSequence: &mut u16, deltaTime: f32, packetLossPercent: i32 )
{
    // port: alloca is a Vec
    let mut packetData: Vec<u8> = vec![0u8; connectionConfig.maxPacketSize as usize];

    let mut packetBytes: i32 = 0;
    if sender.GeneratePacket( std::ptr::null_mut(), *senderSequence, &mut packetData, connectionConfig.maxPacketSize, &mut packetBytes )
    {
        if yojimbo_random_int( 0, 100 ) >= packetLossPercent
        {
            receiver.ProcessPacket( std::ptr::null_mut(), *senderSequence, &packetData, packetBytes );
            sender.ProcessAcks( &[*senderSequence], 1 );
        }
    }

    if receiver.GeneratePacket( std::ptr::null_mut(), *receiverSequence, &mut packetData, connectionConfig.maxPacketSize, &mut packetBytes )
    {
        if yojimbo_random_int( 0, 100 ) >= packetLossPercent
        {
            sender.ProcessPacket( std::ptr::null_mut(), *receiverSequence, &packetData, packetBytes );
            receiver.ProcessAcks( &[*receiverSequence], 1 );
        }
    }

    *time += deltaTime as f64;

    sender.AdvanceTime( *time );
    receiver.AdvanceTime( *time );

    *senderSequence = senderSequence.wrapping_add( 1 );
    *receiverSequence = receiverSequence.wrapping_add( 1 );
}

const ReliableChannel: i32 = 0;

// port: the tests hold a message factory on the stack and hand connections a `*mut dyn MessageFactory` to it, as
// upstream passes `messageFactory` by reference; messages are cast to their concrete type with message_cast, as
// upstream does with `(TestMessage*) message`

fn test_connection_reliable_ordered_messages()
{
    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let connectionConfig = ConnectionConfig::new();

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumMessagesSent: i32 = 64;

    for i in 0..NumMessagesSent
    {
        let message = messageFactory.CreateMessage( TEST_MESSAGE );
        check!( !message.is_null() );
        unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
        sender.SendMessage( ReliableChannel, message, std::ptr::null_mut() );
    }

    let mut numMessagesReceived: i32 = 0;

    const NumIterations: i32 = 1000;

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 90 );

        loop
        {
            let message = receiver.ReceiveMessage( ReliableChannel );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetId() } == numMessagesReceived );
            check!( unsafe { ( *message ).GetType() } == TEST_MESSAGE );

            let testMessage = unsafe { message_cast::<TestMessage>( message ) };

            check!( testMessage.sequence as i32 == numMessagesReceived );

            numMessagesReceived += 1;

            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}

fn test_connection_reliable_ordered_blocks()
{
    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let connectionConfig = ConnectionConfig::new();

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumMessagesSent: i32 = 32;

    for i in 0..NumMessagesSent
    {
        let message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE );
        check!( !message.is_null() );
        let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
        blockMessage.sequence = i as u16;
        let blockSize: i32 = 1 + ( ( i * 901 ) % 3333 );
        let blockData: *mut u8 = YOJIMBO_ALLOCATE!( messageFactory.GetAllocator(), blockSize );
        for j in 0..blockSize
        {
            unsafe { *blockData.add( j as usize ) = ( i + j ) as u8; }
        }
        blockMessage.AttachBlock( messageFactory.GetAllocator(), blockData, blockSize );
        sender.SendMessage( ReliableChannel, message, std::ptr::null_mut() );
    }

    let mut numMessagesReceived: i32 = 0;

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    const NumIterations: i32 = 10000;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 90 );

        loop
        {
            let message = receiver.ReceiveMessage( ReliableChannel );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetId() } == numMessagesReceived );

            check!( unsafe { ( *message ).GetType() } == TEST_BLOCK_MESSAGE );

            let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };

            check!( blockMessage.sequence == numMessagesReceived as u16 );

            let blockSize: i32 = blockMessage.GetBlockSize();

            check!( blockSize == 1 + ( ( numMessagesReceived * 901 ) % 3333 ) );

            let blockData: *const u8 = blockMessage.GetBlockData();

            check!( !blockData.is_null() );

            for j in 0..blockSize
            {
                check!( unsafe { *blockData.add( j as usize ) } == ( numMessagesReceived + j ) as u8 );
            }

            numMessagesReceived += 1;

            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}

fn test_connection_reliable_ordered_blocks_max_size()
{
    // Regression test: when maxBlockSize is not a multiple of blockFragmentSize, a
    // full-size block needs ceil(maxBlockSize/blockFragmentSize) fragments. The
    // send-side fragment buffers used to be sized with floor division, so sending a
    // maxBlockSize block overflowed them. Here 1100/500 => floor 2, ceil 3.
    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let mut connectionConfig = ConnectionConfig::new();
    connectionConfig.channel[ReliableChannel as usize].maxBlockSize = 1100;
    connectionConfig.channel[ReliableChannel as usize].blockFragmentSize = 500;

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumMessagesSent: i32 = 8;
    let BlockSize: i32 = connectionConfig.channel[ReliableChannel as usize].maxBlockSize;

    for i in 0..NumMessagesSent
    {
        let message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE );
        check!( !message.is_null() );
        let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
        blockMessage.sequence = i as u16;
        let blockData: *mut u8 = YOJIMBO_ALLOCATE!( messageFactory.GetAllocator(), BlockSize );
        for j in 0..BlockSize
        {
            unsafe { *blockData.add( j as usize ) = ( i + j ) as u8; }
        }
        blockMessage.AttachBlock( messageFactory.GetAllocator(), blockData, BlockSize );
        sender.SendMessage( ReliableChannel, message, std::ptr::null_mut() );
    }

    let mut numMessagesReceived: i32 = 0;
    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;
    const NumIterations: i32 = 10000;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 90 );

        loop
        {
            let message = receiver.ReceiveMessage( ReliableChannel );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetId() } == numMessagesReceived );
            check!( unsafe { ( *message ).GetType() } == TEST_BLOCK_MESSAGE );

            let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
            check!( blockMessage.sequence == numMessagesReceived as u16 );

            let blockSize: i32 = blockMessage.GetBlockSize();
            check!( blockSize == BlockSize );

            let blockData: *const u8 = blockMessage.GetBlockData();
            check!( !blockData.is_null() );
            for j in 0..blockSize
            {
                check!( unsafe { *blockData.add( j as usize ) } == ( numMessagesReceived + j ) as u8 );
            }

            numMessagesReceived += 1;
            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}

fn test_connection_reliable_ordered_messages_and_blocks()
{
    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let connectionConfig = ConnectionConfig::new();

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumMessagesSent: i32 = 32;

    for i in 0..NumMessagesSent
    {
        if rand() % 2 != 0
        {
            let message = messageFactory.CreateMessage( TEST_MESSAGE );
            check!( !message.is_null() );
            unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
            sender.SendMessage( ReliableChannel, message, std::ptr::null_mut() );
        }
        else
        {
            let message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE );
            check!( !message.is_null() );
            let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
            blockMessage.sequence = i as u16;
            let blockSize: i32 = 1 + ( ( i * 901 ) % 3333 );
            let blockData: *mut u8 = YOJIMBO_ALLOCATE!( messageFactory.GetAllocator(), blockSize );
            for j in 0..blockSize
            {
                unsafe { *blockData.add( j as usize ) = ( i + j ) as u8; }
            }
            blockMessage.AttachBlock( messageFactory.GetAllocator(), blockData, blockSize );
            sender.SendMessage( ReliableChannel, message, std::ptr::null_mut() );
        }
    }

    let mut numMessagesReceived: i32 = 0;

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    const NumIterations: i32 = 10000;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 90 );

        loop
        {
            let message = receiver.ReceiveMessage( ReliableChannel );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetId() } == numMessagesReceived );

            match unsafe { ( *message ).GetType() }
            {
                TEST_MESSAGE =>
                {
                    let testMessage = unsafe { message_cast::<TestMessage>( message ) };

                    check!( testMessage.sequence == numMessagesReceived as u16 );

                    numMessagesReceived += 1;
                }

                TEST_BLOCK_MESSAGE =>
                {
                    let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };

                    check!( blockMessage.sequence == numMessagesReceived as u16 );

                    let blockSize: i32 = blockMessage.GetBlockSize();

                    check!( blockSize == 1 + ( ( numMessagesReceived * 901 ) % 3333 ) );

                    let blockData: *const u8 = blockMessage.GetBlockData();

                    check!( !blockData.is_null() );

                    for j in 0..blockSize
                    {
                        check!( unsafe { *blockData.add( j as usize ) } == ( numMessagesReceived + j ) as u8 );
                    }

                    numMessagesReceived += 1;
                }

                _ => {}
            }

            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}

fn test_connection_reliable_ordered_messages_and_blocks_multiple_channels()
{
    const NumChannels: i32 = 2;

    yojimbo_assert!( NumChannels >= 0 );
    yojimbo_assert!( NumChannels <= MaxChannels );

    let mut time: f64 = 100.0;

    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut connectionConfig = ConnectionConfig::new();
    connectionConfig.numChannels = NumChannels;
    connectionConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    connectionConfig.channel[0].maxMessagesPerPacket = 8;
    connectionConfig.channel[1].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    connectionConfig.channel[1].maxMessagesPerPacket = 8;

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumMessagesSent: i32 = 32;

    for channelIndex in 0..NumChannels
    {
        for i in 0..NumMessagesSent
        {
            if rand() % 2 != 0
            {
                let message = messageFactory.CreateMessage( TEST_MESSAGE );
                check!( !message.is_null() );
                unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
                sender.SendMessage( channelIndex, message, std::ptr::null_mut() );
            }
            else
            {
                let message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE );
                check!( !message.is_null() );
                let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
                blockMessage.sequence = i as u16;
                let blockSize: i32 = 1 + ( ( i * 901 ) % 3333 );
                let blockData: *mut u8 = YOJIMBO_ALLOCATE!( messageFactory.GetAllocator(), blockSize );
                for j in 0..blockSize
                {
                    unsafe { *blockData.add( j as usize ) = ( i + j ) as u8; }
                }
                blockMessage.AttachBlock( messageFactory.GetAllocator(), blockData, blockSize );
                sender.SendMessage( channelIndex, message, std::ptr::null_mut() );
            }
        }
    }

    const NumIterations: i32 = 10000;

    let mut numMessagesReceived = [0i32; NumChannels as usize];

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 90 );

        for channelIndex in 0..NumChannels
        {
            let ci = channelIndex as usize;

            loop
            {
                let message = receiver.ReceiveMessage( channelIndex );
                if message.is_null()
                {
                    break;
                }

                check!( unsafe { ( *message ).GetId() } == numMessagesReceived[ci] );

                match unsafe { ( *message ).GetType() }
                {
                    TEST_MESSAGE =>
                    {
                        let testMessage = unsafe { message_cast::<TestMessage>( message ) };

                        check!( testMessage.sequence == numMessagesReceived[ci] as u16 );

                        numMessagesReceived[ci] += 1;
                    }

                    TEST_BLOCK_MESSAGE =>
                    {
                        let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };

                        check!( blockMessage.sequence == numMessagesReceived[ci] as u16 );

                        let blockSize: i32 = blockMessage.GetBlockSize();

                        check!( blockSize == 1 + ( ( numMessagesReceived[ci] * 901 ) % 3333 ) );

                        let blockData: *const u8 = blockMessage.GetBlockData();

                        check!( !blockData.is_null() );

                        for j in 0..blockSize
                        {
                            check!( unsafe { *blockData.add( j as usize ) } == ( numMessagesReceived[ci] + j ) as u8 );
                        }

                        numMessagesReceived[ci] += 1;
                    }

                    _ => {}
                }

                messageFactory.ReleaseMessage( message );
            }
        }

        let mut receivedAllMessages = true;

        for channelIndex in 0..NumChannels as usize
        {
            if numMessagesReceived[channelIndex] != NumMessagesSent
            {
                receivedAllMessages = false;
                break;
            }
        }

        if receivedAllMessages
        {
            break;
        }
    }

    for channelIndex in 0..NumChannels as usize
    {
        check!( numMessagesReceived[channelIndex] == NumMessagesSent );
    }
}

fn test_connection_unreliable_unordered_messages()
{
    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let mut connectionConfig = ConnectionConfig::new();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumIterations: i32 = 256;

    const NumMessagesSent: i32 = 16;

    for j in 0..NumMessagesSent
    {
        let message = messageFactory.CreateMessage( TEST_MESSAGE );
        check!( !message.is_null() );
        unsafe { message_cast::<TestMessage>( message ) }.sequence = j as u16;
        sender.SendMessage( 0, message, std::ptr::null_mut() );
    }

    let mut numMessagesReceived: i32 = 0;

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 0 );

        loop
        {
            let message = receiver.ReceiveMessage( 0 );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetType() } == TEST_MESSAGE );

            let testMessage = unsafe { message_cast::<TestMessage>( message ) };

            check!( testMessage.sequence == numMessagesReceived as u16 );

            numMessagesReceived += 1;

            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}

fn test_connection_unreliable_unordered_blocks()
{
    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let mut connectionConfig = ConnectionConfig::new();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumIterations: i32 = 256;

    const NumMessagesSent: i32 = 8;

    for j in 0..NumMessagesSent
    {
        let message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE );
        check!( !message.is_null() );
        let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
        blockMessage.sequence = j as u16;
        let blockSize: i32 = 1 + ( j * 7 );
        let blockData: *mut u8 = YOJIMBO_ALLOCATE!( messageFactory.GetAllocator(), blockSize );
        for k in 0..blockSize
        {
            unsafe { *blockData.add( k as usize ) = ( j + k ) as u8; }
        }
        blockMessage.AttachBlock( messageFactory.GetAllocator(), blockData, blockSize );
        sender.SendMessage( 0, message, std::ptr::null_mut() );
    }

    let mut numMessagesReceived: i32 = 0;

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 0 );

        loop
        {
            let message = receiver.ReceiveMessage( 0 );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetType() } == TEST_BLOCK_MESSAGE );

            let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };

            check!( blockMessage.sequence == numMessagesReceived as u16 );

            let blockSize: i32 = blockMessage.GetBlockSize();

            check!( blockSize == 1 + ( numMessagesReceived * 7 ) );

            let blockData: *const u8 = blockMessage.GetBlockData();

            check!( !blockData.is_null() );

            for j in 0..blockSize
            {
                check!( unsafe { *blockData.add( j as usize ) } == ( numMessagesReceived + j ) as u8 );
            }

            numMessagesReceived += 1;

            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}

fn test_connection_reject_empty_packet()
{
    // A packet that is exactly a reliable header reaches Connection::ProcessPacket with
    // zero payload bytes. That must be rejected cleanly, not fed to the bit reader (which
    // used to trip the bufferSize > 0 assert in ReadPacket).

    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let time = 100.0;

    let mut connectionConfig = ConnectionConfig::new();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;

    let mut connection = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    let buffer: [u8; 1] = [ 0 ];

    check!( !connection.ProcessPacket( std::ptr::null_mut(), 0, &buffer, 0 ) );
    check!( connection.GetErrorLevel() == CONNECTION_ERROR_READ_PACKET_FAILED );
}

fn test_connection_process_packet_exact_allocation()
{
    // Production receive hands ProcessPacket an exact payload allocation.
    // BitReader needs 8 bytes of slack; ProcessPacket copies into packetBytes+8.
    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );
    let time = 100.0;
    let mut connectionConfig = ConnectionConfig::new();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    let message = messageFactory.CreateMessage( TEST_MESSAGE );
    check!( !message.is_null() );
    unsafe { message_cast::<TestMessage>( message ) }.sequence = 0;
    sender.SendMessage( 0, message, std::ptr::null_mut() );

    let mut packet = [0u8; 2048];
    let mut packetBytes: i32 = 0;
    check!( sender.GeneratePacket( std::ptr::null_mut(), 0, &mut packet, std::mem::size_of::<[u8; 2048]>() as i32, &mut packetBytes ) );
    check!( packetBytes > 0 );

    let exact = malloc( packetBytes as usize );
    check!( !exact.is_null() );
    unsafe { std::ptr::copy_nonoverlapping( packet.as_ptr(), exact, packetBytes as usize ); }
    // port: the exact allocation is handed over as a slice of exactly packetBytes bytes
    check!( receiver.ProcessPacket( std::ptr::null_mut(), 0, unsafe { std::slice::from_raw_parts( exact, packetBytes as usize ) }, packetBytes ) );
    free( exact );

    let received = receiver.ReceiveMessage( 0 );
    check!( !received.is_null() );
    check!( unsafe { ( *received ).GetType() } == TEST_MESSAGE );
    messageFactory.ReleaseMessage( received );
}

fn test_connection_unreliable_rejects_block_fragment()
{
    // An unreliable-unordered channel never sends a top-level block fragment (its blocks
    // are serialized inline). A peer that puts a block fragment on that channel index used
    // to be misread through the ChannelPacketData union (a BlockMessage* reinterpreted as a
    // message-pointer array) and crash. It must instead be rejected as a serialize failure.

    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time = 100.0;

    // Sender speaks reliable-ordered on channel 0, so it emits a top-level block fragment.
    let mut senderConfig = ConnectionConfig::new();
    senderConfig.numChannels = 1;
    senderConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;

    // Receiver treats channel 0 as unreliable-unordered.
    let mut receiverConfig = ConnectionConfig::new();
    receiverConfig.numChannels = 1;
    receiverConfig.channel[0].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &senderConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &receiverConfig, time );

    let message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE );
    check!( !message.is_null() );
    let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
    blockMessage.sequence = 0;
    let blockSize: i32 = 64;
    let blockData = YOJIMBO_ALLOCATE!( messageFactory.GetAllocator(), blockSize );
    for i in 0..blockSize
    {
        unsafe { *blockData.add( i as usize ) = i as u8; }
    }
    blockMessage.base.AttachBlock( messageFactory.GetAllocator(), blockData, blockSize );
    sender.SendMessage( 0, message, std::ptr::null_mut() );

    // The sender is never acked, so it keeps re-sending the block fragment every tick.
    // Feed each generated packet to the receiver until its unreliable channel rejects the
    // fragment and the connection drops into the channel error state.
    // port: alloca is a Vec
    let mut packetData = vec![ 0u8; senderConfig.maxPacketSize as usize ];
    let mut sequence: u16 = 0;
    let mut sawChannelError = false;

    let mut i = 0;
    while i < 64 && !sawChannelError
    {
        let mut packetBytes: i32 = 0;
        if sender.GeneratePacket( std::ptr::null_mut(), sequence, &mut packetData, senderConfig.maxPacketSize, &mut packetBytes ) && packetBytes > 0
        {
            receiver.ProcessPacket( std::ptr::null_mut(), sequence, &packetData, packetBytes );
        }

        sender.AdvanceTime( time );
        receiver.AdvanceTime( time );
        time += 0.1;
        sequence = sequence.wrapping_add( 1 );

        if receiver.GetErrorLevel() == CONNECTION_ERROR_CHANNEL
        {
            sawChannelError = true;
        }

        i += 1;
    }

    check!( sawChannelError );
}

fn test_connection_reliable_block_fragment_on_disabled_blocks()
{
    // A peer sends a block fragment on a reliable-ordered channel, but the receiver has
    // blocks disabled on that channel. ChannelPacketData::Serialize reads blockMessage=1 then
    // returns early on disableBlocks, before SerializeBlockFragment initializes the block
    // pointers. The packet destructor's Free() must not then dereference an uninitialized
    // block.message (it used to, because Initialize() only zeroed part of the union).

    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time = 100.0;

    // Sender: reliable-ordered with blocks enabled, so it emits a real block fragment.
    let mut senderConfig = ConnectionConfig::new();
    senderConfig.numChannels = 1;
    senderConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;

    // Receiver: reliable-ordered on the same channel, but with blocks disabled.
    let mut receiverConfig = ConnectionConfig::new();
    receiverConfig.numChannels = 1;
    receiverConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    receiverConfig.channel[0].disableBlocks = true;

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &senderConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &receiverConfig, time );

    let message = messageFactory.CreateMessage( TEST_BLOCK_MESSAGE );
    check!( !message.is_null() );
    let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
    blockMessage.sequence = 0;
    let blockSize: i32 = 2000;   // > fragment size, but even a single fragment reproduces it
    let blockData = YOJIMBO_ALLOCATE!( messageFactory.GetAllocator(), blockSize );
    for i in 0..blockSize
    {
        unsafe { *blockData.add( i as usize ) = i as u8; }
    }
    blockMessage.base.AttachBlock( messageFactory.GetAllocator(), blockData, blockSize );
    sender.SendMessage( 0, message, std::ptr::null_mut() );

    // Feed generated block-fragment packets to the receiver. Before the fix this crashed in
    // the packet destructor; after it, the read simply fails and the connection errors.
    // port: alloca is a Vec
    let mut packetData = vec![ 0u8; senderConfig.maxPacketSize as usize ];
    let mut sequence: u16 = 0;

    for _i in 0..64
    {
        let mut packetBytes: i32 = 0;
        if sender.GeneratePacket( std::ptr::null_mut(), sequence, &mut packetData, senderConfig.maxPacketSize, &mut packetBytes ) && packetBytes > 0
        {
            receiver.ProcessPacket( std::ptr::null_mut(), sequence, &packetData, packetBytes );
        }

        sender.AdvanceTime( time );
        receiver.AdvanceTime( time );
        time += 0.1;
        sequence = sequence.wrapping_add( 1 );

        if receiver.GetErrorLevel() != CONNECTION_ERROR_NONE
        {
            break;
        }
    }

    // The receiver rejected the disallowed block fragment without crashing.
    check!( receiver.GetErrorLevel() != CONNECTION_ERROR_NONE );
}

// Hand-serialize a connection packet carrying a single reliable-ordered channel entry that is
// a block fragment. Matches ConnectionPacket + ChannelPacketData::Serialize + SerializeBlockFragment
// for a numChannels==1 config. Lets tests inject fragment fields a well-behaved sender never would.
fn SerializeRawBlockFragmentPacket<S: Stream>( stream: &mut S, maxFragmentsPerBlock: i32, blockFragmentSize: i32, mut numFragments: i32, mut fragmentId: i32, mut fragmentSize: i32 ) -> bool
{
    let mut numChannelEntries: i32 = 1;
    serialize_int!( stream, numChannelEntries, 0, 1 );   // numChannels == 1, so channelIndex is not serialized

    let mut blockMessage = true;
    serialize_bool!( stream, blockMessage );

    let mut messageId: u32 = 0;
    serialize_bits!( stream, messageId, 16 );

    if maxFragmentsPerBlock > 1
    {
        serialize_int!( stream, numFragments, 1, maxFragmentsPerBlock );
    }

    if numFragments > 1
    {
        serialize_int!( stream, fragmentId, 0, numFragments - 1 );
    }

    serialize_int!( stream, fragmentSize, 1, blockFragmentSize );

    let mut payload = [0u8; 2048];
    yojimbo_assert!( fragmentSize <= payload.len() as i32 );
    payload.fill( 0xAB );
    serialize_bytes!( stream, payload, fragmentSize );

    // fragmentId != 0 here, so no message type / block message is serialized.
    true
}

fn test_channel_config_fragment_counts_without_overflow()
{
    // yojimbo#347: ceil(maxBlockSize / blockFragmentSize) used to add in int
    // and overflow for a legal huge maxBlockSize. The 65535 check then saw
    // garbage. The add is 64-bit; a too-large result stays well-defined and
    // still fails Validate's cap.
    let mut channel = ChannelConfig::new();
    channel.maxBlockSize = 2147483647;
    channel.blockFragmentSize = 1024;
    let n = channel.GetMaxFragmentsPerBlock();
    check!( n == ( ( 2147483647i64 + 1023 ) / 1024 ) as i32 );
    check!( n > 65535 );

    // yojimbo#346: fragmentSize on the wire is 16 bits.
    let mut small = ChannelConfig::new();
    small.maxBlockSize = 256 * 1024;
    small.blockFragmentSize = 1024;
    check!( small.GetMaxFragmentsPerBlock() == 256 );
    check!( small.blockFragmentSize <= 65535 );
}

fn test_connection_reliable_block_fragment_overflow()
{
    // Regression test: a peer sends a reliable-ordered block fragment whose final fragment
    // claims a full blockFragmentSize of data, even though maxBlockSize is not a multiple of
    // blockFragmentSize. The receive buffer (blockData) is maxBlockSize bytes, but the final
    // fragment is copied at offset (numFragments-1)*blockFragmentSize, so a full-size copy
    // used to run past the end of the buffer (heap-buffer-overflow, caught by ASan). The
    // fragment must be rejected before the copy. fragmentSize is attacker-controllable in
    // [1,blockFragmentSize], so a legitimate sender never produces this.

    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let time = 100.0;

    let mut config = ConnectionConfig::new();
    config.numChannels = 1;
    config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1100;      // deliberately not a multiple of blockFragmentSize
    config.channel[0].blockFragmentSize = 500;  // => GetMaxFragmentsPerBlock() == ceil(1100/500) == 3

    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &config, time );

    let maxFragmentsPerBlock = config.channel[0].GetMaxFragmentsPerBlock();
    let blockFragmentSize = config.channel[0].blockFragmentSize;

    // messageId=0 (== expected receive sequence), final fragment, full blockFragmentSize payload.
    let numFragments = maxFragmentsPerBlock;   // 3
    let fragmentId = numFragments - 1;         // 2 (final fragment)
    let fragmentSize = blockFragmentSize;      // 500 -> write [1000,1500) into a 1100-byte buffer

    let mut buffer = [0u8; 4096];
    let packetBytes: i32;
    {
        let bufferBytes = buffer.len() as i64;
        let mut stream = WriteStream::new( &mut buffer, bufferBytes );
        check!( SerializeRawBlockFragmentPacket( &mut stream, maxFragmentsPerBlock, blockFragmentSize, numFragments, fragmentId, fragmentSize ) );
        stream.Flush();
        packetBytes = stream.GetBytesProcessed() as i32;
    }
    check!( packetBytes > 0 );

    // Before the fix this overflowed the receive buffer inside ProcessPacketFragment. After the
    // fix the fragment is rejected: the read fails and the channel drops into an error state.
    let processed = receiver.ProcessPacket( std::ptr::null_mut(), 0, &buffer, packetBytes );
    check!( !processed );

    receiver.AdvanceTime( time );
    check!( receiver.GetErrorLevel() == CONNECTION_ERROR_CHANNEL );
}

fn test_connection_reliable_over_budget_packet()
{
    // A peer sends more channel data than the receiver's configured packetBudget. On read this
    // used to trip the YOJIMBO_DEBUG_MESSAGE_BUDGET assert — a remote crash in debug builds
    // reachable from a decrypted-but-attacker-controlled packet. The message count and sizes
    // are already bounded by the serialize_* range checks, so an over-budget read must simply
    // be accepted, not asserted on.

    let mut messageFactory = TestMessageFactory::new( GetDefaultAllocator() );

    let mut time = 100.0;

    // Sender: default (unlimited) packet budget, so it packs messages freely.
    let mut senderConfig = ConnectionConfig::new();
    senderConfig.numChannels = 1;
    senderConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;

    // Receiver: a small per-channel packet budget.
    let mut receiverConfig = ConnectionConfig::new();
    receiverConfig.numChannels = 1;
    receiverConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    receiverConfig.channel[0].packetBudget = 32;

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &senderConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &receiverConfig, time );

    const NumMessages: i32 = 64;
    for i in 0..NumMessages
    {
        let message = messageFactory.CreateMessage( TEST_MESSAGE );
        check!( !message.is_null() );
        unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
        sender.SendMessage( 0, message, std::ptr::null_mut() );
    }

    // The first generated packet carries far more than 32 bytes of channel data. Before the
    // fix, processing it aborted the receiver in the budget assert; after, it reads cleanly.
    // port: alloca is a Vec
    let mut packetData = vec![ 0u8; senderConfig.maxPacketSize as usize ];
    let mut sequence: u16 = 0;
    let mut processed = false;

    let mut i = 0;
    while i < 8 && !processed
    {
        let mut packetBytes: i32 = 0;
        if sender.GeneratePacket( std::ptr::null_mut(), sequence, &mut packetData, senderConfig.maxPacketSize, &mut packetBytes ) && packetBytes > 0
        {
            check!( receiver.ProcessPacket( std::ptr::null_mut(), sequence, &packetData, packetBytes ) );
            processed = true;
        }

        sender.AdvanceTime( time );
        receiver.AdvanceTime( time );
        time += 0.1;
        sequence = sequence.wrapping_add( 1 );

        i += 1;
    }

    check!( processed );
    check!( receiver.GetErrorLevel() == CONNECTION_ERROR_NONE );
}

// port: the C++ arrays of Client * / Server * are slices of `&mut Client` / `&mut Server`, and the deltaTime default
// argument is passed explicitly (0.1) at each call site
fn PumpClientServerUpdate( time: &mut f64, client: &mut [&mut Client], numClients: i32, server: &mut [&mut Server], numServers: i32, deltaTime: f32 )
{
    for i in 0..numClients as usize
    {
        client[i].SendPackets();
    }

    for i in 0..numServers as usize
    {
        server[i].SendPackets();
    }

    for i in 0..numClients as usize
    {
        client[i].ReceivePackets();
    }

    for i in 0..numServers as usize
    {
        server[i].ReceivePackets();
    }

    *time += deltaTime as f64;

    for i in 0..numClients as usize
    {
        client[i].AdvanceTime( *time );
    }

    for i in 0..numServers as usize
    {
        server[i].AdvanceTime( *time );
    }

    yojimbo_sleep( 0.0 );
}

// port: the channelIndex default argument (ReliableChannel) is passed explicitly at each call site
fn SendClientToServerMessages( client: &mut Client, numMessagesToSend: i32, channelIndex: i32 )
{
    for i in 0..numMessagesToSend
    {
        if !client.CanSendMessage( channelIndex )
        {
            break;
        }

        if rand() % 10 != 0
        {
            let message = client.CreateMessage( TEST_MESSAGE );
            check!( !message.is_null() );
            unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
            client.SendMessage( channelIndex, message );
        }
        else
        {
            let message = client.CreateMessage( TEST_BLOCK_MESSAGE );
            check!( !message.is_null() );
            unsafe { message_cast::<TestBlockMessage>( message ) }.sequence = i as u16;
            let blockSize = 1 + ( ( i * 901 ) % 1001 );
            let blockData = client.AllocateBlock( blockSize );
            check!( !blockData.is_null() );
            for j in 0..blockSize
            {
                unsafe { *blockData.add( j as usize ) = ( i + j ) as u8; }
            }
            client.AttachBlockToMessage( message, blockData, blockSize );
            client.SendMessage( channelIndex, message );
        }
    }
}

// port: the channelIndex default argument (ReliableChannel) is passed explicitly at each call site
fn SendServerToClientMessages( server: &mut Server, clientIndex: i32, numMessagesToSend: i32, channelIndex: i32 )
{
    for i in 0..numMessagesToSend
    {
        if !server.CanSendMessage( clientIndex, channelIndex )
        {
            break;
        }

        if rand() % 10 != 0
        {
            let message = server.CreateMessage( clientIndex, TEST_MESSAGE );
            check!( !message.is_null() );
            unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
            server.SendMessage( clientIndex, channelIndex, message );
        }
        else
        {
            let message = server.CreateMessage( clientIndex, TEST_BLOCK_MESSAGE );
            check!( !message.is_null() );
            unsafe { message_cast::<TestBlockMessage>( message ) }.sequence = i as u16;
            let blockSize = 1 + ( ( i * 901 ) % 1001 );
            let blockData = server.AllocateBlock( clientIndex, blockSize );
            check!( !blockData.is_null() );
            for j in 0..blockSize
            {
                unsafe { *blockData.add( j as usize ) = ( i + j ) as u8; }
            }
            server.AttachBlockToMessage( clientIndex, message, blockData, blockSize );
            server.SendMessage( clientIndex, channelIndex, message );
        }
    }
}

// port: the channelIndex default argument (ReliableChannel) is passed explicitly at each call site
fn ProcessServerToClientMessages( client: &mut Client, numMessagesReceivedFromServer: &mut i32, channelIndex: i32 )
{
    loop
    {
        let message = client.ReceiveMessage( channelIndex );

        if message.is_null()
        {
            break;
        }

        check!( unsafe { ( *message ).GetId() } == *numMessagesReceivedFromServer );

        match unsafe { ( *message ).GetType() }
        {
            TEST_MESSAGE =>
            {
                check!( !unsafe { ( *message ).IsBlockMessage() } );
                let testMessage = unsafe { message_cast::<TestMessage>( message ) };
                check!( testMessage.sequence == *numMessagesReceivedFromServer as u16 );
                *numMessagesReceivedFromServer += 1;
            }

            TEST_BLOCK_MESSAGE =>
            {
                check!( unsafe { ( *message ).IsBlockMessage() } );
                let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
                check!( blockMessage.sequence == *numMessagesReceivedFromServer as u16 );
                let blockSize = blockMessage.base.GetBlockSize();
                check!( blockSize == 1 + ( ( *numMessagesReceivedFromServer * 901 ) % 1001 ) );
                let blockData = blockMessage.base.GetBlockData();
                check!( !blockData.is_null() );
                for j in 0..blockSize
                {
                    check!( unsafe { *blockData.add( j as usize ) } == ( *numMessagesReceivedFromServer + j ) as u8 );
                }
                *numMessagesReceivedFromServer += 1;
            }

            _ => {}
        }

        client.ReleaseMessage( message );
    }
}

// port: the channelIndex default argument (ReliableChannel) is passed explicitly at each call site
fn ProcessClientToServerMessages( server: &mut Server, clientIndex: i32, numMessagesReceivedFromClient: &mut i32, channelIndex: i32 )
{
    loop
    {
        let message = server.ReceiveMessage( clientIndex, channelIndex );

        if message.is_null()
        {
            break;
        }

        check!( unsafe { ( *message ).GetId() } == *numMessagesReceivedFromClient );

        match unsafe { ( *message ).GetType() }
        {
            TEST_MESSAGE =>
            {
                check!( !unsafe { ( *message ).IsBlockMessage() } );
                let testMessage = unsafe { message_cast::<TestMessage>( message ) };
                check!( testMessage.sequence == *numMessagesReceivedFromClient as u16 );
                *numMessagesReceivedFromClient += 1;
            }

            TEST_BLOCK_MESSAGE =>
            {
                check!( unsafe { ( *message ).IsBlockMessage() } );
                let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
                check!( blockMessage.sequence == *numMessagesReceivedFromClient as u16 );
                let blockSize = blockMessage.base.GetBlockSize();
                check!( blockSize == 1 + ( ( *numMessagesReceivedFromClient * 901 ) % 1001 ) );
                let blockData = blockMessage.base.GetBlockData();
                check!( !blockData.is_null() );
                for j in 0..blockSize
                {
                    check!( unsafe { *blockData.add( j as usize ) } == ( *numMessagesReceivedFromClient + j ) as u8 );
                }
                *numMessagesReceivedFromClient += 1;
            }

            _ => {}
        }

        server.ReleaseMessage( clientIndex, message );
    }
}

fn test_connection_reliable_message_alloc_failure()
{
    // Regression: on the send path, GetMessagePacketData allocated the message-pointer array
    // without checking for NULL and then wrote through it - a crash on allocator exhaustion.
    // Arm the allocator to fail that first allocation inside GeneratePacket and verify we neither
    // crash nor leak (the queued reliable message is retained and freed at teardown).
    let mut allocator = ArmableAllocator::new();
    {
        let mut messageFactory = TestMessageFactory::new( &mut allocator );

        let mut config = ConnectionConfig::new();
        config.numChannels = 1;
        config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;

        {
            let mut connection = Connection::new( &mut allocator, &mut messageFactory, &config, 100.0 );

            let message = messageFactory.CreateMessage( TEST_MESSAGE );
            check!( !message.is_null() );
            connection.SendMessage( 0, message, std::ptr::null_mut() );

            let mut packetData = [0u8; 4096];
            let mut packetBytes: i32 = 0;

            allocator.Arm( 0 );     // fail the first allocation inside GeneratePacket (message array)
            connection.GeneratePacket( std::ptr::null_mut(), 0, &mut packetData, std::mem::size_of::<[u8; 4096]>() as i32, &mut packetBytes );
            allocator.Disarm();
        }
    }
    check!( allocator.GetOutstanding() == 0 );   // no leak across teardown
}

fn test_connection_unreliable_message_alloc_failure()
{
    // Regression: the unreliable channel's GetPacketData allocated the message-pointer array
    // without a NULL check and then wrote through it. The messages had already been popped off
    // the send queue, so a failure crashed (NULL deref) and would have leaked the popped
    // messages. Arm the allocator to fail that allocation and verify no crash and no leak.
    let mut allocator = ArmableAllocator::new();
    {
        let mut messageFactory = TestMessageFactory::new( &mut allocator );

        let mut config = ConnectionConfig::new();
        config.numChannels = 1;
        config.channel[0].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

        {
            let mut connection = Connection::new( &mut allocator, &mut messageFactory, &config, 100.0 );

            for _i in 0..4
            {
                let message = messageFactory.CreateMessage( TEST_MESSAGE );
                check!( !message.is_null() );
                connection.SendMessage( 0, message, std::ptr::null_mut() );
            }

            let mut packetData = [0u8; 4096];
            let mut packetBytes: i32 = 0;

            allocator.Arm( 0 );     // fail the message-pointer array allocation in GetPacketData
            connection.GeneratePacket( std::ptr::null_mut(), 0, &mut packetData, std::mem::size_of::<[u8; 4096]>() as i32, &mut packetBytes );
            allocator.Disarm();
        }
    }
    check!( allocator.GetOutstanding() == 0 );   // popped messages released, nothing leaked
}

fn test_connection_generate_packet_channel_data_alloc_failure()
{
    // Regression: when AllocateChannelData failed, GeneratePacket returned without freeing the
    // per-channel packet data GetPacketData had already populated (acquired message references
    // and the allocated message-pointer array), leaking them. Arm the allocator so the message
    // array allocation succeeds but the subsequent channel-data allocation fails, and verify
    // nothing leaks.
    let mut allocator = ArmableAllocator::new();
    {
        let mut messageFactory = TestMessageFactory::new( &mut allocator );

        let mut config = ConnectionConfig::new();
        config.numChannels = 1;
        config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;

        {
            let mut connection = Connection::new( &mut allocator, &mut messageFactory, &config, 100.0 );

            let message = messageFactory.CreateMessage( TEST_MESSAGE );
            check!( !message.is_null() );
            connection.SendMessage( 0, message, std::ptr::null_mut() );

            let mut packetData = [0u8; 4096];
            let mut packetBytes: i32 = 0;

            allocator.Arm( 1 );     // 1st alloc (message array) succeeds, 2nd (channel data) fails
            let result = connection.GeneratePacket( std::ptr::null_mut(), 0, &mut packetData, std::mem::size_of::<[u8; 4096]>() as i32, &mut packetBytes );
            allocator.Disarm();
            check!( !result );       // the channel-data allocation failure fails the generate
        }
    }
    check!( allocator.GetOutstanding() == 0 );   // no leak across teardown
}

fn test_message_factory_create_message_alloc_failure()
{
    // Regression: YOJIMBO_NEW used to run the constructor on a NULL pointer when the allocation
    // failed (undefined behavior / crash) before CreateMessage's NULL check. CreateMessage must
    // return NULL cleanly on allocator exhaustion and flag the factory.
    let mut allocator = ArmableAllocator::new();
    {
        let mut factory = TestMessageFactory::new( &mut allocator );
        allocator.Arm( 0 );     // fail the next allocation (the message object)
        let message = factory.CreateMessage( TEST_MESSAGE );
        allocator.Disarm();
        check!( message.is_null() );
        check!( factory.GetErrorLevel() == MESSAGE_FACTORY_ERROR_FAILED_TO_ALLOCATE_MESSAGE );
    }
    check!( allocator.GetOutstanding() == 0 );
}

fn test_connection_process_packet_channel_data_alloc_failure()
{
    // Regression: on the read path, if AllocateChannelData failed, numChannelEntries had already
    // been read from the wire, so the ConnectionPacket destructor iterated a NULL channelEntry
    // array (crash). Feed a valid packet to a receiver whose allocator fails the channel-data
    // allocation, and verify the read fails cleanly without crashing or leaking.
    let mut senderAlloc = ArmableAllocator::new();
    let mut receiverAlloc = ArmableAllocator::new();
    {
        let mut senderFactory = TestMessageFactory::new( &mut senderAlloc );
        let mut receiverFactory = TestMessageFactory::new( &mut receiverAlloc );

        let mut config = ConnectionConfig::new();
        config.numChannels = 1;
        config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;

        {
            let mut sender = Connection::new( &mut senderAlloc, &mut senderFactory, &config, 100.0 );
            let mut receiver = Connection::new( &mut receiverAlloc, &mut receiverFactory, &config, 100.0 );

            let message = senderFactory.CreateMessage( TEST_MESSAGE );
            check!( !message.is_null() );
            sender.SendMessage( 0, message, std::ptr::null_mut() );

            let mut packetData = [0u8; 4096];
            let mut packetBytes: i32 = 0;
            check!( sender.GeneratePacket( std::ptr::null_mut(), 0, &mut packetData, std::mem::size_of::<[u8; 4096]>() as i32, &mut packetBytes ) );
            check!( packetBytes > 0 );

            receiverAlloc.Arm( 0 );     // fail the channel-data allocation in the connection-packet read
            let ok = receiver.ProcessPacket( std::ptr::null_mut(), 0, &packetData, packetBytes );
            receiverAlloc.Disarm();
            check!( !ok );               // read fails cleanly rather than crashing in the destructor
        }
    }
    check!( senderAlloc.GetOutstanding() == 0 );
    check!( receiverAlloc.GetOutstanding() == 0 );
}

// YJ-05: the build added -fno-rtti to every C++ target, so libyojimbo emitted "vtable for
// yojimbo::Allocator" with no matching typeinfo. Allocator, MessageFactory, Adapter and the two
// interfaces are all public polymorphic classes consumers derive from, and consumers build with
// the compiler default, which is RTTI on. Any dynamic_cast or typeid on one of them failed to
// link on the missing typeinfo. RTTI is now on in yojimbo's own build too.
//
// This is a link test as much as a behaviour test: the typeinfo for Allocator and
// DefaultAllocator comes out of libyojimbo, where their key functions live.
//
// port: Rust has no RTTI switch and no typeinfo to fail to link. The traits are not `Any`, so dynamic_cast/typeid
// become std::any::Any on the concrete objects, and the check on the library's default allocator is the size of the
// value behind the trait object (the guard message_cast uses for the C++ downcast).
fn test_rtti_across_the_abi_boundary()
{
    let mut allocator = ArmableAllocator::new();

    let base: *mut dyn Allocator = &mut allocator;
    check!( base as *mut u8 == &mut allocator as *mut ArmableAllocator as *mut u8 );
    let baseAny: &dyn std::any::Any = &allocator;
    check!( baseAny.downcast_ref::<ArmableAllocator>().is_some() );
    check!( baseAny.downcast_ref::<DefaultAllocator>().is_none() );
    check!( baseAny.type_id() == std::any::TypeId::of::<ArmableAllocator>() );

    // DefaultAllocator's key function is in yojimbo_allocator.cpp, so this resolves the library's
    // own typeinfo rather than one the test binary could have emitted for itself.
    let defaultAllocator: *mut dyn Allocator = GetDefaultAllocator();
    check!( !defaultAllocator.is_null() );
    check!( std::mem::size_of_val( unsafe { &*defaultAllocator } ) == std::mem::size_of::<DefaultAllocator>() );

    // ...and the same across the message factory hierarchy.
    let mut factory = TestMessageFactory::new( &mut allocator );
    let factoryBase: *mut dyn MessageFactory = &mut factory;
    check!( factoryBase as *mut u8 == &mut factory as *mut TestMessageFactory as *mut u8 );
    let factoryAny: &dyn std::any::Any = &factory;
    check!( factoryAny.downcast_ref::<TestMessageFactory>().is_some() );
}

// YJ-04: Allocator held a std::map and MessageFactory held another, both compiled in only when
// YOJIMBO_DEBUG_MEMORY_LEAKS / YOJIMBO_DEBUG_MESSAGE_LEAKS were on -- which both derive from the
// consumer's NDEBUG. A release consumer deriving from either class saw a different layout than
// the debug library it linked against (Allocator 16 vs 40 bytes, MessageFactory 24 vs 48 on
// arm64), which is silent memory corruption. Both trackers now live behind one always-present
// pointer to state defined inside the library.
//
// test_layout_debug.cpp and test_layout_release.cpp compile the same public headers with
// YOJIMBO_DEBUG and YOJIMBO_RELEASE forced on, so one binary carries both configurations' idea of
// the layout.
//
// port: test_public_layout_is_configuration_independent (and yojimbo_test_layout_debug / yojimbo_test_layout_release)
// is not ported. A Rust crate is compiled once per profile with one cfg, so one binary cannot carry a debug and a
// release view of the same struct, and the debug trackers are always-present fields (AllocatorBase::m_debug,
// MessageFactoryBase's debug pointer) whose layout does not depend on the profile. Like the TypeScript port, it is
// not run.

// YJ-02: ServerInterface::GetClientUserData was declared non-virtual with no definition
// anywhere in the tree, so any call through a ServerInterface reference failed to link. Nothing
// exercised the interfaces through a base reference, so it went unnoticed.
//
// This is a LINK test. A call to a non-virtual interface method needs a definition of that exact
// symbol; a call to a virtual one goes through the vtable and needs none. Calling every declared
// method of both interfaces through a base reference therefore fails to link the test binary if
// any of them ever loses its "virtual" again.
//
// The calls are guarded by a volatile that is always false: the compiler cannot fold the branch
// away, so it emits every call, and nothing here actually runs against a stopped server.
// port: in Rust every trait method called through `&mut dyn Trait` must exist, so this is a compile test; the volatile
// is an AtomicBool read through std::hint::black_box
static g_callInterfaceMethods: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new( false );

fn CallEveryServerInterfaceMethod( server: &mut dyn ServerInterface )
{
    let mut info = NetworkInfo::default();
    let mut userData = [0u8; 256];
    userData.fill( 0 );
    let mut packet = [0u8; 16];
    packet.fill( 0 );

    server.SetContext( std::ptr::null_mut() );
    server.Start( 1 );
    server.Stop();
    server.DisconnectClient( 0 );
    server.DisconnectAllClients();
    server.SendPackets();
    server.ReceivePackets();
    server.AdvanceTime( 0.0 );
    let _ = server.IsRunning();
    let _ = server.GetMaxClients();
    let _ = server.IsClientConnected( 0 );
    let _ = server.GetClientId( 0 );
    let _ = server.GetClientUserData( 0 );
    let _ = server.GetClientAddress( 0 );
    let _ = server.GetNumConnectedClients();
    let _ = server.GetTime();
    let message = server.CreateMessage( 0, TEST_MESSAGE );
    let block = server.AllocateBlock( 0, 16 );
    server.AttachBlockToMessage( 0, message, block, 16 );
    server.FreeBlock( 0, block );
    let _ = server.CanSendMessage( 0, 0 );
    server.SendMessage( 0, 0, message );
    let _ = server.ReceiveMessage( 0, 0 );
    server.ReleaseMessage( 0, message );
    server.GetNetworkInfo( 0, &mut info );
    server.ConnectLoopbackClient( 0, 1, Some( &userData[..] ) );
    server.DisconnectLoopbackClient( 0 );
    let _ = server.IsLoopbackClient( 0 );
    server.ProcessLoopbackPacket( 0, &packet, packet.len() as i32, 0 );
}

fn CallEveryClientInterfaceMethod( client: &mut dyn ClientInterface )
{
    let mut info = NetworkInfo::default();
    let mut packet = [0u8; 16];
    packet.fill( 0 );

    client.SetContext( std::ptr::null_mut() );
    client.Disconnect();
    client.SendPackets();
    client.ReceivePackets();
    client.AdvanceTime( 0.0 );
    let _ = client.IsConnecting();
    let _ = client.IsConnected();
    let _ = client.IsDisconnected();
    let _ = client.ConnectionFailed();
    let _ = client.GetClientState();
    let _ = client.GetClientIndex();
    let _ = client.GetClientId();
    let _ = client.GetTime();
    let message = client.CreateMessage( TEST_MESSAGE );
    let block = client.AllocateBlock( 16 );
    client.AttachBlockToMessage( message, block, 16 );
    client.FreeBlock( block );
    let _ = client.CanSendMessage( 0 );
    client.SendMessage( 0, message );
    let _ = client.ReceiveMessage( 0 );
    client.ReleaseMessage( message );
    client.GetNetworkInfo( &mut info );
    let _ = client.ConnectLoopback( 0, 1, 1 );
    client.DisconnectLoopback();
    let _ = client.IsLoopback();
    client.ProcessLoopbackPacket( &packet, packet.len() as i32, 0 );
}

fn test_interface_methods_link()
{
    let config = ClientServerConfig::new();

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &Address::from_string_port( "127.0.0.1", ServerPort as u16 ), &config, GetTestAdapter(), 100.0 );
    let mut client = Client::new( GetDefaultAllocator(), &Address::from_string_port( "0.0.0.0", 0 ), &config, GetTestAdapter(), 100.0 );

    if std::hint::black_box( g_callInterfaceMethods.load( std::sync::atomic::Ordering::Relaxed ) )
    {
        CallEveryServerInterfaceMethod( &mut *server );
        CallEveryClientInterfaceMethod( &mut *client );
    }

    // The binary linked, which is the whole point. Prove the base reference really does reach
    // the derived implementation for the method that had no definition at all. That method needs
    // a running server, so start one for the comparison.
    check!( server.Start( 1 ) );
    {
        // port: upstream compares the two `const uint8_t *`; the Option<&[u8]> results are compared by address
        let serverUserData = server.GetClientUserData( 0 ).map( |userData| userData.as_ptr() );
        let serverInterface: &mut dyn ServerInterface = &mut *server;
        check!( serverInterface.GetClientUserData( 0 ).map( |userData| userData.as_ptr() ) == serverUserData );
        check!( serverInterface.GetMaxClients() == 1 );
    }
    server.Stop();

    let clientState = client.GetClientState();
    let clientInterface: &mut dyn ClientInterface = &mut *client;
    check!( clientInterface.GetClientState() == clientState );
}

// Adapter whose factory methods can be made to fail, so the startup paths are exercised at the
// two points an ArmableAllocator cannot reach: a user allocator class that fails to construct,
// and a message factory that fails to construct. Both return NULL from the adapter, which the
// library must treat exactly like an allocation failure.
// port: `class FailingFactoryAdapter : public TestAdapter` embeds the TestAdapter as `base` and calls through it for
// TestAdapter::CreateAllocator / TestAdapter::CreateMessageFactory
struct FailingFactoryAdapter
{
    base: TestAdapter,
    m_allocatorsUntilFail: i32,
    m_factoriesUntilFail: i32,
}

impl FailingFactoryAdapter
{
    fn new() -> FailingFactoryAdapter
    {
        FailingFactoryAdapter { base: TestAdapter, m_allocatorsUntilFail: -1, m_factoriesUntilFail: -1 }
    }

    fn FailAllocatorAfter( &mut self, n: i32 ) { self.m_allocatorsUntilFail = n; }
    fn FailMessageFactoryAfter( &mut self, n: i32 ) { self.m_factoriesUntilFail = n; }
}

impl Adapter for FailingFactoryAdapter
{
    fn CreateAllocator( &mut self, allocator: *mut dyn Allocator, memory: *mut u8, bytes: usize ) -> *mut dyn Allocator
    {
        if self.m_allocatorsUntilFail == 0
        {
            return null_allocator();
        }
        if self.m_allocatorsUntilFail > 0
        {
            self.m_allocatorsUntilFail -= 1;
        }
        self.base.CreateAllocator( allocator, memory, bytes )
    }

    fn CreateMessageFactory( &mut self, allocator: *mut dyn Allocator ) -> *mut dyn MessageFactory
    {
        if self.m_factoriesUntilFail == 0
        {
            return null_message_factory();
        }
        if self.m_factoriesUntilFail > 0
        {
            self.m_factoriesUntilFail -= 1;
        }
        self.base.CreateMessageFactory( allocator )
    }
}

// The number of startup allocations a sweep is allowed to walk before we call it a runaway. Well
// above the real counts (6 for a two-client server, 3 for a client) so the sweep terminates on a
// bug instead of looping forever.
const MaxStartupAllocations: i32 = 64;

fn test_server_start_alloc_failure()
{
    // YJ-01: BaseServer::Start guarded its allocations with yojimbo_assert, which compiles out
    // under NDEBUG, so a release build bound references to failed allocations and ran on with a
    // half-built server. Fail at allocation N for every N up to the first N that succeeds: each
    // failure must return false, leave the server stopped, and free everything already taken.
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let config = ClientServerConfig::new();

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut n = 0;
    while n < MaxStartupAllocations
    {
        let mut allocator = ArmableAllocator::new();
        // port: the C++ `break` inside the scope runs the Server destructor and skips the outstanding check; the
        // block yields whether it broke
        let started =
        {
            let mut server = Server::new( &mut allocator, &privateKey, &serverAddress, &config, GetTestAdapter(), 100.0 );
            allocator.Arm( n );
            let started = server.Start( 2 );
            allocator.Disarm();
            if started
            {
                check!( server.IsRunning() );
                server.Stop();
                check!( !server.IsRunning() );
            }
            else
            {
                check!( !server.IsRunning() );           // no half-built server left behind
                check!( server.GetMaxClients() == 0 );
            }
            started
        };
        if started
        {
            break;
        }
        check!( allocator.GetOutstanding() == 0 );   // everything already allocated was unwound
        n += 1;
    }
    check!( n > 0 );                                 // the sweep really did force failures
    check!( n < MaxStartupAllocations );             // ...and a fully armed start eventually succeeds
}

fn test_server_start_factory_failure()
{
    // Same contract for the adapter factory results, which no allocator arming can reach: a user
    // allocator or message factory that fails to construct returns NULL and must be handled like
    // an allocation failure rather than dereferenced.
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let config = ClientServerConfig::new();

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    // allocator index 0 is the global allocator, 1 and 2 are the two per-client allocators
    for n in 0..3
    {
        let mut allocator = ArmableAllocator::new();
        {
            let mut failingAdapter = FailingFactoryAdapter::new();
            failingAdapter.FailAllocatorAfter( n );
            let mut server = Server::new( &mut allocator, &privateKey, &serverAddress, &config, &mut failingAdapter, 100.0 );
            check!( !server.Start( 2 ) );
            check!( !server.IsRunning() );
        }
        check!( allocator.GetOutstanding() == 0 );
    }

    for n in 0..2
    {
        let mut allocator = ArmableAllocator::new();
        {
            let mut failingAdapter = FailingFactoryAdapter::new();
            failingAdapter.FailMessageFactoryAfter( n );
            let mut server = Server::new( &mut allocator, &privateKey, &serverAddress, &config, &mut failingAdapter, 100.0 );
            check!( !server.Start( 2 ) );
            check!( !server.IsRunning() );
        }
        check!( allocator.GetOutstanding() == 0 );
    }
}

fn test_client_connect_alloc_failure()
{
    // YJ-01 on the client side: BaseClient::CreateInternal bound a reference to *m_clientAllocator
    // one line after allocating it, with no check in any build. Same sweep: every failure point
    // returns false, leaves the client disconnected with an out-of-memory reason, and leaks
    // nothing.
    let clientAddress = Address::from_string_port( "0.0.0.0", 0 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let config = ClientServerConfig::new();

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut n = 0;
    while n < MaxStartupAllocations
    {
        let mut allocator = ArmableAllocator::new();
        {
            let mut client = Client::new( &mut allocator, &clientAddress, &config, GetTestAdapter(), 100.0 );
            allocator.Arm( n );
            let connecting = client.InsecureConnect( &privateKey, 1, &serverAddress );
            allocator.Disarm();
            if connecting
            {
                check!( client.IsConnecting() );
                client.Disconnect();
                break;
            }
            check!( !client.IsConnecting() );
            check!( !client.IsConnected() );
            check!( client.ConnectionFailed() );
            check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY );
        }
        check!( allocator.GetOutstanding() == 0 );
        n += 1;
    }
    check!( n > 0 );
    check!( n < MaxStartupAllocations );
}

fn test_client_connect_factory_failure()
{
    let clientAddress = Address::from_string_port( "0.0.0.0", 0 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let config = ClientServerConfig::new();

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    {
        let mut allocator = ArmableAllocator::new();
        {
            let mut failingAdapter = FailingFactoryAdapter::new();
            failingAdapter.FailAllocatorAfter( 0 );
            let mut client = Client::new( &mut allocator, &clientAddress, &config, &mut failingAdapter, 100.0 );
            check!( !client.InsecureConnect( &privateKey, 1, &serverAddress ) );
            check!( client.ConnectionFailed() );
        }
        check!( allocator.GetOutstanding() == 0 );
    }

    {
        let mut allocator = ArmableAllocator::new();
        {
            let mut failingAdapter = FailingFactoryAdapter::new();
            failingAdapter.FailMessageFactoryAfter( 0 );
            let mut client = Client::new( &mut allocator, &clientAddress, &config, &mut failingAdapter, 100.0 );
            check!( !client.InsecureConnect( &privateKey, 1, &serverAddress ) );
            check!( client.ConnectionFailed() );
        }
        check!( allocator.GetOutstanding() == 0 );
    }
}

fn test_client_connect_socket_failure_no_crash()
{
    // Regression: Connect() and ConnectLoopback() called into netcode_client_connect() without
    // checking that CreateClient() succeeded. When the socket can't be created - forced here with
    // an unparseable bind address - m_client is NULL and netcode dereferences it (crash in
    // release; assert trap in debug). Both must bail like InsecureConnect() already does.
    let config = ClientServerConfig::new();

    let invalidAddress = Address::new();        // ADDRESS_NONE -> "NONE" -> netcode_client_create fails
    check!( !invalidAddress.IsValid() );

    let mut client = Client::new( GetDefaultAllocator(), &invalidAddress, &config, GetTestAdapter(), 100.0 );

    let mut connectToken = [0u8; ConnectTokenBytes as usize];
    connectToken.fill( 0 );

    client.Connect( 1, &connectToken );         // must not crash - CreateClient failed
    check!( !client.IsConnected() );

    client.ConnectLoopback( 0, 1, 1 );          // must not crash either
    check!( !client.IsConnected() );

    client.Disconnect();
}

fn test_client_is_loopback_when_disconnected()
{
    // Regression: IsLoopback() called netcode_client_loopback(m_client) with no NULL guard, so a
    // never-connected client (m_client == NULL) crashed. Like GetClientIndex(), it must be safe
    // to query in any state and simply report false.
    let config = ClientServerConfig::new();
    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), 100.0 );

    check!( !client.IsLoopback() );             // must not crash; not connected -> not a loopback client
    check!( client.GetClientIndex() == -1 );
    check!( !client.IsConnected() );
}

fn test_client_connect_twice_with_one_connect_token()
{
    // Mirrors netcode's test_client_reconnect_with_used_connect_token through yojimbo's API.
    // A connect token is spent by the connection it admits: once the server has accepted a
    // client holding it, presenting the same token again connects nothing, from the same
    // address, after the client's slot is free again.
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();

    // The second connect attempt has to run all the way out to a connection request timeout,
    // and the connect token's expiry has to stay above that so the failure is the timeout and
    // not an expired token. A short timeout keeps both waits short.
    config.timeout = 2;

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    check!( server.Start( MaxClients ) );

    // One connect token, minted once and held, the way a matchmaker hands one to a client.

    // port: Address::ToString returns a String (no char buffer of MaxAddressLength)
    let serverAddressString = serverAddress.ToString();
    let serverAddressStrings: [&str; 1] = [ serverAddressString.as_str() ];

    let mut userData = [0u8; 256];
    userData.fill( 0 );

    let mut connectToken = [0u8; ConnectTokenBytes as usize];
    check!( netcode_generate_connect_token( 1,
                                            &serverAddressStrings,
                                            &serverAddressStrings,
                                            InsecureConnectTokenExpirySeconds,
                                            config.timeout,
                                            clientId,
                                            config.protocolId,
                                            &privateKey,
                                            &userData,
                                            &mut connectToken ) == NETCODE_OK );

    const NumIterations: i32 = 1000;

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    // First use of the token connects.

    check!( client.Connect( clientId, &connectToken ) );

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( client.IsConnected() );
    check!( server.GetNumConnectedClients() == 1 );
    check!( client.GetClientIndex() == 0 );

    // Free the slot server side and let the client see it, so the second attempt runs against
    // a server with room for it and nothing left over from the first connection.

    server.DisconnectClient( 0 );

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if !client.IsConnected() && server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( !client.IsConnected() );
    check!( server.GetNumConnectedClients() == 0 );

    // Second use of the same token connects nothing. The server ignores the connection
    // requests, so the client runs out of retries and reports a connection request timeout.

    check!( client.Connect( clientId, &connectToken ) );

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        check!( !client.IsConnected() );
        check!( server.GetNumConnectedClients() == 0 );
    }

    check!( client.ConnectionFailed() );
    check!( !client.IsConnected() );
    check!( server.GetNumConnectedClients() == 0 );
    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT );

    client.Disconnect();
    server.Stop();
}

fn test_client_server_messages()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.channel[0].messageSendQueueSize = 32;
    config.channel[0].maxMessagesPerPacket = 8;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    server.SetLatency( 250.0 );
    server.SetJitter( 100.0 );
    server.SetPacketLoss( 25.0 );
    server.SetDuplicates( 25.0 );

    for _iteration in 0..2
    {
        // connect and wait until connection completes

        client.InsecureConnect( &privateKey, clientId, &serverAddress );

        client.SetLatency( 250.0 );
        client.SetJitter( 100.0 );
        client.SetPacketLoss( 25.0 );
        client.SetDuplicates( 25.0 );

        const NumIterations: i32 = 10000;

        for _i in 0..NumIterations
        {
            PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

            if client.ConnectionFailed()
            {
                break;
            }

            if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
            {
                break;
            }
        }

        // verify connection has completed successfully

        check!( !client.IsConnecting() );
        check!( client.IsConnected() );
        check!( server.GetNumConnectedClients() == 1 );
        check!( client.GetClientIndex() == 0 );
        check!( server.IsClientConnected(0) );

        // send a bunch of messages and pump until they are received

        let NumMessagesSent = config.channel[0].messageSendQueueSize;

        SendClientToServerMessages( &mut client, NumMessagesSent, ReliableChannel );

        SendServerToClientMessages( &mut server, client.GetClientIndex(), NumMessagesSent, ReliableChannel );

        let mut numMessagesReceivedFromClient: i32 = 0;
        let mut numMessagesReceivedFromServer: i32 = 0;

        for _i in 0..NumIterations
        {
            PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

            if !client.IsConnected()
            {
                break;
            }

            ProcessServerToClientMessages( &mut client, &mut numMessagesReceivedFromServer, ReliableChannel );

            ProcessClientToServerMessages( &mut server, client.GetClientIndex(), &mut numMessagesReceivedFromClient, ReliableChannel );

            if numMessagesReceivedFromClient == NumMessagesSent && numMessagesReceivedFromServer == NumMessagesSent
            {
                break;
            }
        }

        check!( client.IsConnected() );
        check!( server.IsClientConnected( client.GetClientIndex() ) );
        check!( numMessagesReceivedFromClient == NumMessagesSent );
        check!( numMessagesReceivedFromServer == NumMessagesSent );

        // disconnect and pump until client disconnects

        client.Disconnect();

        for _i in 0..NumIterations
        {
            PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

            if !client.IsConnected() && server.GetNumConnectedClients() == 0
            {
                break;
            }
        }

        check!( !client.IsConnected() && server.GetNumConnectedClients() == 0 );
    }

    server.Stop();
}

// port: `Client ** clients` is a Vec<Box<Client>>. Client::new returns the client boxed (netcode keeps pointers to it
// while it is connected, so it must not move), so CreateClients pushes the boxes instead of YOJIMBO_NEW-ing each
// client from the default allocator, and DestroyClients drains them instead of YOJIMBO_DELETE.
fn CreateClients( numClients: i32, clients: &mut Vec<Box<Client>>, address: &Address, config: &ClientServerConfig, _adapter: *mut dyn Adapter, time: f64 )
{
    for _i in 0..numClients
    {
        clients.push( Client::new( GetDefaultAllocator(), address, config, _adapter, time ) );
    }
}

fn ConnectClients( numClients: i32, clients: &mut Vec<Box<Client>>, privateKey: &[u8], serverAddress: &Address )
{
    for i in 0..numClients as usize
    {
        clients[i].InsecureConnect( privateKey, ( i + 1 ) as u64, serverAddress );
        clients[i].SetLatency( 250.0 );
        clients[i].SetJitter( 100.0 );
        clients[i].SetPacketLoss( 25.0 );
        clients[i].SetDuplicates( 25.0 );
    }
}

fn DestroyClients( numClients: i32, clients: &mut Vec<Box<Client>> )
{
    for i in 0..numClients as usize
    {
        clients[i].Disconnect();
    }

    clients.clear();
}

fn AllClientsConnected( numClients: i32, server: &Server, clients: &Vec<Box<Client>> ) -> bool
{
    if server.GetNumConnectedClients() != numClients
    {
        return false;
    }

    for i in 0..numClients as usize
    {
        if !clients[i].IsConnected()
        {
            return false;
        }
    }

    true
}

fn AnyClientDisconnected( numClients: i32, clients: &Vec<Box<Client>> ) -> bool
{
    for i in 0..numClients as usize
    {
        if clients[i].IsDisconnected()
        {
            return true;
        }
    }

    false
}

fn test_client_server_start_stop_restart()
{
    let clientAddress = Address::from_string_port( "0.0.0.0", 0 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.channel[0].messageSendQueueSize = 32;
    config.channel[0].maxMessagesPerPacket = 8;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    let mut numClients: [i32; 5] = [ 3, 5, 1, 32, 5 ];

    let NumIterations = numClients.len();

    for iteration in 0..NumIterations
    {
        numClients[iteration] = numClients[iteration] % MaxClients;
        if numClients[iteration] == 0
        {
            numClients[iteration] = 1;
        }

        server.Start( numClients[iteration] );

        server.SetLatency( 250.0 );
        server.SetJitter( 100.0 );
        server.SetPacketLoss( 25.0 );
        server.SetDuplicates( 25.0 );

        let mut clients: Vec<Box<Client>> = Vec::with_capacity( MaxClients as usize );

        CreateClients( numClients[iteration], &mut clients, &clientAddress, &config, GetTestAdapter(), time );

        ConnectClients( numClients[iteration], &mut clients, &privateKey, &serverAddress );

        loop
        {
            {
                // port: the Client * array PumpClientServerUpdate takes
                let mut clientPointers: Vec<&mut Client> = clients.iter_mut().map( |client| &mut **client ).collect();

                PumpClientServerUpdate( &mut time, &mut clientPointers, numClients[iteration], &mut [&mut *server], 1, 0.1 );
            }

            if AnyClientDisconnected( numClients[iteration], &clients )
            {
                break;
            }

            if AllClientsConnected( numClients[iteration], &server, &clients )
            {
                break;
            }
        }

        check!( AllClientsConnected( numClients[iteration], &server, &clients ) );

        let NumMessagesSent = config.channel[0].messageSendQueueSize;

        for clientIndex in 0..numClients[iteration]
        {
            SendClientToServerMessages( &mut clients[clientIndex as usize], NumMessagesSent, ReliableChannel );
            SendServerToClientMessages( &mut server, clientIndex, NumMessagesSent, ReliableChannel );
        }

        let mut numMessagesReceivedFromClient = [0i32; MaxClients as usize];
        let mut numMessagesReceivedFromServer = [0i32; MaxClients as usize];

        numMessagesReceivedFromClient.fill( 0 );
        numMessagesReceivedFromServer.fill( 0 );

        const NumInternalIterations: i32 = 10000;

        for _i in 0..NumInternalIterations
        {
            {
                let mut clientPointers: Vec<&mut Client> = clients.iter_mut().map( |client| &mut **client ).collect();

                PumpClientServerUpdate( &mut time, &mut clientPointers, numClients[iteration], &mut [&mut *server], 1, 0.1 );
            }

            let mut allMessagesReceived = true;

            for j in 0..numClients[iteration] as usize
            {
                ProcessServerToClientMessages( &mut clients[j], &mut numMessagesReceivedFromServer[j], ReliableChannel );

                if numMessagesReceivedFromServer[j] != NumMessagesSent
                {
                    allMessagesReceived = false;
                }

                let clientIndex = clients[j].GetClientIndex();

                ProcessClientToServerMessages( &mut server, clientIndex, &mut numMessagesReceivedFromClient[clientIndex as usize], ReliableChannel );

                if numMessagesReceivedFromClient[clientIndex as usize] != NumMessagesSent
                {
                    allMessagesReceived = false;
                }
            }

            if allMessagesReceived
            {
                break;
            }
        }

        for clientIndex in 0..numClients[iteration] as usize
        {
            check!( numMessagesReceivedFromClient[clientIndex] == NumMessagesSent );
            check!( numMessagesReceivedFromServer[clientIndex] == NumMessagesSent );
        }

        DestroyClients( numClients[iteration], &mut clients );

        server.Stop();
    }
}

fn test_client_server_message_failed_to_serialize_reliable_ordered()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.maxPacketSize = 1100;
    config.numChannels = 1;
    config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    const NumIterations: i32 = 10000;

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( !client.IsConnecting() );
    check!( client.IsConnected() );
    check!( server.GetNumConnectedClients() == 1 );
    check!( client.GetClientIndex() == 0 );
    check!( server.IsClientConnected(0) );

    // send a message from client to server that fails to serialize on read, this should disconnect the client from the server

    let message = client.CreateMessage( TEST_SERIALIZE_FAIL_ON_READ_MESSAGE );
    check!( !message.is_null() );
    client.SendMessage( 0, message );

    for _i in 0..256
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if !client.IsConnected() && server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( !client.IsConnected() && server.GetNumConnectedClients() == 0 );

    client.Disconnect();

    server.Stop();
}

fn test_server_client_disconnect_reason()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let config = ClientServerConfig::new();

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    // all client slots are cleared to none at server start

    for i in 0..MaxClients
    {
        check!( server.GetClientDisconnectReason( i ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );
    }

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    const NumIterations: i32 = 10000;

    // connect a client. while it is connected the reason stays none

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( client.IsConnected() );
    check!( server.IsClientConnected( 0 ) );
    check!( server.GetClientDisconnectReason( 0 ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    // kick the client. the reason is recorded immediately, before the adapter callback fires

    server.DisconnectClient( 0 );

    check!( server.GetClientDisconnectReason( 0 ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if !client.IsConnected()
        {
            break;
        }
    }

    check!( !client.IsConnected() );
    check!( server.GetClientDisconnectReason( 0 ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );

    // reconnect. a new client connecting to the slot clears the reason back to none

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( client.IsConnected() );
    check!( server.IsClientConnected( 0 ) );
    check!( server.GetClientDisconnectReason( 0 ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    // clean client-side disconnect is recorded as disconnected, distinct from a timeout

    client.Disconnect();

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( server.GetNumConnectedClients() == 0 );
    check!( server.GetClientDisconnectReason( 0 ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED );

    // reconnect, then let the client go silent. the server times it out and records that
    // as timed out, distinct from a clean disconnect

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( client.IsConnected() );
    check!( server.GetClientDisconnectReason( 0 ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );

    for _i in 0..NumIterations
    {
        // port: the NULL client array is an empty slice
        PumpClientServerUpdate( &mut time, &mut [], 0, &mut [&mut *server], 1, 0.1 );

        if server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( server.GetNumConnectedClients() == 0 );
    check!( server.GetClientDisconnectReason( 0 ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT );

    client.Disconnect();

    // restarting the server clears all slots back to none

    server.Stop();

    server.Start( MaxClients );

    for i in 0..MaxClients
    {
        check!( server.GetClientDisconnectReason( i ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );
    }

    server.Stop();
}

fn test_server_client_disconnect_reason_failed_to_serialize()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.maxPacketSize = 1100;
    config.numChannels = 1;
    config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    const NumIterations: i32 = 10000;

    for _i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( !client.IsConnecting() );
    check!( client.IsConnected() );
    check!( server.GetNumConnectedClients() == 1 );

    // send a message that fails to serialize on read. the server disconnects the client
    // and records the specific channel error as the disconnect reason

    let message = client.CreateMessage( TEST_SERIALIZE_FAIL_ON_READ_MESSAGE );
    check!( !message.is_null() );
    client.SendMessage( 0, message );

    for _i in 0..256
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if !client.IsConnected() && server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( !client.IsConnected() && server.GetNumConnectedClients() == 0 );
    check!( server.GetClientDisconnectReason( 0 ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE );

    client.Disconnect();

    server.Stop();
}

fn test_client_disconnect_reason()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let config = ClientServerConfig::new();

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    // no disconnect has happened yet

    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );

    const NumIterations: i32 = 10000;

    // connect. while connected the reason stays none

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    for i in 0..NumIterations
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( client.IsConnected() );
    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );

    // deliberate local disconnect is recorded immediately

    client.Disconnect();

    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED );

    for i in 0..NumIterations
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( server.GetNumConnectedClients() == 0 );

    // reconnect. a new connect attempt clears the reason back to none

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );

    for i in 0..NumIterations
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( client.IsConnected() );

    // when the server kicks us, the client records disconnected by server

    server.DisconnectClient( 0 );

    for i in 0..NumIterations
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if !client.IsConnected()
        {
            break;
        }
    }

    check!( !client.IsConnected() );
    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER );

    // connecting to a server that isn't there times out at the connection request stage.
    // the insecure connect token expiry is deliberately much longer than the connection
    // timeout, so this behaves the same way as a secure connect token from a matchmaker.

    server.Stop();

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );

    for i in 0..NumIterations
    {
        let mut clients: [&mut Client; 1] = [&mut *client];

        // port: NULL, 0 is an empty slice
        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut [], 0, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }
    }

    check!( client.ConnectionFailed() );
    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT );

    client.Disconnect();
}

fn test_client_disconnect_reason_failed_to_serialize()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.maxPacketSize = 1100;
    config.numChannels = 1;
    config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    const NumIterations: i32 = 10000;

    for i in 0..NumIterations
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( !client.IsConnecting() );
    check!( client.IsConnected() );
    check!( server.GetNumConnectedClients() == 1 );

    // send a message from the server that fails to serialize on read. the client disconnects
    // itself and records the specific channel error as its disconnect reason

    let message = server.CreateMessage( 0, TEST_SERIALIZE_FAIL_ON_READ_MESSAGE );
    check!( !message.is_null() );
    server.SendMessage( 0, 0, message );

    for i in 0..256
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if !client.IsConnected()
        {
            break;
        }
    }

    check!( !client.IsConnected() );
    check!( client.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE );

    client.Disconnect();

    server.Stop();
}

fn test_client_server_message_failed_to_serialize_unreliable_unordered()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.maxPacketSize = 1100;
    config.numChannels = 1;
    config.channel[0].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    const NumIterations: i32 = 10000;

    for i in 0..NumIterations
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( !client.IsConnecting() );
    check!( client.IsConnected() );
    check!( server.GetNumConnectedClients() == 1 );
    check!( client.GetClientIndex() == 0 );
    check!( server.IsClientConnected(0) );

    // send a message from client to server that fails to serialize on read, this should disconnect the client from the server

    for i in 0..256
    {
        let message = client.CreateMessage( TEST_SERIALIZE_FAIL_ON_READ_MESSAGE );
        check!( !message.is_null() );
        client.SendMessage( 0, message );

        // port: the clients / servers arrays borrow client and server mutably, so they are built after the
        // message is sent instead of at the top of the loop body
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if !client.IsConnected() && server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( !client.IsConnected() );
    check!( server.GetNumConnectedClients() == 0 );

    client.Disconnect();

    server.Stop();
}

fn test_client_server_message_exhaust_stream_allocator()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.maxPacketSize = 1100;
    config.numChannels = 1;
    config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    const NumIterations: i32 = 10000;

    for i in 0..NumIterations
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( !client.IsConnecting() );
    check!( client.IsConnected() );
    check!( server.GetNumConnectedClients() == 1 );
    check!( client.GetClientIndex() == 0 );
    check!( server.IsClientConnected(0) );

    // send a message from client to server that exhausts the stream allocator on read, this should disconnect the client from the server

    let message = client.CreateMessage( TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE );
    check!( !message.is_null() );
    client.SendMessage( 0, message );

    for i in 0..256
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if !client.IsConnected() && server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( !client.IsConnected() && server.GetNumConnectedClients() == 0 );

    client.Disconnect();

    server.Stop();
}

fn test_client_server_message_receive_queue_overflow()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.maxPacketSize = 1100;
    config.numChannels = 1;
    config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1024;
    config.channel[0].blockFragmentSize = 200;
    config.channel[0].messageSendQueueSize = 1024;
    config.channel[0].messageReceiveQueueSize = 256;

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    loop
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( !client.IsConnecting() );
    check!( client.IsConnected() );
    check!( server.GetNumConnectedClients() == 1 );
    check!( client.GetClientIndex() == 0 );
    check!( server.IsClientConnected(0) );

    // send a lot of messages, but don't dequeue them, this tests that the receive queue is able to handle overflow
    // eg. the receiver should detect an error and disconnect the client, because the message is out of bounds.

    let NumMessagesSent: i32 = config.channel[0].messageSendQueueSize;

    SendClientToServerMessages( &mut client, NumMessagesSent, ReliableChannel );

    for i in 0..NumMessagesSent * 4
    {
        let mut clients: [&mut Client; 1] = [&mut *client];
        let mut servers: [&mut Server; 1] = [&mut *server];

        PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );
    }

    check!( !client.IsConnected() );
    check!( server.GetNumConnectedClients() == 0 );

    client.Disconnect();

    server.Stop();
}

fn test_reliable_outbound_sequence_outdated()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;
    let deltaTime: f64 = 1.0 / 60.0;

    let mut config = ClientServerConfig::new();
    config.numChannels = 2;
    config.timeout = -1;

    yojimbo_assert!( config.numChannels <= MaxChannels );

    let BlockSize: i32 = config.channel[0].blockFragmentSize * 2;

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    // port: upstream builds `Client * clients[] = { &client }` and `Server * servers[] = { &server }` once here and
    // keeps using client and server directly; in Rust the arrays hold the only mutable borrows, so each
    // PumpClientServerUpdate call builds them in place: &mut [&mut *client] / &mut [&mut *server]

    const NumIterations: i32 = 50000;

    for i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if client.ConnectionFailed()
        {
            break;
        }

        if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
        {
            break;
        }
    }

    check!( !client.IsConnecting() );
    check!( client.IsConnected() );
    check!( server.GetNumConnectedClients() == 1 );
    check!( client.GetClientIndex() == 0 );
    check!( server.IsClientConnected(0) );

    let mut numMessagesSent: i32 = 0;

    let clientMessage = client.CreateMessage( TEST_MESSAGE );
    check!( !clientMessage.is_null() );
    client.SendMessage( 0, clientMessage );
    numMessagesSent += 1;

    let clientBlockMessage = client.CreateMessage( TEST_BLOCK_MESSAGE );
    check!( !clientBlockMessage.is_null() );
    let clientBlockData: *mut u8 = client.AllocateBlock( BlockSize );
    unsafe { std::ptr::write_bytes( clientBlockData, 0, BlockSize as usize ); }
    client.AttachBlockToMessage( clientBlockMessage, clientBlockData, BlockSize );
    client.SendMessage( 1, clientBlockMessage );
    numMessagesSent += 1;

    // Simulate packet sequence being incremented by unreliable messages until it appears outdated.
    for i in 0..32000 // Test takes much longer when sending 32768 at once.
    {
        client.SendPackets();
    }
    PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, deltaTime as f32 );
    for j in 0..768
    {
        client.SendPackets();
    }

    let clientMessage2 = client.CreateMessage( TEST_MESSAGE );
    check!( !clientMessage2.is_null() );
    client.SendMessage( 0, clientMessage2 );
    numMessagesSent += 1;

    let clientBlockMessage2 = client.CreateMessage( TEST_BLOCK_MESSAGE );
    check!( !clientBlockMessage2.is_null() );
    let clientBlockData2: *mut u8 = client.AllocateBlock( BlockSize );
    unsafe { std::ptr::write_bytes( clientBlockData2, 0, BlockSize as usize ); }
    client.AttachBlockToMessage( clientBlockMessage2, clientBlockData2, BlockSize );
    client.SendMessage( 1, clientBlockMessage2 );
    numMessagesSent += 1;

    let mut numMessagesReceived: i32 = 0;

    for i in 0..NumIterations
    {
        if !client.IsConnected()
        {
            break;
        }

        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, deltaTime as f32 );

        for channelIndex in 0..config.numChannels
        {
            let messageFromClient = server.ReceiveMessage( 0, channelIndex );
            if !messageFromClient.is_null()
            {
                server.ReleaseMessage( 0, messageFromClient );
                numMessagesReceived += 1;
             }
        }

        if numMessagesReceived == numMessagesSent
        {
            break;
        }
    }

    check!( client.IsConnected() );
    check!( server.IsClientConnected( client.GetClientIndex() ) );
    check!( numMessagesReceived == numMessagesSent );

    client.Disconnect();

    for i in 0..NumIterations
    {
        PumpClientServerUpdate( &mut time, &mut [&mut *client], 1, &mut [&mut *server], 1, 0.1 );

        if !client.IsConnected() && server.GetNumConnectedClients() == 0
        {
            break;
        }
    }

    check!( !client.IsConnected() && server.GetNumConnectedClients() == 0 );

    server.Stop();
}

fn test_single_message_type_reliable()
{
	let mut messageFactory = SingleTestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let connectionConfig = ConnectionConfig::new();

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumMessagesSent: i32 = 64;

    for i in 0..NumMessagesSent
    {
        let message = messageFactory.CreateMessage( SINGLE_TEST_MESSAGE );
        check!( !message.is_null() );
        unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
        sender.SendMessage( 0, message, std::ptr::null_mut() );
    }

    let mut numMessagesReceived: i32 = 0;

    const NumIterations: i32 = 1000;

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 90 );

        loop
        {
            let message = receiver.ReceiveMessage( 0 );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetId() } == numMessagesReceived as i32 );
            check!( unsafe { ( *message ).GetType() } == SINGLE_TEST_MESSAGE );

            let testMessage = unsafe { message_cast::<TestMessage>( message ) };

            check!( testMessage.sequence as i32 == numMessagesReceived );

            numMessagesReceived += 1;

            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}

fn test_single_message_type_reliable_blocks()
{
	let mut messageFactory = SingleBlockTestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let connectionConfig = ConnectionConfig::new();

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumMessagesSent: i32 = 32;

    for i in 0..NumMessagesSent
    {
        let message = messageFactory.CreateMessage( SINGLE_BLOCK_TEST_MESSAGE );
        check!( !message.is_null() );
        let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
        blockMessage.sequence = i as u16;
        let blockSize: i32 = 1 + ( ( i * 901 ) % 3333 );
        let blockData: *mut u8 = YOJIMBO_ALLOCATE!( messageFactory.GetAllocator(), blockSize );
        for j in 0..blockSize
        {
            unsafe { *blockData.add( j as usize ) = ( i + j ) as u8; }
        }
        blockMessage.AttachBlock( messageFactory.GetAllocator(), blockData, blockSize );
        sender.SendMessage( 0, message, std::ptr::null_mut() );
    }

    let mut numMessagesReceived: i32 = 0;

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    const NumIterations: i32 = 10000;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 90 );

        loop
        {
            let message = receiver.ReceiveMessage( 0 );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetId() } == numMessagesReceived as i32 );

            check!( unsafe { ( *message ).GetType() } == SINGLE_BLOCK_TEST_MESSAGE );

            let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };

            check!( blockMessage.sequence == numMessagesReceived as u16 );

            let blockSize: i32 = blockMessage.GetBlockSize();

            check!( blockSize == 1 + ( ( numMessagesReceived * 901 ) % 3333 ) );

            let blockData: *const u8 = blockMessage.GetBlockData();

            check!( !blockData.is_null() );

            for j in 0..blockSize
            {
                check!( unsafe { *blockData.add( j as usize ) } == ( numMessagesReceived + j ) as u8 );
            }

            numMessagesReceived += 1;

            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}

fn test_single_message_type_unreliable()
{
    let mut messageFactory = SingleTestMessageFactory::new( GetDefaultAllocator() );

    let mut time: f64 = 100.0;

    let mut connectionConfig = ConnectionConfig::new();
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    let mut sender = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );
    let mut receiver = Connection::new( GetDefaultAllocator(), &mut messageFactory, &connectionConfig, time );

    const NumIterations: i32 = 256;

    const NumMessagesSent: i32 = 16;

    for j in 0..NumMessagesSent
    {
        let message = messageFactory.CreateMessage( SINGLE_TEST_MESSAGE );
        check!( !message.is_null() );
        unsafe { message_cast::<TestMessage>( message ) }.sequence = j as u16;
        sender.SendMessage( 0, message, std::ptr::null_mut() );
    }

    let mut numMessagesReceived: i32 = 0;

    let mut senderSequence: u16 = 0;
    let mut receiverSequence: u16 = 0;

    for i in 0..NumIterations
    {
        PumpConnectionUpdate( &connectionConfig, &mut time, &mut sender, &mut receiver, &mut senderSequence, &mut receiverSequence, 0.1, 0 );

        loop
        {
            let message = receiver.ReceiveMessage( 0 );
            if message.is_null()
            {
                break;
            }

            check!( unsafe { ( *message ).GetType() } == SINGLE_TEST_MESSAGE );

            let testMessage = unsafe { message_cast::<TestMessage>( message ) };

            check!( testMessage.sequence == numMessagesReceived as u16 );

            numMessagesReceived += 1;

            messageFactory.ReleaseMessage( message );
        }

        if numMessagesReceived == NumMessagesSent
        {
            break;
        }
    }

    check!( numMessagesReceived == NumMessagesSent );
}


// port: the channelIndex default argument (0) is passed explicitly at each call site
fn SendClientToServerMessagesSample( client: &mut Client, numMessagesToSend: i32, channelIndex: i32 )
{
    for i in 0..numMessagesToSend
    {
        if !client.CanSendMessage( channelIndex )
        {
            break;
        }

        let message = client.CreateMessage( TEST_MESSAGE );
        check!( !message.is_null() );
        unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
        client.SendMessage( channelIndex, message );
    }
}

// port: the channelIndex default argument (0) is passed explicitly at each call site
fn SendServerToClientMessagesSample( server: &mut Server, clientIndex: i32, numMessagesToSend: i32, channelIndex: i32 )
{
    for i in 0..numMessagesToSend
    {
        if !server.CanSendMessage( clientIndex, channelIndex )
        {
            break;
        }

        let message = server.CreateMessage( clientIndex, TEST_MESSAGE );
        check!( !message.is_null() );
        unsafe { message_cast::<TestMessage>( message ) }.sequence = i as u16;
        server.SendMessage( clientIndex, channelIndex, message );
    }
}

fn ProcessServerToClientMessagesSample( client: &mut Client, numMessagesReceivedFromServer: &mut i32 )
{
    loop
    {
        let message = client.ReceiveMessage( 0 );

        if message.is_null()
        {
            break;
        }

        match unsafe { ( *message ).GetType() }
        {
            TEST_MESSAGE =>
            {
                *numMessagesReceivedFromServer += 1;
            }

            _ => {}
        }

        client.ReleaseMessage( message );
    }
}

fn ProcessClientToServerMessagesSample( server: &mut Server, clientIndex: i32, numMessagesReceivedFromClient: &mut i32 )
{
    loop
    {
        let message = server.ReceiveMessage( clientIndex, 0 );

        if message.is_null()
        {
            break;
        }

        match unsafe { ( *message ).GetType() }
        {
            TEST_MESSAGE =>
            {
                check!( !unsafe { ( *message ).IsBlockMessage() } );
                *numMessagesReceivedFromClient += 1;
            }

            _ => {}
        }

        server.ReleaseMessage( clientIndex, message );
    }
}

fn test_client_server_messages_network_sim_leak()
{
    let clientId: u64 = 1;

    let clientAddress = Address::from_string_port( "0.0.0.0", ClientPort as u16 );
    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    let mut time: f64 = 100.0;

    let mut config = ClientServerConfig::new();
    config.networkSimulator = true;
    config.channel[0].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

    let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, GetTestAdapter(), time );

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( MaxClients );

    server.SetLatency( 500.0 );
    server.SetJitter( 100.0 );
    server.SetPacketLoss( 5.0 );
    server.SetDuplicates( 5.0 );

    for iteration in 0..2
    {
        client.InsecureConnect( &privateKey, clientId, &serverAddress );

        client.SetLatency( 500.0 );
        client.SetJitter( 100.0 );
        client.SetPacketLoss( 5.0 );
        client.SetDuplicates( 5.0 );

        const NumIterations: i32 = 10000;

        for i in 0..NumIterations
        {
            let mut clients: [&mut Client; 1] = [&mut *client];
            let mut servers: [&mut Server; 1] = [&mut *server];

            PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

            if client.ConnectionFailed()
            {
                break;
            }

            if !client.IsConnecting() && client.IsConnected() && server.GetNumConnectedClients() == 1
            {
                break;
            }
        }

        check!( !client.IsConnecting() );
        check!( client.IsConnected() );
        check!( server.GetNumConnectedClients() == 1 );
        check!( client.GetClientIndex() == 0 );
        check!( server.IsClientConnected(0) );

        const NumMessagesSent: i32 = 2000;

        SendClientToServerMessagesSample( &mut client, NumMessagesSent, 0 );

        SendServerToClientMessagesSample( &mut server, client.GetClientIndex(), NumMessagesSent, 0 );

        let mut numMessagesReceivedFromClient: i32 = 0;
        let mut numMessagesReceivedFromServer: i32 = 0;

        for i in 0..100
        {
            if !client.IsConnected()
            {
                break;
            }

            let mut clients: [&mut Client; 1] = [&mut *client];
            let mut servers: [&mut Server; 1] = [&mut *server];

            PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

            ProcessServerToClientMessagesSample( &mut client, &mut numMessagesReceivedFromServer );
            ProcessClientToServerMessagesSample( &mut server, client.GetClientIndex(), &mut numMessagesReceivedFromClient );
        }

        check!( client.IsConnected() );
        check!( server.IsClientConnected( client.GetClientIndex() ) );

        client.Disconnect();

        for i in 0..NumIterations
        {
            let mut clients: [&mut Client; 1] = [&mut *client];
            let mut servers: [&mut Server; 1] = [&mut *server];

            PumpClientServerUpdate( &mut time, &mut clients, 1, &mut servers, 1, 0.1 );

            if !client.IsConnected() && server.GetNumConnectedClients() == 0
            {
                break;
            }
        }

        check!( !client.IsConnected() && server.GetNumConnectedClients() == 0 );
    }

    server.Stop();
}

// port: #ifndef YOJIMBO_SYSTEM_DEPS has no Rust counterpart (there are no system dependencies: sodium is the port's
// own crate::sodium), so the test is always compiled

fn test_crypto_aead_vectors()
{
    // Known-answer test for the two AEAD primitives netcode relies on. On Windows
    // this exercises the vendored libsodium in sodium/ (including its SSE2/SSSE3/AVX2
    // paths); on other platforms the system libsodium. Expected ciphertext was
    // generated from libsodium 1.0.20 reference output. Do not edit the arrays by hand.
    // Not built with YOJIMBO_SYSTEM_DEPS: there the system netcode carries its own
    // crypto, and sodium.h is not on the include path.
    // port: here it exercises the port's own ChaCha20/Poly1305 (yojimbo::sodium) on every platform
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

    // ChaCha20-Poly1305 (IETF)
    check!( yojimbo::sodium::crypto_aead_chacha20poly1305_ietf_encrypt( &mut c, Some( &mut clen ), &kat_msg, kat_msg.len() as u64, Some( &kat_ad ), kat_ad.len() as u64, None, &kat_npub_ietf, &kat_key ) == 0 );
    check!( clen == kat_ct_ietf.len() as u64 );
    check!( c[..clen as usize] == kat_ct_ietf[..clen as usize] );
    check!( yojimbo::sodium::crypto_aead_chacha20poly1305_ietf_decrypt( &mut m, Some( &mut mlen ), None, &c, clen, Some( &kat_ad ), kat_ad.len() as u64, &kat_npub_ietf, &kat_key ) == 0 );
    check!( mlen == kat_msg.len() as u64 );
    check!( m[..mlen as usize] == kat_msg[..mlen as usize] );
    c[0] ^= 0x01;
    check!( yojimbo::sodium::crypto_aead_chacha20poly1305_ietf_decrypt( &mut m, Some( &mut mlen ), None, &c, clen, Some( &kat_ad ), kat_ad.len() as u64, &kat_npub_ietf, &kat_key ) != 0 );

    // XChaCha20-Poly1305
    check!( yojimbo::sodium::crypto_aead_xchacha20poly1305_ietf_encrypt( &mut c, Some( &mut clen ), &kat_msg, kat_msg.len() as u64, Some( &kat_ad ), kat_ad.len() as u64, None, &kat_npub_xchacha, &kat_key ) == 0 );
    check!( clen == kat_ct_xchacha.len() as u64 );
    check!( c[..clen as usize] == kat_ct_xchacha[..clen as usize] );
    check!( yojimbo::sodium::crypto_aead_xchacha20poly1305_ietf_decrypt( &mut m, Some( &mut mlen ), None, &c, clen, Some( &kat_ad ), kat_ad.len() as u64, &kat_npub_xchacha, &kat_key ) == 0 );
    check!( mlen == kat_msg.len() as u64 );
    check!( m[..mlen as usize] == kat_msg[..mlen as usize] );
    c[0] ^= 0x01;
    check!( yojimbo::sodium::crypto_aead_xchacha20poly1305_ietf_decrypt( &mut m, Some( &mut mlen ), None, &c, clen, Some( &kat_ad ), kat_ad.len() as u64, &kat_npub_xchacha, &kat_key ) != 0 );
}

// port: the do { ... } while (0) statement macro is a block
macro_rules! RUN_TEST {
    ( $test_function:ident ) => {
        {
            println!( "{}", stringify!( $test_function ) );
            if !InitializeYojimbo()
            {
                println!( "error: failed to initialize yojimbo" );
                std::process::exit( 1 );
            }
            $test_function();
            ShutdownYojimbo();
        }
    };
}

// The vendored netcode and reliable test suites are compiled into those libraries with
// NETCODE_ENABLE_TESTS / RELIABLE_ENABLE_TESTS. System-installed libraries (eg. homebrew,
// -DYOJIMBO_SYSTEM_DEPS=ON) are built without them, so these only exist in vendored builds.
// port: there are no system-installed libraries for the port: netcode_test is yojimbo::netcode::netcode_test and
// reliable_test is yojimbo::reliable::reliable_test, always compiled, so the extern "C" declarations have no
// counterpart and main calls them by path

/*
#ifndef SOAK
#define SOAK 1
#endif
*/
// port: the SOAK preprocessor switch is this const (off by default, as upstream); set it to true to soak
const SOAK: bool = false;

// port: <signal.h>'s signal() is the C runtime's, declared here. Every platform the port builds for has it (the
// Windows CRT included) and SIGINT is 2 on all of them. The handler only stores to an atomic, which is
// async-signal-safe.
const SIGINT: i32 = 2;

extern "C"
{
    fn signal( signum: i32, handler: extern "C" fn( i32 ) ) -> usize;
}

// port: static volatile int quit is an atomic
static quit: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new( 0 );

extern "C" fn interrupt_handler( _dummy: i32 )
{
    quit.store( 1, std::sync::atomic::Ordering::SeqCst );
}

// port: strtoul( string, NULL, 0 ): leading whitespace, an optional sign, then base 16 for 0x / 0X, base 8 for a
// leading 0, otherwise base 10; parsing stops at the first character that is not a digit of the base, and a value
// too large saturates (to the 64-bit ULONG_MAX of LP64 platforms)
fn strtoul( string: &str ) -> u64
{
    let bytes = string.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && ( bytes[i] == b' ' || ( bytes[i] >= b'\t' && bytes[i] <= b'\r' ) )
    {
        i += 1;
    }
    let mut negative = false;
    if i < bytes.len() && ( bytes[i] == b'+' || bytes[i] == b'-' )
    {
        negative = bytes[i] == b'-';
        i += 1;
    }
    let mut base: u64 = 10;
    if i < bytes.len() && bytes[i] == b'0'
    {
        if i + 2 < bytes.len() && ( bytes[i + 1] == b'x' || bytes[i + 1] == b'X' ) && ( bytes[i + 2] as char ).is_ascii_hexdigit()
        {
            base = 16;
            i += 2;
        }
        else
        {
            base = 8;
        }
    }
    let mut value: u64 = 0;
    let mut overflow = false;
    while i < bytes.len()
    {
        let digit = match ( bytes[i] as char ).to_digit( base as u32 )
        {
            Some( digit ) => digit as u64,
            None => break,
        };
        match value.checked_mul( base ).and_then( |v| v.checked_add( digit ) )
        {
            Some( v ) => value = v,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow
    {
        return u64::MAX;
    }
    if negative { value.wrapping_neg() } else { value }
}

fn main()
{
    // port: argc / argv are std::env::args()
    let argv: Vec<String> = std::env::args().collect();
    let argc = argv.len();

    // The tests are randomized (packet loss, ordering, ids). Seed rand() from the clock by
    // default, but let a seed be passed on the command line so a flaky failure can be
    // reproduced exactly: rerun `./bin/test <seed>` with the value printed below. Print and
    // flush the seed first so it survives even if a later test aborts.
    // port: time( NULL ) is the seconds since the Unix epoch from std::time::SystemTime
    let seed: u32 = if argc > 1 { strtoul( &argv[1] ) as u32 }
                    else { std::time::SystemTime::now().duration_since( std::time::UNIX_EPOCH ).map( |d| d.as_secs() ).unwrap_or( 0 ) as u32 };

    println!( "test random seed {}", seed );
    let _ = std::io::Write::flush( &mut std::io::stdout() );

    srand( seed );

    println!();

    // port: #if SOAK ... while ( true ) is a loop that runs once unless SOAK is set
    if SOAK
    {
        unsafe { signal( SIGINT, interrupt_handler ); }
    }
    let mut iter: i32 = 0;
    loop
    {
        {
            println!( "[serialize]\n" );

            check!( InitializeYojimbo() );

            yojimbo::serialize::serialize_test();

            ShutdownYojimbo();
        }

        {
            println!( "\n[netcode]\n" );

            check!( InitializeYojimbo() );

            yojimbo::netcode::netcode_test();

            ShutdownYojimbo();
        }

        {
            println!( "\n[reliable]\n" );

            check!( InitializeYojimbo() );

            yojimbo::reliable::reliable_test();

            ShutdownYojimbo();
        }

        println!( "\n[yojimbo]\n" );

        RUN_TEST!( test_crypto_aead_vectors );
        RUN_TEST!( test_queue );
        RUN_TEST!( test_address );
        RUN_TEST!( test_address_malformed_port );
        RUN_TEST!( test_address_classification );
        RUN_TEST!( test_network_simulator_drains_all_slots );
        RUN_TEST!( test_bit_array );
        RUN_TEST!( test_sequence_buffer );
        RUN_TEST!( test_allocator_tlsf );

        RUN_TEST!( test_connection_reliable_ordered_messages );
        RUN_TEST!( test_connection_reliable_ordered_blocks );
        RUN_TEST!( test_connection_reliable_ordered_blocks_max_size );
        RUN_TEST!( test_connection_reliable_ordered_messages_and_blocks );
        RUN_TEST!( test_connection_reliable_ordered_messages_and_blocks_multiple_channels );
        RUN_TEST!( test_connection_unreliable_unordered_messages );
        RUN_TEST!( test_connection_unreliable_unordered_blocks );
        RUN_TEST!( test_connection_reject_empty_packet );
        RUN_TEST!( test_connection_process_packet_exact_allocation );
        RUN_TEST!( test_connection_unreliable_rejects_block_fragment );
        RUN_TEST!( test_connection_reliable_block_fragment_on_disabled_blocks );
        RUN_TEST!( test_channel_config_fragment_counts_without_overflow );
        RUN_TEST!( test_connection_reliable_block_fragment_overflow );
        RUN_TEST!( test_connection_reliable_over_budget_packet );
        RUN_TEST!( test_connection_reliable_message_alloc_failure );
        RUN_TEST!( test_connection_unreliable_message_alloc_failure );
        RUN_TEST!( test_connection_generate_packet_channel_data_alloc_failure );
        RUN_TEST!( test_message_factory_create_message_alloc_failure );
        RUN_TEST!( test_connection_process_packet_channel_data_alloc_failure );

        RUN_TEST!( test_rtti_across_the_abi_boundary );
        // port: test_public_layout_is_configuration_independent is not ported: it compares the debug and release
        // layouts of the public classes, and one Rust binary is built in only one of the two configurations
        RUN_TEST!( test_interface_methods_link );
        RUN_TEST!( test_server_start_alloc_failure );
        RUN_TEST!( test_server_start_factory_failure );
        RUN_TEST!( test_client_connect_alloc_failure );
        RUN_TEST!( test_client_connect_factory_failure );
        RUN_TEST!( test_client_connect_socket_failure_no_crash );
        RUN_TEST!( test_client_is_loopback_when_disconnected );
        RUN_TEST!( test_client_connect_twice_with_one_connect_token );
        RUN_TEST!( test_client_server_messages );
        RUN_TEST!( test_client_server_start_stop_restart );
        RUN_TEST!( test_client_server_message_failed_to_serialize_reliable_ordered );
        RUN_TEST!( test_server_client_disconnect_reason );
        RUN_TEST!( test_server_client_disconnect_reason_failed_to_serialize );
        RUN_TEST!( test_client_disconnect_reason );
        RUN_TEST!( test_client_disconnect_reason_failed_to_serialize );
        RUN_TEST!( test_client_server_message_failed_to_serialize_unreliable_unordered );
        RUN_TEST!( test_client_server_message_exhaust_stream_allocator );
        RUN_TEST!( test_client_server_message_receive_queue_overflow );
        RUN_TEST!( test_reliable_outbound_sequence_outdated );

        RUN_TEST!( test_single_message_type_reliable );
        RUN_TEST!( test_single_message_type_reliable_blocks );
        RUN_TEST!( test_single_message_type_unreliable );

        RUN_TEST!( test_client_server_messages_network_sim_leak );

        if !SOAK
        {
            break;
        }

        if quit.load( std::sync::atomic::Ordering::SeqCst ) != 0
        {
            break;
        }
        iter += 1;
        for j in 0..iter % 10
        {
            print!( "." );
        }
        println!();
    }

    if SOAK
    {
        if quit.load( std::sync::atomic::Ordering::SeqCst ) != 0
        {
            println!();
        }
    }
    else
    {
        print!( "\n*** ALL TESTS PASS ***\n\n" );
    }
}
