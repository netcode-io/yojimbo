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

// port: include/yojimbo_address.h + source/yojimbo_address.cpp, plus the internal header
// source/yojimbo_address_conversion.h (AddressFromNetcode / AddressToNetcode) at the end of this file, as the C# port does.

use crate::*;
use crate::netcode::*;
use std::fmt;

// port: the winsock / BSD socket includes are not needed. inet_pton and inet_ntop are ported below (from glibc, as the
// C# port does), so parsing and printing accept and produce exactly the same strings on every platform. std's
// Ipv4Addr / Ipv6Addr parsers are deliberately not used: they differ from inet_pton at the edges.

/**
    Address type.
    @see Address::GetType.
 */

// port: C++ enum -> i32 constants (README, "Names"); AddressType is their type
pub type AddressType = i32;

pub const ADDRESS_NONE: AddressType = 0;                                    //< Not an address. Set by the default constructor.
pub const ADDRESS_IPV4: AddressType = 1;                                    //< An IPv4 address, eg: "146.95.129.237"
pub const ADDRESS_IPV6: AddressType = 2;                                    //< An IPv6 address, eg: "48d9:4a08:b543:ae31:89d8:3226:b92c:cbba"

/// port: the C++ anonymous union `m_address`. Rust keeps both members side by side (like netcode_address_data_t);
/// only the one matching m_type is meaningful, as upstream, and Clear zeroes both.
#[derive(Clone, Copy, Default, Debug)]
struct AddressData
{
    ipv4: [u8; 4],                                                          //< IPv4 address data. Valid if type is ADDRESS_IPV4.
    ipv6: [u16; 8],                                                         //< IPv6 address data. Valid if type is ADDRESS_IPV6.
}

/**
    An IP address and port number.
    Supports both IPv4 and IPv6 addresses.
    Identifies where a packet came from, and where a packet should be sent.
 */

// port: Address is a value type in C++ (copied by assignment), hence Clone + Copy
#[derive(Clone, Copy, Debug)]
pub struct Address
{
    m_type: AddressType,                                                    //< The address type: IPv4 or IPv6.
    m_address: AddressData,
    m_port: u16,                                                            //< The IP port. Valid for IPv4 and IPv6 address types.
}

// port: C++ constructor overloads -> named constructors (upstream's default `port = 0` arguments are passed explicitly):
//   Address()                                  -> Address::new()
//   Address( a, b, c, d, port )                -> Address::from_ipv4( a, b, c, d, port )
//   Address( const uint8_t address[], port )   -> Address::from_ipv4_array( &address, port )
//   Address( a, b, c, d, e, f, g, h, port )    -> Address::from_ipv6( a, b, c, d, e, f, g, h, port )
//   Address( const uint16_t address[], port )  -> Address::from_ipv6_array( &address, port )
//   Address( const char * address )            -> Address::from_string( address )
//   Address( const char * address, port )      -> Address::from_string_port( address, port )
impl Address
{
    /**
        Address default constructor.
        Designed for convenience so you can have address members of classes and initialize them via assignment.
        An address created by the default constructor will have address type set to ADDRESS_NONE. Address::IsValid will return false.
        @see IsValid
     */

    pub fn new() -> Address
    {
        let mut address = Address { m_type: ADDRESS_NONE, m_address: AddressData::default(), m_port: 0 };
        address.Clear();
        address
    }

    /**
        Create an IPv4 address.
        IMPORTANT: Pass in port in local byte order. The address class handles the conversion to network order for you.
        @param a The first field of the IPv4 address.
        @param b The second field of the IPv4 address.
        @param c The third field of the IPv4 address.
        @param d The fourth field of the IPv4 address.
        @param port The IPv4 port (local byte order).
     */

    pub fn from_ipv4( a: u8, b: u8, c: u8, d: u8, port: u16 ) -> Address
    {
        let mut address = Address::new();
        address.m_type = ADDRESS_IPV4;
        address.m_address.ipv4[0] = a;
        address.m_address.ipv4[1] = b;
        address.m_address.ipv4[2] = c;
        address.m_address.ipv4[3] = d;
        address.m_port = port;
        address
    }

    /**
        Create an IPv4 address.
        @param address Array of four address fields for the IPv4 address.
        @param port The port number (local byte order).
     */

    pub fn from_ipv4_array( address: &[u8], port: u16 ) -> Address
    {
        let mut result = Address::new();
        result.m_type = ADDRESS_IPV4;
        for i in 0..4
        {
            result.m_address.ipv4[i] = address[i];
        }
        result.m_port = port;
        result
    }

    /**
        Create an IPv6 address.
        IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.
        @param a First field of the IPv6 address (local byte order).
        @param b Second field of the IPv6 address (local byte order).
        @param c Third field of the IPv6 address (local byte order).
        @param d Fourth field of the IPv6 address (local byte order).
        @param e Fifth field of the IPv6 address (local byte order).
        @param f Sixth field of the IPv6 address (local byte order).
        @param g Seventh field of the IPv6 address (local byte order).
        @param h Eighth field of the IPv6 address (local byte order).
        @param port The port number (local byte order).
     */

    pub fn from_ipv6( a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16, port: u16 ) -> Address
    {
        let mut address = Address::new();
        address.m_type = ADDRESS_IPV6;
        address.m_address.ipv6[0] = a;
        address.m_address.ipv6[1] = b;
        address.m_address.ipv6[2] = c;
        address.m_address.ipv6[3] = d;
        address.m_address.ipv6[4] = e;
        address.m_address.ipv6[5] = f;
        address.m_address.ipv6[6] = g;
        address.m_address.ipv6[7] = h;
        address.m_port = port;
        address
    }

    /**
        Create an IPv6 address.
        IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.
        @param address Array of 8 16 bit address fields for the IPv6 address (local byte order).
        @param port The IPv6 port (local byte order).
     */

    pub fn from_ipv6_array( address: &[u16], port: u16 ) -> Address
    {
        let mut result = Address::new();
        result.m_type = ADDRESS_IPV6;
        for i in 0..8
        {
            result.m_address.ipv6[i] = address[i];
        }
        result.m_port = port;
        result
    }

    /**
        Parse a string to an address.
        This versions supports parsing a port included in the address string. For example, "127.0.0.1:4000" and "[::1]:40000".
        Parsing is performed via inet_pton once the port # has been extracted from the string, so you may specify any IPv4 or IPv6 address formatted in any valid way, and it should work as you expect.
        Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
        If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE, causing Address::IsValid to return false. Please check that after creating an address from a string.
        @param address The string to parse to create the address.
        @see Address::IsValid
        @see Address::GetType
     */

    pub fn from_string( address: &str ) -> Address
    {
        // port: starts from a cleared address (C++ parses into uninitialized members)
        let mut result = Address::new();
        result.Parse( address );
        result
    }

    /**
        Parse a string to an address.
        This versions overrides any port read in the address with the port parameter. This lets you parse "127.0.0.1" and "[::1]" and pass in the port you want programmatically.
        Parsing is performed via inet_pton once the port # has been extracted from the string, so you may specify any IPv4 or IPv6 address formatted in any valid way, and it should work as you expect.
        Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
        If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE, causing Address::IsValid to return false. Please check that after creating an address from a string.
        @param address The string to parse to create the address.
        @param port Overrides the port number read from the string (if any).
        @see Address::IsValid
        @see Address::GetType
     */

    pub fn from_string_port( address: &str, port: u16 ) -> Address
    {
        let mut result = Address::new();
        result.Parse( address );
        result.m_port = port;
        result
    }
}

// Parse a port string. The whole string must be a decimal number in [0,65535] and nothing
// else: at least one digit, no sign, no leading space, no trailing characters, no overflow.
// strtol alone stops at the first character it cannot use and reports success on what it
// read, so "40k" parsed as 40, "" as 0, and "99999999999999999999" saturated to LONG_MAX --
// all of them accepted addresses that the documented contract calls invalid (YJ-11).
// port: `string` is the NUL-terminated rest of the parse buffer
fn ParsePort( string: &[u8], port: &mut u16 ) -> bool
{
    if string[0] < b'0' || string[0] > b'9'
    {
        return false;                                   // no digits, or a sign or space first
    }
    // port: strtoul( string, &end, 10 ) inline: consume every digit; ERANGE when the value overflows (u64 here)
    let mut end: usize = 0;
    let mut erange = false;
    let mut value: u64 = 0;
    while string[end] >= b'0' && string[end] <= b'9'
    {
        match value.checked_mul( 10 ).and_then( |v| v.checked_add( ( string[end] - b'0' ) as u64 ) )
        {
            Some( v ) => value = v,
            None => { erange = true; value = u64::MAX; }
        }
        end += 1;
    }
    if erange
    {
        return false;                                   // more digits than an unsigned long
    }
    if string[end] != 0
    {
        return false;                                   // trailing junk
    }
    if value > 65535
    {
        return false;
    }
    *port = value as u16;
    true
}

// port: strlen / strchr on the NUL-terminated parse buffer
fn strlen( s: &[u8] ) -> usize
{
    s.iter().position( |&c| c == 0 ).unwrap_or( s.len() )
}

fn strchr( s: &[u8], c: u8 ) -> Option<usize>
{
    let length = strlen( s );
    s[..length].iter().position( |&x| x == c )
}

impl Address
{
    /**
        Helper function to parse an address string.
        Used by the constructors that take a string parameter.
        @param address The string to parse.
     */

    // port: C++ protected; private here (no subclasses in Rust)
    fn Parse( &mut self, address_in: &str )
    {
        // first try to parse as an IPv6 address:
        // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
        // 2. otherwise try to parse as raw IPv6 address, parse using inet_pton

        // port: yojimbo_assert( address_in ) -- a &str is never null

        let mut buffer = [0u8; MaxAddressLength as usize];
        // port: `char * address` is an index into buffer
        let mut address: usize = 0;
        yojimbo_copy_string( &mut buffer, address_in, MaxAddressLength as usize );

        let mut addressLength = strlen( &buffer[address..] ) as i32;
        self.m_port = 0;
        if buffer[address] == b'['
        {
            // Bracketed IPv6: exactly "[addr6]" or "[addr6]:port", and nothing else. Locate the
            // closing bracket, then treat only a ':' immediately after it as the port separator.
            // Scanning for ':' from the end (as we do for IPv4 below) is wrong here because
            // addr6 itself is full of colons, so "[::1]" with no port would misparse a colon
            // inside the address.
            //
            // A missing bracket, or anything at all after the closing one other than ":port",
            // is invalid: "[::1" and "[::1]junk" used to be accepted, the first because the
            // opening bracket was simply skipped and the second because everything past the
            // bracket was truncated away unread (YJ-11).
            let closing = match strchr( &buffer[address..], b']' )
            {
                Some( index ) => address + index,
                None =>
                {
                    self.Clear();
                    return;
                }
            };
            if buffer[closing + 1] == b':'
            {
                if !ParsePort( &buffer[closing + 2..], &mut self.m_port )
                {
                    self.Clear();
                    return;
                }
            }
            else if buffer[closing + 1] != 0
            {
                self.Clear();
                return;
            }
            buffer[closing] = 0;
            address += 1;
        }
        let mut sockaddr6 = [0u8; 16];
        if inet_pton6( &buffer[address..address + strlen( &buffer[address..] )], &mut sockaddr6 )
        {
            for i in 0..8
            {
                // port: ntohs of each network order 16 bit group
                self.m_address.ipv6[i] = ( ( sockaddr6[i * 2] as u16 ) << 8 ) | ( sockaddr6[i * 2 + 1] as u16 );
            }
            self.m_type = ADDRESS_IPV6;
            return;
        }

        // otherwise it's probably an IPv4 address:
        // 1. look for ":portnum", if found save the portnum and strip it out
        // 2. parse remaining ipv4 address via inet_pton

        addressLength = strlen( &buffer[address..] ) as i32;
        let base_index = addressLength - 1;
        for i in 0..6
        {
            let index = base_index - i;
            if index < 0
            {
                break;
            }
            if buffer[address + index as usize] == b':'
            {
                if !ParsePort( &buffer[address + index as usize + 1..], &mut self.m_port )
                {
                    self.Clear();
                    return;
                }
                buffer[address + index as usize] = 0;
            }
        }

        let mut sockaddr4 = [0u8; 4];
        if inet_pton4( &buffer[address..address + strlen( &buffer[address..] )], &mut sockaddr4 )
        {
            self.m_type = ADDRESS_IPV4;
            // port: sin_addr is in network order, so the bytes are already a.b.c.d
            self.m_address.ipv4[3] = sockaddr4[3];
            self.m_address.ipv4[2] = sockaddr4[2];
            self.m_address.ipv4[1] = sockaddr4[1];
            self.m_address.ipv4[0] = sockaddr4[0];
        }
        else
        {
            // Not a valid IPv4 address. Set address as invalid.
            self.Clear();
        }
    }

    /**
        Clear the address.
        The address type is set to ADDRESS_TYPE_NONE.
        After this function is called Address::IsValid will return false.
     */

    pub fn Clear( &mut self )
    {
        self.m_type = ADDRESS_NONE;
        self.m_address = AddressData::default();
        self.m_port = 0;
    }

    /**
        Get the IPv4 address data.
        @returns The IPv4 address as an array of bytes.
     */

    pub fn GetAddress4( &self ) -> &[u8; 4]
    {
        yojimbo_assert!( self.m_type == ADDRESS_IPV4 );
        &self.m_address.ipv4
    }

    /**
        Get the IPv6 address data.
        @returns the IPv6 address data as an array of uint16_t (local byte order).
     */

    pub fn GetAddress6( &self ) -> &[u16; 8]
    {
        yojimbo_assert!( self.m_type == ADDRESS_IPV6 );
        &self.m_address.ipv6
    }

    /**
        Set the port.
        This is useful when you want to programmatically set a server port, eg. try to open a server on ports 40000, 40001, etc...
        @param port The port number (local byte order). Works for both IPv4 and IPv6 addresses.
     */

    pub fn SetPort( &mut self, port: u16 )
    {
        self.m_port = port;
    }

    /**
        Get the port number.
        @returns The port number (local byte order).
     */

    pub fn GetPort( &self ) -> u16
    {
        self.m_port
    }

    /**
        Get the address type.
        @returns The address type: ADDRESS_NONE, ADDRESS_IPV4 or ADDRESS_IPV6.
     */

    pub fn GetType( &self ) -> AddressType
    {
        self.m_type
    }

    /**
        Convert the address to a string.
        @returns The address as a string, at most MaxAddressLength - 1 characters.
     */

    // port: returns String instead of formatting into the caller's buffer (README, "Strings"); Display does the same
    pub fn ToString( &self ) -> String
    {
        if self.m_type == ADDRESS_IPV4
        {
            let a = self.m_address.ipv4[0];
            let b = self.m_address.ipv4[1];
            let c = self.m_address.ipv4[2];
            let d = self.m_address.ipv4[3];
            if self.m_port != 0
            {
                format!( "{}.{}.{}.{}:{}", a, b, c, d, self.m_port )
            }
            else
            {
                format!( "{}.{}.{}.{}", a, b, c, d )
            }
        }
        else if self.m_type == ADDRESS_IPV6
        {
            if self.m_port == 0
            {
                inet_ntop6( &self.m_address.ipv6 )
            }
            else
            {
                let addressString = inet_ntop6( &self.m_address.ipv6 );
                format!( "[{}]:{}", addressString, self.m_port )
            }
        }
        else
        {
            String::from( "NONE" )
        }
    }

    /**
        True if the address is valid.
        A valid address is any address with a type other than ADDRESS_TYPE_NONE.
        @returns True if the address is valid, false otherwise.
     */

    pub fn IsValid( &self ) -> bool
    {
        self.m_type != ADDRESS_NONE
    }

    /**
        Is this an IPv6 link local address?
        Corresponds to the first field of the address being 0xfe80
        @returns True if this address is a link local IPv6 address.
     */

    pub fn IsLinkLocal( &self ) -> bool
    {
        // fe80::/10 -- the prefix is 10 bits, so mask rather than compare the whole group.
        // Comparing == 0xfe80 matched only fe80::/16 and missed the rest of the range.
        self.m_type == ADDRESS_IPV6 && ( self.m_address.ipv6[0] & 0xffc0 ) == 0xfe80
    }

    /**
        Is this an IPv6 site local address?
        Corresponds to the first field of the address being 0xfec0
        @returns True if this address is a site local IPv6 address.
     */

    pub fn IsSiteLocal( &self ) -> bool
    {
        // fec0::/10
        self.m_type == ADDRESS_IPV6 && ( self.m_address.ipv6[0] & 0xffc0 ) == 0xfec0
    }

    /**
        Is this an IPv6 multicast address?
        Corresponds to the first field of the IPv6 address being 0xff00
        @returns True if this address is a multicast IPv6 address.
     */

    pub fn IsMulticast( &self ) -> bool
    {
        // ff00::/8. Comparing == 0xff00 matched only the single group ff00 and missed every
        // real multicast address, including ff02::1 (all nodes).
        self.m_type == ADDRESS_IPV6 && ( self.m_address.ipv6[0] & 0xff00 ) == 0xff00
    }

    /**
        Is this a loopback address?
        Corresponds to an IPv4 address of "127.0.0.1", or an IPv6 address of "::1".
        @returns True if this is the loopback address.
     */

    pub fn IsLoopback( &self ) -> bool
    {
        ( self.m_type == ADDRESS_IPV4 && self.m_address.ipv4[0] == 127
                                      && self.m_address.ipv4[1] == 0
                                      && self.m_address.ipv4[2] == 0
                                      && self.m_address.ipv4[3] == 1 )
                                          ||
        ( self.m_type == ADDRESS_IPV6 && self.m_address.ipv6[0] == 0
                                      && self.m_address.ipv6[1] == 0
                                      && self.m_address.ipv6[2] == 0
                                      && self.m_address.ipv6[3] == 0
                                      && self.m_address.ipv6[4] == 0
                                      && self.m_address.ipv6[5] == 0
                                      && self.m_address.ipv6[6] == 0
                                      && self.m_address.ipv6[7] == 0x0001 )
    }

    /**
        Is this in IPv6 global unicast address?
        Corresponds to any IPv6 address that is not any of the following: Link Local, Site Local, Multicast or Loopback.
        @returns True if this is a global unicast IPv6 address.
     */

    pub fn IsGlobalUnicast( &self ) -> bool
    {
        // Defined as the negation of the others, so a missed classification above did not
        // merely return false here -- it returned TRUE, reporting multicast as global unicast.
        self.m_type == ADDRESS_IPV6 && !self.IsLinkLocal()
                                    && !self.IsSiteLocal()
                                    && !self.IsMulticast()
                                    && !self.IsLoopback()
    }
}

// port: Address() as Default, so Address members can be #[derive(Default)]
impl Default for Address
{
    fn default() -> Address
    {
        Address::new()
    }
}

// port: operator == and operator != (ne is the negation of eq, as upstream). Like upstream, two ADDRESS_NONE addresses
// do not compare equal, so Address is PartialEq but not Eq.
impl PartialEq for Address
{
    fn eq( &self, other: &Address ) -> bool
    {
        if self.m_type != other.m_type
        {
            return false;
        }
        if self.m_port != other.m_port
        {
            return false;
        }
        if self.m_type == ADDRESS_IPV4 && self.m_address.ipv4 == other.m_address.ipv4
        {
            true
        }
        else if self.m_type == ADDRESS_IPV6 && self.m_address.ipv6 == other.m_address.ipv6
        {
            true
        }
        else
        {
            false
        }
    }
}

// port addition: `{}` formatting and .to_string(), the same text as Address::ToString
impl fmt::Display for Address
{
    fn fmt( &self, f: &mut fmt::Formatter ) -> fmt::Result
    {
        f.write_str( &self.ToString() )
    }
}

// port: inet_pton( AF_INET, ... ). A port of glibc inet_pton4: exactly four dotted decimal octets, no leading zeros.
// `src` is the whole string (no terminator); `dst` receives the address in network order.
fn inet_pton4( src: &[u8], dst: &mut [u8; 4] ) -> bool
{
    let mut saw_digit = false;
    let mut octets = 0;
    let mut tmp = [0u8; 4];
    let mut tp: usize = 0;
    for &ch in src
    {
        if ch >= b'0' && ch <= b'9'
        {
            let new = tmp[tp] as u32 * 10 + ( ch - b'0' ) as u32;
            if saw_digit && tmp[tp] == 0
            {
                return false;
            }
            if new > 255
            {
                return false;
            }
            tmp[tp] = new as u8;
            if !saw_digit
            {
                octets += 1;
                if octets > 4
                {
                    return false;
                }
                saw_digit = true;
            }
        }
        else if ch == b'.' && saw_digit
        {
            if octets == 4
            {
                return false;
            }
            tp += 1;
            tmp[tp] = 0;
            saw_digit = false;
        }
        else
        {
            return false;
        }
    }
    if octets < 4
    {
        return false;
    }
    *dst = tmp;
    true
}

fn hex_digit_value( ch: u8 ) -> i32
{
    if ch >= b'0' && ch <= b'9' { return ( ch - b'0' ) as i32; }
    if ch >= b'a' && ch <= b'f' { return ( ch - b'a' + 10 ) as i32; }
    if ch >= b'A' && ch <= b'F' { return ( ch - b'A' + 10 ) as i32; }
    -1
}

// port: inet_pton( AF_INET6, ... ). A port of glibc inet_pton6, including embedded IPv4 ("::ffff:1.2.3.4").
// `src` is the whole string (no terminator); `dst` receives the 16 address bytes in network order.
fn inet_pton6( src: &[u8], dst: &mut [u8; 16] ) -> bool
{
    let mut tmp = [0u8; 16];
    let mut tp: usize = 0;
    const endp: usize = 16;
    let mut colonp: Option<usize> = None;
    let mut i: usize = 0;
    let src_endp = src.len();

    if i == src_endp
    {
        return false;
    }
    // Leading :: requires some special handling.
    if src[i] == b':'
    {
        i += 1;
        if i == src_endp || src[i] != b':'
        {
            return false;
        }
    }

    let mut curtok = i;
    let mut xdigits_seen = 0;
    let mut val: u32 = 0;
    while i < src_endp
    {
        let ch = src[i];
        i += 1;
        let digit = hex_digit_value( ch );
        if digit >= 0
        {
            if xdigits_seen == 4
            {
                return false;
            }
            val <<= 4;
            val |= digit as u32;
            if val > 0xffff
            {
                return false;
            }
            xdigits_seen += 1;
            continue;
        }
        if ch == b':'
        {
            curtok = i;
            if xdigits_seen == 0
            {
                if colonp.is_some()
                {
                    return false;
                }
                colonp = Some( tp );
                continue;
            }
            else if i == src_endp
            {
                return false;
            }
            if tp + 2 > endp
            {
                return false;
            }
            tmp[tp] = ( ( val >> 8 ) & 0xff ) as u8;
            tmp[tp + 1] = ( val & 0xff ) as u8;
            tp += 2;
            xdigits_seen = 0;
            val = 0;
            continue;
        }
        if ch == b'.' && ( tp + 4 ) <= endp
        {
            let mut v4 = [0u8; 4];
            if inet_pton4( &src[curtok..src_endp], &mut v4 )
            {
                tmp[tp..tp + 4].copy_from_slice( &v4 );
                tp += 4;
                xdigits_seen = 0;
                break;
            }
        }
        return false;
    }
    if xdigits_seen > 0
    {
        if tp + 2 > endp
        {
            return false;
        }
        tmp[tp] = ( ( val >> 8 ) & 0xff ) as u8;
        tmp[tp + 1] = ( val & 0xff ) as u8;
        tp += 2;
    }
    if let Some( colonp ) = colonp
    {
        // Replace :: with zeros.
        if tp == endp
        {
            return false;       // :: would expand to a zero-width field
        }
        let n = tp - colonp;
        tmp.copy_within( colonp..colonp + n, endp - n );
        for x in &mut tmp[colonp..endp - n]
        {
            *x = 0;
        }
        tp = endp;
    }
    if tp != endp
    {
        return false;
    }
    *dst = tmp;
    true
}

// port: inet_ntop( AF_INET6, ... ). A port of glibc inet_ntop6: compress the longest run (>= 2) of zero groups, lower
// case hex, embedded IPv4 for ::a.b.c.d and ::ffff:a.b.c.d. `words` are the 8 groups in local byte order.
fn inet_ntop6( words: &[u16; 8] ) -> String
{
    let mut best_base: i32 = -1;
    let mut best_len: i32 = 0;
    let mut cur_base: i32 = -1;
    let mut cur_len: i32 = 0;
    for i in 0..8
    {
        if words[i as usize] == 0
        {
            if cur_base == -1 { cur_base = i; cur_len = 1; }
            else { cur_len += 1; }
        }
        else if cur_base != -1
        {
            if best_base == -1 || cur_len > best_len { best_base = cur_base; best_len = cur_len; }
            cur_base = -1;
        }
    }
    if cur_base != -1 && ( best_base == -1 || cur_len > best_len ) { best_base = cur_base; best_len = cur_len; }
    if best_base != -1 && best_len < 2
    {
        best_base = -1;
    }

    let mut s = String::new();
    for i in 0..8
    {
        if best_base != -1 && i >= best_base && i < best_base + best_len
        {
            if i == best_base
            {
                s.push( ':' );
            }
            continue;
        }
        if i != 0
        {
            s.push( ':' );
        }
        if i == 6 && best_base == 0 && ( best_len == 6 || ( best_len == 5 && words[5] == 0xffff ) )
        {
            s.push_str( &format!( "{}.{}.{}.{}", words[6] >> 8, words[6] & 0xff, words[7] >> 8, words[7] & 0xff ) );
            return s;
        }
        s.push_str( &format!( "{:x}", words[i as usize] ) );
    }
    if best_base != -1 && best_base + best_len == 8
    {
        s.push( ':' );
    }
    s
}

// ---------------------------------------------------------------------------------------------------------------------
// port: source/yojimbo_address_conversion.h
//
// Internal header, shared by yojimbo_client.cpp and yojimbo_server.cpp. Not installed:
// it names netcode types, and netcode.h is not part of the yojimbo public interface.
// port: pub so yojimbo_client.rs and yojimbo_server.rs can use them (C# keeps them internal); used for custom packet I/O.
// ---------------------------------------------------------------------------------------------------------------------

pub fn AddressFromNetcode( address: &netcode_address_t ) -> Address
{
    if address.r#type == NETCODE_ADDRESS_IPV4 as u8
    {
        return Address::from_ipv4_array( &address.data.ipv4, address.port );
    }
    if address.r#type == NETCODE_ADDRESS_IPV6 as u8
    {
        return Address::from_ipv6_array( &address.data.ipv6, address.port );
    }
    Address::new()
}

pub fn AddressToNetcode( address: &Address, result: &mut netcode_address_t ) -> bool
{
    // port: memset( &result, 0, sizeof( result ) )
    *result = netcode_address_t::default();
    result.port = address.GetPort();
    if address.GetType() == ADDRESS_IPV4
    {
        result.r#type = NETCODE_ADDRESS_IPV4 as u8;
        result.data.ipv4.copy_from_slice( address.GetAddress4() );
        return true;
    }
    if address.GetType() == ADDRESS_IPV6
    {
        result.r#type = NETCODE_ADDRESS_IPV6 as u8;
        result.data.ipv6.copy_from_slice( address.GetAddress6() );
        return true;
    }
    false
}
