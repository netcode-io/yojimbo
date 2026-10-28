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

// port: include/yojimbo_adapter.h

use crate::*;

/**
    Complete netcode.io datagrams passed to and from the adapter are at most this many bytes
    (netcode's internal NETCODE_MAX_PACKET_BYTES). Size custom transport buffers to THIS
    constant, not to the payload-size constants — a full datagram carries netcode framing
    and encryption overhead on top of the payload.
    @see Adapter::SendPacket
    @see Adapter::ReceivePacket
 */

pub const MaxAdapterPacketBytes: i32 = 1300;

/**
    Specifies the message factory and callbacks for clients and servers.
    An instance of this class is passed into the client and server constructors.
    You can share the same adapter across a client/server pair if you have local multiplayer, eg. loopback.
 */

// port: the class becomes a trait whose methods all have upstream's default bodies; a derived adapter is a struct
// that implements Adapter and overrides what it needs. It is held as `*mut dyn Adapter` (README, "Pointers and memory").
// `virtual ~Adapter() {}` has no Rust counterpart: an implementor's Drop runs through the trait object.
pub trait Adapter
{
    /**
        Override this function to specify your own custom allocator class.
        @param allocator The base allocator that must be used to allocate your allocator instance.
        @param memory The block of memory backing your allocator.
        @param bytes The number of bytes of memory available to your allocator.
        @returns A pointer to the allocator instance you created.
     */

    fn CreateAllocator( &mut self, allocator: *mut dyn Allocator, memory: *mut u8, bytes: usize ) -> *mut dyn Allocator
    {
        YOJIMBO_NEW!( allocator, TLSF_Allocator, TLSF_Allocator::new( memory, bytes ) ) as *mut dyn Allocator
    }

    /**
        You must override this method to create the message factory used by the client and server.
        @param allocator The allocator that must be used to create your message factory instance via YOJIMBO_NEW
        @returns The message factory pointer you created.

     */

    fn CreateMessageFactory( &mut self, allocator: *mut dyn Allocator ) -> *mut dyn MessageFactory
    {
        let _ = allocator;
        yojimbo_assert!( false );
        null_message_factory()
    }

    /**
        Override to route netcode.io packets through a custom datagram transport.
        The result must remain stable for the lifetime of the client or server.
        The default is false and preserves yojimbo's native UDP sockets.
     */

    fn UseCustomPacketIO( &self ) -> bool
    {
        false
    }

    /**
        Send one complete netcode.io datagram through the custom transport.
        Called only when UseCustomPacketIO returns true. packetBytes is never larger than
        MaxAdapterPacketBytes, so buffers sized to that constant always fit the datagram.
        An adapter with UseCustomPacketIO() == true must be dedicated to a single Client
        or Server instance — never share it between two objects. The loopback-style
        sharing described in the class documentation above does not extend to custom
        packet I/O.
     */

    fn SendPacket( &mut self, to: &Address, packetData: &[u8], packetBytes: i32 )
    {
        let _ = to;
        let _ = packetData;
        let _ = packetBytes;
        yojimbo_assert!( false );
    }

    /**
        Receive one complete netcode.io datagram from the custom transport.
        Set from to the stable transport-visible source address and return the byte count.
        Return zero when no packet is available.
        This function MUST be non-blocking: netcode calls it in a loop each update and
        drains packets until it returns zero, so a blocking implementation stalls the
        client or server. maxPacketBytes is MaxAdapterPacketBytes — size transport-side
        receive buffers to that constant.
     */

    fn ReceivePacket( &mut self, from: &mut Address, packetData: &mut [u8], maxPacketBytes: i32 ) -> i32
    {
        let _ = from;
        let _ = packetData;
        let _ = maxPacketBytes;
        yojimbo_assert!( false );
        0
    }

    /**
        Override this callback to process packets sent from client to server over loopback.
        @param clientIndex The client index in range [0,maxClients-1]
        @param packetData The packet data (raw) to be sent to the server.
        @param packetBytes The number of packet bytes in the server.
        @param packetSequence The sequence number of the packet.
        @see Client::ConnectLoopback
     */

    fn ClientSendLoopbackPacket( &mut self, clientIndex: i32, packetData: &[u8], packetBytes: i32, packetSequence: u64 )
    {
        let _ = clientIndex;
        let _ = packetData;
        let _ = packetBytes;
        let _ = packetSequence;
        yojimbo_assert!( false );
    }

    /**
        Override this callback to process packets sent from client to server over loopback.
        @param clientIndex The client index in range [0,maxClients-1]
        @param packetData The packet data (raw) to be sent to the server.
        @param packetBytes The number of packet bytes in the server.
        @param packetSequence The sequence number of the packet.
        @see Server::ConnectLoopbackClient
     */

    fn ServerSendLoopbackPacket( &mut self, clientIndex: i32, packetData: &[u8], packetBytes: i32, packetSequence: u64 )
    {
        let _ = clientIndex;
        let _ = packetData;
        let _ = packetBytes;
        let _ = packetSequence;
        yojimbo_assert!( false );
    }

    /**
        Override this to get a callback when a client connects on the server.
     */

    fn OnServerClientConnected( &mut self, clientIndex: i32 )
    {
        let _ = clientIndex;
    }

    /**
        Override this to get a callback when a client disconnects from the server.
     */

    fn OnServerClientDisconnected( &mut self, clientIndex: i32 )
    {
        let _ = clientIndex;
    }
}

/// port: upstream's Adapter class instantiated as is, with every default. It is the concrete type behind null_adapter()
/// and can be used where C++ would construct a plain `Adapter`.
pub struct DefaultAdapter;

impl Adapter for DefaultAdapter {}

/// port addition: a null `*mut dyn Adapter` (README, "Pointers and memory"); test with `.is_null()`.
pub fn null_adapter() -> *mut dyn Adapter
{
    std::ptr::null_mut::<DefaultAdapter>() as *mut dyn Adapter
}
