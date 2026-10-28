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

// port: the program keeps upstream's names (README, "Names")
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_imports, unused_unsafe, static_mut_refs)]
#![allow(clippy::all)]

// port: #include "yojimbo.h" is the crate, <deque> is std::collections::VecDeque, <stdio.h> and <string.h> are std
use yojimbo::*;
use std::collections::VecDeque;

#[path = "shared.rs"]
mod shared;
use shared::*;

#[derive(Clone, Copy)]
struct MemoryPacket
{
    from: Address,
    bytes: i32,
    data: [u8; MaxAdapterPacketBytes as usize],
}

// port: `class MemoryPacketAdapter : public TestAdapter` embeds the TestAdapter as `base` and calls through it for
// TestAdapter::CreateMessageFactory. The peer is a raw pointer, as upstream.
struct MemoryPacketAdapter
{
    base: TestAdapter,
    m_localAddress: Address,
    m_peer: *mut MemoryPacketAdapter,
    m_packets: VecDeque<MemoryPacket>,
    m_sentPackets: i32,
    m_receivedPackets: i32,
}

impl MemoryPacketAdapter
{
    fn new( localAddress: &Address ) -> MemoryPacketAdapter
    {
        MemoryPacketAdapter
        {
            base: TestAdapter,
            m_localAddress: *localAddress,
            m_peer: std::ptr::null_mut(),
            m_packets: VecDeque::new(),
            m_sentPackets: 0,
            m_receivedPackets: 0,
        }
    }

    fn Connect( &mut self, peer: *mut MemoryPacketAdapter )
    {
        self.m_peer = peer;
    }

    fn SentPackets( &self ) -> i32 { self.m_sentPackets }
    fn ReceivedPackets( &self ) -> i32 { self.m_receivedPackets }
}

impl Adapter for MemoryPacketAdapter
{
    fn CreateMessageFactory( &mut self, allocator: *mut dyn Allocator ) -> *mut dyn MessageFactory
    {
        self.base.CreateMessageFactory( allocator )
    }

    fn UseCustomPacketIO( &self ) -> bool
    {
        true
    }

    fn SendPacket( &mut self, to: &Address, packetData: &[u8], packetBytes: i32 )
    {
        if self.m_peer.is_null() || *to != unsafe { ( *self.m_peer ).m_localAddress } || packetBytes <= 0 || packetBytes > MaxAdapterPacketBytes
        {
            return;
        }

        let mut packet = MemoryPacket { from: self.m_localAddress, bytes: packetBytes, data: [0; MaxAdapterPacketBytes as usize] };
        packet.data[..packetBytes as usize].copy_from_slice( &packetData[..packetBytes as usize] );
        unsafe { ( *self.m_peer ).m_packets.push_back( packet ); }
        self.m_sentPackets += 1;
    }

    fn ReceivePacket( &mut self, from: &mut Address, packetData: &mut [u8], maxPacketBytes: i32 ) -> i32
    {
        if self.m_packets.is_empty()
        {
            return 0;
        }

        let packet = self.m_packets.pop_front().unwrap();
        if packet.bytes > maxPacketBytes
        {
            return 0;
        }

        *from = packet.from;
        packetData[..packet.bytes as usize].copy_from_slice( &packet.data[..packet.bytes as usize] );
        self.m_receivedPackets += 1;
        packet.bytes
    }
}

/**
    Hostile adapter for the teardown-reentrancy regression: once armed, every teardown-time
    SendPacket re-enters the owning object's own Disconnect/Stop from inside the callback.
    The stop-in-progress guards in Client::Disconnect and Server::Stop must make those
    reentrant calls harmless no-ops — without them the inner call tears down the allocator
    the live netcode object was allocated from (leak assert in debug, use-after-free beyond).
 */

// port: `class ReentrantTeardownAdapter : public MemoryPacketAdapter` embeds the MemoryPacketAdapter as `base`
// (Deref to it, so base members read as upstream) and calls through it for the methods it does not override
struct ReentrantTeardownAdapter
{
    base: MemoryPacketAdapter,
    m_client: *mut Client,
    m_server: *mut Server,
    m_teardown: bool,
    m_reentrantCalls: i32,
}

impl ReentrantTeardownAdapter
{
    fn new( localAddress: &Address ) -> ReentrantTeardownAdapter
    {
        ReentrantTeardownAdapter
        {
            base: MemoryPacketAdapter::new( localAddress ),
            m_client: std::ptr::null_mut(),
            m_server: std::ptr::null_mut(),
            m_teardown: false,
            m_reentrantCalls: 0,
        }
    }

    fn BeginHostileTeardown( &mut self, client: *mut Client, server: *mut Server )
    {
        self.m_client = client;
        self.m_server = server;
        self.m_teardown = true;
    }

    fn ReentrantCalls( &self ) -> i32 { self.m_reentrantCalls }
}

impl std::ops::Deref for ReentrantTeardownAdapter
{
    type Target = MemoryPacketAdapter;
    fn deref( &self ) -> &MemoryPacketAdapter { &self.base }
}

impl std::ops::DerefMut for ReentrantTeardownAdapter
{
    fn deref_mut( &mut self ) -> &mut MemoryPacketAdapter { &mut self.base }
}

impl Adapter for ReentrantTeardownAdapter
{
    fn CreateMessageFactory( &mut self, allocator: *mut dyn Allocator ) -> *mut dyn MessageFactory
    {
        self.base.CreateMessageFactory( allocator )
    }

    fn UseCustomPacketIO( &self ) -> bool
    {
        self.base.UseCustomPacketIO()
    }

    fn SendPacket( &mut self, to: &Address, packetData: &[u8], packetBytes: i32 )
    {
        if self.m_teardown
        {
            self.m_reentrantCalls += 1;
            if !self.m_client.is_null()
            {
                unsafe { ( *self.m_client ).Disconnect(); }
            }
            if !self.m_server.is_null()
            {
                unsafe { ( *self.m_server ).Stop(); }
            }
        }
        self.base.SendPacket( to, packetData, packetBytes );
    }

    fn ReceivePacket( &mut self, from: &mut Address, packetData: &mut [u8], maxPacketBytes: i32 ) -> i32
    {
        self.base.ReceivePacket( from, packetData, maxPacketBytes )
    }
}

fn Require( condition: bool, message: &str ) -> bool
{
    if condition
    {
        return true;
    }
    print!( "FAIL: {}\n", message );
    false
}

fn main()
{
    if !InitializeYojimbo()
    {
        std::process::exit( 1 );
    }

    let mut ok = true;
    {
        let clientAddress = Address::from_string_port( "203.0.113.2", 41230 );
        let serverAddress = Address::from_string_port( "203.0.113.1", 41230 );
        let mut clientAdapter = MemoryPacketAdapter::new( &clientAddress );
        let mut serverAdapter = MemoryPacketAdapter::new( &serverAddress );
        // port: the client, the server and the peer adapter hold each adapter by pointer, as upstream holds it by
        // reference; the program reaches the adapters through those same pointers afterwards
        let clientAdapterPointer: *mut MemoryPacketAdapter = std::ptr::addr_of_mut!( clientAdapter );
        let serverAdapterPointer: *mut MemoryPacketAdapter = std::ptr::addr_of_mut!( serverAdapter );
        unsafe
        {
            ( *clientAdapterPointer ).Connect( serverAdapterPointer );
            ( *serverAdapterPointer ).Connect( clientAdapterPointer );
        }

        let mut config = ClientServerConfig::new();
        config.numChannels = 2;
        config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
        config.channel[1].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

        // port: memset( privateKey, 0, sizeof( privateKey ) ) is the zero initializer
        let privateKey = [0u8; KeyBytes as usize];
        let mut time: f64 = 100.0;

        // port: Server::new and Client::new return the object boxed (it must not move while in use)
        let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, serverAdapterPointer as *mut dyn Adapter, time );
        server.Start( 1 );
        let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, clientAdapterPointer as *mut dyn Adapter, time );
        client.InsecureConnect( &privateKey, 1, &serverAddress );

        let mut i = 0;
        while i < 256 && !client.IsConnected()
        {
            client.SendPackets();
            server.SendPackets();
            client.ReceivePackets();
            server.ReceivePackets();
            time += 0.1;
            client.AdvanceTime( time );
            server.AdvanceTime( time );
            i += 1;
        }

        ok &= Require( *client.GetAddress() == clientAddress, "client synthetic local address changed" );
        ok &= Require( *server.GetAddress() == serverAddress, "server synthetic local address changed" );
        ok &= Require( client.IsConnected(), "client did not connect over custom packet I/O" );
        ok &= Require( server.GetNumConnectedClients() == 1, "server did not admit the custom-I/O client" );
        ok &= Require( unsafe { ( *clientAdapterPointer ).SentPackets() > 0 && ( *clientAdapterPointer ).ReceivedPackets() > 0 },
                       "client adapter did not send and receive packets" );
        ok &= Require( unsafe { ( *serverAdapterPointer ).SentPackets() > 0 && ( *serverAdapterPointer ).ReceivedPackets() > 0 },
                       "server adapter did not send and receive packets" );

        // port: (TestMessage*) CreateMessage( ... ) stays a `*mut dyn Message`; message_cast reaches the TestMessage fields
        let toServer = client.CreateMessage( TEST_MESSAGE );
        let toClient = server.CreateMessage( 0, TEST_MESSAGE );
        ok &= Require( !toServer.is_null() && !toClient.is_null(), "could not allocate channel test messages" );
        if !toServer.is_null() && !toClient.is_null()
        {
            unsafe { message_cast::<TestMessage>( toServer ) }.sequence = 11;
            unsafe { message_cast::<TestMessage>( toClient ) }.sequence = 22;
            client.SendMessage( 0, toServer );
            server.SendMessage( 0, 1, toClient );

            let mut fromClient: *mut dyn Message = null_message();
            let mut fromServer: *mut dyn Message = null_message();
            let mut i = 0;
            while i < 256 && ( fromClient.is_null() || fromServer.is_null() )
            {
                client.SendPackets();
                server.SendPackets();
                client.ReceivePackets();
                server.ReceivePackets();
                if fromClient.is_null()
                {
                    fromClient = server.ReceiveMessage( 0, 0 );
                }
                if fromServer.is_null()
                {
                    fromServer = client.ReceiveMessage( 1 );
                }
                time += 0.1;
                client.AdvanceTime( time );
                server.AdvanceTime( time );
                i += 1;
            }

            ok &= Require( !fromClient.is_null() && unsafe { message_cast::<TestMessage>( fromClient ) }.sequence == 11,
                           "reliable client message did not cross custom packet I/O" );
            ok &= Require( !fromServer.is_null() && unsafe { message_cast::<TestMessage>( fromServer ) }.sequence == 22,
                           "unreliable server message did not cross custom packet I/O" );
            if !fromClient.is_null()
            {
                server.ReleaseMessage( 0, fromClient );
            }
            if !fromServer.is_null()
            {
                client.ReleaseMessage( fromServer );
            }
        }

        client.Disconnect();
        server.Stop();
    }

    // Scenario 2: hostile reentrant teardown. Connect and exchange messages as above, then tear
    // down with adapters that call the owning object's Disconnect/Stop from inside its own
    // teardown-time SendPacket callback. The test completing cleanly (no assert, no crash, no
    // leak) is the proof that teardown is reentrancy-safe.
    {
        let clientAddress = Address::from_string_port( "203.0.113.2", 41230 );
        let serverAddress = Address::from_string_port( "203.0.113.1", 41230 );
        let mut clientAdapter = ReentrantTeardownAdapter::new( &clientAddress );
        let mut serverAdapter = ReentrantTeardownAdapter::new( &serverAddress );
        // port: as in scenario 1, the adapters are reached through the pointers the client and server hold
        let clientAdapterPointer: *mut ReentrantTeardownAdapter = std::ptr::addr_of_mut!( clientAdapter );
        let serverAdapterPointer: *mut ReentrantTeardownAdapter = std::ptr::addr_of_mut!( serverAdapter );
        unsafe
        {
            ( *clientAdapterPointer ).Connect( std::ptr::addr_of_mut!( ( *serverAdapterPointer ).base ) );
            ( *serverAdapterPointer ).Connect( std::ptr::addr_of_mut!( ( *clientAdapterPointer ).base ) );
        }

        let mut config = ClientServerConfig::new();
        config.numChannels = 2;
        config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
        config.channel[1].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;

        // port: memset( privateKey, 0, sizeof( privateKey ) ) is the zero initializer
        let privateKey = [0u8; KeyBytes as usize];
        let mut time: f64 = 100.0;

        let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, serverAdapterPointer as *mut dyn Adapter, time );
        server.Start( 1 );
        let mut client = Client::new( GetDefaultAllocator(), &clientAddress, &config, clientAdapterPointer as *mut dyn Adapter, time );
        client.InsecureConnect( &privateKey, 1, &serverAddress );

        let mut i = 0;
        while i < 256 && !client.IsConnected()
        {
            client.SendPackets();
            server.SendPackets();
            client.ReceivePackets();
            server.ReceivePackets();
            time += 0.1;
            client.AdvanceTime( time );
            server.AdvanceTime( time );
            i += 1;
        }

        ok &= Require( client.IsConnected(), "client did not connect before the hostile teardown" );
        ok &= Require( server.GetNumConnectedClients() == 1, "server did not admit the client before the hostile teardown" );

        let toServer = client.CreateMessage( TEST_MESSAGE );
        let toClient = server.CreateMessage( 0, TEST_MESSAGE );
        ok &= Require( !toServer.is_null() && !toClient.is_null(), "could not allocate hostile-teardown test messages" );
        if !toServer.is_null() && !toClient.is_null()
        {
            unsafe { message_cast::<TestMessage>( toServer ) }.sequence = 33;
            unsafe { message_cast::<TestMessage>( toClient ) }.sequence = 44;
            client.SendMessage( 0, toServer );
            server.SendMessage( 0, 1, toClient );

            let mut fromClient: *mut dyn Message = null_message();
            let mut fromServer: *mut dyn Message = null_message();
            let mut i = 0;
            while i < 256 && ( fromClient.is_null() || fromServer.is_null() )
            {
                client.SendPackets();
                server.SendPackets();
                client.ReceivePackets();
                server.ReceivePackets();
                if fromClient.is_null()
                {
                    fromClient = server.ReceiveMessage( 0, 0 );
                }
                if fromServer.is_null()
                {
                    fromServer = client.ReceiveMessage( 1 );
                }
                time += 0.1;
                client.AdvanceTime( time );
                server.AdvanceTime( time );
                i += 1;
            }

            ok &= Require( !fromClient.is_null() && !fromServer.is_null(), "messages did not cross before the hostile teardown" );
            if !fromClient.is_null()
            {
                server.ReleaseMessage( 0, fromClient );
            }
            if !fromServer.is_null()
            {
                client.ReleaseMessage( fromServer );
            }
        }

        // Arm the adapters, then tear down. Stop the server first, while the client is still
        // connected, so netcode_server_stop actually sends disconnect packets (the reentrancy
        // window). The client has not processed those packets, so its own disconnect also
        // sends packets and re-enters on the client side.
        // port: the client and server are reached through raw pointers from here on, as the adapters reach them
        let clientPointer: *mut Client = &mut *client;
        let serverPointer: *mut Server = &mut *server;
        unsafe
        {
            ( *serverAdapterPointer ).BeginHostileTeardown( std::ptr::null_mut(), serverPointer );
            ( *clientAdapterPointer ).BeginHostileTeardown( clientPointer, std::ptr::null_mut() );
            ( *serverPointer ).Stop();
            ( *clientPointer ).Disconnect();
        }

        // Prove the hostile path actually ran — a teardown that never fired SendPacket would
        // pass without testing anything.
        ok &= Require( unsafe { ( *serverAdapterPointer ).ReentrantCalls() } > 0, "server teardown did not exercise the reentrant Stop path" );
        ok &= Require( unsafe { ( *clientAdapterPointer ).ReentrantCalls() } > 0, "client teardown did not exercise the reentrant Disconnect path" );

        // Teardown completed and the guards cleared: calling again must still be a safe no-op.
        unsafe
        {
            ( *serverPointer ).Stop();
            ( *clientPointer ).Disconnect();
        }
    }
    ShutdownYojimbo();

    if !ok
    {
        std::process::exit( 1 );
    }

    print!( "OK: custom packet I/O handshake and hostile reentrant teardown passed without native sockets\n" );
    std::process::exit( 0 );
}
