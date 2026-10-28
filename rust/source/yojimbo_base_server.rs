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

// port: include/yojimbo_base_server.h + source/yojimbo_base_server.cpp
//
// Port notes:
//   - BaseServer is a struct holding upstream's data members and non-virtual methods; a derived server (Server) embeds
//     it as `base` and implements ServerInterface, delegating to it (README, "Classes with virtual methods").
//   - The virtual calls BaseServer makes into the derived server (Stop and DisconnectClient from Start / AdvanceTime,
//     IsClientConnected from GetNetworkInfo, TransmitPacketFunction / ProcessPacketFunction / ResetClient) go through the
//     BaseServerVirtual trait below. The BaseServer methods that make them (Start, AdvanceTime, GetNetworkInfo) are
//     associated functions taking the derived server, `BaseServer::AdvanceTime( self, time )`, as C++ calls
//     `BaseServer::AdvanceTime( time )`.
//   - The reliable endpoint callbacks get the derived server as their `void * context`, as upstream passes `this`:
//     StaticTransmitPacketFunction / StaticProcessPacketFunction are generic over the derived type and turn the context
//     back into it. The server registers its own address, so it must not move between Start and Stop (Server::new
//     returns a Box for this reason).
//   - Reliable endpoints are created as Box (reliable_endpoint_create) and held as the raw pointer of that Box, as
//     upstream holds `reliable_endpoint_t *`, so a callback re-entering the server never aliases a Box field.

use crate::*;
use crate::reliable::*;
use std::ffi::c_void;
use std::ptr;

/**
    The virtual functions BaseServer calls on the server that derives from it.
 */

// port: BaseServer's protected virtual methods (pure virtual TransmitPacketFunction / ProcessPacketFunction, and ResetClient
// with its default body), plus access to the embedded BaseServer. The ServerInterface supertrait carries the public virtuals
// BaseServer calls (Stop, DisconnectClient, IsClientConnected).
pub trait BaseServerVirtual: ServerInterface
{
    // port: accessors for the embedded BaseServer
    fn base( &self ) -> &BaseServer;

    fn base_mut( &mut self ) -> &mut BaseServer;

    fn TransmitPacketFunction( &mut self, clientIndex: i32, packetSequence: u16, packetData: &[u8], packetBytes: i32 );

    fn ProcessPacketFunction( &mut self, clientIndex: i32, packetSequence: u16, packetData: &[u8], packetBytes: i32 ) -> i32;

    // protected:

    fn ResetClient( &mut self, clientIndex: i32 )
    {
        self.base_mut().ResetClient( clientIndex );
    }
}

/**
    Common functionality across all server implementations.
 */

pub struct BaseServer
{
    m_config: ClientServerConfig,                                           //< Base client/server config.
    m_allocator: *mut dyn Allocator,                                        //< Allocator passed in to constructor.
    m_adapter: *mut dyn Adapter,                                            //< The adapter specifies the allocator to use, and the message factory class.
    m_context: *mut c_void,                                                 //< Optional serialization context.
    m_maxClients: i32,                                                      //< Maximum number of clients supported.
    m_running: bool,                                                        //< True if server is currently running, eg. after "Start" is called, before "Stop".
    m_time: f64,                                                            //< Current server time in seconds.
    m_globalMemory: *mut u8,                                                //< The block of memory backing the global allocator. Allocated with m_allocator.
    m_clientMemory: [*mut u8; MaxClients as usize],                         //< The block of memory backing the per-client allocators. Allocated with m_allocator.
    m_globalAllocator: *mut dyn Allocator,                                  //< The global allocator. Used for allocations that don't belong to a specific client.
    m_clientAllocator: [*mut dyn Allocator; MaxClients as usize],           //< Array of per-client allocator. These are used for allocations related to connected clients.
    m_clientMessageFactory: [*mut dyn MessageFactory; MaxClients as usize], //< Array of per-client message factories. This silos message allocations per-client slot.
    m_clientConnection: [*mut Connection; MaxClients as usize],             //< Array of per-client connection classes. This is how messages are exchanged with clients.
    m_clientEndpoint: [*mut reliable_endpoint_t; MaxClients as usize],      //< Array of per-client reliable endpoints. port: the raw pointer of the Box reliable_endpoint_create returns
    m_clientDisconnectReason: [i32; MaxClients as usize],                   //< Per-client slot reason the last client in that slot was disconnected (ServerClientDisconnectReason). Reset to none at server start, and when a new client connects to the slot.
    m_networkSimulator: *mut NetworkSimulator,                              //< The network simulator used to simulate packet loss, latency, jitter etc. Optional.
    m_packetBuffer: *mut u8,                                                //< Buffer used when writing packets.
}

impl BaseServer
{
    pub fn new( allocator: *mut dyn Allocator, config: &ClientServerConfig, adapter: *mut dyn Adapter, time: f64 ) -> BaseServer
    {
        BaseServer
        {
            m_config: config.clone(),
            m_allocator: allocator,
            m_adapter: adapter,
            m_context: ptr::null_mut(),
            m_time: time,
            m_running: false,
            m_maxClients: 0,
            m_globalMemory: ptr::null_mut(),
            m_globalAllocator: null_allocator(),
            m_clientMemory: [ptr::null_mut(); MaxClients as usize],
            m_clientAllocator: [null_allocator(); MaxClients as usize],
            m_clientMessageFactory: [null_message_factory(); MaxClients as usize],
            m_clientConnection: [ptr::null_mut(); MaxClients as usize],
            m_clientEndpoint: [ptr::null_mut(); MaxClients as usize],
            m_clientDisconnectReason: [YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE; MaxClients as usize],
            m_networkSimulator: ptr::null_mut(),
            m_packetBuffer: ptr::null_mut(),
        }
    }
}

// port: ~BaseServer()
impl Drop for BaseServer
{
    fn drop( &mut self )
    {
        // IMPORTANT: Please stop the server before destroying it!
        yojimbo_assert!( !self.IsRunning () );
        self.m_allocator = null_allocator();
    }
}

impl BaseServer
{
    pub fn SetContext( &mut self, context: *mut c_void )
    {
        yojimbo_assert!( !self.IsRunning() );
        self.m_context = context;
    }

    // Startup is transactional: every allocation and every adapter factory result is checked in
    // every build (Debug and Release alike -- yojimbo_assert compiles out under NDEBUG, so an
    // assert is not a check), and the first failure unwinds through Stop() and leaves the server
    // stopped and holding nothing. The caller learns that from the return value.

    /**
        Allocate the global and per-client memory the server needs to run.
        Transactional: on the first allocation or adapter factory failure everything already
        created is destroyed, the server is left stopped, and false is returned. Checked in
        every build, not by an assert.
     */

    // port: takes the derived server, as Stop() here is the virtual Server::Stop, and `this` is the reliable callback context
    pub fn Start<T: BaseServerVirtual>( this: &mut T, maxClients: i32 ) -> bool
    {
        yojimbo_assert!( maxClients > 0 );
        yojimbo_assert!( maxClients <= MaxClients );

        this.base().m_config.Validate();

        this.Stop();

        let context: *mut c_void = this as *mut T as *mut c_void;

        {
            let base = this.base_mut();

            base.m_running = true;
            base.m_maxClients = maxClients;

            for i in 0..MaxClients as usize
            {
                base.m_clientDisconnectReason[i] = YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE;
            }

            yojimbo_assert!( base.m_globalMemory.is_null() );
            yojimbo_assert!( base.m_globalAllocator.is_null() );
            base.m_globalMemory = YOJIMBO_ALLOCATE!( base.m_allocator, base.m_config.serverGlobalMemory );
        }
        if this.base().m_globalMemory.is_null()
        {
            this.Stop();
            return false;
        }

        {
            let base = this.base_mut();
            base.m_globalAllocator = unsafe { ( *base.m_adapter ).CreateAllocator( base.m_allocator, base.m_globalMemory, base.m_config.serverGlobalMemory as usize ) };
        }
        if this.base().m_globalAllocator.is_null()
        {
            this.Stop();
            return false;
        }

        if this.base().m_config.networkSimulator
        {
            {
                let base = this.base_mut();
                let globalAllocator = base.m_globalAllocator;
                let maxSimulatorPackets = base.m_config.maxSimulatorPackets;
                let time = base.m_time;
                base.m_networkSimulator = YOJIMBO_NEW!( globalAllocator, NetworkSimulator, NetworkSimulator::new( globalAllocator, maxSimulatorPackets, time ) );
            }
            if this.base().m_networkSimulator.is_null()
            {
                this.Stop();
                return false;
            }
        }

        let mut i: i32 = 0;
        while i < this.base().m_maxClients
        {
            let ci = i as usize;

            {
                let base = this.base_mut();

                yojimbo_assert!( base.m_clientMemory[ci].is_null() );
                yojimbo_assert!( base.m_clientAllocator[ci].is_null() );

                base.m_clientMemory[ci] = YOJIMBO_ALLOCATE!( base.m_allocator, base.m_config.serverPerClientMemory );
            }
            if this.base().m_clientMemory[ci].is_null()
            {
                this.Stop();
                return false;
            }

            {
                let base = this.base_mut();
                base.m_clientAllocator[ci] = unsafe { ( *base.m_adapter ).CreateAllocator( base.m_allocator, base.m_clientMemory[ci], base.m_config.serverPerClientMemory as usize ) };
            }
            if this.base().m_clientAllocator[ci].is_null()
            {
                this.Stop();
                return false;
            }

            {
                let base = this.base_mut();
                base.m_clientMessageFactory[ci] = unsafe { ( *base.m_adapter ).CreateMessageFactory( base.m_clientAllocator[ci] ) };
            }
            if this.base().m_clientMessageFactory[ci].is_null()
            {
                this.Stop();
                return false;
            }

            {
                let base = this.base_mut();
                let clientAllocator = base.m_clientAllocator[ci];
                let clientMessageFactory = base.m_clientMessageFactory[ci];
                let time = base.m_time;
                base.m_clientConnection[ci] = YOJIMBO_NEW!( clientAllocator, Connection, Connection::new( clientAllocator, clientMessageFactory, &base.m_config, time ) );
            }
            if this.base().m_clientConnection[ci].is_null()
            {
                this.Stop();
                return false;
            }

            {
                let base = this.base_mut();

                let mut reliable_config = reliable_config_t::default();
                reliable_default_config( &mut reliable_config );
                let nameSize = reliable_config.name.len();
                yojimbo_copy_string( &mut reliable_config.name, "server endpoint", nameSize );
                reliable_config.context = context;
                reliable_config.id = i as u64;
                reliable_config.max_packet_size = base.m_config.maxPacketSize;
                reliable_config.fragment_above = base.m_config.fragmentPacketsAbove;
                reliable_config.max_fragments = base.m_config.maxPacketFragments;
                reliable_config.fragment_size = base.m_config.packetFragmentSize;
                reliable_config.ack_buffer_size = base.m_config.ackedPacketsBufferSize;
                reliable_config.received_packets_buffer_size = base.m_config.receivedPacketsBufferSize;
                reliable_config.fragment_reassembly_buffer_size = base.m_config.packetReassemblyBufferSize;
                reliable_config.rtt_smoothing_factor = base.m_config.rttSmoothingFactor;
                reliable_config.transmit_packet_function = Some( BaseServer::StaticTransmitPacketFunction::<T> );
                reliable_config.process_packet_function = Some( BaseServer::StaticProcessPacketFunction::<T> );
                reliable_config.allocator_context = base.GetGlobalAllocatorContext();
                reliable_config.allocate_function = Some( BaseServer::StaticAllocateFunction );
                reliable_config.free_function = Some( BaseServer::StaticFreeFunction );
                let time = base.m_time;
                base.m_clientEndpoint[ci] = match reliable_endpoint_create( &reliable_config, time )
                {
                    Some( endpoint ) => Box::into_raw( endpoint ),
                    None => ptr::null_mut(),
                };
            }
            if this.base().m_clientEndpoint[ci].is_null()
            {
                this.Stop();
                return false;
            }
            reliable_endpoint_reset( unsafe { &mut *this.base().m_clientEndpoint[ci] } );

            i += 1;
        }
        {
            let base = this.base_mut();
            base.m_packetBuffer = YOJIMBO_ALLOCATE!( base.m_globalAllocator, base.m_config.maxPacketSize );
        }
        if this.base().m_packetBuffer.is_null()
        {
            this.Stop();
            return false;
        }
        true
    }

    // Safe to call on a partially started server: Start unwinds through it, so every slot is
    // torn down by what it actually holds rather than by what a complete start would have held.
    pub fn Stop( &mut self )
    {
        if self.IsRunning()
        {
            if !self.m_globalAllocator.is_null()
            {
                YOJIMBO_FREE!( self.m_globalAllocator, self.m_packetBuffer );
                YOJIMBO_DELETE!( self.m_globalAllocator, NetworkSimulator, self.m_networkSimulator );
            }
            for i in 0..MaxClients as usize
            {
                if !self.m_clientEndpoint[i].is_null()
                {
                    reliable_endpoint_destroy( unsafe { Box::from_raw( self.m_clientEndpoint[i] ) } );
                    self.m_clientEndpoint[i] = ptr::null_mut();
                }
                if !self.m_clientAllocator[i].is_null()
                {
                    YOJIMBO_DELETE!( self.m_clientAllocator[i], Connection, self.m_clientConnection[i] );
                    YOJIMBO_DELETE!( self.m_clientAllocator[i], dyn MessageFactory, self.m_clientMessageFactory[i] );
                    YOJIMBO_DELETE!( self.m_allocator, dyn Allocator, self.m_clientAllocator[i] );
                }
                YOJIMBO_FREE!( self.m_allocator, self.m_clientMemory[i] );
            }
            YOJIMBO_DELETE!( self.m_allocator, dyn Allocator, self.m_globalAllocator );
            YOJIMBO_FREE!( self.m_allocator, self.m_globalMemory );
        }
        for i in 0..MaxClients as usize
        {
            self.m_clientMemory[i] = ptr::null_mut();
            self.m_clientAllocator[i] = null_allocator();
            self.m_clientMessageFactory[i] = null_message_factory();
            self.m_clientConnection[i] = ptr::null_mut();
            self.m_clientEndpoint[i] = ptr::null_mut();
        }
        self.m_networkSimulator = ptr::null_mut();
        self.m_running = false;
        self.m_maxClients = 0;
        self.m_packetBuffer = ptr::null_mut();
    }
}

// Map the error that drove a connection into an error state to the disconnect reason we
// record for the client slot. For channel errors, drill into the channels to find the one
// in error, because that is where the actionable detail lives (eg. serialize failure vs
// desync vs out of memory).
fn ClientDisconnectReasonForConnectionError( connection: &Connection, errorLevel: ConnectionErrorLevel, numChannels: i32 ) -> i32
{
    match errorLevel
    {
        CONNECTION_ERROR_ALLOCATOR =>            return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
        CONNECTION_ERROR_MESSAGE_FACTORY =>      return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
        CONNECTION_ERROR_READ_PACKET_FAILED =>   return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED,

        CONNECTION_ERROR_CHANNEL =>
        {
            for i in 0..numChannels
            {
                match connection.GetChannelErrorLevel( i )
                {
                    CHANNEL_ERROR_DESYNC =>                 return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC,
                    CHANNEL_ERROR_SEND_QUEUE_FULL =>        return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL,
                    CHANNEL_ERROR_BLOCKS_DISABLED =>        return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED,
                    CHANNEL_ERROR_FAILED_TO_SERIALIZE =>    return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE,
                    CHANNEL_ERROR_OUT_OF_MEMORY =>          return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
                    CHANNEL_ERROR_MESSAGE_TOO_LARGE =>      return YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE,
                    CHANNEL_ERROR_NONE =>                   {}
                    _ =>                                    {}      // port: the error level is an i32, so the match needs a catch-all
                }
            }
        }

        CONNECTION_ERROR_NONE => {}

        _ => {}     // port: the error level is an i32, so the match needs a catch-all
    }

    // A connection in an error state always matches one of the cases above; keep a sane
    // value if that ever changes rather than reporting garbage.
    YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED
}

impl BaseServer
{
    // port: takes the derived server, as DisconnectClient() here is the virtual Server::DisconnectClient
    pub fn AdvanceTime<T: BaseServerVirtual + ?Sized>( this: &mut T, time: f64 )
    {
        this.base_mut().m_time = time;
        if this.base().IsRunning()
        {
            // port: a while loop re-reading m_maxClients each iteration, as the C++ for loop does
            let mut i: i32 = 0;
            while i < this.base().m_maxClients
            {
                let ci = i as usize;
                let connection: *mut Connection = this.base().m_clientConnection[ci];
                let connectionErrorLevel: ConnectionErrorLevel;
                unsafe
                {
                    ( *connection ).AdvanceTime( time );
                    connectionErrorLevel = ( *connection ).GetErrorLevel();
                }
                if connectionErrorLevel != CONNECTION_ERROR_NONE
                {
                    yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "client {} connection is in error state. disconnecting client\n", i );
                    let numChannels = this.base().m_config.numChannels;
                    let reason = ClientDisconnectReasonForConnectionError( unsafe { &*connection }, connectionErrorLevel, numChannels );
                    this.base_mut().SetClientDisconnectReason( i, reason );
                    this.DisconnectClient( i );
                    i += 1;
                    continue;
                }
                let base = this.base_mut();
                let endpoint: &mut reliable_endpoint_t = unsafe { &mut *base.m_clientEndpoint[ci] };
                reliable_endpoint_update( endpoint, base.m_time );
                let mut numAcks: i32 = 0;
                let acks: &[u16] = reliable_endpoint_get_acks( endpoint, &mut numAcks );
                unsafe { ( *connection ).ProcessAcks( acks, numAcks ) };
                reliable_endpoint_clear_acks( endpoint );
                i += 1;
            }
            let networkSimulator: *mut NetworkSimulator = this.base().GetNetworkSimulator();
            if !networkSimulator.is_null()
            {
                unsafe { ( *networkSimulator ).AdvanceTime( time ) };
            }
        }
    }

    pub fn IsRunning( &self ) -> bool { self.m_running }

    pub fn GetMaxClients( &self ) -> i32 { self.m_maxClients }

    pub fn GetTime( &self ) -> f64 { self.m_time }

    pub fn SetLatency( &mut self, milliseconds: f32 )
    {
        yojimbo_assert!( !self.m_networkSimulator.is_null() );
        if !self.m_networkSimulator.is_null()
        {
            unsafe { ( *self.m_networkSimulator ).SetLatency( milliseconds ) };
        }
    }

    pub fn SetJitter( &mut self, milliseconds: f32 )
    {
        yojimbo_assert!( !self.m_networkSimulator.is_null() );
        if !self.m_networkSimulator.is_null()
        {
            unsafe { ( *self.m_networkSimulator ).SetJitter( milliseconds ) };
        }
    }

    pub fn SetPacketLoss( &mut self, percent: f32 )
    {
        yojimbo_assert!( !self.m_networkSimulator.is_null() );
        if !self.m_networkSimulator.is_null()
        {
            unsafe { ( *self.m_networkSimulator ).SetPacketLoss( percent ) };
        }
    }

    pub fn SetDuplicates( &mut self, percent: f32 )
    {
        yojimbo_assert!( !self.m_networkSimulator.is_null() );
        if !self.m_networkSimulator.is_null()
        {
            unsafe { ( *self.m_networkSimulator ).SetDuplicates( percent ) };
        }
    }

    pub fn CreateMessage( &mut self, clientIndex: i32, r#type: i32 ) -> *mut dyn Message
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !self.m_clientMessageFactory[clientIndex as usize].is_null() );
        unsafe { ( *self.m_clientMessageFactory[clientIndex as usize] ).CreateMessage( r#type ) }
    }

    pub fn AllocateBlock( &mut self, clientIndex: i32, bytes: i32 ) -> *mut u8
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !self.m_clientAllocator[clientIndex as usize].is_null() );
        YOJIMBO_ALLOCATE!( self.m_clientAllocator[clientIndex as usize], bytes )
    }

    pub fn AttachBlockToMessage( &mut self, clientIndex: i32, message: *mut dyn Message, block: *mut u8, bytes: i32 )
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !message.is_null() );
        yojimbo_assert!( !block.is_null() );
        yojimbo_assert!( bytes > 0 );
        yojimbo_assert!( unsafe { ( *message ).IsBlockMessage() } );
        // port: the C-style cast to BlockMessage * is the AsBlockMessage downcast
        let blockMessage: Option<&mut BlockMessage> = unsafe { ( *message ).AsBlockMessage() };
        yojimbo_assert!( blockMessage.is_some() );
        if let Some( blockMessage ) = blockMessage
        {
            blockMessage.AttachBlock( self.m_clientAllocator[clientIndex as usize], block, bytes );
        }
    }

    pub fn FreeBlock( &mut self, clientIndex: i32, block: *mut u8 )
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        let mut block = block;
        YOJIMBO_FREE!( self.m_clientAllocator[clientIndex as usize], block );
    }

    pub fn CanSendMessage( &self, clientIndex: i32, channelIndex: i32 ) -> bool
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_config.numChannels );
        yojimbo_assert!( !self.m_clientConnection[clientIndex as usize].is_null() );
        unsafe { ( *self.m_clientConnection[clientIndex as usize] ).CanSendMessage( channelIndex ) }
    }

    pub fn HasMessagesToSend( &self, clientIndex: i32, channelIndex: i32 ) -> bool
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !self.m_clientConnection[clientIndex as usize].is_null() );
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_config.numChannels );
        unsafe { ( *self.m_clientConnection[clientIndex as usize] ).HasMessagesToSend( channelIndex ) }
    }

    pub fn SendMessage( &mut self, clientIndex: i32, channelIndex: i32, message: *mut dyn Message )
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !self.m_clientConnection[clientIndex as usize].is_null() );
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_config.numChannels );
        let context = self.GetContext();
        unsafe { ( *self.m_clientConnection[clientIndex as usize] ).SendMessage( channelIndex, message, context ) }
    }

    pub fn ReceiveMessage( &mut self, clientIndex: i32, channelIndex: i32 ) -> *mut dyn Message
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !self.m_clientConnection[clientIndex as usize].is_null() );
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_config.numChannels );
        unsafe { ( *self.m_clientConnection[clientIndex as usize] ).ReceiveMessage( channelIndex ) }
    }

    pub fn ReleaseMessage( &mut self, clientIndex: i32, message: *mut dyn Message )
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !self.m_clientConnection[clientIndex as usize].is_null() );
        unsafe { ( *self.m_clientConnection[clientIndex as usize] ).ReleaseMessage( message ) };
    }

    // port: takes the derived server, as IsClientConnected() here is the virtual Server::IsClientConnected
    pub fn GetNetworkInfo<T: BaseServerVirtual + ?Sized>( this: &T, clientIndex: i32, info: &mut NetworkInfo )
    {
        let base = this.base();
        yojimbo_assert!( base.IsRunning() );
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < base.m_maxClients );
        // port: memset( &info, 0, sizeof( info ) )
        *info = NetworkInfo::default();
        if this.IsClientConnected( clientIndex )
        {
            yojimbo_assert!( !base.m_clientEndpoint[clientIndex as usize].is_null() );
            let endpoint: &reliable_endpoint_t = unsafe { &*base.m_clientEndpoint[clientIndex as usize] };
            let counters: &[u64] = reliable_endpoint_counters( endpoint );
            info.numPacketsSent = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT];
            info.numPacketsReceived = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
            info.numPacketsAcked = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
            info.RTT = reliable_endpoint_rtt( endpoint );
            info.minRTT = reliable_endpoint_rtt_min( endpoint );
            info.maxRTT = reliable_endpoint_rtt_max( endpoint );
            info.averageRTT = reliable_endpoint_rtt_avg( endpoint );
            info.averageJitter = reliable_endpoint_jitter_avg_vs_min_rtt( endpoint );
            info.maxJitter = reliable_endpoint_jitter_max_vs_min_rtt( endpoint );
            info.stddevJitter = reliable_endpoint_jitter_stddev_vs_avg_rtt( endpoint );
            info.packetLoss = reliable_endpoint_packet_loss( endpoint );
            reliable_endpoint_bandwidth( endpoint, &mut info.sentBandwidth, &mut info.receivedBandwidth, &mut info.ackedBandwidth );
        }
    }

    // port: GetClientDisconnectReason is defined further down, with the .cpp definitions

    // protected:
    // port: the protected members are pub, since the derived server lives in another module

    pub fn GetPacketBuffer( &mut self ) -> *mut u8 { self.m_packetBuffer }

    pub fn GetContext( &self ) -> *mut c_void { self.m_context }

    pub fn GetAdapter( &mut self ) -> &mut dyn Adapter { yojimbo_assert!( !self.m_adapter.is_null() ); unsafe { &mut *self.m_adapter } }

    // port: `Allocator &` is the `*mut dyn Allocator` every allocator API takes
    pub fn GetGlobalAllocator( &mut self ) -> *mut dyn Allocator { yojimbo_assert!( !self.m_globalAllocator.is_null() ); self.m_globalAllocator }

    // port: `&GetGlobalAllocator()` as a `void * allocator_context`. A `*mut dyn Allocator` is a fat pointer and does not fit
    // in a `void *`, so the context is the address of the m_globalAllocator member holding it, which stays put while the
    // server is running. StaticAllocateFunction / StaticFreeFunction read the allocator back through it.
    pub fn GetGlobalAllocatorContext( &mut self ) -> *mut c_void
    {
        yojimbo_assert!( !self.m_globalAllocator.is_null() );
        &mut self.m_globalAllocator as *mut *mut dyn Allocator as *mut c_void
    }

    // port: GetClientMessageFactory, GetClientEndpoint and GetClientConnection are defined further down, with the .cpp definitions

    pub fn GetNetworkSimulator( &self ) -> *mut NetworkSimulator { self.m_networkSimulator }
}

impl BaseServer
{
    pub fn GetClientMessageFactory( &mut self, clientIndex: i32 ) -> &mut dyn MessageFactory
    {
        yojimbo_assert!( self.IsRunning() );
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        unsafe { &mut *self.m_clientMessageFactory[clientIndex as usize] }
    }

    // port: `reliable_endpoint_t *` is never NULL while the server is running, so this returns the reference
    pub fn GetClientEndpoint( &mut self, clientIndex: i32 ) -> &mut reliable_endpoint_t
    {
        yojimbo_assert!( self.IsRunning() );
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !self.m_clientEndpoint[clientIndex as usize].is_null() );
        unsafe { &mut *self.m_clientEndpoint[clientIndex as usize] }
    }

    pub fn GetClientConnection( &mut self, clientIndex: i32 ) -> &mut Connection
    {
        yojimbo_assert!( self.IsRunning() );
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        yojimbo_assert!( !self.m_clientConnection[clientIndex as usize].is_null() );
        unsafe { &mut *self.m_clientConnection[clientIndex as usize] }
    }

    // port: generic over the derived server: the context is the derived server Start registered (upstream's `this`)
    pub fn StaticTransmitPacketFunction<T: BaseServerVirtual>( context: *mut c_void, index: u64, packetSequence: u16, packetData: &[u8], packetBytes: i32 )
    {
        let server: &mut T = unsafe { &mut *( context as *mut T ) };
        server.TransmitPacketFunction( index as i32, packetSequence, packetData, packetBytes );
    }

    pub fn StaticProcessPacketFunction<T: BaseServerVirtual>( context: *mut c_void, index: u64, packetSequence: u16, packetData: &[u8], packetBytes: i32 ) -> i32
    {
        let server: &mut T = unsafe { &mut *( context as *mut T ) };
        server.ProcessPacketFunction( index as i32, packetSequence, packetData, packetBytes )
    }

    // port: the context points at a `*mut dyn Allocator` (see GetGlobalAllocatorContext)
    pub fn StaticAllocateFunction( context: *mut c_void, bytes: usize ) -> *mut c_void
    {
        yojimbo_assert!( !context.is_null() );
        let allocator: *mut dyn Allocator = unsafe { *( context as *mut *mut dyn Allocator ) };
        YOJIMBO_ALLOCATE!( allocator, bytes ) as *mut c_void
    }

    pub fn StaticFreeFunction( context: *mut c_void, pointer: *mut c_void )
    {
        yojimbo_assert!( !context.is_null() );
        yojimbo_assert!( !pointer.is_null() );
        let allocator: *mut dyn Allocator = unsafe { *( context as *mut *mut dyn Allocator ) };
        let mut pointer = pointer as *mut u8;
        YOJIMBO_FREE!( allocator, pointer );
    }

    /**
        Get the reason the client in this slot was last disconnected.
        Valid while the server is running. Recorded before Adapter::OnServerClientDisconnected is called,
        so you can query it from inside that callback. See ServerClientDisconnectReason for the values.
        @param clientIndex The index of the client slot in [0,maxClients-1].
        @returns The disconnect reason (a ServerClientDisconnectReason value). YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE if no client has disconnected from this slot since the server started, or if a new client has since connected to it.
     */

    pub fn GetClientDisconnectReason( &self, clientIndex: i32 ) -> i32
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        self.m_clientDisconnectReason[clientIndex as usize]
    }

    // port: protected upstream
    pub fn SetClientDisconnectReason( &mut self, clientIndex: i32, disconnectReason: i32 )
    {
        yojimbo_assert!( clientIndex >= 0 );
        yojimbo_assert!( clientIndex < self.m_maxClients );
        self.m_clientDisconnectReason[clientIndex as usize] = disconnectReason;
    }

    // port: the body of the virtual BaseServer::ResetClient; BaseServerVirtual::ResetClient calls it by default
    pub fn ResetClient( &mut self, clientIndex: i32 )
    {
        unsafe { ( *self.m_clientConnection[clientIndex as usize] ).Reset() };
    }
}
