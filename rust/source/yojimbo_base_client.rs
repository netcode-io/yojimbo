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

// port: include/yojimbo_base_client.h + source/yojimbo_base_client.cpp
//
// class BaseClient : public ClientInterface is extended (by Client), so it is a struct holding its data members and
// non-virtual methods, which the derived client embeds as `base` and delegates to (README, "Classes with virtual
// methods"). Its virtual methods are split three ways:
//   - The ClientInterface methods BaseClient implements are inherent methods here. The derived client's
//     `impl ClientInterface` delegates to them (`fn IsConnected( &self ) -> bool { self.base.IsConnected() }`).
//   - BaseClient's own virtual methods (the pure virtual TransmitPacketFunction and ProcessPacketFunction, and Reset)
//     are the trait BaseClientVirtual, which the derived client implements.
//   - The methods that make virtual calls on `this` (Disconnect calls Reset, AdvanceTime calls Disconnect,
//     CreateInternal registers `this` as the reliable endpoint context) are associated functions taking the derived
//     client as `this: &mut T`, so those calls dispatch to the derived client as in C++. The derived client calls
//     them as `BaseClient::AdvanceTime( self, time )` where C++ writes `BaseClient::AdvanceTime( time )`.
//
// Callback contexts: as upstream, the reliable endpoint's context is `this` -- the derived client, the outermost
// object -- and the static callbacks turn it back into the derived client in an unsafe block. The pointer is taken in
// CreateInternal and used until DestroyInternal, so the derived client must not move in between (Client::new boxes
// the client for this reason).

use crate::*;
use crate::reliable::*;
use std::ffi::c_void;

/**
    Functionality that is common across all client implementations.
 */

pub struct BaseClient
{
    m_config: ClientServerConfig,                                       //< The client/server configuration.
    m_allocator: *mut dyn Allocator,                                    //< The allocator passed to the client on creation.
    m_adapter: *mut dyn Adapter,                                        //< The adapter specifies the allocator to use, and the message factory class.
    m_context: *mut c_void,                                             //< Context lets the user pass information to packet serialize functions.
    m_clientMemory: *mut u8,                                            //< The memory backing the client allocator. Allocated from m_allocator.
    m_clientAllocator: *mut dyn Allocator,                              //< The client allocator. Everything allocated between connect and disconnected is allocated and freed via this allocator.
    m_endpoint: *mut reliable_endpoint_t,                               //< reliable endpoint. port: the Box from reliable_endpoint_create, held as a raw pointer (Box::into_raw / Box::from_raw) so it can be NULL and reached from &self and from the callbacks, as upstream.
    m_messageFactory: *mut dyn MessageFactory,                          //< The client message factory. Created and destroyed on each connection attempt.
    m_connection: *mut Connection,                                      //< The client connection for exchanging messages with the server.
    m_networkSimulator: *mut NetworkSimulator,                          //< The network simulator used to simulate packet loss, latency, jitter etc. Optional.
    m_clientState: ClientState,                                         //< The current client state. See ClientInterface::GetClientState
    m_clientIndex: i32,                                                 //< The client slot index on the server [0,maxClients-1]. -1 if not connected.
    m_disconnectReason: i32,                                            //< The reason this client was last disconnected (ClientDisconnectReason). Cleared back to none when a new connect attempt starts.
    m_time: f64,                                                        //< The current client time. See ClientInterface::AdvanceTime
    m_packetBuffer: *mut u8,                                            //< Buffer used to read and write packets.
}

// port: BaseClient( const BaseClient & other ) and operator = are private and undefined upstream (non-copyable); a
// Rust struct is not Clone or Copy unless it says so.

/**
    BaseClient's own virtual methods, implemented by the derived client.
 */

// port: the protected virtual methods of BaseClient (see the top of the file). base() / base_mut() return the embedded
// BaseClient, as the README's `<Class>Base` traits do.
pub trait BaseClientVirtual: ClientInterface
{
    /// port: the embedded BaseClient
    fn base( &self ) -> &BaseClient;

    /// port: the embedded BaseClient
    fn base_mut( &mut self ) -> &mut BaseClient;

    fn TransmitPacketFunction( &mut self, packetSequence: u16, packetData: &[u8], packetBytes: i32 );

    fn ProcessPacketFunction( &mut self, packetSequence: u16, packetData: &[u8], packetBytes: i32 ) -> i32;

    // protected:

    /// port: virtual void Reset(), with BaseClient::Reset as the default body
    fn Reset( &mut self )
    {
        self.base_mut().Reset();
    }
}

impl BaseClient
{
    /**
        Base client constructor.
        @param allocator The allocator for all memory used by the client.
        @param config The base client/server configuration.
        @param time The current time in seconds. See ClientInterface::AdvanceTime
        @param adapter The adapter to the game program. Specifies allocators, message factory to use etc.
     */

    pub fn new( allocator: *mut dyn Allocator, config: &ClientServerConfig, adapter: *mut dyn Adapter, time: f64 ) -> BaseClient
    {
        BaseClient
        {
            m_config: *config,
            m_allocator: allocator,
            m_adapter: adapter,
            m_time: time,
            m_context: std::ptr::null_mut(),
            m_clientMemory: std::ptr::null_mut(),
            m_clientAllocator: null_allocator(),
            m_endpoint: std::ptr::null_mut(),
            m_connection: std::ptr::null_mut(),
            m_messageFactory: null_message_factory(),
            m_networkSimulator: std::ptr::null_mut(),
            m_clientState: CLIENT_STATE_DISCONNECTED,
            m_clientIndex: -1,
            m_disconnectReason: YOJIMBO_CLIENT_DISCONNECT_REASON_NONE,
            m_packetBuffer: std::ptr::null_mut(),
        }
    }
}

// port: ~BaseClient(). It runs after the derived client's Drop, as the C++ base destructor does.
impl Drop for BaseClient
{
    fn drop( &mut self )
    {
        // IMPORTANT: Please disconnect the client before destroying it
        yojimbo_assert!( self.m_clientState <= CLIENT_STATE_DISCONNECTED );
        yojimbo_assert!( self.m_packetBuffer.is_null() );
        self.m_allocator = null_allocator();
    }
}

// port: the methods defined inline in the header, in header order
impl BaseClient
{
    pub fn SetContext( &mut self, context: *mut c_void ) { yojimbo_assert!( self.IsDisconnected() ); self.m_context = context; }

    pub fn IsConnecting( &self ) -> bool { self.m_clientState == CLIENT_STATE_CONNECTING }

    pub fn IsConnected( &self ) -> bool { self.m_clientState == CLIENT_STATE_CONNECTED }

    pub fn IsDisconnected( &self ) -> bool { self.m_clientState <= CLIENT_STATE_DISCONNECTED }

    pub fn ConnectionFailed( &self ) -> bool { self.m_clientState == CLIENT_STATE_ERROR }

    pub fn GetClientState( &self ) -> ClientState { self.m_clientState }

    pub fn GetClientIndex( &self ) -> i32 { self.m_clientIndex }

    pub fn GetTime( &self ) -> f64 { self.m_time }

    /**
        Get the reason this client was last disconnected.
        See ClientDisconnectReason for the values. Cleared back to YOJIMBO_CLIENT_DISCONNECT_REASON_NONE
        when a new connect attempt starts.
        @returns The disconnect reason (a ClientDisconnectReason value). YOJIMBO_CLIENT_DISCONNECT_REASON_NONE if no disconnect has happened yet.
     */

    pub fn GetDisconnectReason( &self ) -> i32 { self.m_disconnectReason }

    // protected:
    // port: the protected members are pub, so a client derived in another module (Client) can reach them

    pub fn SetDisconnectReason( &mut self, disconnectReason: i32 ) { self.m_disconnectReason = disconnectReason; }

    pub fn GetPacketBuffer( &mut self ) -> *mut u8 { self.m_packetBuffer }

    pub fn GetContext( &self ) -> *mut c_void { self.m_context }

    pub fn GetAdapter( &mut self ) -> &mut dyn Adapter { yojimbo_assert!( !self.m_adapter.is_null() ); unsafe { &mut *self.m_adapter } }

    pub fn GetClientAllocator( &mut self ) -> *mut dyn Allocator { yojimbo_assert!( !self.m_clientAllocator.is_null() ); self.m_clientAllocator }

    /// port: `&GetClientAllocator()` as a `void *` allocator context for netcode and reliable, which can't hold a
    /// `*mut dyn Allocator` (a fat pointer): a pointer to m_clientAllocator instead (see AllocatorToContext). It stays
    /// valid while the client doesn't move.
    pub fn GetClientAllocatorContext( &mut self ) -> *mut c_void { yojimbo_assert!( !self.m_clientAllocator.is_null() ); AllocatorToContext( &mut self.m_clientAllocator ) }

    pub fn GetMessageFactory( &mut self ) -> *mut dyn MessageFactory { yojimbo_assert!( !self.m_messageFactory.is_null() ); self.m_messageFactory }

    pub fn GetNetworkSimulator( &mut self ) -> *mut NetworkSimulator { self.m_networkSimulator }

    pub fn GetEndpoint( &mut self ) -> *mut reliable_endpoint_t { self.m_endpoint }

    pub fn GetConnection( &mut self ) -> &mut Connection { yojimbo_assert!( !self.m_connection.is_null() ); unsafe { &mut *self.m_connection } }
}

impl BaseClient
{
    // port: takes the derived client as `this`, because Reset is virtual (see the top of the file)
    pub fn Disconnect<T: BaseClientVirtual + ?Sized>( this: &mut T )
    {
        this.base_mut().SetClientState( CLIENT_STATE_DISCONNECTED );
        this.Reset();
    }
}

// Map the error that drove the connection into an error state to the disconnect reason we
// record for this client. For channel errors, drill into the channels to find the one in
// error, because that is where the actionable detail lives (eg. serialize failure vs desync
// vs out of memory).
fn ClientDisconnectReasonForConnectionError( connection: &Connection, errorLevel: ConnectionErrorLevel, numChannels: i32 ) -> i32
{
    match errorLevel
    {
        CONNECTION_ERROR_ALLOCATOR =>           return YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
        CONNECTION_ERROR_MESSAGE_FACTORY =>     return YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
        CONNECTION_ERROR_READ_PACKET_FAILED =>  return YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED,

        CONNECTION_ERROR_CHANNEL =>
        {
            for i in 0..numChannels
            {
                match connection.GetChannelErrorLevel( i )
                {
                    CHANNEL_ERROR_DESYNC =>                 return YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC,
                    CHANNEL_ERROR_SEND_QUEUE_FULL =>        return YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL,
                    CHANNEL_ERROR_BLOCKS_DISABLED =>        return YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED,
                    CHANNEL_ERROR_FAILED_TO_SERIALIZE =>    return YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE,
                    CHANNEL_ERROR_OUT_OF_MEMORY =>          return YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY,
                    CHANNEL_ERROR_MESSAGE_TOO_LARGE =>      return YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE,
                    CHANNEL_ERROR_NONE =>                   {}
                    _ =>                                    {}      // port: the C++ switch has no default; an i32 match needs one
                }
            }
        }

        CONNECTION_ERROR_NONE => {}

        _ => {}     // port: as above
    }

    // A connection in an error state always matches one of the cases above; keep a sane
    // value if that ever changes rather than reporting garbage.
    YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED
}

impl BaseClient
{
    // port: takes the derived client as `this`, because Disconnect is virtual (see the top of the file)
    pub fn AdvanceTime<T: BaseClientVirtual + ?Sized>( this: &mut T, time: f64 )
    {
        let base = this.base_mut();
        base.m_time = time;
        if !base.m_endpoint.is_null()
        {
            let connection = unsafe { &mut *base.m_connection };
            connection.AdvanceTime( time );
            let connectionErrorLevel: ConnectionErrorLevel = connection.GetErrorLevel();
            if connectionErrorLevel != CONNECTION_ERROR_NONE
            {
                yojimbo_printf!( YOJIMBO_LOG_LEVEL_DEBUG, "connection error. disconnecting client\n" );
                let disconnectReason = ClientDisconnectReasonForConnectionError( connection, connectionErrorLevel, base.m_config.numChannels );
                base.SetDisconnectReason( disconnectReason );
                this.Disconnect();
                return;
            }
            reliable_endpoint_update( unsafe { &mut *base.m_endpoint }, base.m_time );
            let mut numAcks: i32 = 0;
            let acks: &[u16] = reliable_endpoint_get_acks( unsafe { &*base.m_endpoint }, &mut numAcks );
            connection.ProcessAcks( acks, numAcks );
            reliable_endpoint_clear_acks( unsafe { &mut *base.m_endpoint } );
        }
        let networkSimulator: *mut NetworkSimulator = base.GetNetworkSimulator();
        if !networkSimulator.is_null()
        {
            unsafe { ( *networkSimulator ).AdvanceTime( time ); }
        }
    }

    pub fn SetLatency( &mut self, milliseconds: f32 )
    {
        yojimbo_assert!( !self.m_networkSimulator.is_null() );
        if !self.m_networkSimulator.is_null()
        {
            unsafe { ( *self.m_networkSimulator ).SetLatency( milliseconds ); }
        }
    }

    pub fn SetJitter( &mut self, milliseconds: f32 )
    {
        yojimbo_assert!( !self.m_networkSimulator.is_null() );
        if !self.m_networkSimulator.is_null()
        {
            unsafe { ( *self.m_networkSimulator ).SetJitter( milliseconds ); }
        }
    }

    pub fn SetPacketLoss( &mut self, percent: f32 )
    {
        yojimbo_assert!( !self.m_networkSimulator.is_null() );
        if !self.m_networkSimulator.is_null()
        {
            unsafe { ( *self.m_networkSimulator ).SetPacketLoss( percent ); }
        }
    }

    pub fn SetDuplicates( &mut self, percent: f32 )
    {
        yojimbo_assert!( !self.m_networkSimulator.is_null() );
        if !self.m_networkSimulator.is_null()
        {
            unsafe { ( *self.m_networkSimulator ).SetDuplicates( percent ); }
        }
    }

    pub fn SetClientState( &mut self, clientState: ClientState )
    {
        self.m_clientState = clientState;
    }

    // Startup is transactional: every allocation and every adapter factory result is checked in
    // every build (Debug and Release alike -- yojimbo_assert compiles out under NDEBUG, so an
    // assert is not a check), and the first failure unwinds everything already created and leaves
    // the client exactly as it was before the call. The caller learns that from the return value.

    /**
        Allocate everything the client needs to run.
        Transactional: on the first allocation or adapter factory failure everything already
        created is destroyed, the client is left as it was before the call, and false is
        returned. Checked in every build, not by an assert.
        @returns True if the client was created, false if it ran out of memory.
     */

    // port: takes the derived client as `this`, the reliable endpoint context (see the top of the file). The
    // callbacks are instantiated for T, so they turn the context back into the derived client.
    pub fn CreateInternal<T: BaseClientVirtual>( this: &mut T ) -> bool
    {
        let context = this as *mut T as *mut c_void;
        let base = this.base_mut();

        yojimbo_assert!( !base.m_allocator.is_null() );
        yojimbo_assert!( !base.m_adapter.is_null() );
        yojimbo_assert!( base.m_clientMemory.is_null() );
        yojimbo_assert!( base.m_clientAllocator.is_null() );
        yojimbo_assert!( base.m_messageFactory.is_null() );

        base.m_config.Validate();

        base.m_packetBuffer = YOJIMBO_ALLOCATE!( base.m_allocator, base.m_config.maxPacketSize );
        if base.m_packetBuffer.is_null()
        {
            base.DestroyInternal();
            return false;
        }

        base.m_clientMemory = YOJIMBO_ALLOCATE!( base.m_allocator, base.m_config.clientMemory );
        if base.m_clientMemory.is_null()
        {
            base.DestroyInternal();
            return false;
        }

        base.m_clientAllocator = unsafe { ( *base.m_adapter ).CreateAllocator( base.m_allocator, base.m_clientMemory, base.m_config.clientMemory as usize ) };
        if base.m_clientAllocator.is_null()
        {
            base.DestroyInternal();
            return false;
        }

        base.m_messageFactory = unsafe { ( *base.m_adapter ).CreateMessageFactory( base.m_clientAllocator ) };
        if base.m_messageFactory.is_null()
        {
            base.DestroyInternal();
            return false;
        }

        base.m_connection = YOJIMBO_NEW!( base.m_clientAllocator, Connection, Connection::new( base.m_clientAllocator, base.m_messageFactory, &base.m_config, base.m_time ) );
        if base.m_connection.is_null()
        {
            base.DestroyInternal();
            return false;
        }

        if base.m_config.networkSimulator
        {
            base.m_networkSimulator = YOJIMBO_NEW!( base.m_clientAllocator, NetworkSimulator, NetworkSimulator::new( base.m_clientAllocator, base.m_config.maxSimulatorPackets, base.m_time ) );
            if base.m_networkSimulator.is_null()
            {
                base.DestroyInternal();
                return false;
            }
        }

        let mut reliable_config = reliable_config_t::default();
        reliable_default_config( &mut reliable_config );
        let nameBytes = reliable_config.name.len();
        yojimbo_copy_string( &mut reliable_config.name, "client endpoint", nameBytes );
        reliable_config.context = context;
        reliable_config.max_packet_size = base.m_config.maxPacketSize;
        reliable_config.fragment_above = base.m_config.fragmentPacketsAbove;
        reliable_config.max_fragments = base.m_config.maxPacketFragments;
        reliable_config.fragment_size = base.m_config.packetFragmentSize;
        reliable_config.ack_buffer_size = base.m_config.ackedPacketsBufferSize;
        reliable_config.received_packets_buffer_size = base.m_config.receivedPacketsBufferSize;
        reliable_config.fragment_reassembly_buffer_size = base.m_config.packetReassemblyBufferSize;
        reliable_config.rtt_smoothing_factor = base.m_config.rttSmoothingFactor;
        reliable_config.transmit_packet_function = Some( BaseClient::StaticTransmitPacketFunction::<T> );
        reliable_config.process_packet_function = Some( BaseClient::StaticProcessPacketFunction::<T> );
        reliable_config.allocator_context = AllocatorToContext( &mut base.m_clientAllocator );       // port: see GetClientAllocatorContext
        reliable_config.allocate_function = Some( BaseClient::StaticAllocateFunction );
        reliable_config.free_function = Some( BaseClient::StaticFreeFunction );

        // port: the Box is held as a raw pointer (see m_endpoint)
        base.m_endpoint = match reliable_endpoint_create( &reliable_config, base.m_time ) { Some( endpoint ) => Box::into_raw( endpoint ), None => std::ptr::null_mut() };
        if base.m_endpoint.is_null()
        {
            base.DestroyInternal();
            return false;
        }

        reliable_endpoint_reset( unsafe { &mut *base.m_endpoint } );

        true
    }

    // Safe to call on a partially created client: CreateInternal unwinds through it, so every
    // pointer is checked rather than assumed.
    pub fn DestroyInternal( &mut self )
    {
        yojimbo_assert!( !self.m_allocator.is_null() );
        if !self.m_endpoint.is_null()
        {
            reliable_endpoint_destroy( unsafe { Box::from_raw( self.m_endpoint ) } );
            self.m_endpoint = std::ptr::null_mut();
        }
        if !self.m_clientAllocator.is_null()
        {
            YOJIMBO_DELETE!( self.m_clientAllocator, NetworkSimulator, self.m_networkSimulator );
            YOJIMBO_DELETE!( self.m_clientAllocator, Connection, self.m_connection );
            YOJIMBO_DELETE!( self.m_clientAllocator, dyn MessageFactory, self.m_messageFactory );
            YOJIMBO_DELETE!( self.m_allocator, dyn Allocator, self.m_clientAllocator );
        }
        else
        {
            // Nothing was ever built inside the client allocator, so nothing can be outstanding.
            self.m_networkSimulator = std::ptr::null_mut();
            self.m_connection = std::ptr::null_mut();
            self.m_messageFactory = null_message_factory();
        }
        YOJIMBO_FREE!( self.m_allocator, self.m_clientMemory );
        YOJIMBO_FREE!( self.m_allocator, self.m_packetBuffer );
    }

    // port: instantiated for the derived client T, whose `this` CreateInternal set as the context (upstream casts the
    // context to BaseClient * and makes a virtual call)
    pub fn StaticTransmitPacketFunction<T: BaseClientVirtual>( context: *mut c_void, index: u64, packetSequence: u16, packetData: &[u8], packetBytes: i32 )
    {
        let _ = index;
        let client = unsafe { &mut *( context as *mut T ) };
        client.TransmitPacketFunction( packetSequence, packetData, packetBytes );
    }

    // port: as StaticTransmitPacketFunction
    pub fn StaticProcessPacketFunction<T: BaseClientVirtual>( context: *mut c_void, index: u64, packetSequence: u16, packetData: &[u8], packetBytes: i32 ) -> i32
    {
        let _ = index;
        let client = unsafe { &mut *( context as *mut T ) };
        client.ProcessPacketFunction( packetSequence, packetData, packetBytes )
    }

    // port: the context is a pointer to the `*mut dyn Allocator` (see GetClientAllocatorContext)
    pub fn StaticAllocateFunction( context: *mut c_void, bytes: usize ) -> *mut c_void
    {
        yojimbo_assert!( !context.is_null() );
        let allocator: *mut dyn Allocator = unsafe { AllocatorFromContext( context ) };
        YOJIMBO_ALLOCATE!( allocator, bytes ) as *mut c_void
    }

    // port: as StaticAllocateFunction
    pub fn StaticFreeFunction( context: *mut c_void, pointer: *mut c_void )
    {
        yojimbo_assert!( !context.is_null() );
        yojimbo_assert!( !pointer.is_null() );
        let allocator: *mut dyn Allocator = unsafe { AllocatorFromContext( context ) };
        let mut pointer = pointer as *mut u8;
        YOJIMBO_FREE!( allocator, pointer );
    }

    pub fn CreateMessage( &mut self, r#type: i32 ) -> *mut dyn Message
    {
        yojimbo_assert!( !self.m_messageFactory.is_null() );
        unsafe { ( *self.m_messageFactory ).CreateMessage( r#type ) }
    }

    pub fn AllocateBlock( &mut self, bytes: i32 ) -> *mut u8
    {
        YOJIMBO_ALLOCATE!( self.m_clientAllocator, bytes )
    }

    pub fn AttachBlockToMessage( &mut self, message: *mut dyn Message, block: *mut u8, bytes: i32 )
    {
        yojimbo_assert!( !message.is_null() );
        yojimbo_assert!( !block.is_null() );
        yojimbo_assert!( bytes > 0 );
        yojimbo_assert!( unsafe { ( *message ).IsBlockMessage() } );
        // port: the C++ cast to BlockMessage * is Message::AsBlockMessage (README, "Port additions")
        if let Some( blockMessage ) = unsafe { ( *message ).AsBlockMessage() }
        {
            blockMessage.AttachBlock( self.m_clientAllocator, block, bytes );
        }
    }

    pub fn FreeBlock( &mut self, block: *mut u8 )
    {
        let mut block = block;
        YOJIMBO_FREE!( self.m_clientAllocator, block );
    }

    pub fn CanSendMessage( &self, channelIndex: i32 ) -> bool
    {
        yojimbo_assert!( !self.m_connection.is_null() );
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_config.numChannels );
        unsafe { ( *self.m_connection ).CanSendMessage( channelIndex ) }
    }

    pub fn HasMessagesToSend( &self, channelIndex: i32 ) -> bool
    {
        yojimbo_assert!( !self.m_connection.is_null() );
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_config.numChannels );
        unsafe { ( *self.m_connection ).HasMessagesToSend( channelIndex ) }
    }

    pub fn SendMessage( &mut self, channelIndex: i32, message: *mut dyn Message )
    {
        yojimbo_assert!( !self.m_connection.is_null() );
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_config.numChannels );
        let context = self.GetContext();
        unsafe { ( *self.m_connection ).SendMessage( channelIndex, message, context ); }
    }

    pub fn ReceiveMessage( &mut self, channelIndex: i32 ) -> *mut dyn Message
    {
        yojimbo_assert!( !self.m_connection.is_null() );
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_config.numChannels );
        unsafe { ( *self.m_connection ).ReceiveMessage( channelIndex ) }
    }

    pub fn ReleaseMessage( &mut self, message: *mut dyn Message )
    {
        yojimbo_assert!( !self.m_connection.is_null() );
        unsafe { ( *self.m_connection ).ReleaseMessage( message ); }
    }

    pub fn GetNetworkInfo( &self, info: &mut NetworkInfo )
    {
        *info = NetworkInfo::default();     // port: memset( &info, 0, sizeof( info ) )
        if !self.m_connection.is_null()
        {
            yojimbo_assert!( !self.m_endpoint.is_null() );
            let endpoint = unsafe { &*self.m_endpoint };
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

    // port: the body of the virtual BaseClient::Reset; BaseClientVirtual::Reset calls it by default
    pub fn Reset( &mut self )
    {
        if !self.m_connection.is_null()
        {
            unsafe { ( *self.m_connection ).Reset(); }
        }
    }
}
