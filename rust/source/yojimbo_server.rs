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

// port: include/yojimbo_server.h + source/yojimbo_server.cpp
//
// Port notes:
//   - Server embeds BaseServer as `base` and implements ServerInterface (delegating what BaseServer implements upstream)
//     and BaseServerVirtual (the virtuals BaseServer calls back into). BaseServer's public non-virtual methods
//     (SetLatency, SetJitter, SetPacketLoss, SetDuplicates, HasMessagesToSend, GetClientDisconnectReason) are forwarded
//     by inherent methods, so `server.SetLatency( ... )` reads as upstream.
//   - Server::new returns Box<Server>. Start registers the server's own address as the `void * context` of the netcode
//     server callbacks and of every reliable endpoint (as upstream passes `this`), and the address of its global allocator
//     member as their allocator context, so the server must not move while it is running. Boxing it gives it a fixed
//     address for its whole life.
//   - m_server is the raw pointer of the Box netcode_server_create returns (upstream's `netcode_server_t *`), turned back
//     into a Box for netcode_server_destroy. The callbacks netcode and reliable make re-enter the server through the
//     context pointer while the outer call is still running, exactly as upstream; the library is single-threaded and no
//     reference into the re-entered state is held across those calls.
//   - Upstream's netcode_server_* asserts on a NULL server; the queries here also return a stopped server's answer
//     (false / 0 / None) when m_server is null, rather than dereferencing it.

use crate::*;
use crate::netcode::*;
use crate::reliable::*;
use std::ffi::c_void;
use std::ptr;

/**
    The reason the client in a server client slot was last disconnected.

    This lets you distinguish problems you need to act on (eg. serialize failures indicating a client/server protocol
    mismatch, or per-client memory exhaustion indicating an undersized config) from normal network behavior (a client
    cleanly disconnecting or timing out), and route that into your own logging, metrics and analytics.

    Tracked per-client slot. All slots reset to YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE when the server starts,
    and a slot resets back to NONE when a new client connects to it. The reason is recorded before
    Adapter::OnServerClientDisconnected is called, so you can query it from inside that callback.

    @see Server::GetClientDisconnectReason
 */

pub type ServerClientDisconnectReason = i32;
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE: i32 = 0;                    //< No client has disconnected from this slot since the server started, or a new client has since connected to this slot.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED: i32 = 1;            //< The client cleanly disconnected. It sent disconnect packets, eg. the player quit.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT: i32 = 2;               //< The client timed out. We stopped hearing from it, eg. network problem or the client crashed.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED: i32 = 3;                  //< Server code called Server::DisconnectClient or Server::DisconnectAllClients for this client.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE: i32 = 4;     //< A message from this client failed to serialize read. Usually a client/server protocol version mismatch, or a bug in a message serialize function.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC: i32 = 5;                  //< A channel for this client desynced and cannot recover. See CHANNEL_ERROR_DESYNC.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL: i32 = 6;         //< A channel send queue for this client filled up. See CHANNEL_ERROR_SEND_QUEUE_FULL.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED: i32 = 7;         //< This client sent block data on a channel that is configured with blocks disabled.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE: i32 = 8;       //< A message sent to this client is too large to ever fit into a packet. See CHANNEL_ERROR_MESSAGE_TOO_LARGE.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY: i32 = 9;           //< The per-client memory budget for this client was exhausted. Consider increasing ClientServerConfig::serverPerClientMemory.
pub const YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED: i32 = 10;     //< A connection packet from this client failed to deserialize.

/// Helper function to convert a server client disconnect reason to a user friendly string.

pub fn GetServerClientDisconnectReasonString( reason: i32 ) -> &'static str
{
    match reason
    {
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE =>                 "none",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED =>         "disconnected",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT =>            "timed out",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED =>               "kicked",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE =>  "failed to serialize",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DESYNC =>               "desync",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL =>      "send queue full",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED =>      "blocks disabled",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE =>    "message too large",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY =>        "out of memory",
        YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED =>   "read packet failed",
        _ =>
        {
            yojimbo_assert!( false );
            "(unknown)"
        }
    }
}

/**
    Server implementation.
 */

pub struct Server
{
    pub base: BaseServer,                               // port: the BaseServer base class
    m_config: ClientServerConfig,
    m_server: *mut netcode_server_t,                    // port: the raw pointer of the Box netcode_server_create returns
    m_address: Address,                                 // original address passed to ctor
    m_boundAddress: Address,                            // address after socket bind, eg. valid port. custom packet I/O: stays the ctor-supplied synthetic address (no socket bind)
    m_privateKey: [u8; KeyBytes as usize],
    m_stopping: bool,                                   // true while Stop tears the server down. makes a reentrant Stop from an adapter callback during teardown a harmless no-op
}

impl Server
{
    // port: Server( Allocator & allocator, const uint8_t privateKey[], const Address & address, const ClientServerConfig & config, Adapter & adapter, double time ).
    // Returns a Box: Start registers the server's address with netcode and reliable, so it must not move (see the notes at the top).
    pub fn new( allocator: *mut dyn Allocator, privateKey: &[u8], address: &Address, config: &ClientServerConfig, adapter: *mut dyn Adapter, time: f64 ) -> Box<Server>
    {
        yojimbo_assert!( KeyBytes == NETCODE_KEY_BYTES );
        yojimbo_assert!( DefaultMaxConnectTokenLifetime == NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME );
        let mut this = Box::new( Server
        {
            base: BaseServer::new( allocator, config, adapter, time ),
            m_config: config.clone(),
            m_server: ptr::null_mut(),
            m_address: *address,
            m_boundAddress: *address,
            m_privateKey: [0; KeyBytes as usize],
            m_stopping: false,
        } );
        this.m_privateKey.copy_from_slice( &privateKey[..NETCODE_KEY_BYTES as usize] );
        this
    }
}

// port: ~Server()
impl Drop for Server
{
    fn drop( &mut self )
    {
        // IMPORTANT: Please stop the server before destroying it!
        yojimbo_assert!( self.m_server.is_null() );
    }
}

impl ServerInterface for Server
{
    fn SetContext( &mut self, context: *mut c_void )
    {
        self.base.SetContext( context );
    }

    fn Start( &mut self, maxClients: i32 ) -> bool
    {
        yojimbo_assert!( maxClients <= MaxClients );

        if !BaseServer::Start( self, maxClients )
        {
            return false;
        }

        // port: char addressString[MaxAddressLength] + ToString( addressString, MaxAddressLength )
        let addressString: String = self.m_address.ToString();

        let mut netcodeConfig = netcode_server_config_t::default();
        netcode_default_server_config( &mut netcodeConfig );
        netcodeConfig.protocol_id = self.m_config.protocolId;
        netcodeConfig.private_key.copy_from_slice( &self.m_privateKey[..NETCODE_KEY_BYTES as usize] );
        netcodeConfig.allocator_context = self.base.GetGlobalAllocatorContext();
        netcodeConfig.allocate_function = Some( BaseServer::StaticAllocateFunction );
        netcodeConfig.free_function     = Some( BaseServer::StaticFreeFunction );
        netcodeConfig.max_connect_token_lifetime = self.m_config.maxConnectTokenLifetime;
        netcodeConfig.callback_context = self as *mut Server as *mut c_void;
        netcodeConfig.connect_disconnect_callback = Some( Server::StaticConnectDisconnectCallbackFunction );
        netcodeConfig.send_loopback_packet_callback = Some( Server::StaticSendLoopbackPacketCallbackFunction );
        let useCustomPacketIO = self.base.GetAdapter().UseCustomPacketIO();
        if useCustomPacketIO
        {
            netcodeConfig.override_send_and_receive = 1;
            netcodeConfig.send_packet_override = Some( Server::StaticSendPacketOverride );
            netcodeConfig.receive_packet_override = Some( Server::StaticReceivePacketOverride );
        }

        self.m_server = match netcode_server_create( &addressString, &netcodeConfig, self.base.GetTime() )
        {
            Some( server ) => Box::into_raw( server ),
            None => ptr::null_mut(),
        };

        if self.m_server.is_null()
        {
            self.Stop();
            return false;
        }

        netcode_server_start( unsafe { &mut *self.m_server }, maxClients );

        if !useCustomPacketIO
        {
            let port = netcode_server_get_port( unsafe { &mut *self.m_server } );
            self.m_boundAddress.SetPort( port );
        }

        true
    }

    fn Stop( &mut self )
    {
        // Stop-in-progress guard: netcode_server_stop below sends disconnect packets and fires
        // OnServerClientDisconnected, so an adapter callback can call Stop from inside this
        // teardown. That reentrant call must be a harmless no-op — the outer call completes the
        // teardown exactly once. Without this, the inner call reaches BaseServer::Stop and
        // destroys the global allocator while the netcode server (allocated from it) still lives.
        if self.m_stopping
        {
            return;
        }
        self.m_stopping = true;
        if !self.m_server.is_null()
        {
            self.m_boundAddress = self.m_address;
            // Clear the member before stopping, so an adapter that calls Stop from inside a
            // teardown-time SendPacket callback (disconnect packets sent by netcode_server_stop)
            // can't re-enter here and stop/destroy the same netcode server twice.
            // ConnectDisconnectCallbackFunction handles m_server being NULL during this window.
            let mut server: Box<netcode_server_t> = unsafe { Box::from_raw( self.m_server ) };
            self.m_server = ptr::null_mut();
            netcode_server_stop( &mut server );
            netcode_server_destroy( server );
        }
        self.base.Stop();
        self.m_stopping = false;
    }

    fn DisconnectClient( &mut self, clientIndex: i32 )
    {
        yojimbo_assert!( !self.m_server.is_null() );
        // Record the kick, but only if no reason is set yet: when the disconnect comes from
        // BaseServer::AdvanceTime, the specific connection error reason is already recorded
        // and must not be overwritten with the generic "kicked".
        if self.IsClientConnected( clientIndex ) && self.base.GetClientDisconnectReason( clientIndex ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE
        {
            self.base.SetClientDisconnectReason( clientIndex, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );
        }
        // port: guarded, rather than dereferencing a NULL server in release builds
        if !self.m_server.is_null()
        {
            netcode_server_disconnect_client( unsafe { &mut *self.m_server }, clientIndex );
        }
        self.ResetClient( clientIndex );
    }

    fn DisconnectAllClients( &mut self )
    {
        yojimbo_assert!( !self.m_server.is_null() );
        let maxClients = self.base.GetMaxClients();
        for i in 0..maxClients
        {
            if self.IsClientConnected( i ) && self.base.GetClientDisconnectReason( i ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE
            {
                self.base.SetClientDisconnectReason( i, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );
            }
        }
        // port: guarded, rather than dereferencing a NULL server in release builds
        if !self.m_server.is_null()
        {
            netcode_server_disconnect_all_clients( unsafe { &mut *self.m_server } );
        }
        for i in 0..maxClients
        {
            self.ResetClient( i );
        }
    }

    fn SendPackets( &mut self )
    {
        if !self.m_server.is_null()
        {
            let maxClients = self.base.GetMaxClients();
            for i in 0..maxClients
            {
                if self.IsClientConnected( i )
                {
                    // port: the packet buffer is maxPacketSize bytes from the global allocator (BaseServer::Start)
                    let maxPacketSize = self.m_config.maxPacketSize;
                    let packetData: &mut [u8] = unsafe { std::slice::from_raw_parts_mut( self.base.GetPacketBuffer(), maxPacketSize as usize ) };
                    let mut packetBytes: i32 = 0;
                    let packetSequence: u16 = reliable_endpoint_next_packet_sequence( self.base.GetClientEndpoint( i ) );
                    let context = self.base.GetContext();
                    if self.base.GetClientConnection( i ).GeneratePacket( context, packetSequence, packetData, maxPacketSize, &mut packetBytes )
                    {
                        reliable_endpoint_send_packet( self.base.GetClientEndpoint( i ), packetData, packetBytes );
                    }
                }
            }
        }
    }

    fn ReceivePackets( &mut self )
    {
        if !self.m_server.is_null()
        {
            let maxClients = self.base.GetMaxClients();
            for clientIndex in 0..maxClients
            {
                loop
                {
                    let mut packetBytes: i32 = 0;
                    let mut packetSequence: u64 = 0;
                    let packetData: Vec<u8> = match netcode_server_receive_packet( unsafe { &mut *self.m_server }, clientIndex, &mut packetBytes, &mut packetSequence )
                    {
                        Some( packetData ) => packetData,
                        None => break,
                    };
                    reliable_endpoint_receive_packet( self.base.GetClientEndpoint( clientIndex ), &packetData, packetBytes );
                    netcode_server_free_packet( unsafe { &mut *self.m_server }, packetData );
                }
            }
        }
    }

    fn AdvanceTime( &mut self, time: f64 )
    {
        if !self.m_server.is_null()
        {
            netcode_server_update( unsafe { &mut *self.m_server }, time );
        }
        BaseServer::AdvanceTime( self, time );
        let networkSimulator: *mut NetworkSimulator = self.base.GetNetworkSimulator();
        if !networkSimulator.is_null() && unsafe { ( *networkSimulator ).IsActive() }
        {
            // Drain the simulator in fixed size batches, so stack usage here doesn't scale
            // with maxSimulatorPackets. Each batch scans the simulator ring again, but the
            // simulator is a development tool, not a production path.
            const MaxBatchPackets: usize = 64;
            let mut packetData: [*mut u8; MaxBatchPackets] = [ptr::null_mut(); MaxBatchPackets];
            let mut packetBytes: [i32; MaxBatchPackets] = [0; MaxBatchPackets];
            let mut to: [i32; MaxBatchPackets] = [0; MaxBatchPackets];
            loop
            {
                let numPackets = unsafe { ( *networkSimulator ).ReceivePackets( MaxBatchPackets as i32, &mut packetData, &mut packetBytes, Some( &mut to ) ) };
                if numPackets == 0
                {
                    break;
                }
                for i in 0..numPackets as usize
                {
                    // port: guarded, rather than dereferencing a NULL server in release builds
                    if !self.m_server.is_null()
                    {
                        let data: &[u8] = unsafe { std::slice::from_raw_parts( packetData[i], packetBytes[i] as usize ) };
                        netcode_server_send_packet( unsafe { &mut *self.m_server }, to[i], data, packetBytes[i] );
                    }
                    YOJIMBO_FREE!( unsafe { ( *networkSimulator ).GetAllocator() }, packetData[i] );
                }
            }
        }
    }

    fn IsRunning( &self ) -> bool
    {
        self.base.IsRunning()
    }

    fn GetMaxClients( &self ) -> i32
    {
        self.base.GetMaxClients()
    }

    fn IsClientConnected( &self, clientIndex: i32 ) -> bool
    {
        if self.m_server.is_null()
        {
            return false;
        }
        netcode_server_client_connected( unsafe { &mut *self.m_server }, clientIndex ) != 0
    }

    fn GetClientId( &self, clientIndex: i32 ) -> u64
    {
        if self.m_server.is_null()
        {
            return 0;
        }
        netcode_server_client_id( unsafe { &mut *self.m_server }, clientIndex )
    }

    fn GetClientUserData( &self, clientIndex: i32 ) -> Option<&[u8]>
    {
        if self.m_server.is_null()
        {
            return None;
        }
        let server: &mut netcode_server_t = unsafe { &mut *self.m_server };
        netcode_server_client_user_data( server, clientIndex ).map( |userData| &*userData )
    }

    fn GetClientAddress( &self, clientIndex: i32 ) -> Option<&netcode_address_t>
    {
        if self.m_server.is_null()
        {
            return None;
        }
        let server: &mut netcode_server_t = unsafe { &mut *self.m_server };
        netcode_server_client_address( server, clientIndex ).map( |address| &*address )
    }

    fn GetNumConnectedClients( &self ) -> i32
    {
        if self.m_server.is_null()
        {
            return 0;
        }
        netcode_server_num_connected_clients( unsafe { &mut *self.m_server } )
    }

    fn GetTime( &self ) -> f64
    {
        self.base.GetTime()
    }

    fn CreateMessage( &mut self, clientIndex: i32, r#type: i32 ) -> *mut dyn Message
    {
        self.base.CreateMessage( clientIndex, r#type )
    }

    fn AllocateBlock( &mut self, clientIndex: i32, bytes: i32 ) -> *mut u8
    {
        self.base.AllocateBlock( clientIndex, bytes )
    }

    fn AttachBlockToMessage( &mut self, clientIndex: i32, message: *mut dyn Message, block: *mut u8, bytes: i32 )
    {
        self.base.AttachBlockToMessage( clientIndex, message, block, bytes );
    }

    fn FreeBlock( &mut self, clientIndex: i32, block: *mut u8 )
    {
        self.base.FreeBlock( clientIndex, block );
    }

    fn CanSendMessage( &self, clientIndex: i32, channelIndex: i32 ) -> bool
    {
        self.base.CanSendMessage( clientIndex, channelIndex )
    }

    fn SendMessage( &mut self, clientIndex: i32, channelIndex: i32, message: *mut dyn Message )
    {
        self.base.SendMessage( clientIndex, channelIndex, message );
    }

    fn ReceiveMessage( &mut self, clientIndex: i32, channelIndex: i32 ) -> *mut dyn Message
    {
        self.base.ReceiveMessage( clientIndex, channelIndex )
    }

    fn ReleaseMessage( &mut self, clientIndex: i32, message: *mut dyn Message )
    {
        self.base.ReleaseMessage( clientIndex, message );
    }

    fn GetNetworkInfo( &self, clientIndex: i32, info: &mut NetworkInfo )
    {
        BaseServer::GetNetworkInfo( self, clientIndex, info );
    }

    fn ConnectLoopbackClient( &mut self, clientIndex: i32, clientId: u64, userData: Option<&[u8]> )
    {
        yojimbo_assert!( !self.m_server.is_null() );
        if !self.m_server.is_null()
        {
            netcode_server_connect_loopback_client( unsafe { &mut *self.m_server }, clientIndex, clientId, userData );
        }
    }

    fn DisconnectLoopbackClient( &mut self, clientIndex: i32 )
    {
        // Same recording rule as DisconnectClient: disconnecting a loopback client is a kick,
        // and must not overwrite a more specific reason recorded before the disconnect.
        if self.IsClientConnected( clientIndex ) && self.base.GetClientDisconnectReason( clientIndex ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE
        {
            self.base.SetClientDisconnectReason( clientIndex, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_KICKED );
        }
        yojimbo_assert!( !self.m_server.is_null() );
        if !self.m_server.is_null()
        {
            netcode_server_disconnect_loopback_client( unsafe { &mut *self.m_server }, clientIndex );
        }
    }

    fn IsLoopbackClient( &self, clientIndex: i32 ) -> bool
    {
        if self.m_server.is_null()
        {
            return false;
        }
        netcode_server_client_loopback( unsafe { &mut *self.m_server }, clientIndex ) != 0
    }

    fn ProcessLoopbackPacket( &mut self, clientIndex: i32, packetData: &[u8], packetBytes: i32, packetSequence: u64 )
    {
        yojimbo_assert!( !self.m_server.is_null() );
        if !self.m_server.is_null()
        {
            netcode_server_process_loopback_packet( unsafe { &mut *self.m_server }, clientIndex, packetData, packetBytes, packetSequence );
        }
    }
}

impl Server
{
    /**
        Gets the local address the server socket is bound to (with the actual port, when port 0 was passed in).
        Under custom packet I/O (Adapter::UseCustomPacketIO) there is no socket: this is the
        constructor-supplied synthetic address, unchanged.
     */

    pub fn GetAddress( &self ) -> &Address { &self.m_boundAddress }

    // port: BaseServer's public non-virtual methods, inherited by Server upstream

    pub fn SetLatency( &mut self, milliseconds: f32 ) { self.base.SetLatency( milliseconds ); }

    pub fn SetJitter( &mut self, milliseconds: f32 ) { self.base.SetJitter( milliseconds ); }

    pub fn SetPacketLoss( &mut self, percent: f32 ) { self.base.SetPacketLoss( percent ); }

    pub fn SetDuplicates( &mut self, percent: f32 ) { self.base.SetDuplicates( percent ); }

    pub fn HasMessagesToSend( &self, clientIndex: i32, channelIndex: i32 ) -> bool { self.base.HasMessagesToSend( clientIndex, channelIndex ) }

    pub fn GetClientDisconnectReason( &self, clientIndex: i32 ) -> i32 { self.base.GetClientDisconnectReason( clientIndex ) }
}

impl BaseServerVirtual for Server
{
    fn base( &self ) -> &BaseServer { &self.base }

    fn base_mut( &mut self ) -> &mut BaseServer { &mut self.base }

    fn TransmitPacketFunction( &mut self, clientIndex: i32, packetSequence: u16, packetData: &[u8], packetBytes: i32 )
    {
        let _ = packetSequence;
        let networkSimulator: *mut NetworkSimulator = self.base.GetNetworkSimulator();
        if !networkSimulator.is_null() && unsafe { ( *networkSimulator ).IsActive() }
        {
            unsafe { ( *networkSimulator ).SendPacket( clientIndex, packetData, packetBytes ) };
        }
        else
        {
            // port: guarded, rather than dereferencing a NULL server in release builds
            if !self.m_server.is_null()
            {
                netcode_server_send_packet( unsafe { &mut *self.m_server }, clientIndex, packetData, packetBytes );
            }
        }
    }

    fn ProcessPacketFunction( &mut self, clientIndex: i32, packetSequence: u16, packetData: &[u8], packetBytes: i32 ) -> i32
    {
        let context = self.base.GetContext();
        self.base.GetClientConnection( clientIndex ).ProcessPacket( context, packetSequence, packetData, packetBytes ) as i32
    }
}

impl Server
{
    fn ConnectDisconnectCallbackFunction( &mut self, clientIndex: i32, connected: i32 )
    {
        if connected == 0
        {
            // If no reason was recorded before the transport-level disconnect (connection error,
            // kick), ask netcode why: the client either timed out or cleanly disconnected.
            // Record it before the adapter callback, so OnServerClientDisconnected can query it.
            if self.base.GetClientDisconnectReason( clientIndex ) == YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE
            {
                // m_server is NULL while Stop tears the netcode server down (cleared before
                // netcode_server_stop, see Server::Stop). Disconnects delivered during that
                // window are always netcode SERVER_DISCONNECT, never TIMED_OUT.
                let netcodeReason = if !self.m_server.is_null() { netcode_server_client_disconnect_reason( unsafe { &mut *self.m_server }, clientIndex ) }
                                    else { NETCODE_SERVER_CLIENT_DISCONNECT_REASON_SERVER_DISCONNECT };
                self.base.SetClientDisconnectReason( clientIndex, if netcodeReason == NETCODE_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT
                                                                  { YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_TIMED_OUT }
                                                                  else { YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_DISCONNECTED } );
            }
            self.base.GetAdapter().OnServerClientDisconnected( clientIndex );
            reliable_endpoint_reset( self.base.GetClientEndpoint( clientIndex ) );
            self.base.GetClientConnection( clientIndex ).Reset();
            let networkSimulator: *mut NetworkSimulator = self.base.GetNetworkSimulator();
            if !networkSimulator.is_null() && unsafe { ( *networkSimulator ).IsActive() }
            {
                unsafe { ( *networkSimulator ).DiscardClientPackets( clientIndex ) };
            }
        }
        else
        {
            // This slot now belongs to a new client: clear any disconnect reason left behind by
            // the previous occupant of the slot.
            self.base.SetClientDisconnectReason( clientIndex, YOJIMBO_SERVER_CLIENT_DISCONNECT_REASON_NONE );
            self.base.GetAdapter().OnServerClientConnected( clientIndex );
        }
    }

    fn SendLoopbackPacketCallbackFunction( &mut self, clientIndex: i32, packetData: &[u8], packetBytes: i32, packetSequence: u64 )
    {
        self.base.GetAdapter().ServerSendLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
    }

    // port: the static callbacks turn the `void * context` (the Server, registered in Start) back into the server

    fn StaticConnectDisconnectCallbackFunction( context: *mut c_void, clientIndex: i32, connected: i32 )
    {
        let server: &mut Server = unsafe { &mut *( context as *mut Server ) };
        server.ConnectDisconnectCallbackFunction( clientIndex, connected );
    }

    fn StaticSendLoopbackPacketCallbackFunction( context: *mut c_void, clientIndex: i32, packetData: &[u8], packetBytes: i32, packetSequence: u64 )
    {
        let server: &mut Server = unsafe { &mut *( context as *mut Server ) };
        server.SendLoopbackPacketCallbackFunction( clientIndex, packetData, packetBytes, packetSequence );
    }

    fn StaticSendPacketOverride( context: *mut c_void, to: &netcode_address_t, packetData: &[u8], packetBytes: i32 )
    {
        let server: &mut Server = unsafe { &mut *( context as *mut Server ) };
        let address: Address = AddressFromNetcode( to );
        if address.IsValid()
        {
            server.base.GetAdapter().SendPacket( &address, packetData, packetBytes );
        }
    }

    fn StaticReceivePacketOverride( context: *mut c_void, from: &mut netcode_address_t, packetData: &mut [u8], maxPacketBytes: i32 ) -> i32
    {
        let server: &mut Server = unsafe { &mut *( context as *mut Server ) };
        let mut address = Address::new();
        let packetBytes = server.base.GetAdapter().ReceivePacket( &mut address, packetData, maxPacketBytes );
        if packetBytes <= 0 || packetBytes > maxPacketBytes || !AddressToNetcode( &address, from )
        {
            return 0;
        }
        packetBytes
    }
}
