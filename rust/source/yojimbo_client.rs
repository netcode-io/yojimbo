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

// port: include/yojimbo_client.h + source/yojimbo_client.cpp
//
// class Client : public BaseClient is a struct embedding `base: BaseClient` (see yojimbo_base_client.rs). It
// implements ClientInterface (the methods BaseClient implements upstream delegate to `base`) and BaseClientVirtual
// (TransmitPacketFunction, ProcessPacketFunction). BaseClient's public non-virtual methods (SetLatency, ...,
// GetDisconnectReason) are forwarded by inherent methods, as there is no inheritance.
//
// Callback contexts: as upstream, netcode's callback context and the reliable endpoint's context are `this`, the
// Client, turned back into the Client in an unsafe block inside each static callback. They are registered on connect
// and used until disconnect, so a connected Client must not move: Client::new returns Box<Client>, which keeps its
// address stable (never move it out of the box). The allocator context is a pointer into the boxed Client too.

use crate::*;
use crate::netcode::*;
use crate::reliable::*;
use std::ffi::c_void;

/**
    The reason this client was last disconnected.

    This lets you distinguish what to show the player and what to do next: a denied connection (eg. server full),
    an expired or invalid connect token (eg. matchmaking took too long, or a client/server version mismatch),
    a timeout, or a protocol error such as a message that failed to serialize.

    Cleared to YOJIMBO_CLIENT_DISCONNECT_REASON_NONE when a new connect attempt starts. The first reason recorded
    for a disconnect wins, so a specific error is never overwritten by the generic disconnect that follows it.

    @see BaseClient::GetDisconnectReason
 */

// port: C++ enum -> i32 constants (README, "Names"); ClientDisconnectReason is their type
pub type ClientDisconnectReason = i32;
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_NONE: i32 = 0;                           //< No disconnect has happened yet (or a new connect attempt is in progress).
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED: i32 = 1;                   //< You called Client::Disconnect. A deliberate local disconnect.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER: i32 = 2;         //< The server disconnected us. The server was stopped, or it kicked this client.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED: i32 = 3;              //< The server denied the connection request. For example, the server is full.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT: i32 = 4;   //< No response from the server to our connection request. Server not running, unreachable, or wrong address.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT: i32 = 5;  //< No response from the server to our challenge response while establishing the connection.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT: i32 = 6;           //< The established connection timed out. We stopped hearing from the server.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN: i32 = 7;          //< The connect token is invalid, or could not be generated.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED: i32 = 8;          //< The connect token expired before we could connect. Request a fresh one from the matchmaker and retry.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE: i32 = 9;            //< A message from the server failed to serialize read. Usually a client/server protocol version mismatch, or a bug in a message serialize function.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC: i32 = 10;                        //< A channel desynced and cannot recover. See CHANNEL_ERROR_DESYNC.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL: i32 = 11;               //< A channel send queue filled up. See CHANNEL_ERROR_SEND_QUEUE_FULL.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED: i32 = 12;               //< The server sent block data on a channel that is configured with blocks disabled.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE: i32 = 13;             //< Tried to send a message too large to ever fit into a packet. See CHANNEL_ERROR_MESSAGE_TOO_LARGE.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY: i32 = 14;                 //< The client memory budget was exhausted. Consider increasing ClientServerConfig::clientMemory.
pub const YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED: i32 = 15;            //< A connection packet from the server failed to deserialize.

/// Helper function to convert a client disconnect reason to a user friendly string.

pub fn GetClientDisconnectReasonString( reason: i32 ) -> &'static str
{
    match reason
    {
        YOJIMBO_CLIENT_DISCONNECT_REASON_NONE =>                            "none",
        YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED =>                    "disconnected",
        YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER =>          "disconnected by server",
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED =>               "connection denied",
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT =>    "connection request timed out",
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT =>   "connection response timed out",
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT =>            "connection timed out",
        YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN =>           "invalid connect token",
        YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED =>           "connect token expired",
        YOJIMBO_CLIENT_DISCONNECT_REASON_FAILED_TO_SERIALIZE =>             "failed to serialize",
        YOJIMBO_CLIENT_DISCONNECT_REASON_DESYNC =>                          "desync",
        YOJIMBO_CLIENT_DISCONNECT_REASON_SEND_QUEUE_FULL =>                 "send queue full",
        YOJIMBO_CLIENT_DISCONNECT_REASON_BLOCKS_DISABLED =>                 "blocks disabled",
        YOJIMBO_CLIENT_DISCONNECT_REASON_MESSAGE_TOO_LARGE =>               "message too large",
        YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY =>                   "out of memory",
        YOJIMBO_CLIENT_DISCONNECT_REASON_READ_PACKET_FAILED =>              "read packet failed",
        _ =>
        {
            yojimbo_assert!( false );
            "(unknown)"
        }
    }
}

/**
    Client implementation
 */

pub struct Client
{
    pub base: BaseClient,                           //< port: the BaseClient base class
    m_config: ClientServerConfig,                   //< Client/server configuration.
    m_client: *mut netcode_client_t,                //< netcode client data. port: the Box from netcode_client_create, held as a raw pointer (Box::into_raw / Box::from_raw) so it can be NULL and reached from &self and from the callbacks, as upstream.
    m_address: Address,                             //< Original address passed to ctor.
    m_boundAddress: Address,                        //< Address after socket bind, eg. with valid port. Custom packet I/O: stays the ctor-supplied synthetic address (no socket bind).
    m_clientId: u64,                                //< The globally unique client id (set on each call to connect)
    m_disconnecting: bool,                          //< True while Disconnect tears the client down. Makes a reentrant Disconnect from an adapter callback during teardown a harmless no-op.
}

// Map a netcode client error state to the disconnect reason we record for this client.
// This is where "server is full" vs "update your client" vs "network problem" comes from.
fn ClientDisconnectReasonForNetcodeState( netcodeState: i32 ) -> i32
{
    match netcodeState
    {
        NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED =>           YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECT_TOKEN_EXPIRED,
        NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN =>           YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN,
        NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT =>            YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_TIMED_OUT,
        NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT =>   YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_RESPONSE_TIMED_OUT,
        NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT =>    YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_REQUEST_TIMED_OUT,
        NETCODE_CLIENT_STATE_CONNECTION_DENIED =>               YOJIMBO_CLIENT_DISCONNECT_REASON_CONNECTION_DENIED,
        _ =>                                                    YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER,
    }
}

impl Client
{
    /**
        The client constructor.
        @param allocator The allocator for all memory used by the client.
        @param address The address the client should bind to.
        @param config The client/server configuration.
        @param adapter The adapter to the game program. Specifies the allocator and the message factory to use.
        @param time The current time in seconds. See ClientInterface::AdvanceTime
     */

    // port: returns the client boxed. netcode and reliable keep raw pointers to it (callback contexts) from connect
    // to disconnect, so its address must stay put, as a C++ object's does; keep it in the box. The allocator and
    // adapter must outlive the client, as upstream.
    pub fn new( allocator: *mut dyn Allocator, address: &Address, config: &ClientServerConfig, adapter: *mut dyn Adapter, time: f64 ) -> Box<Client>
    {
        let mut client = Box::new( Client
        {
            base: BaseClient::new( allocator, config, adapter, time ),
            m_config: *config,
            m_address: *address,
            m_clientId: 0,
            m_client: std::ptr::null_mut(),
            m_boundAddress: Address::new(),
            m_disconnecting: false,
        } );
        client.m_boundAddress = client.m_address;
        client
    }
}

// port: ~Client(). BaseClient's Drop (~BaseClient) runs after it, as in C++.
impl Drop for Client
{
    fn drop( &mut self )
    {
        // IMPORTANT: Please disconnect the client before destroying it
        yojimbo_assert!( self.m_client.is_null() );
    }
}

impl Client
{
    /**
        Connect to a server with a locally generated connect token.
        @returns True if the connect attempt started. False if the client ran out of memory or could not generate the token, in which case nothing is allocated and the client is left disconnected or in the error state.
     */

    pub fn InsecureConnect( &mut self, privateKey: &[u8], clientId: u64, address: &Address ) -> bool
    {
        self.InsecureConnectAddresses( privateKey, clientId, std::slice::from_ref( address ), 1 )
    }

    /// @see Client::InsecureConnect

    // port: the overload taking an array of server addresses (README, "Names": overloads get a suffix)
    pub fn InsecureConnectAddresses( &mut self, privateKey: &[u8], clientId: u64, serverAddresses: &[Address], numServerAddresses: i32 ) -> bool
    {
        // port: yojimbo_assert( serverAddresses ) -- a slice is never null; checks it holds numServerAddresses instead
        yojimbo_assert!( serverAddresses.len() >= numServerAddresses as usize );
        yojimbo_assert!( numServerAddresses > 0 );
        yojimbo_assert!( numServerAddresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
        self.Disconnect();
        if !BaseClient::CreateInternal( self )
        {
            // Out of memory. CreateInternal already unwound everything it had allocated, so the
            // client is exactly as it was before this call: disconnected and holding nothing.
            self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY );
            self.base.SetClientState( CLIENT_STATE_ERROR );
            return false;
        }
        self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );        // new connect attempt: clear the reason from any previous disconnect
        self.m_clientId = clientId;
        let address = self.m_address;       // port: a copy, as CreateClient takes &mut self
        self.CreateClient( &address );
        if self.m_client.is_null()
        {
            self.Disconnect();
            return false;
        }
        let mut connectToken = [0u8; NETCODE_CONNECT_TOKEN_BYTES as usize];
        if !self.GenerateInsecureConnectToken( &mut connectToken, privateKey, clientId, serverAddresses, numServerAddresses )
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to generate insecure connect token\n" );
            self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_INVALID_CONNECT_TOKEN );
            self.base.SetClientState( CLIENT_STATE_ERROR );
            return false;
        }
        netcode_client_connect( unsafe { &mut *self.m_client }, &connectToken );
        self.base.SetClientState( CLIENT_STATE_CONNECTING );
        true
    }

    fn GenerateInsecureConnectToken( &mut self,
                                     connectToken: &mut [u8],
                                     privateKey: &[u8],
                                     clientId: u64,
                                     serverAddresses: &[Address],
                                     numServerAddresses: i32 ) -> bool
    {
        // port: char serverAddressStrings[NETCODE_MAX_SERVERS_PER_CONNECT][MaxAddressLength] are Strings, as Address::ToString returns one
        let mut serverAddressStrings: Vec<String> = Vec::with_capacity( numServerAddresses as usize );
        for i in 0..numServerAddresses as usize
        {
            serverAddressStrings.push( serverAddresses[i].ToString() );
        }
        let serverAddressStringPointers: Vec<&str> = serverAddressStrings.iter().map( |s| s.as_str() ).collect();

        let userData = [0u8; 256];

        // Give the insecure connect token an expiry well above the connection timeout, so a
        // failed insecure connect reports "connection request timed out" just like a secure
        // connect token from a matchmaker would. With expiry == timeout, netcode checks token
        // expiry first and every failed connect reports "connect token expired" instead.
        let expireSeconds: i32 = yojimbo_max( InsecureConnectTokenExpirySeconds, self.m_config.timeout * 2 );

        netcode_generate_connect_token( numServerAddresses,
                                        &serverAddressStringPointers,
                                        &serverAddressStringPointers,
                                        expireSeconds,
                                        self.m_config.timeout,
                                        clientId,
                                        self.m_config.protocolId,
                                        privateKey,
                                        &userData,
                                        connectToken ) == NETCODE_OK
    }

    /**
        Connect to a server with a connect token from a matchmaker.
        @returns True if the connect attempt started. False if the client ran out of memory, could not open its socket, or the token was rejected. In every false case nothing stays allocated.
     */

    pub fn Connect( &mut self, clientId: u64, connectToken: &[u8] ) -> bool
    {
        // port: yojimbo_assert( connectToken ) -- a slice is never null
        self.Disconnect();
        if !BaseClient::CreateInternal( self )
        {
            self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY );
            self.base.SetClientState( CLIENT_STATE_ERROR );
            return false;
        }
        self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );        // new connect attempt: clear the reason from any previous disconnect
        self.m_clientId = clientId;
        let address = self.m_address;       // port: a copy, as CreateClient takes &mut self
        self.CreateClient( &address );
        if self.m_client.is_null()
        {
            // Socket creation/bind failed (e.g. port in use, invalid bind address). Bail before
            // calling into netcode, which dereferences the client pointer without checking.
            self.Disconnect();
            return false;
        }
        netcode_client_connect( unsafe { &mut *self.m_client }, connectToken );
        if netcode_client_state( unsafe { &mut *self.m_client } ) > NETCODE_CLIENT_STATE_DISCONNECTED
        {
            self.base.SetClientState( CLIENT_STATE_CONNECTING );
            return true;
        }
        // The connect failed immediately, eg. an invalid connect token.
        self.base.SetDisconnectReason( ClientDisconnectReasonForNetcodeState( netcode_client_state( unsafe { &mut *self.m_client } ) ) );
        self.Disconnect();
        false
    }
}

impl ClientInterface for Client
{
    fn Disconnect( &mut self )
    {
        // Stop-in-progress guard: netcode_client_destroy (inside DestroyClient below) sends
        // disconnect packets, so an adapter SendPacket callback can call Disconnect from inside
        // this teardown. That reentrant call must be a harmless no-op — the outer call completes
        // the teardown exactly once. Without this, the inner call reaches DestroyInternal and
        // destroys the client allocator while the netcode client (allocated from it) still lives.
        if self.m_disconnecting
        {
            return;
        }
        self.m_disconnecting = true;
        // Record a deliberate local disconnect, but only if no more specific reason was already
        // recorded (connection error, netcode error state) — the first reason recorded wins.
        // Checked before BaseClient::Disconnect below, because that resets the client state.
        if ( self.base.IsConnecting() || self.base.IsConnected() ) && self.base.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_NONE
        {
            self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED );
        }
        BaseClient::Disconnect( self );
        self.DestroyClient();
        self.base.DestroyInternal();
        self.m_clientId = 0;
        self.m_disconnecting = false;
    }

    fn SendPackets( &mut self )
    {
        if !self.base.IsConnected()
        {
            return;
        }
        yojimbo_assert!( !self.m_client.is_null() );
        let packetData: *mut u8 = self.base.GetPacketBuffer();
        let mut packetBytes: i32 = 0;
        let packetSequence: u16 = reliable_endpoint_next_packet_sequence( unsafe { &*self.base.GetEndpoint() } );
        // port: the packet buffer (m_config.maxPacketSize bytes, allocated by CreateInternal) as a slice
        let packetData: &mut [u8] = unsafe { std::slice::from_raw_parts_mut( packetData, self.m_config.maxPacketSize as usize ) };
        let context = self.base.GetContext();
        if self.base.GetConnection().GeneratePacket( context, packetSequence, packetData, self.m_config.maxPacketSize, &mut packetBytes )
        {
            reliable_endpoint_send_packet( unsafe { &mut *self.base.GetEndpoint() }, packetData, packetBytes );
        }
    }

    fn ReceivePackets( &mut self )
    {
        if !self.base.IsConnected()
        {
            return;
        }
        yojimbo_assert!( !self.m_client.is_null() );
        loop
        {
            let mut packetBytes: i32 = 0;
            let mut packetSequence: u64 = 0;
            let packetData: Option<Vec<u8>> = netcode_client_receive_packet( unsafe { &mut *self.m_client }, &mut packetBytes, &mut packetSequence );
            let packetData = match packetData { Some( packetData ) => packetData, None => break };
            reliable_endpoint_receive_packet( unsafe { &mut *self.base.GetEndpoint() }, &packetData, packetBytes );
            netcode_client_free_packet( unsafe { &mut *self.m_client }, packetData );
        }
    }

    fn AdvanceTime( &mut self, time: f64 )
    {
        BaseClient::AdvanceTime( self, time );
        if !self.m_client.is_null()
        {
            netcode_client_update( unsafe { &mut *self.m_client }, time );
            let state: i32 = netcode_client_state( unsafe { &mut *self.m_client } );
            if state < NETCODE_CLIENT_STATE_DISCONNECTED
            {
                // Record why netcode failed (denied, token expired/invalid, timed out) before the
                // disconnect, so the game can tell the player what actually happened.
                if self.base.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_NONE
                {
                    self.base.SetDisconnectReason( ClientDisconnectReasonForNetcodeState( state ) );
                }
                self.Disconnect();
                self.base.SetClientState( CLIENT_STATE_ERROR );
            }
            else if state == NETCODE_CLIENT_STATE_DISCONNECTED
            {
                // netcode dropped to disconnected while we thought we were connecting/connected:
                // the server disconnected us (server stopped, or kicked this client).
                if self.base.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_NONE
                {
                    self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED_BY_SERVER );
                }
                self.Disconnect();
                self.base.SetClientState( CLIENT_STATE_DISCONNECTED );
            }
            else if state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST || state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE
            {
                self.base.SetClientState( CLIENT_STATE_CONNECTING );
            }
            else
            {
                self.base.SetClientState( CLIENT_STATE_CONNECTED );
            }
            let networkSimulator: *mut NetworkSimulator = self.base.GetNetworkSimulator();
            if !networkSimulator.is_null() && unsafe { ( *networkSimulator ).IsActive() }
            {
                // Drain the simulator in fixed size batches, so stack usage here doesn't scale
                // with maxSimulatorPackets. Each batch scans the simulator ring again, but the
                // simulator is a development tool, not a production path.
                const MaxBatchPackets: usize = 64;
                let mut packetData: [*mut u8; MaxBatchPackets] = [std::ptr::null_mut(); MaxBatchPackets];
                let mut packetBytes: [i32; MaxBatchPackets] = [0; MaxBatchPackets];
                loop
                {
                    let numPackets: i32 = unsafe { ( *networkSimulator ).ReceivePackets( MaxBatchPackets as i32, &mut packetData, &mut packetBytes, None ) };
                    if numPackets == 0
                    {
                        break;
                    }
                    for i in 0..numPackets as usize
                    {
                        let packet: &[u8] = unsafe { std::slice::from_raw_parts( packetData[i], packetBytes[i] as usize ) };
                        netcode_client_send_packet( unsafe { &mut *self.m_client }, packet, packetBytes[i] );
                        YOJIMBO_FREE!( unsafe { ( *networkSimulator ).GetAllocator() }, packetData[i] );
                    }
                }
            }
        }
    }

    fn GetClientIndex( &self ) -> i32
    {
        if !self.m_client.is_null() { netcode_client_index( unsafe { &mut *self.m_client } ) } else { -1 }
    }

    fn GetClientId( &self ) -> u64 { self.m_clientId }

    fn ConnectLoopback( &mut self, clientIndex: i32, clientId: u64, maxClients: i32 ) -> bool
    {
        self.Disconnect();
        if !BaseClient::CreateInternal( self )
        {
            self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_OUT_OF_MEMORY );
            self.base.SetClientState( CLIENT_STATE_ERROR );
            return false;
        }
        self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_NONE );        // new connect attempt: clear the reason from any previous disconnect
        self.m_clientId = clientId;
        let address = self.m_address;       // port: a copy, as CreateClient takes &mut self
        self.CreateClient( &address );
        if self.m_client.is_null()
        {
            // Socket creation/bind failed. Bail before netcode dereferences the client pointer.
            self.Disconnect();
            return false;
        }
        netcode_client_connect_loopback( unsafe { &mut *self.m_client }, clientIndex, maxClients );
        self.base.SetClientState( CLIENT_STATE_CONNECTED );
        true
    }

    fn DisconnectLoopback( &mut self )
    {
        // Same stop-in-progress guard as Client::Disconnect: this is the same teardown shape,
        // so a reentrant Disconnect/DisconnectLoopback from an adapter callback is a no-op.
        if self.m_disconnecting
        {
            return;
        }
        self.m_disconnecting = true;
        // Same recording rule as Client::Disconnect: a deliberate local disconnect, unless a more
        // specific reason was already recorded.
        if ( self.base.IsConnecting() || self.base.IsConnected() ) && self.base.GetDisconnectReason() == YOJIMBO_CLIENT_DISCONNECT_REASON_NONE
        {
            self.base.SetDisconnectReason( YOJIMBO_CLIENT_DISCONNECT_REASON_DISCONNECTED );
        }
        // port: upstream passes m_client unchecked (netcode asserts it); dereferencing a null pointer is undefined in
        // Rust, so a client with no netcode client skips the call, as the C# port does
        if !self.m_client.is_null()
        {
            netcode_client_disconnect_loopback( unsafe { &mut *self.m_client } );
        }
        BaseClient::Disconnect( self );
        self.DestroyClient();
        self.base.DestroyInternal();
        self.m_clientId = 0;
        self.m_disconnecting = false;
    }

    fn IsLoopback( &self ) -> bool
    {
        // Safe to query in any state: when not connected there is no netcode client, so this is
        // not a loopback client. netcode_client_loopback() would dereference a NULL m_client.
        if !self.m_client.is_null() { netcode_client_loopback( unsafe { &mut *self.m_client } ) != 0 } else { false }
    }

    fn ProcessLoopbackPacket( &mut self, packetData: &[u8], packetBytes: i32, packetSequence: u64 )
    {
        // port: upstream passes m_client unchecked (netcode asserts it); see DisconnectLoopback
        yojimbo_assert!( !self.m_client.is_null() );
        if self.m_client.is_null()
        {
            return;
        }
        netcode_client_process_loopback_packet( unsafe { &mut *self.m_client }, packetData, packetBytes, packetSequence );
    }

    // port: the ClientInterface methods BaseClient implements upstream, delegated to it

    fn SetContext( &mut self, context: *mut c_void ) { self.base.SetContext( context ) }

    fn IsConnecting( &self ) -> bool { self.base.IsConnecting() }

    fn IsConnected( &self ) -> bool { self.base.IsConnected() }

    fn IsDisconnected( &self ) -> bool { self.base.IsDisconnected() }

    fn ConnectionFailed( &self ) -> bool { self.base.ConnectionFailed() }

    fn GetClientState( &self ) -> ClientState { self.base.GetClientState() }

    fn GetTime( &self ) -> f64 { self.base.GetTime() }

    fn CreateMessage( &mut self, r#type: i32 ) -> *mut dyn Message { self.base.CreateMessage( r#type ) }

    fn AllocateBlock( &mut self, bytes: i32 ) -> *mut u8 { self.base.AllocateBlock( bytes ) }

    fn AttachBlockToMessage( &mut self, message: *mut dyn Message, block: *mut u8, bytes: i32 ) { self.base.AttachBlockToMessage( message, block, bytes ) }

    fn FreeBlock( &mut self, block: *mut u8 ) { self.base.FreeBlock( block ) }

    fn CanSendMessage( &self, channelIndex: i32 ) -> bool { self.base.CanSendMessage( channelIndex ) }

    fn SendMessage( &mut self, channelIndex: i32, message: *mut dyn Message ) { self.base.SendMessage( channelIndex, message ) }

    fn ReceiveMessage( &mut self, channelIndex: i32 ) -> *mut dyn Message { self.base.ReceiveMessage( channelIndex ) }

    fn ReleaseMessage( &mut self, message: *mut dyn Message ) { self.base.ReleaseMessage( message ) }

    fn GetNetworkInfo( &self, info: &mut NetworkInfo ) { self.base.GetNetworkInfo( info ) }
}

impl Client
{
    /**
        Gets the local address the client socket is bound to (with the actual port, when port 0 was passed in).
        Under custom packet I/O (Adapter::UseCustomPacketIO) there is no socket: this is the
        constructor-supplied synthetic address, unchanged.
     */

    pub fn GetAddress( &self ) -> &Address { &self.m_boundAddress }

    // port: BaseClient's public non-virtual methods, forwarded to `base` (no inheritance in Rust)

    pub fn SetLatency( &mut self, milliseconds: f32 ) { self.base.SetLatency( milliseconds ) }

    pub fn SetJitter( &mut self, milliseconds: f32 ) { self.base.SetJitter( milliseconds ) }

    pub fn SetPacketLoss( &mut self, percent: f32 ) { self.base.SetPacketLoss( percent ) }

    pub fn SetDuplicates( &mut self, percent: f32 ) { self.base.SetDuplicates( percent ) }

    pub fn HasMessagesToSend( &self, channelIndex: i32 ) -> bool { self.base.HasMessagesToSend( channelIndex ) }

    pub fn GetDisconnectReason( &self ) -> i32 { self.base.GetDisconnectReason() }

    fn CreateClient( &mut self, address: &Address )
    {
        self.DestroyClient();
        let addressString: String = address.ToString();        // port: char addressString[MaxAddressLength]; Address::ToString returns a String

        let mut netcodeConfig = netcode_client_config_t::default();
        netcode_default_client_config( &mut netcodeConfig );
        netcodeConfig.allocator_context             = self.base.GetClientAllocatorContext();     // port: &GetClientAllocator(), see GetClientAllocatorContext
        netcodeConfig.allocate_function             = Some( BaseClient::StaticAllocateFunction );
        netcodeConfig.free_function                 = Some( BaseClient::StaticFreeFunction );
        netcodeConfig.callback_context              = self as *mut Client as *mut c_void;
        netcodeConfig.state_change_callback         = Some( Client::StaticStateChangeCallbackFunction );
        netcodeConfig.send_loopback_packet_callback = Some( Client::StaticSendLoopbackPacketCallbackFunction );
        let useCustomPacketIO: bool = self.base.GetAdapter().UseCustomPacketIO();
        if useCustomPacketIO
        {
            netcodeConfig.override_send_and_receive = 1;
            netcodeConfig.send_packet_override = Some( Client::StaticSendPacketOverride );
            netcodeConfig.receive_packet_override = Some( Client::StaticReceivePacketOverride );
        }
        // port: the Box is held as a raw pointer (see m_client)
        self.m_client = match netcode_client_create( &addressString, &netcodeConfig, self.base.GetTime() ) { Some( client ) => Box::into_raw( client ), None => std::ptr::null_mut() };

        if !self.m_client.is_null()
        {
            if !useCustomPacketIO
            {
                self.m_boundAddress.SetPort( netcode_client_get_port( unsafe { &mut *self.m_client } ) );
            }
        }
    }

    fn DestroyClient( &mut self )
    {
        if !self.m_client.is_null()
        {
            self.m_boundAddress = self.m_address;
            // Clear the member before destroying, so an adapter that calls Disconnect from
            // inside a teardown-time SendPacket callback can't re-enter here and destroy
            // the same netcode client twice.
            let client: *mut netcode_client_t = self.m_client;
            self.m_client = std::ptr::null_mut();
            netcode_client_destroy( unsafe { Box::from_raw( client ) } );
        }
    }

    fn StateChangeCallbackFunction( &mut self, previous: i32, current: i32 )
    {
        let _ = previous;
        let _ = current;
    }

    fn StaticStateChangeCallbackFunction( context: *mut c_void, previous: i32, current: i32 )
    {
        let client = unsafe { &mut *( context as *mut Client ) };
        client.StateChangeCallbackFunction( previous, current );
    }
}

impl BaseClientVirtual for Client
{
    fn base( &self ) -> &BaseClient { &self.base }

    fn base_mut( &mut self ) -> &mut BaseClient { &mut self.base }

    fn TransmitPacketFunction( &mut self, packetSequence: u16, packetData: &[u8], packetBytes: i32 )
    {
        let _ = packetSequence;
        let networkSimulator: *mut NetworkSimulator = self.base.GetNetworkSimulator();
        if !networkSimulator.is_null() && unsafe { ( *networkSimulator ).IsActive() }
        {
            unsafe { ( *networkSimulator ).SendPacket( 0, packetData, packetBytes ); }
        }
        else
        {
            // port: upstream passes m_client unchecked (netcode asserts it)
            yojimbo_assert!( !self.m_client.is_null() );
            netcode_client_send_packet( unsafe { &mut *self.m_client }, packetData, packetBytes );
        }
    }

    fn ProcessPacketFunction( &mut self, packetSequence: u16, packetData: &[u8], packetBytes: i32 ) -> i32
    {
        let context = self.base.GetContext();
        self.base.GetConnection().ProcessPacket( context, packetSequence, packetData, packetBytes ) as i32
    }
}

impl Client
{
    fn SendLoopbackPacketCallbackFunction( &mut self, clientIndex: i32, packetData: &[u8], packetBytes: i32, packetSequence: u64 )
    {
        self.base.GetAdapter().ClientSendLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
    }

    fn StaticSendLoopbackPacketCallbackFunction( context: *mut c_void, clientIndex: i32, packetData: &[u8], packetBytes: i32, packetSequence: u64 )
    {
        let client = unsafe { &mut *( context as *mut Client ) };
        client.SendLoopbackPacketCallbackFunction( clientIndex, packetData, packetBytes, packetSequence );
    }

    fn StaticSendPacketOverride( context: *mut c_void, to: &netcode_address_t, packetData: &[u8], packetBytes: i32 )
    {
        let client = unsafe { &mut *( context as *mut Client ) };
        let address: Address = AddressFromNetcode( to );
        if address.IsValid()
        {
            client.base.GetAdapter().SendPacket( &address, packetData, packetBytes );
        }
    }

    fn StaticReceivePacketOverride( context: *mut c_void, from: &mut netcode_address_t, packetData: &mut [u8], maxPacketBytes: i32 ) -> i32
    {
        let client = unsafe { &mut *( context as *mut Client ) };
        let mut address = Address::new();
        let packetBytes: i32 = client.base.GetAdapter().ReceivePacket( &mut address, packetData, maxPacketBytes );
        if packetBytes <= 0 || packetBytes > maxPacketBytes || !AddressToNetcode( &address, from )
        {
            return 0;
        }
        packetBytes
    }
}
