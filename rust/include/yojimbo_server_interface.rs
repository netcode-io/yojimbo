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

// port: include/yojimbo_server_interface.h

use crate::*;
use crate::netcode::netcode_address_t;
use std::ffi::c_void;

// port: the `#undef SendMessage` for windows.h has no Rust meaning

/**
    The server interface.
 */

// port: the abstract class becomes a trait with every pure virtual method, same names and order. `virtual ~ServerInterface() {}`
// has no Rust counterpart: an implementor's Drop runs through the trait object. Pointers the server hands out follow the README:
// the client user data and address are borrowed (None where upstream returns NULL), messages and blocks are raw pointers.
pub trait ServerInterface
{
    /**
        Set the context for reading and writing packets.
        This is optional. It lets you pass in a pointer to some structure that you want to have available when reading and writing packets via Stream::GetContext.
        Typical use case is to pass in an array of min/max ranges for values determined by some data that is loaded from a toolchain vs. being known at compile time.
        If you do use a context, make sure the same context data is set on client and server, and include a checksum of the context data in the protocol id.
     */

    fn SetContext( &mut self, context: *mut c_void );

    /**
        Start the server and allocate client slots.
        Each client that connects to this server occupies one of the client slots allocated by this function.
        @param maxClients The number of client slots to allocate. Must be in range [1,MaxClients]
        @returns True if the server started. False if it ran out of memory or could not open its socket, in which case the server is left stopped and holding nothing.
        @see Server::Stop
     */

    fn Start( &mut self, maxClients: i32 ) -> bool;

    /**
        Stop the server and free client slots.
        Any clients that are connected at the time you call stop will be disconnected.
        When the server is stopped, clients cannot connect to the server.
        @see Server::Start.
     */

    fn Stop( &mut self );

    /**
        Disconnect the client at the specified client index.
        @param clientIndex The index of the client to disconnect in range [0,maxClients-1], where maxClients is the number of client slots allocated in Server::Start.
        @see Server::IsClientConnected
     */

    fn DisconnectClient( &mut self, clientIndex: i32 );

    /**
        Disconnect all clients from the server.
        Client slots remain allocated as per the last call to Server::Start, they are simply made available for new clients to connect.
     */

    fn DisconnectAllClients( &mut self );

    /**
        Send packets to connected clients.
        This function drives the sending of packets that transmit messages to clients.
     */

    fn SendPackets( &mut self );

    /**
        Receive packets from connected clients.
        This function drives the procesing of messages included in packets received from connected clients.
     */

    fn ReceivePackets( &mut self );

    /**
        Advance server time.
        Call this at the end of each frame to advance the server time forward.
        IMPORTANT: Please use a double for your time value so it maintains sufficient accuracy as time increases.
     */

    fn AdvanceTime( &mut self, time: f64 );

    /**
        Is the server running?
        The server is running after you have called Server::Start. It is not running before the first server start, and after you call Server::Stop.
        Clients can only connect to the server while it is running.
        @returns true if the server is currently running.
     */

    fn IsRunning( &self ) -> bool;

    /**
        Get the maximum number of clients that can connect to the server.
        Corresponds to the maxClients parameter passed into the last call to Server::Start.
        @returns The maximum number of clients that can connect to the server. In other words, the number of client slots.
     */

    fn GetMaxClients( &self ) -> i32;

    /**
        Is a client connected to a client slot?
        @param clientIndex the index of the client slot in [0,maxClients-1], where maxClients corresponds to the value passed into the last call to Server::Start.
        @returns True if the client is connected.
     */

    fn IsClientConnected( &self, clientIndex: i32 ) -> bool;

    /**
        Get the unique id of the client
        @param clientIndex the index of the client slot in [0,maxClients-1], where maxClients corresponds to the value passed into the last call to Server::Start.
        @returns The unique id of the client.
     */

    fn GetClientId( &self, clientIndex: i32 ) -> u64;

    /**
        Get the user data of the client.
        @param clientIndex the index of the client slot in [0,maxClients-1], where maxClients corresponds to the value passed into the last call to Server::Start.
        @returns The user data of the client.
     */

    // port: `const uint8_t *` (NULL when not running or out of range) is Option<&[u8]>, the NETCODE_USER_DATA_BYTES user data
    fn GetClientUserData( &self, clientIndex: i32 ) -> Option<&[u8]>;

    /**
        Get the address of the client
        @param clientIndex the index of the client slot in [0,maxClients-1], where maxClients corresponds to the value passed into the last call to Server::Start.
        @returns The address of the client.
     */

    // port: `netcode_address_t *` (NULL when not running or out of range) is Option<&netcode_address_t>: shared, since a
    // `&mut` handed out from `&self` could alias, and nothing writes through it
    fn GetClientAddress( &self, clientIndex: i32 ) -> Option<&netcode_address_t>;

    /**
        Get the number of clients that are currently connected to the server.
        @returns the number of connected clients.
     */

    fn GetNumConnectedClients( &self ) -> i32;

    /**
        Gets the current server time.
        @see Server::AdvanceTime
     */

    fn GetTime( &self ) -> f64;

    /**
        Create a message of the specified type for a specific client.
        @param clientIndex The index of the client this message belongs to. Determines which client heap is used to allocate the message.
        @param type The type of the message to create. The message types corresponds to the message factory created by the adapter set on the server.
     */

    fn CreateMessage( &mut self, clientIndex: i32, r#type: i32 ) -> *mut dyn Message;

    /**
        Helper function to allocate a data block.
        This is typically used to create blocks of data to attach to block messages. See BlockMessage for details.
        @param clientIndex The index of the client this message belongs to. Determines which client heap is used to allocate the data.
        @param bytes The number of bytes to allocate.
        @returns The pointer to the data block. This must be attached to a message via Client::AttachBlockToMessage, or freed via Client::FreeBlock.
     */

    fn AllocateBlock( &mut self, clientIndex: i32, bytes: i32 ) -> *mut u8;

    /**
        Attach data block to message.
        @param clientIndex The index of the client this block belongs to.
        @param message The message to attach the block to. This message must be derived from BlockMessage.
        @param block Pointer to the block of data to attach. Must be created via Client::AllocateBlock.
        @param bytes Length of the block of data in bytes.
     */

    fn AttachBlockToMessage( &mut self, clientIndex: i32, message: *mut dyn Message, block: *mut u8, bytes: i32 );

    /**
        Free a block of memory.
        @param clientIndex The index of the client this block belongs to.
        @param block The block of memory created by Client::AllocateBlock.
     */

    fn FreeBlock( &mut self, clientIndex: i32, block: *mut u8 );

    /**
        Can we send a message to a particular client on a channel?
        @param clientIndex The index of the client to send a message to.
        @param channelIndex The channel index in range [0,numChannels-1].
        @returns True if a message can be sent over the channel, false otherwise.
     */

    fn CanSendMessage( &self, clientIndex: i32, channelIndex: i32 ) -> bool;

    /**
        Send a message to a client over a channel.
        @param clientIndex The index of the client to send a message to.
        @param channelIndex The channel index in range [0,numChannels-1].
        @param message The message to send.
     */

    fn SendMessage( &mut self, clientIndex: i32, channelIndex: i32, message: *mut dyn Message );

    /**
        Receive a message from a client over a channel.
        @param clientIndex The index of the client to receive messages from.
        @param channelIndex The channel index in range [0,numChannels-1].
        @returns The message received, or NULL if no message is available. Make sure to release this message by calling Server::ReleaseMessage.
     */

    fn ReceiveMessage( &mut self, clientIndex: i32, channelIndex: i32 ) -> *mut dyn Message;

    /**
        Release a message.
        Call this for messages received by Server::ReceiveMessage.
        @param clientIndex The index of the client that the message belongs to.
        @param message The message to release.
     */

    fn ReleaseMessage( &mut self, clientIndex: i32, message: *mut dyn Message );

    /**
        Get client network info.
        Call this to receive information about the client network connection, eg. round trip time, packet loss %, # of packets sent and so on.
        @param clientIndex The index of the client.
        @param info The struct to be filled with network info [out].
     */

    fn GetNetworkInfo( &self, clientIndex: i32, info: &mut NetworkInfo );

    /**
        Connect a loopback client.
        This allows you to have local clients connected to a server, for example for integrated server or singleplayer.
        @param clientIndex The index of the client.
        @param clientId The unique client id.
        @param userData User data for this client. Optional. Pass NULL if not needed.
     */

    // port: the optional `const uint8_t * userData` is Option<&[u8]> (None for NULL), as netcode_server_connect_loopback_client
    fn ConnectLoopbackClient( &mut self, clientIndex: i32, clientId: u64, userData: Option<&[u8]> );

    /**
        Disconnect a loopback client.
        Loopback clients are not disconnected by regular Disconnect or DisconnectAllClient calls. You need to call this function instead.
        @param clientIndex The index of the client to disconnect. Must already be a connected loopback client.
     */

    fn DisconnectLoopbackClient( &mut self, clientIndex: i32 );

    /**
        Is this client a loopback client?
        @param clientIndex The client index.
        @returns true if the client is a connected loopback client, false otherwise.
     */

    fn IsLoopbackClient( &self, clientIndex: i32 ) -> bool;

    /**
        Process loopback packet.
        Use this to pass packets from a client directly to the loopback client slot on the server.
        @param clientIndex The client index. Must be an already connected loopback client.
        @param packetData The packet data to process.
        @param packetBytes The number of bytes of packet data.
        @param packetSequence The packet sequence number.
     */

    fn ProcessLoopbackPacket( &mut self, clientIndex: i32, packetData: &[u8], packetBytes: i32, packetSequence: u64 );
}
