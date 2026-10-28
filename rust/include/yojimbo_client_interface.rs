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

// port: include/yojimbo_client_interface.h
//
// The `#undef SendMessage` for windows.h has no Rust counterpart.

use crate::*;
use std::ffi::c_void;

/**
    The set of client states.
 */

// port: C++ enum -> i32 constants (README, "Names"); ClientState is their type
pub type ClientState = i32;
pub const CLIENT_STATE_ERROR: i32 = -1;
pub const CLIENT_STATE_DISCONNECTED: i32 = 0;
pub const CLIENT_STATE_CONNECTING: i32 = 1;
pub const CLIENT_STATE_CONNECTED: i32 = 2;

/**
    The common interface for all clients.
 */

// port: the class's pure virtual methods. `virtual ~ClientInterface() {}` has no Rust counterpart: an implementor's
// Drop runs through the trait object.
pub trait ClientInterface
{
    /**
        Set the context for reading and writing packets.
        This is optional. It lets you pass in a pointer to some structure that you want to have available when reading and writing packets via Stream::GetContext.
        Typical use case is to pass in an array of min/max ranges for values determined by some data that is loaded from a toolchain vs. being known at compile time.
        If you do use a context, make sure the same context data is set on client and server, and include a checksum of the context data in the protocol id.
     */

    fn SetContext( &mut self, context: *mut c_void );

    /**
        Disconnect from the server.
     */

    fn Disconnect( &mut self );

    /**
        Send packets to server.
     */

    fn SendPackets( &mut self );

    /**
        Receive packets from the server.
     */

    fn ReceivePackets( &mut self );

    /**
        Advance client time.
        Call this at the end of each frame to advance the client time forward.
        IMPORTANT: Please use a double for your time value so it maintains sufficient accuracy as time increases.
     */

    fn AdvanceTime( &mut self, time: f64 );

    /**
        Is the client connecting to a server?
        This is true while the client is negotiation connection with a server.
        @returns true if the client is currently connecting to, but is not yet connected to a server.
     */

    fn IsConnecting( &self ) -> bool;

    /**
        Is the client connected to a server?
        This is true once a client successfully finishes connection negotiation, and connects to a server. It is false while connecting to a server.
        @returns true if the client is connected to a server.
     */

    fn IsConnected( &self ) -> bool;

    /**
        Is the client in a disconnected state?
        A disconnected state corresponds to the client being in the disconnected, or in an error state. Both are logically "disconnected".
        @returns true if the client is disconnected.
     */

    fn IsDisconnected( &self ) -> bool;

    /**
        Is the client in an error state?
        When the client disconnects because of an error, it enters into this error state.
        @returns true if the client is in an error state.
     */

    fn ConnectionFailed( &self ) -> bool;

    /**
        Get the current client state.
     */

    fn GetClientState( &self ) -> ClientState;

    /**
        Get the client index.
        The client index is the slot number that the client is occupying on the server.
        @returns The client index in [0,maxClients-1], where maxClients is the number of client slots allocated on the server in Server::Start.
     */

    fn GetClientIndex( &self ) -> i32;

    /**
        Get the client id.
        The client id is a unique identifier of this client.
        @returns The client id.
     */

    fn GetClientId( &self ) -> u64;

    /**
        Get the current client time.
        @see Client::AdvanceTime
     */

    fn GetTime( &self ) -> f64;

    /**
        Create a message of the specified type.
        @param type The type of the message to create. The message types corresponds to the message factory created by the adapter set on this client.
     */

    fn CreateMessage( &mut self, r#type: i32 ) -> *mut dyn Message;

    /**
        Helper function to allocate a data block.
        This is typically used to create blocks of data to attach to block messages. See BlockMessage for details.
        @param bytes The number of bytes to allocate.
        @returns The pointer to the data block. This must be attached to a message via Client::AttachBlockToMessage, or freed via Client::FreeBlock.
     */

    fn AllocateBlock( &mut self, bytes: i32 ) -> *mut u8;

    /**
        Attach data block to message.
        @param message The message to attach the block to. This message must be derived from BlockMessage.
        @param block Pointer to the block of data to attach. Must be created via Client::AllocateBlock.
        @param bytes Length of the block of data in bytes.
     */

    fn AttachBlockToMessage( &mut self, message: *mut dyn Message, block: *mut u8, bytes: i32 );

    /**
        Free a block of memory.
        @param block The block of memory created by Client::AllocateBlock.
     */

    fn FreeBlock( &mut self, block: *mut u8 );

    /**
        Can we send a message on a channel?
        @param channelIndex The channel index in range [0,numChannels-1].
        @returns True if a message can be sent over the channel, false otherwise.
     */

    fn CanSendMessage( &self, channelIndex: i32 ) -> bool;

    /**
        Send a message on a channel.
        @param channelIndex The channel index in range [0,numChannels-1].
        @param message The message to send.
     */

    fn SendMessage( &mut self, channelIndex: i32, message: *mut dyn Message );

    /**
        Receive a message from a channel.
        @param channelIndex The channel index in range [0,numChannels-1].
        @returns The message received, or NULL if no message is available. Make sure to release this message by calling Client::ReleaseMessage.
     */

    fn ReceiveMessage( &mut self, channelIndex: i32 ) -> *mut dyn Message;

    /**
        Release a message.
        Call this for messages received by Client::ReceiveMessage.
        @param message The message to release.
     */

    fn ReleaseMessage( &mut self, message: *mut dyn Message );

    /**
        Get client network info.
        Call this to receive information about the client network connection to the server, eg. round trip time, packet loss %, # of packets sent and so on.
        @param info The struct to be filled with network info [out].
     */

    fn GetNetworkInfo( &self, info: &mut NetworkInfo );

    /**
        Connect to server over loopback.
        This allows you to have local clients connected to a server, for example for integrated server or singleplayer.
        @param clientIndex The index of the client.
        @param clientId The unique client id.
        @param maxClients The maximum number of clients supported by the server.
        @returns True if the loopback connection was established. False if the client ran out of memory, in which case the client is left disconnected and nothing is allocated.
     */

    fn ConnectLoopback( &mut self, clientIndex: i32, clientId: u64, maxClients: i32 ) -> bool;

    /**
        Disconnect from server over loopback.
     */

    fn DisconnectLoopback( &mut self );

    /**
        Is this a loopback client?
        @returns true if the client is a loopback client, false otherwise.
     */

    fn IsLoopback( &self ) -> bool;

    /**
        Process loopback packet.
        Use this to pass packets from a server directly to the loopback client.
        @param packetData The packet data to process.
        @param packetBytes The number of bytes of packet data.
        @param packetSequence The packet sequence number.
     */

    fn ProcessLoopbackPacket( &mut self, packetData: &[u8], packetBytes: i32, packetSequence: u64 );
}
