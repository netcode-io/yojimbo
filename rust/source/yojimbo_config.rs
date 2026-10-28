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

/*
    Rust port of include/yojimbo_config.h + source/yojimbo_config.cpp (yojimbo 1.13.5).

    Port notes:
      - The preprocessor switches are consts: YOJIMBO_DEBUG / YOJIMBO_RELEASE follow cfg(debug_assertions) (upstream:
        NDEBUG), and the YOJIMBO_DEBUG_* feature flags and YOJIMBO_ENABLE_LOGGING are bools.
      - ChannelType is i32 consts, as every upstream enum. ChannelConfig, ConnectionConfig and ClientServerConfig are
        Copy structs (C++ copies them by value); their C++ constructors are new() (and Default).
      - ClientServerConfig derives from ConnectionConfig upstream: it embeds it as `base` and derefs to it, so
        config.numChannels, config.channel[i] and &config as &ConnectionConfig work as in C++.
*/

use crate::*;

pub const YOJIMBO_MAJOR_VERSION: i32 = 1;
pub const YOJIMBO_MINOR_VERSION: i32 = 13;
pub const YOJIMBO_PATCH_VERSION: i32 = 5;

// port: #define YOJIMBO_DEBUG / YOJIMBO_RELEASE from NDEBUG
pub const YOJIMBO_DEBUG: bool = cfg!(debug_assertions);
pub const YOJIMBO_RELEASE: bool = !YOJIMBO_DEBUG;

pub const YOJIMBO_DEFAULT_TIMEOUT: i32 = 10;

// port: the _MSC_VER warning pragmas and _CRT_SECURE_NO_WARNINGS have no Rust meaning

pub const YOJIMBO_PLATFORM_WINDOWS: i32 = 1;
pub const YOJIMBO_PLATFORM_MAC: i32 = 2;
pub const YOJIMBO_PLATFORM_UNIX: i32 = 3;

#[cfg(windows)]
pub const YOJIMBO_PLATFORM: i32 = YOJIMBO_PLATFORM_WINDOWS;
#[cfg(target_os = "macos")]
pub const YOJIMBO_PLATFORM: i32 = YOJIMBO_PLATFORM_MAC;
#[cfg(not(any(windows, target_os = "macos")))]
pub const YOJIMBO_PLATFORM: i32 = YOJIMBO_PLATFORM_UNIX;

// port: YOJIMBO_OVERRIDE has no Rust meaning (trait impls are always overrides)

pub const YOJIMBO_DEBUG_MEMORY_LEAKS: bool = YOJIMBO_DEBUG;
pub const YOJIMBO_DEBUG_MESSAGE_LEAKS: bool = YOJIMBO_DEBUG;
pub const YOJIMBO_DEBUG_MESSAGE_BUDGET: bool = YOJIMBO_DEBUG;

// Logging is ON by default, matching netcode and reliable: a networking library
// that goes silent in a release build is worse than one that costs a few
// nanoseconds per call. Guarded so it can still be compiled out from the build
// system (-DYOJIMBO_ENABLE_LOGGING=0) without editing this header, which is
// what netcode.c and reliable.c already allow.
// port: a const; set it to false here to compile logging out
pub const YOJIMBO_ENABLE_LOGGING: bool = true;

/// Determines the reliability and ordering guarantees for a channel.

pub type ChannelType = i32;
pub const CHANNEL_TYPE_RELIABLE_ORDERED: i32 = 0;                   //< Messages are received reliably and in the same order they were sent.
pub const CHANNEL_TYPE_UNRELIABLE_UNORDERED: i32 = 1;               //< Messages are sent unreliably. Messages may arrive out of order, or not at all.

/**
    Configuration properties for a message channel.

    Channels let you specify different reliability and ordering guarantees for messages sent across a connection.

    They may be configured as one of two types: reliable-ordered or unreliable-unordered.

    Reliable ordered channels guarantee that messages (see Message) are received reliably and in the same order they were sent.
    This channel type is designed for control messages and RPCs sent between the client and server.

    Unreliable unordered channels are like UDP. There is no guarantee that messages will arrive, and messages may arrive out of order.
    This channel type is designed for data that is time critical and should not be resent if dropped, like snapshots of world state sent rapidly
    from server to client, or cosmetic events such as effects and sounds.

    Both channel types support blocks of data attached to messages (see BlockMessage), but their treatment of blocks is quite different.

    Reliable ordered channels are designed for blocks that must be received reliably and in-order with the rest of the messages sent over the channel.
    Examples of these sort of blocks include the initial state of a level, or server configuration data sent down to a client on connect. These blocks
    are sent by splitting them into fragments and resending each fragment until the other side has received the entire block. This allows for sending
    blocks of data larger that maximum packet size quickly and reliably even under packet loss.

    Unreliable-unordered channels send blocks as-is without splitting them up into fragments. The idea is that transport level packet fragmentation
    should be used on top of the generated packet to split it up into into smaller packets that can be sent across typical Internet MTU (<1500 bytes).
    Because of this, you need to make sure that the maximum block size for an unreliable-unordered channel fits within the maximum packet size.

    Channels are typically configured as part of a ConnectionConfig, which is included inside the ClientServerConfig that is passed into the Client and Server constructors.
 */

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChannelConfig
{
    pub r#type: ChannelType,                                    //< Channel type: reliable-ordered or unreliable-unordered.
    pub disableBlocks: bool,                                    //< Disables blocks being sent across this channel.
    pub sentPacketBufferSize: i32,                              //< Number of packet entries in the sent packet sequence buffer. Please consider your packet send rate and make sure you have at least a few seconds worth of entries in this buffer.
    pub messageSendQueueSize: i32,                              //< Number of messages in the send queue for this channel.
    pub messageReceiveQueueSize: i32,                           //< Number of messages in the receive queue for this channel.
    pub maxMessagesPerPacket: i32,                              //< Maximum number of messages to include in each packet. Will write up to this many messages, provided the messages fit into the channel packet budget and the number of bytes remaining in the packet.
    pub packetBudget: i32,                                      //< Maximum amount of message data to write to the packet for this channel (bytes). Specifying -1 means the channel can use up to the rest of the bytes remaining in the packet.
    pub maxBlockSize: i32,                                      //< The size of the largest block that can be sent across this channel (bytes).
    pub blockFragmentSize: i32,                                 //< Blocks are split up into fragments of this size (bytes). Reliable-ordered channel only.
    pub messageResendTime: f32,                                 //< Minimum delay between message resends (seconds). Avoids sending the same message too frequently. Reliable-ordered channel only.
    pub blockFragmentResendTime: f32,                           //< Minimum delay between block fragment resends (seconds). Avoids sending the same fragment too frequently. Reliable-ordered channel only.
    pub allocateBlocksOnDemand: bool,                           //< Port addition (not in upstream): allocate the block receive buffer when a block starts arriving, sized to that block, and free it once delivered, instead of reserving maxBlockSize per connection when the channel is created. Lets a server raise maxBlockSize without reserving it for every client. Local only, not on the wire. Reliable-ordered channel only.
}

impl ChannelConfig
{
    pub const fn new() -> ChannelConfig
    {
        ChannelConfig
        {
            r#type: CHANNEL_TYPE_RELIABLE_ORDERED,
            disableBlocks: false,
            sentPacketBufferSize: 1024,
            messageSendQueueSize: 1024,
            messageReceiveQueueSize: 1024,
            maxMessagesPerPacket: 256,
            packetBudget: -1,
            maxBlockSize: 256 * 1024,
            blockFragmentSize: 1024,
            messageResendTime: 0.1,
            blockFragmentResendTime: 0.25,
            allocateBlocksOnDemand: false,                      // port addition
        }
    }

    pub fn GetMaxFragmentsPerBlock( &self ) -> i32
    {
        // Round up: a block of maxBlockSize needs ceil(maxBlockSize/blockFragmentSize)
        // fragments. Using floor here under-sizes the send-side fragment buffers when
        // maxBlockSize is not a multiple of blockFragmentSize (see GetFragmentToSend,
        // which counts fragments with ceil).
        //
        // The add is 64-bit so a legal huge maxBlockSize cannot overflow signed int
        // before the 65535 check in Validate (yojimbo#347).
        if self.blockFragmentSize <= 0
        {
            return 0;
        }
        let n: i64 = ( self.maxBlockSize as i64 + self.blockFragmentSize as i64 - 1 ) / self.blockFragmentSize as i64;
        if n > 2147483647
        {
            return 2147483647;
        }
        if n < 0
        {
            return 0;
        }
        n as i32
    }

    // port: Validate( channelIndex, maxPacketSize ) is defined below, with source/yojimbo_config.cpp
}

impl Default for ChannelConfig
{
    fn default() -> Self { ChannelConfig::new() }
}

/**
    Configures connection properties and the set of channels for sending and receiving messages.
    Specifies the maximum packet size to generate, and the number of message channels, and the per-channel configuration data. See ChannelConfig for details.
    Typically configured as part of a ClientServerConfig which is passed into Client and Server constructors.
 */

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConnectionConfig
{
    pub numChannels: i32,                                       //< Number of message channels in [1,MaxChannels]. Each message channel must have a corresponding configuration below.
    pub maxPacketSize: i32,                                     //< The maximum size of packets generated to transmit messages between client and server (bytes).
    pub channel: [ChannelConfig; MaxChannels as usize],         //< Per-channel configuration. See ChannelConfig for details.
}

impl ConnectionConfig
{
    pub const fn new() -> ConnectionConfig
    {
        let mut config = ConnectionConfig
        {
            numChannels: 2,
            maxPacketSize: 8 * 1024,
            channel: [ChannelConfig::new(); MaxChannels as usize],
        };
        config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
        config
    }

    // port: Validate() is defined below, with source/yojimbo_config.cpp
}

impl Default for ConnectionConfig
{
    fn default() -> Self { ConnectionConfig::new() }
}

/**
    Configuration shared between client and server.
    Passed to Client and Server constructors to configure their behavior.
    Please make sure that the message configuration is identical between client and server.
 */

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClientServerConfig
{
    pub base: ConnectionConfig,                                 //< port: the ConnectionConfig base class (ClientServerConfig derefs to it)
    pub protocolId: u64,                                        //< Clients can only connect to servers with the same protocol id. Use this for versioning.
    pub timeout: i32,                                           //< Timeout value in seconds. Set to negative value to disable timeouts (for debugging only).
    pub clientMemory: i32,                                      //< Memory allocated inside Client for packets, messages and stream allocations (bytes)
    pub serverGlobalMemory: i32,                                //< Memory allocated inside Server for global connection request and challenge response packets (bytes)
    pub serverPerClientMemory: i32,                             //< Memory allocated inside Server for packets, messages and stream allocations per-client (bytes)
    pub networkSimulator: bool,                                 //< If true then a network simulator is created for simulating latency, jitter, packet loss and duplicates.
    pub maxSimulatorPackets: i32,                               //< Maximum number of packets that can be stored in the network simulator. Additional packets are dropped.
    pub fragmentPacketsAbove: i32,                              //< Packets above this size (bytes) are split apart into fragments and reassembled on the other side.
    pub packetFragmentSize: i32,                                //< Size of each packet fragment (bytes).
    pub maxPacketFragments: i32,                                //< Maximum number of fragments a packet can be split up into.
    pub packetReassemblyBufferSize: i32,                        //< Number of packet entries in the fragmentation reassembly buffer.
    pub ackedPacketsBufferSize: i32,                            //< Number of packet entries in the acked packet buffer. Consider your packet send rate and aim to have at least a few seconds worth of entries.
    pub receivedPacketsBufferSize: i32,                         //< Number of packet entries in the received packet sequence buffer. Consider your packet send rate and aim to have at least a few seconds worth of entries.
    pub rttSmoothingFactor: f32,                                //< Round-Trip Time (RTT) smoothing factor over time.
    pub maxConnectTokenLifetime: i32,                           //< The longest lifetime in seconds your backend issues connect tokens with. Server only. The server refuses any connect token whose expiry, minus this lifetime, is earlier than the time the server started, so a token that could have been issued before a restart cannot be presented after it. Set it to the lifetime your matchmaker actually issues: too large refuses legitimate connect tokens until the difference has elapsed, too small lets tokens issued shortly before the server started through. Zero or less takes DefaultMaxConnectTokenLifetime.
}

impl ClientServerConfig
{
    pub fn new() -> ClientServerConfig
    {
        let base = ConnectionConfig::new();
        let packetFragmentSize: i32 = 1024;
        ClientServerConfig
        {
            protocolId: 0,
            timeout: YOJIMBO_DEFAULT_TIMEOUT,
            clientMemory: 10 * 1024 * 1024,
            serverGlobalMemory: 10 * 1024 * 1024,
            serverPerClientMemory: 10 * 1024 * 1024,
            networkSimulator: true,
            maxSimulatorPackets: 4 * 1024,
            fragmentPacketsAbove: 1024,
            packetFragmentSize: packetFragmentSize,
            maxPacketFragments: ( base.maxPacketSize as f64 / packetFragmentSize as f64 ).ceil() as i32,
            packetReassemblyBufferSize: 64,
            ackedPacketsBufferSize: 256,
            receivedPacketsBufferSize: 256,
            rttSmoothingFactor: 0.0025,
            maxConnectTokenLifetime: DefaultMaxConnectTokenLifetime,
            base: base,
        }
    }

    // port: Validate() is defined below, with source/yojimbo_config.cpp
}

impl Default for ClientServerConfig
{
    fn default() -> Self { ClientServerConfig::new() }
}

// port: the C++ base class ConnectionConfig
impl std::ops::Deref for ClientServerConfig
{
    type Target = ConnectionConfig;
    fn deref( &self ) -> &ConnectionConfig { &self.base }
}

impl std::ops::DerefMut for ClientServerConfig
{
    fn deref_mut( &mut self ) -> &mut ConnectionConfig { &mut self.base }
}

// ---------------------------------------------------------------------------------------------
// source/yojimbo_config.cpp

// Print what is wrong with the config (with the offending values), then assert. Debug builds
// only: config validation follows the library-wide contract that asserts enforce correct usage
// in debug and the programmer has already validated their integration before shipping release.
#[cfg(debug_assertions)]
macro_rules! YOJIMBO_CONFIG_CHECK {
    ( $condition:expr, $($arg:tt)* ) => {
        if !( $condition )
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, $($arg)* );
            yojimbo_assert!( $condition );
        }
    };
}

#[cfg(debug_assertions)]
impl ChannelConfig
{
    /**
        Validate this channel configuration.
        Asserts (debug builds only, zero overhead in release) on invariants the channel implementations rely on,
        so an invalid channel config fails loudly at startup rather than corrupting channel state at runtime.
        Called for each channel by ConnectionConfig::Validate.
        @param channelIndex The index of this channel in the connection config. Used for error reporting.
        @param maxPacketSize The maximum packet size from the connection config (bytes).
     */

    pub fn Validate( &self, channelIndex: i32, maxPacketSize: i32 )
    {
        YOJIMBO_CONFIG_CHECK!( self.messageSendQueueSize > 0,
            "error: invalid config: channel {} messageSendQueueSize ({}) must be > 0\n", channelIndex, self.messageSendQueueSize );

        YOJIMBO_CONFIG_CHECK!( self.messageReceiveQueueSize > 0,
            "error: invalid config: channel {} messageReceiveQueueSize ({}) must be > 0\n", channelIndex, self.messageReceiveQueueSize );

        YOJIMBO_CONFIG_CHECK!( self.maxMessagesPerPacket > 0,
            "error: invalid config: channel {} maxMessagesPerPacket ({}) must be > 0\n", channelIndex, self.maxMessagesPerPacket );

        if !self.disableBlocks
        {
            YOJIMBO_CONFIG_CHECK!( self.maxBlockSize > 0,
                "error: invalid config: channel {} maxBlockSize ({}) must be > 0\n", channelIndex, self.maxBlockSize );
        }

        if self.r#type == CHANNEL_TYPE_RELIABLE_ORDERED
        {
            // The reliable-ordered channel stores its state in sequence buffers indexed by
            // sequence % size, which only works when the size divides 65536 (ie. a power of two).
            // Any other size aliases sequence numbers and corrupts channel state.

            YOJIMBO_CONFIG_CHECK!( self.sentPacketBufferSize > 0,
                "error: invalid config: channel {} sentPacketBufferSize ({}) must be > 0\n", channelIndex, self.sentPacketBufferSize );

            // port: the "> 0 &&" guards keep a zero size from panicking on the remainder (a custom assert function can return)
            YOJIMBO_CONFIG_CHECK!( self.sentPacketBufferSize > 0 && ( 65536 % self.sentPacketBufferSize ) == 0,
                "error: invalid config: channel {} sentPacketBufferSize ({}) must be a power of two\n", channelIndex, self.sentPacketBufferSize );

            YOJIMBO_CONFIG_CHECK!( self.messageSendQueueSize > 0 && ( 65536 % self.messageSendQueueSize ) == 0,
                "error: invalid config: channel {} messageSendQueueSize ({}) must be a power of two\n", channelIndex, self.messageSendQueueSize );

            YOJIMBO_CONFIG_CHECK!( self.messageReceiveQueueSize > 0 && ( 65536 % self.messageReceiveQueueSize ) == 0,
                "error: invalid config: channel {} messageReceiveQueueSize ({}) must be a power of two\n", channelIndex, self.messageReceiveQueueSize );

            if !self.disableBlocks
            {
                YOJIMBO_CONFIG_CHECK!( self.blockFragmentSize > 0,
                    "error: invalid config: channel {} blockFragmentSize ({}) must be > 0\n", channelIndex, self.blockFragmentSize );

                // On the wire fragmentSize is a 16-bit field (yojimbo#346).
                YOJIMBO_CONFIG_CHECK!( self.blockFragmentSize <= 65535,
                    "error: invalid config: channel {} blockFragmentSize ({}) must be <= 65535\n", channelIndex, self.blockFragmentSize );

                // A block fragment must fit inside a packet, or the channel stalls forever trying
                // to send the block (see ReliableOrderedChannel::GetPacketData).
                YOJIMBO_CONFIG_CHECK!( self.blockFragmentSize <= maxPacketSize,
                    "error: invalid config: channel {} blockFragmentSize ({}) must be <= maxPacketSize ({})\n", channelIndex, self.blockFragmentSize, maxPacketSize );

                // Fragment id 0xFFFF is reserved as a sentinel (see GetFragmentToSend).
                YOJIMBO_CONFIG_CHECK!( self.GetMaxFragmentsPerBlock() <= 65535,
                    "error: invalid config: channel {} maxBlockSize ({}) / blockFragmentSize ({}) gives too many fragments per block (max 65535)\n", channelIndex, self.maxBlockSize, self.blockFragmentSize );
            }
        }
    }
}

#[cfg(debug_assertions)]
impl ConnectionConfig
{
    /**
        Validate this connection configuration.
        Asserts (debug builds only, zero overhead in release) on invariants the connection and channels rely on,
        so an invalid config fails loudly at startup rather than corrupting state at runtime.
        IMPORTANT: The connection config must be identical on the client and the server. This validates each side
        locally -- keeping the two sides in sync is your responsibility.
     */

    pub fn Validate( &self )
    {
        YOJIMBO_CONFIG_CHECK!( self.numChannels >= 1 && self.numChannels <= MaxChannels,
            "error: invalid config: numChannels ({}) must be in [1,{}]\n", self.numChannels, MaxChannels );

        YOJIMBO_CONFIG_CHECK!( self.maxPacketSize > 0,
            "error: invalid config: maxPacketSize ({}) must be > 0\n", self.maxPacketSize );

        // port: clamped to the channel array, so a custom assert function that returns can't index out of bounds
        for i in 0..yojimbo_min( self.numChannels, MaxChannels )
        {
            self.channel[i as usize].Validate( i, self.maxPacketSize );
        }
    }
}

#[cfg(debug_assertions)]
impl ClientServerConfig
{
    /**
        Validate this client/server configuration.
        Asserts (debug builds only, zero overhead in release) on invariants the client and server rely on,
        so an invalid config fails loudly at startup rather than misbehaving at runtime.
        Called automatically by Server::Start and when the client connects. You can also call it directly.
        IMPORTANT: If you increase maxPacketSize after construction, you must also update maxPacketFragments,
        because it is derived from maxPacketSize inside the ClientServerConfig constructor. This is one of the
        things validated here.
     */

    pub fn Validate( &self )
    {
        self.base.Validate();

        YOJIMBO_CONFIG_CHECK!( self.clientMemory > 0,
            "error: invalid config: clientMemory ({}) must be > 0\n", self.clientMemory );

        YOJIMBO_CONFIG_CHECK!( self.serverGlobalMemory > 0,
            "error: invalid config: serverGlobalMemory ({}) must be > 0\n", self.serverGlobalMemory );

        YOJIMBO_CONFIG_CHECK!( self.serverPerClientMemory > 0,
            "error: invalid config: serverPerClientMemory ({}) must be > 0\n", self.serverPerClientMemory );

        if self.networkSimulator
        {
            YOJIMBO_CONFIG_CHECK!( self.maxSimulatorPackets > 0,
                "error: invalid config: maxSimulatorPackets ({}) must be > 0\n", self.maxSimulatorPackets );
        }

        YOJIMBO_CONFIG_CHECK!( self.packetFragmentSize > 0,
            "error: invalid config: packetFragmentSize ({}) must be > 0\n", self.packetFragmentSize );

        YOJIMBO_CONFIG_CHECK!( self.fragmentPacketsAbove > 0,
            "error: invalid config: fragmentPacketsAbove ({}) must be > 0\n", self.fragmentPacketsAbove );

        // maxPacketFragments is derived from maxPacketSize inside the ClientServerConfig
        // constructor, which runs *before* your code adjusts any fields. If you increase
        // maxPacketSize you must update maxPacketFragments too, otherwise packets larger than
        // packetFragmentSize * maxPacketFragments cannot be fragmented and are dropped.
        let neededPacketFragments: i32 = ( self.maxPacketSize as f64 / self.packetFragmentSize as f64 ).ceil() as i32;

        YOJIMBO_CONFIG_CHECK!( self.maxPacketFragments >= neededPacketFragments,
            "error: invalid config: maxPacketFragments ({}) is too small for maxPacketSize ({}) with packetFragmentSize ({}). It must be at least {}.\n\
             maxPacketFragments is computed in the ClientServerConfig constructor, so if you increase maxPacketSize afterwards, update maxPacketFragments as well\n",
            self.maxPacketFragments, self.maxPacketSize, self.packetFragmentSize, neededPacketFragments );

        // The reliable endpoint encodes (num fragments - 1) as a uint8_t and asserts max_fragments <= 256.
        YOJIMBO_CONFIG_CHECK!( self.maxPacketFragments <= 256,
            "error: invalid config: maxPacketFragments ({}) must be <= 256\n", self.maxPacketFragments );

        YOJIMBO_CONFIG_CHECK!( self.packetReassemblyBufferSize > 0,
            "error: invalid config: packetReassemblyBufferSize ({}) must be > 0\n", self.packetReassemblyBufferSize );

        YOJIMBO_CONFIG_CHECK!( self.ackedPacketsBufferSize > 0,
            "error: invalid config: ackedPacketsBufferSize ({}) must be > 0\n", self.ackedPacketsBufferSize );

        YOJIMBO_CONFIG_CHECK!( self.receivedPacketsBufferSize > 0,
            "error: invalid config: receivedPacketsBufferSize ({}) must be > 0\n", self.receivedPacketsBufferSize );
    }
}

#[cfg(not(debug_assertions))]
impl ChannelConfig
{
    pub fn Validate( &self, channelIndex: i32, maxPacketSize: i32 )
    {
    }
}

#[cfg(not(debug_assertions))]
impl ConnectionConfig
{
    pub fn Validate( &self ) {}
}

#[cfg(not(debug_assertions))]
impl ClientServerConfig
{
    pub fn Validate( &self ) {}
}
