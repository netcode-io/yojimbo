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

// port: include/yojimbo_connection.h + source/yojimbo_connection.cpp

use crate::*;
use crate::serialize::*;
use std::ffi::c_void;

/// Connection error level.

pub type ConnectionErrorLevel = i32;
pub const CONNECTION_ERROR_NONE: i32 = 0;                       //< No error. All is well.
pub const CONNECTION_ERROR_CHANNEL: i32 = 1;                    //< A channel is in an error state.
pub const CONNECTION_ERROR_ALLOCATOR: i32 = 2;                  //< The allocator is an error state.
pub const CONNECTION_ERROR_MESSAGE_FACTORY: i32 = 3;            //< The message factory is in an error state.
pub const CONNECTION_ERROR_READ_PACKET_FAILED: i32 = 4;         //< Failed to read packet. Received an invalid packet?

// port: from source/yojimbo_connection.cpp (file-local there)

struct ConnectionPacket
{
    numChannelEntries: i32,
    channelEntry: *mut ChannelPacketData,                       // port: allocated from the message factory's allocator, numChannelEntries entries
    messageFactory: *mut dyn MessageFactory,
}

impl ConnectionPacket
{
    fn new() -> ConnectionPacket
    {
        ConnectionPacket
        {
            messageFactory: null_message_factory(),
            numChannelEntries: 0,
            channelEntry: std::ptr::null_mut(),
        }
    }
}

// port: ~ConnectionPacket()
impl Drop for ConnectionPacket
{
    fn drop( &mut self )
    {
        if !self.messageFactory.is_null()
        {
            for i in 0..self.numChannelEntries as usize
            {
                unsafe { ( *self.channelEntry.add( i ) ).Free( self.messageFactory ) };
            }
            let allocator = unsafe { (*self.messageFactory).GetAllocator() };
            YOJIMBO_FREE!( allocator, self.channelEntry );
            self.messageFactory = null_message_factory();
        }
    }
}

impl ConnectionPacket
{

    fn AllocateChannelData( &mut self, _messageFactory: *mut dyn MessageFactory, numEntries: i32 ) -> bool
    {
        yojimbo_assert!( numEntries > 0 );
        yojimbo_assert!( numEntries <= MaxChannels );
        self.messageFactory = _messageFactory;
        let allocator = unsafe { (*self.messageFactory).GetAllocator() };
        self.channelEntry = YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<ChannelPacketData>() * numEntries as usize ) as *mut ChannelPacketData;
        if self.channelEntry.is_null()
        {
            // On the read path numChannelEntries was already set from the wire before this
            // call; reset it so the destructor doesn't iterate a NULL channelEntry array.
            self.numChannelEntries = 0;
            return false;
        }
        for i in 0..numEntries as usize
        {
            // port: write() a value first, the array is fresh allocator memory
            unsafe
            {
                self.channelEntry.add( i ).write( ChannelPacketData::new() );
                ( *self.channelEntry.add( i ) ).Initialize();
            }
        }
        self.numChannelEntries = numEntries;
        true
    }

    fn Serialize<S: SerializeInternalStream>( &mut self, stream: &mut S, messageFactory: *mut dyn MessageFactory, connectionConfig: &ConnectionConfig ) -> bool
    {
        let numChannels = connectionConfig.numChannels;
        serialize_int!( stream, self.numChannelEntries, 0, connectionConfig.numChannels );
        // port: #if YOJIMBO_DEBUG_MESSAGE_BUDGET is `if YOJIMBO_DEBUG_MESSAGE_BUDGET` (a const, so the code compiles away)
        if YOJIMBO_DEBUG_MESSAGE_BUDGET
        {
            // Write/measure only — validates our own header-size estimate. (On read this is
            // fixed-width and can't exceed the bound anyway, but keep it off the untrusted path.)
            if !S::IsReading
            {
                yojimbo_assert!( stream.GetBitsProcessed() <= ConservativePacketHeaderBits as i64 );
            }
        }
        if self.numChannelEntries > 0
        {
            if S::IsReading
            {
                if !self.AllocateChannelData( messageFactory, self.numChannelEntries )
                {
                    yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate channel data (ConnectionPacket)\n" );
                    return false;
                }
                for i in 0..self.numChannelEntries as usize
                {
                    yojimbo_assert!( unsafe { !( *self.channelEntry.add( i ) ).messageFailedToSerialize } );
                }
            }
            for i in 0..self.numChannelEntries as usize
            {
                let channelEntry = unsafe { &mut *self.channelEntry.add( i ) };
                yojimbo_assert!( !channelEntry.messageFailedToSerialize );
                // port: upstream calls the SerializeInternal overload for this Stream, which calls Serialize; generic Rust calls Serialize directly
                if !channelEntry.Serialize( stream, messageFactory, &connectionConfig.channel, numChannels )
                {
                    yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize channel {}\n", i );
                    return false;
                }
            }
        }
        true
    }

    fn SerializeInternalRead( &mut self, stream: &mut ReadStream, _messageFactory: *mut dyn MessageFactory, connectionConfig: &ConnectionConfig ) -> bool
    {
        self.Serialize( stream, _messageFactory, connectionConfig )
    }

    fn SerializeInternalWrite( &mut self, stream: &mut WriteStream, _messageFactory: *mut dyn MessageFactory, connectionConfig: &ConnectionConfig ) -> bool
    {
        self.Serialize( stream, _messageFactory, connectionConfig )
    }

    fn SerializeInternalMeasure( &mut self, stream: &mut MeasureStream, _messageFactory: *mut dyn MessageFactory, connectionConfig: &ConnectionConfig ) -> bool
    {
        self.Serialize( stream, _messageFactory, connectionConfig )
    }
}

// ------------------------------------------------------------------------------

/**
    Sends and receives messages across a set of user defined channels.
 */

pub struct Connection
{
    m_allocator: *mut dyn Allocator,                            //< Allocator passed in to the connection constructor.
    m_messageFactory: *mut dyn MessageFactory,                  //< Message factory for creating and destroying messages.
    m_connectionConfig: ConnectionConfig,                       //< Connection configuration.
    m_channel: [*mut dyn Channel; MaxChannels as usize],        //< Array of connection channels. Array size corresponds to m_connectionConfig.numChannels
    m_errorLevel: ConnectionErrorLevel,                         //< The connection error level.
}

impl Connection
{
    pub fn new( allocator: *mut dyn Allocator, messageFactory: *mut dyn MessageFactory, connectionConfig: &ConnectionConfig, time: f64 ) -> Connection
    {
        let mut this = Connection
        {
            m_connectionConfig: connectionConfig.clone(),
            m_allocator: allocator,
            m_messageFactory: messageFactory,
            m_errorLevel: CONNECTION_ERROR_NONE,
            m_channel: [null_channel(); MaxChannels as usize],
        };
        yojimbo_assert!( this.m_connectionConfig.numChannels >= 1 );
        yojimbo_assert!( this.m_connectionConfig.numChannels <= MaxChannels );
        for channelIndex in 0..this.m_connectionConfig.numChannels
        {
            let ci = channelIndex as usize;
            match this.m_connectionConfig.channel[ci].r#type
            {
                CHANNEL_TYPE_RELIABLE_ORDERED =>
                {
                    this.m_channel[ci] = YOJIMBO_NEW!( this.m_allocator,
                                                       ReliableOrderedChannel,
                                                       ReliableOrderedChannel::new( this.m_allocator,
                                                                                    messageFactory,
                                                                                    &this.m_connectionConfig.channel[ci],
                                                                                    this.m_connectionConfig.maxPacketSize,
                                                                                    channelIndex,
                                                                                    time ) ) as *mut dyn Channel;
                }

                CHANNEL_TYPE_UNRELIABLE_UNORDERED =>
                {
                    this.m_channel[ci] = YOJIMBO_NEW!( this.m_allocator,
                                                       UnreliableUnorderedChannel,
                                                       UnreliableUnorderedChannel::new( this.m_allocator,
                                                                                        messageFactory,
                                                                                        &this.m_connectionConfig.channel[ci],
                                                                                        this.m_connectionConfig.maxPacketSize,
                                                                                        channelIndex,
                                                                                        time ) ) as *mut dyn Channel;
                }

                _ =>
                {
                    yojimbo_assert!( false /* unknown channel type */ );
                }
            }
        }
        this
    }
}

// port: ~Connection()
impl Drop for Connection
{
    fn drop( &mut self )
    {
        yojimbo_assert!( !self.m_allocator.is_null() );
        self.Reset();
        for i in 0..self.m_connectionConfig.numChannels as usize
        {
            YOJIMBO_DELETE!( self.m_allocator, dyn Channel, self.m_channel[i] );
        }
        self.m_allocator = null_allocator();
    }
}

impl Connection
{
    pub fn Reset( &mut self )
    {
        self.m_errorLevel = CONNECTION_ERROR_NONE;
        for i in 0..self.m_connectionConfig.numChannels as usize
        {
            unsafe { ( *self.m_channel[i] ).Reset() };
        }
    }

    pub fn CanSendMessage( &self, channelIndex: i32 ) -> bool
    {
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_connectionConfig.numChannels );
        unsafe { ( *self.m_channel[channelIndex as usize] ).CanSendMessage() }
    }

    pub fn HasMessagesToSend( &self, channelIndex: i32 ) -> bool
    {
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_connectionConfig.numChannels );
        unsafe { ( *self.m_channel[channelIndex as usize] ).HasMessagesToSend() }
    }

    // port: upstream's context defaults to NULL; Rust has no default arguments, so pass std::ptr::null_mut()
    pub fn SendMessage( &mut self, channelIndex: i32, message: *mut dyn Message, context: *mut c_void )
    {
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_connectionConfig.numChannels );
        unsafe { ( *self.m_channel[channelIndex as usize] ).SendMessage( message, context ) };
    }

    pub fn ReceiveMessage( &mut self, channelIndex: i32 ) -> *mut dyn Message
    {
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_connectionConfig.numChannels );
        unsafe { ( *self.m_channel[channelIndex as usize] ).ReceiveMessage() }
    }

    pub fn ReleaseMessage( &mut self, message: *mut dyn Message )
    {
        yojimbo_assert!( !message.is_null() );
        unsafe { ( *self.m_messageFactory ).ReleaseMessage( message ) };
    }
}

fn WritePacket( context: *mut c_void,
                messageFactory: *mut dyn MessageFactory,
                connectionConfig: &ConnectionConfig,
                packet: &mut ConnectionPacket,
                buffer: &mut [u8],
                bufferSize: i32 ) -> i32
{
    let mut stream = WriteStream::new( buffer, bufferSize as i64 );

    stream.SetContext( context );

    // port: the stream's allocator is a thin pointer; the fat *mut dyn Allocator's metadata is dropped
    stream.SetAllocator( unsafe { (*messageFactory).GetAllocatorContext() } );

    if !packet.SerializeInternalWrite( &mut stream, messageFactory, connectionConfig )
    {
        yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: serialize connection packet failed (write packet)\n" );
        return 0;
    }

    stream.Flush();

    stream.GetBytesProcessed() as i32
}

impl Connection
{
    // port: packetData is a slice; packetBytes is an out-parameter
    pub fn GeneratePacket( &mut self, context: *mut c_void, packetSequence: u16, packetData: &mut [u8], mut maxPacketBytes: i32, packetBytes: &mut i32 ) -> bool
    {
        let mut packet = ConnectionPacket::new();

        // The serialize BitWriter stores qwords, so its buffer size must be a multiple of 8
        // bytes (it may flush a full final qword past the written data). Round the write size
        // down to the nearest multiple of 8: rounding down (never up) keeps packets within the
        // configured maxPacketSize on the wire, and the packet buffer is physically
        // maxPacketBytes so the writer can never overflow it. Budget the channels against the
        // same rounded size so what we pack always fits what we write.
        maxPacketBytes &= !7;

        if self.m_connectionConfig.numChannels > 0
        {
            let mut numChannelsWithData: i32 = 0;
            let mut channelHasData = [false; MaxChannels as usize];
            let mut channelData = [ChannelPacketData::new(); MaxChannels as usize];

            let mut availableBits = maxPacketBytes * 8 - ConservativePacketHeaderBits;

            for channelIndex in 0..self.m_connectionConfig.numChannels as usize
            {
                let packetDataBits = unsafe { ( *self.m_channel[channelIndex] ).GetPacketData( context, &mut channelData[channelIndex], packetSequence, availableBits ) };
                if packetDataBits > 0
                {
                    availableBits -= ConservativeChannelHeaderBits;
                    availableBits -= packetDataBits;
                    channelHasData[channelIndex] = true;
                    numChannelsWithData += 1;
                }
            }

            if numChannelsWithData > 0
            {
                if !packet.AllocateChannelData( self.m_messageFactory, numChannelsWithData )
                {
                    yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate channel data\n" );
                    // GetPacketData already populated channelData for each channel with data
                    // (acquired message references, allocated message-pointer arrays, copied
                    // fragment data). Ownership hasn't transferred to the packet yet, so free
                    // those entries here or they leak on this error path.
                    for channelIndex in 0..self.m_connectionConfig.numChannels as usize
                    {
                        if channelHasData[channelIndex]
                        {
                            channelData[channelIndex].Free( self.m_messageFactory );
                        }
                    }
                    return false;
                }

                let mut index: usize = 0;

                for channelIndex in 0..self.m_connectionConfig.numChannels as usize
                {
                    if channelHasData[channelIndex]
                    {
                        // port: the memcpy (ChannelPacketData is Copy)
                        unsafe { *packet.channelEntry.add( index ) = channelData[channelIndex] };
                        index += 1;
                    }
                }
            }
        }

        *packetBytes = WritePacket( context, self.m_messageFactory, &self.m_connectionConfig, &mut packet, packetData, maxPacketBytes );

        true
    }
}

fn ReadPacket( context: *mut c_void,
               messageFactory: *mut dyn MessageFactory,
               connectionConfig: &ConnectionConfig,
               packet: &mut ConnectionPacket,
               buffer: &[u8],
               bufferSize: i32 ) -> bool
{
    yojimbo_assert!( !buffer.is_empty() );
    yojimbo_assert!( bufferSize > 0 );

    let mut stream = ReadStream::new( buffer, bufferSize as i64 );

    stream.SetContext( context );

    // port: the stream's allocator is a thin pointer; the fat *mut dyn Allocator's metadata is dropped
    stream.SetAllocator( unsafe { (*messageFactory).GetAllocatorContext() } );

    if !packet.SerializeInternalRead( &mut stream, messageFactory, connectionConfig )
    {
        yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: serialize connection packet failed (read packet)\n" );
        return false;
    }

    true
}

impl Connection
{
    // port: packetData is a slice; a NULL packetData is an empty slice
    pub fn ProcessPacket( &mut self, context: *mut c_void, packetSequence: u16, packetData: &[u8], packetBytes: i32 ) -> bool
    {
        if self.m_errorLevel != CONNECTION_ERROR_NONE
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_DEBUG, "failed to read packet because connection is in error state\n" );
            return false;
        }

        // A packet that is exactly a reliable header reaches us with zero payload bytes.
        // That's never a valid connection packet, so fail it like any other malformed read.
        if packetData.is_empty() || packetBytes <= 0
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to read packet (empty payload)\n" );
            self.m_errorLevel = CONNECTION_ERROR_READ_PACKET_FAILED;
            return false;
        }

        let mut packet = ConnectionPacket::new();

        // BitReader loads an 8-byte window. netcode/reliable hand back an exact
        // payload allocation, so copy into packetBytes+8 before deserialize.
        let mut padded = YOJIMBO_ALLOCATE!( self.m_allocator, packetBytes as usize + 8 );
        if padded.is_null()
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate padded read buffer\n" );
            self.m_errorLevel = CONNECTION_ERROR_ALLOCATOR;
            return false;
        }
        let paddedSlice = unsafe { std::slice::from_raw_parts_mut( padded, packetBytes as usize + 8 ) };
        paddedSlice[..packetBytes as usize].copy_from_slice( &packetData[..packetBytes as usize] );
        paddedSlice[packetBytes as usize..].fill( 0 );

        let readOk = ReadPacket( context, self.m_messageFactory, &self.m_connectionConfig, &mut packet, paddedSlice, packetBytes );
        YOJIMBO_FREE!( self.m_allocator, padded );

        if !readOk
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to read packet\n" );
            self.m_errorLevel = CONNECTION_ERROR_READ_PACKET_FAILED;
            return false;
        }

        for i in 0..packet.numChannelEntries as usize
        {
            let channelEntry = unsafe { &*packet.channelEntry.add( i ) };
            let channelIndex = channelEntry.channelIndex as i32;
            yojimbo_assert!( channelIndex >= 0 );
            yojimbo_assert!( channelIndex < self.m_connectionConfig.numChannels );
            let channel = self.m_channel[channelIndex as usize];
            unsafe { ( *channel ).ProcessPacketData( channelEntry, packetSequence ) };
            if unsafe { ( *channel ).GetErrorLevel() } != CHANNEL_ERROR_NONE
            {
                yojimbo_printf!( YOJIMBO_LOG_LEVEL_DEBUG, "failed to read packet because channel {} is in error state\n", channelIndex );
                return false;
            }
        }

        true
    }

    /**
        Get the error level of a channel on this connection.
        Use this to find out which channel error drove the connection into CONNECTION_ERROR_CHANNEL.
        @param channelIndex The channel index in [0,numChannels-1].
        @returns The channel error level.
     */

    pub fn GetChannelErrorLevel( &self, channelIndex: i32 ) -> ChannelErrorLevel
    {
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < self.m_connectionConfig.numChannels );
        unsafe { ( *self.m_channel[channelIndex as usize] ).GetErrorLevel() }
    }

    // port: acks is a slice
    pub fn ProcessAcks( &mut self, acks: &[u16], numAcks: i32 )
    {
        for i in 0..numAcks as usize
        {
            for channelIndex in 0..self.m_connectionConfig.numChannels as usize
            {
                unsafe { ( *self.m_channel[channelIndex] ).ProcessAck( acks[i] ) };
            }
        }
    }

    pub fn AdvanceTime( &mut self, time: f64 )
    {
        for i in 0..self.m_connectionConfig.numChannels as usize
        {
            unsafe { ( *self.m_channel[i] ).AdvanceTime( time ) };

            if unsafe { ( *self.m_channel[i] ).GetErrorLevel() } != CHANNEL_ERROR_NONE
            {
                self.m_errorLevel = CONNECTION_ERROR_CHANNEL;
                return;
            }
        }
        if unsafe { ( *self.m_allocator ).GetErrorLevel() } != ALLOCATOR_ERROR_NONE
        {
            self.m_errorLevel = CONNECTION_ERROR_ALLOCATOR;
            return;
        }
        if unsafe { ( *self.m_messageFactory ).GetErrorLevel() } != MESSAGE_FACTORY_ERROR_NONE
        {
            self.m_errorLevel = CONNECTION_ERROR_MESSAGE_FACTORY;
            return;
        }
    }

    pub fn GetErrorLevel( &self ) -> ConnectionErrorLevel { self.m_errorLevel }
}
