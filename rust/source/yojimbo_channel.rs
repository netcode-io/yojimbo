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

// port: include/yojimbo_channel.h + source/yojimbo_channel.cpp

use crate::*;
use crate::serialize::*;
use std::ffi::c_void;

// port: C++ overload resolution picks Message::SerializeInternal( ReadStream & / WriteStream & / MeasureStream & )
// for the Stream a template is instantiated with. A generic Rust function can't name the overload, so the
// templates below that call SerializeInternal on a message take `S: SerializeInternalStream`, which makes the
// same compile-time choice. Implemented for the three streams only.

pub trait SerializeInternalStream: Stream
{
    fn SerializeInternal<T: Serializable + ?Sized>( object: &mut T, stream: &mut Self ) -> bool;
}

impl<'a> SerializeInternalStream for ReadStream<'a>
{
    fn SerializeInternal<T: Serializable + ?Sized>( object: &mut T, stream: &mut Self ) -> bool { object.SerializeInternalRead( stream ) }
}

impl<'a> SerializeInternalStream for WriteStream<'a>
{
    fn SerializeInternal<T: Serializable + ?Sized>( object: &mut T, stream: &mut Self ) -> bool { object.SerializeInternalWrite( stream ) }
}

impl SerializeInternalStream for MeasureStream
{
    fn SerializeInternal<T: Serializable + ?Sized>( object: &mut T, stream: &mut Self ) -> bool { object.SerializeInternalMeasure( stream ) }
}

// port: the C++ bitfields (channelIndex : 16, the 1-bit flags, the 16-bit block fields) are plain u16 / bool,
// as in the C# port. Copy because Connection::GeneratePacket memcpys entries into the packet.

#[derive(Clone, Copy)]
pub struct ChannelPacketData_MessageData
{
    pub numMessages: i32,
    pub messages: *mut *mut dyn Message,            // port: allocated from the message factory's allocator, numMessages entries
}

#[derive(Clone, Copy)]
pub struct ChannelPacketData_BlockData
{
    // port: upstream holds a BlockMessage *. A Rust `*mut BlockMessage` would lose the derived message's vtable
    // (ReleaseMessage must destroy the derived type), so it is the `*mut dyn Message` of the block message;
    // reach its block with AsBlockMessage().
    pub message: *mut dyn Message,
    pub fragmentData: *mut u8,
    pub messageId: u16,
    pub fragmentId: u16,
    pub fragmentSize: u16,
    pub numFragments: u16,
    pub messageType: i32,
}

#[derive(Clone, Copy)]
pub struct ChannelPacketData
{
    pub channelIndex: u16,
    pub initialized: bool,
    pub blockMessage: bool,
    pub messageFailedToSerialize: bool,

    // `blockMessage` selects which of these is live for a given packet. They were once a
    // union to save a few bytes; that overlap made every access unsafe — a read of the
    // wrong arm returned a reinterpreted pointer, and partial initialization of one arm
    // left the other holding garbage. Three memory-safety bugs came from it. As separate
    // members both are always present and zero-initialized, so a mistaken access is benign
    // (NULL / zero) rather than a wild pointer. ChannelPacketData is transient (at most
    // MaxChannels per packet), so the extra bytes are irrelevant.
    pub message: ChannelPacketData_MessageData,
    pub block: ChannelPacketData_BlockData,
}

impl ChannelPacketData
{
    // port: C++ leaves a default-constructed ChannelPacketData uninitialized; Rust needs a value. All zero / null,
    // with initialized = false (call Initialize, as upstream).
    pub fn new() -> ChannelPacketData
    {
        ChannelPacketData
        {
            channelIndex: 0,
            initialized: false,
            blockMessage: false,
            messageFailedToSerialize: false,
            message: ChannelPacketData_MessageData { numMessages: 0, messages: std::ptr::null_mut() },
            block: ChannelPacketData_BlockData
            {
                message: null_message(),
                fragmentData: std::ptr::null_mut(),
                messageId: 0,
                fragmentId: 0,
                fragmentSize: 0,
                numFragments: 0,
                messageType: 0,
            },
        }
    }

    pub fn Initialize( &mut self )
    {
        self.channelIndex = 0;
        self.blockMessage = false;
        self.messageFailedToSerialize = false;
        // Fully initialize both arms so Free() and any reader are safe no matter which one the
        // serializer populates (or if it bails out early, e.g. a block fragment on a
        // disableBlocks channel).
        self.message.numMessages = 0;
        self.message.messages = std::ptr::null_mut();
        self.block.message = null_message();
        self.block.fragmentData = std::ptr::null_mut();
        self.block.messageId = 0;
        self.block.fragmentId = 0;
        self.block.fragmentSize = 0;
        self.block.numFragments = 0;
        self.block.messageType = 0;
        self.initialized = true;
    }

    pub fn Free( &mut self, messageFactory: *mut dyn MessageFactory )
    {
        yojimbo_assert!( self.initialized );
        let allocator = unsafe { (*messageFactory).GetAllocator() };
        if !self.blockMessage
        {
            if self.message.numMessages > 0
            {
                for i in 0..self.message.numMessages as usize
                {
                    let message = unsafe { *self.message.messages.add( i ) };
                    if !message.is_null()
                    {
                        unsafe { (*messageFactory).ReleaseMessage( message ) };
                    }
                }
                YOJIMBO_FREE!( allocator, self.message.messages );
            }
        }
        else
        {
            if !self.block.message.is_null()
            {
                unsafe { (*messageFactory).ReleaseMessage( self.block.message ) };
                self.block.message = null_message();
            }
            YOJIMBO_FREE!( allocator, self.block.fragmentData );
        }
        self.initialized = false;
    }
}

fn SerializeOrderedMessagesInternal<S: SerializeInternalStream>( stream: &mut S,
                                                                 messageFactory: *mut dyn MessageFactory,
                                                                 numMessages: &mut i32,
                                                                 messages: &mut *mut *mut ( dyn Message + 'static ),
                                                                 messageTypes: &mut [i32],
                                                                 messageIds: &mut [u16] ) -> bool
{
    let maxMessageType = unsafe { (*messageFactory).GetNumTypes() } - 1;

    let n = *numMessages as usize;

    for i in 0..n { messageTypes[i] = 0; }
    for i in 0..n { messageIds[i] = 0; }

    if S::IsWriting
    {
        yojimbo_assert!( !( *messages ).is_null() );

        for i in 0..n
        {
            let message = unsafe { *( *messages ).add( i ) };
            yojimbo_assert!( !message.is_null() );
            messageTypes[i] = unsafe { (*message).GetType() };
            messageIds[i] = unsafe { (*message).GetId() } as u16;
        }
    }
    else
    {
        let allocator = unsafe { (*messageFactory).GetAllocator() };

        *messages = YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<*mut dyn Message>() * n ) as *mut *mut dyn Message;

        if ( *messages ).is_null()
        {
            // Out of memory. Leave the arm empty (numMessages = 0) so ChannelPacketData::Free
            // stays safe, then fail the read; the channel treats this as a serialize failure.
            *numMessages = 0;
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate messages (SerializeOrderedMessages)\n" );
            return false;
        }

        for i in 0..n
        {
            unsafe { ( *messages ).add( i ).write( null_message() ) };
        }
    }

    serialize_bits!( stream, messageIds[0], 16 );

    for i in 1..n
    {
        serialize_sequence_relative!( stream, messageIds[i-1], messageIds[i] );
    }

    for i in 0..n
    {
        if maxMessageType > 0
        {
            serialize_int!( stream, messageTypes[i], 0, maxMessageType );
        }
        else
        {
            messageTypes[i] = 0;
        }

        if S::IsReading
        {
            let message = unsafe { (*messageFactory).CreateMessage( messageTypes[i] ) };
            unsafe { *( *messages ).add( i ) = message };

            if message.is_null()
            {
                yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create message of type {} (SerializeOrderedMessages)\n", messageTypes[i] );
                return false;
            }

            unsafe { (*message).SetId( messageIds[i] ) };
        }

        let message = unsafe { *( *messages ).add( i ) };

        yojimbo_assert!( !message.is_null() );

        if !S::SerializeInternal( unsafe { &mut *message }, stream )
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message of type {} (SerializeOrderedMessages)\n", messageTypes[i] );
            return false;
        }
    }

    true
}

fn SerializeOrderedMessages<S: SerializeInternalStream>( stream: &mut S,
                                                         messageFactory: *mut dyn MessageFactory,
                                                         numMessages: &mut i32,
                                                         messages: &mut *mut *mut ( dyn Message + 'static ),
                                                         maxMessagesPerPacket: i32 ) -> bool
{
    let mut hasMessages = S::IsWriting && *numMessages != 0;

    serialize_bool!( stream, hasMessages );

    if !hasMessages
    {
        return true;
    }

    serialize_int!( stream, *numMessages, 1, maxMessagesPerPacket );

    // One heap block for the message type and id scratch arrays, so stack usage doesn't
    // scale with maxMessagesPerPacket. The serialize body lives in a separate function so
    // all its early returns (including the ones hidden inside serialize_* macros) funnel
    // through the single free below.
    let allocator = unsafe { (*messageFactory).GetAllocator() };

    let n = *numMessages as usize;

    let mut scratch = YOJIMBO_ALLOCATE!( allocator, ( std::mem::size_of::<i32>() + std::mem::size_of::<u16>() ) * n );

    if scratch.is_null()
    {
        if S::IsReading
        {
            // Leave the arm empty (numMessages = 0) so ChannelPacketData::Free stays safe.
            // On write the messages remain owned by the packet data, so leave them alone.
            *numMessages = 0;
        }
        yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate serialize scratch (SerializeOrderedMessages)\n" );
        return false;
    }

    // port: the scratch block viewed as the two arrays (the allocator aligns to 16, so the int array is aligned,
    // and the uint16_t array follows it at a multiple of 4)
    let messageTypes = unsafe { std::slice::from_raw_parts_mut( scratch as *mut i32, n ) };
    let messageIds = unsafe { std::slice::from_raw_parts_mut( scratch.add( std::mem::size_of::<i32>() * n ) as *mut u16, n ) };

    let result = SerializeOrderedMessagesInternal( stream, messageFactory, numMessages, messages, messageTypes, messageIds );

    YOJIMBO_FREE!( allocator, scratch );

    result
}

fn SerializeUnorderedMessagesInternal<S: SerializeInternalStream>( stream: &mut S,
                                                                   messageFactory: *mut dyn MessageFactory,
                                                                   numMessages: &mut i32,
                                                                   messages: &mut *mut *mut ( dyn Message + 'static ),
                                                                   maxBlockSize: i32,
                                                                   messageTypes: &mut [i32] ) -> bool
{
    let maxMessageType = unsafe { (*messageFactory).GetNumTypes() } - 1;

    let n = *numMessages as usize;

    for i in 0..n { messageTypes[i] = 0; }

    if S::IsWriting
    {
        yojimbo_assert!( !( *messages ).is_null() );

        for i in 0..n
        {
            let message = unsafe { *( *messages ).add( i ) };
            yojimbo_assert!( !message.is_null() );
            messageTypes[i] = unsafe { (*message).GetType() };
        }
    }
    else
    {
        let allocator = unsafe { (*messageFactory).GetAllocator() };

        *messages = YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<*mut dyn Message>() * n ) as *mut *mut dyn Message;

        if ( *messages ).is_null()
        {
            // Out of memory. Leave the arm empty (numMessages = 0) so ChannelPacketData::Free
            // stays safe, then fail the read; the channel treats this as a serialize failure.
            *numMessages = 0;
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate messages (SerializeUnorderedMessages)\n" );
            return false;
        }

        for i in 0..n
        {
            unsafe { ( *messages ).add( i ).write( null_message() ) };
        }
    }

    for i in 0..n
    {
        if maxMessageType > 0
        {
            serialize_int!( stream, messageTypes[i], 0, maxMessageType );
        }
        else
        {
            messageTypes[i] = 0;
        }

        if S::IsReading
        {
            let message = unsafe { (*messageFactory).CreateMessage( messageTypes[i] ) };
            unsafe { *( *messages ).add( i ) = message };

            if message.is_null()
            {
                yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create message type {} (SerializeUnorderedMessages)\n", messageTypes[i] );
                return false;
            }
        }

        let message = unsafe { *( *messages ).add( i ) };

        yojimbo_assert!( !message.is_null() );

        if !S::SerializeInternal( unsafe { &mut *message }, stream )
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message type {} (SerializeUnorderedMessages)\n", messageTypes[i] );
            return false;
        }

        if unsafe { (*message).IsBlockMessage() }
        {
            // port: the C++ cast to BlockMessage * is AsBlockMessage()
            let blockMessage = unsafe { (*message).AsBlockMessage() }.unwrap() as *mut BlockMessage;
            if !SerializeMessageBlock( stream, messageFactory, blockMessage, maxBlockSize )
            {
                yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize message block (SerializeUnorderedMessages)\n" );
                return false;
            }
        }
    }

    true
}

fn SerializeUnorderedMessages<S: SerializeInternalStream>( stream: &mut S,
                                                           messageFactory: *mut dyn MessageFactory,
                                                           numMessages: &mut i32,
                                                           messages: &mut *mut *mut ( dyn Message + 'static ),
                                                           maxMessagesPerPacket: i32,
                                                           maxBlockSize: i32 ) -> bool
{
    let mut hasMessages = S::IsWriting && *numMessages != 0;

    serialize_bool!( stream, hasMessages );

    if !hasMessages
    {
        return true;
    }

    serialize_int!( stream, *numMessages, 1, maxMessagesPerPacket );

    // Heap scratch for the message types, so stack usage doesn't scale with
    // maxMessagesPerPacket. The serialize body lives in a separate function so all its
    // early returns (including the ones hidden inside serialize_* macros) funnel through
    // the single free below.
    let allocator = unsafe { (*messageFactory).GetAllocator() };

    let n = *numMessages as usize;

    let mut messageTypes = YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<i32>() * n ) as *mut i32;

    if messageTypes.is_null()
    {
        if S::IsReading
        {
            // Leave the arm empty (numMessages = 0) so ChannelPacketData::Free stays safe.
            // On write the messages remain owned by the packet data, so leave them alone.
            *numMessages = 0;
        }
        yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate serialize scratch (SerializeUnorderedMessages)\n" );
        return false;
    }

    let result = SerializeUnorderedMessagesInternal( stream, messageFactory, numMessages, messages, maxBlockSize, unsafe { std::slice::from_raw_parts_mut( messageTypes, n ) } );

    YOJIMBO_FREE!( allocator, messageTypes );

    result
}

fn SerializeBlockFragment<S: SerializeInternalStream>( stream: &mut S,
                                                       messageFactory: *mut dyn MessageFactory,
                                                       block: &mut ChannelPacketData_BlockData,
                                                       channelConfig: &ChannelConfig ) -> bool
{
    let maxMessageType = unsafe { (*messageFactory).GetNumTypes() } - 1;

    if S::IsReading
    {
        block.message = null_message();
        block.fragmentData = std::ptr::null_mut();
        // messageType is only serialized with fragment 0 (below); default it so a
        // non-zero fragment leaves it defined rather than read uninitialized by callers.
        block.messageType = 0;
    }

    serialize_bits!( stream, block.messageId, 16 );

    if channelConfig.GetMaxFragmentsPerBlock() > 1
    {
        serialize_int!( stream, block.numFragments, 1, channelConfig.GetMaxFragmentsPerBlock() );
    }
    else
    {
        if S::IsReading
        {
            block.numFragments = 1;
        }
    }

    if block.numFragments > 1
    {
        serialize_int!( stream, block.fragmentId, 0, block.numFragments as i32 - 1 );
    }
    else
    {
        if S::IsReading
        {
            block.fragmentId = 0;
        }
    }

    serialize_int!( stream, block.fragmentSize, 1, channelConfig.blockFragmentSize );

    if S::IsReading
    {
        block.fragmentData = YOJIMBO_ALLOCATE!( unsafe { (*messageFactory).GetAllocator() }, block.fragmentSize as usize );

        if block.fragmentData.is_null()
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize block fragment (SerializeBlockFragment)\n" );
            return false;
        }
    }

    serialize_bytes!( stream, unsafe { std::slice::from_raw_parts_mut( block.fragmentData, block.fragmentSize as usize ) }, block.fragmentSize );

    if block.fragmentId == 0
    {
        // block message

        if maxMessageType > 0
        {
            serialize_int!( stream, block.messageType, 0, maxMessageType );
        }
        else
        {
            block.messageType = 0;
        }

        if S::IsReading
        {
            let message = unsafe { (*messageFactory).CreateMessage( block.messageType ) };

            if message.is_null()
            {
                yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to create block message type {} (SerializeBlockFragment)\n", block.messageType );
                return false;
            }

            if !unsafe { (*message).IsBlockMessage() }
            {
                yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: received block fragment attached to non-block message (SerializeBlockFragment)\n" );
                unsafe { (*messageFactory).ReleaseMessage( message ) };
                return false;
            }

            block.message = message;
        }

        yojimbo_assert!( !block.message.is_null() );

        if !S::SerializeInternal( unsafe { &mut *block.message }, stream )
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to serialize block message of type {} (SerializeBlockFragment)\n", block.messageType );
            return false;
        }
    }

    true
}

impl ChannelPacketData
{
    // port: `const ChannelConfig * channelConfigs` is a slice
    pub fn Serialize<S: SerializeInternalStream>( &mut self,
                                                  stream: &mut S,
                                                  messageFactory: *mut dyn MessageFactory,
                                                  channelConfigs: &[ChannelConfig],
                                                  numChannels: i32 ) -> bool
    {
        yojimbo_assert!( self.initialized );

        // port: #if YOJIMBO_DEBUG_MESSAGE_BUDGET is `if YOJIMBO_DEBUG_MESSAGE_BUDGET` (a const, so the code compiles away)
        let startBits = if YOJIMBO_DEBUG_MESSAGE_BUDGET { stream.GetBitsProcessed() } else { 0 };

        if numChannels > 1
        {
            serialize_int!( stream, self.channelIndex, 0, numChannels - 1 );
        }
        else
        {
            self.channelIndex = 0;
        }

        let channelConfig = &channelConfigs[self.channelIndex as usize];

        serialize_bool!( stream, self.blockMessage );

        if !self.blockMessage
        {
            match channelConfig.r#type
            {
                CHANNEL_TYPE_RELIABLE_ORDERED =>
                {
                    if !SerializeOrderedMessages( stream, messageFactory, &mut self.message.numMessages, &mut self.message.messages, channelConfig.maxMessagesPerPacket )
                    {
                        self.messageFailedToSerialize = true;
                        return true;
                    }
                }

                CHANNEL_TYPE_UNRELIABLE_UNORDERED =>
                {
                    if !SerializeUnorderedMessages( stream,
                                                    messageFactory,
                                                    &mut self.message.numMessages,
                                                    &mut self.message.messages,
                                                    channelConfig.maxMessagesPerPacket,
                                                    channelConfig.maxBlockSize )
                    {
                        self.messageFailedToSerialize = true;
                        return true;
                    }
                }

                _ => {}
            }

            if YOJIMBO_DEBUG_MESSAGE_BUDGET
            {
                // Only assert on write/measure: this validates that *we* stay within the packet
                // budget when producing a packet. On read the data is untrusted (post-decrypt, but
                // still attacker-controlled), so a peer that ignores the budget must not be able to
                // crash a debug build — the message count and sizes are already bounded by the
                // serialize_* range checks, so an over-budget read is harmless, just larger.
                if !S::IsReading && channelConfig.packetBudget > 0
                {
                    yojimbo_assert!( stream.GetBitsProcessed() - startBits <= channelConfig.packetBudget as i64 * 8 );
                }
            }
        }
        else
        {
            if channelConfig.disableBlocks
            {
                return false;
            }

            if !SerializeBlockFragment( stream, messageFactory, &mut self.block, channelConfig )
            {
                return false;
            }
        }

        true
    }

    pub fn SerializeInternalRead( &mut self, stream: &mut ReadStream, messageFactory: *mut dyn MessageFactory, channelConfigs: &[ChannelConfig], numChannels: i32 ) -> bool
    {
        self.Serialize( stream, messageFactory, channelConfigs, numChannels )
    }

    pub fn SerializeInternalWrite( &mut self, stream: &mut WriteStream, messageFactory: *mut dyn MessageFactory, channelConfigs: &[ChannelConfig], numChannels: i32 ) -> bool
    {
        self.Serialize( stream, messageFactory, channelConfigs, numChannels )
    }

    pub fn SerializeInternalMeasure( &mut self, stream: &mut MeasureStream, messageFactory: *mut dyn MessageFactory, channelConfigs: &[ChannelConfig], numChannels: i32 ) -> bool
    {
        self.Serialize( stream, messageFactory, channelConfigs, numChannels )
    }
}

/**
    Channel counters provide insight into the number of times an action was performed by a channel.
    They are intended for use in a telemetry system, eg. reported to some backend logging system to track behavior in a production environment.
 */

pub type ChannelCounters = i32;
pub const CHANNEL_COUNTER_MESSAGES_SENT: i32 = 0;                       //< Number of messages sent over this channel.
pub const CHANNEL_COUNTER_MESSAGES_RECEIVED: i32 = 1;                   //< Number of messages received over this channel.
pub const CHANNEL_COUNTER_NUM_COUNTERS: i32 = 2;                        //< The number of channel counters.

/**
    Channel error level.
    If the channel gets into an error state, it sets an error state on the corresponding connection. See yojimbo::CONNECTION_ERROR_CHANNEL.
    This way if any channel on a client/server connection gets into a bad state, that client is automatically kicked from the server.
    @see Client
    @see Server
    @see Connection
 */

pub type ChannelErrorLevel = i32;
pub const CHANNEL_ERROR_NONE: i32 = 0;                                  //< No error. All is well.
pub const CHANNEL_ERROR_DESYNC: i32 = 1;                                //< This channel has desynced. This means that the connection protocol has desynced and cannot recover. The client should be disconnected.
pub const CHANNEL_ERROR_SEND_QUEUE_FULL: i32 = 2;                       //< The user tried to send a message but the send queue was full. This will assert out in development, but in production it sets this error on the channel.
pub const CHANNEL_ERROR_BLOCKS_DISABLED: i32 = 3;                       //< The channel received a packet containing data for blocks, but this channel is configured to disable blocks. See ChannelConfig::disableBlocks.
pub const CHANNEL_ERROR_FAILED_TO_SERIALIZE: i32 = 4;                   //< Serialize read failed for a message sent to this channel. Check your message serialize functions, one of them is returning false on serialize read. This can also be caused by a desync in message read and write.
pub const CHANNEL_ERROR_OUT_OF_MEMORY: i32 = 5;                         //< The channel tried to allocate some memory but couldn't.
pub const CHANNEL_ERROR_MESSAGE_TOO_LARGE: i32 = 6;                     //< The user tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message instead. This will assert out in development, but in production it sets this error on the channel.

/// Helper function to convert a channel error to a user friendly string.

pub fn GetChannelErrorString( error: ChannelErrorLevel ) -> &'static str
{
    match error
    {
        CHANNEL_ERROR_NONE                  => "none",
        CHANNEL_ERROR_DESYNC                => "desync",
        CHANNEL_ERROR_SEND_QUEUE_FULL       => "send queue full",
        CHANNEL_ERROR_OUT_OF_MEMORY         => "out of memory",
        CHANNEL_ERROR_BLOCKS_DISABLED       => "blocks disabled",
        CHANNEL_ERROR_FAILED_TO_SERIALIZE   => "failed to serialize",
        CHANNEL_ERROR_MESSAGE_TOO_LARGE     => "message too large",
        _ =>
        {
            yojimbo_assert!( false );
            "(unknown)"
        }
    }
}

/// Common functionality shared across all channel types.

// port: the data members of class Channel, embedded by each channel type (as `base`), with its constructor and
// non-virtual methods. The trait Channel below holds the virtual methods and forwards the non-virtual ones here.

pub struct ChannelBase
{
    pub m_config: ChannelConfig,                                        //< Channel configuration data.
    pub m_maxPacketSize: i32,                                           //< The maximum packet size in bytes (from ConnectionConfig::maxPacketSize). Used to detect messages that are too large to ever fit into a packet.
    pub m_allocator: *mut dyn Allocator,                                //< Allocator for allocations matching life cycle of this channel.
    pub m_channelIndex: i32,                                            //< The channel index in [0,numChannels-1].
    pub m_time: f64,                                                    //< The current time.
    pub m_errorLevel: ChannelErrorLevel,                                //< The channel error level.
    pub m_messageFactory: *mut dyn MessageFactory,                      //< Message factory for creating and destroying messages.
    pub m_counters: [u64; CHANNEL_COUNTER_NUM_COUNTERS as usize],       //< Counters for unit testing, stats etc.
}

impl ChannelBase
{
    /**
        Channel constructor.
     */

    pub fn new( allocator: *mut dyn Allocator, messageFactory: *mut dyn MessageFactory, config: &ChannelConfig, maxPacketSize: i32, channelIndex: i32, time: f64 ) -> ChannelBase
    {
        yojimbo_assert!( channelIndex >= 0 );
        yojimbo_assert!( channelIndex < MaxChannels );
        let mut channel = ChannelBase
        {
            m_config: config.clone(),
            m_maxPacketSize: maxPacketSize,
            m_allocator: allocator,
            m_channelIndex: channelIndex,
            m_time: time,
            m_errorLevel: CHANNEL_ERROR_NONE,
            m_messageFactory: messageFactory,
            m_counters: [0; CHANNEL_COUNTER_NUM_COUNTERS as usize],
        };
        channel.ResetCounters();
        channel
    }

    pub fn GetCounter( &self, index: i32 ) -> u64
    {
        yojimbo_assert!( index >= 0 );
        yojimbo_assert!( index < CHANNEL_COUNTER_NUM_COUNTERS );
        self.m_counters[index as usize]
    }

    pub fn ResetCounters( &mut self )
    {
        self.m_counters = [0; CHANNEL_COUNTER_NUM_COUNTERS as usize];
    }

    pub fn GetChannelIndex( &self ) -> i32
    {
        self.m_channelIndex
    }

    pub fn SetErrorLevel( &mut self, errorLevel: ChannelErrorLevel )
    {
        if errorLevel != self.m_errorLevel && errorLevel != CHANNEL_ERROR_NONE
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "channel went into error state: {}\n", GetChannelErrorString( errorLevel ) );
        }
        self.m_errorLevel = errorLevel;
    }

    pub fn GetErrorLevel( &self ) -> ChannelErrorLevel
    {
        self.m_errorLevel
    }
}

// port: virtual ~Channel() is Drop on each channel type (YOJIMBO_DELETE! drops through *mut dyn Channel)

pub trait Channel
{
    fn base( &self ) -> &ChannelBase;

    fn base_mut( &mut self ) -> &mut ChannelBase;

    /**
        Reset the channel.
     */

    fn Reset( &mut self );

    /**
        Returns true if a message can be sent over this channel.
     */

    fn CanSendMessage( &self ) -> bool;

    /**
        Are there any messages in the send queue?
        @returns True if there is at least one message in the send queue.
     */

    fn HasMessagesToSend( &self ) -> bool;

    /**
        Queue a message to be sent across this channel.
        @param message The message to be sent.
        @param context The serialization context, from Client::GetContext or Server::GetContext. Passed through to the message serialize functions. May be NULL.
     */

    fn SendMessage( &mut self, message: *mut dyn Message, context: *mut c_void );

    /**
        Pops the next message off the receive queue if one is available.
        @returns A pointer to the received message, NULL if there are no messages to receive. The caller owns the message object returned by this function and is responsible for releasing it via Message::Release.
     */

    fn ReceiveMessage( &mut self ) -> *mut dyn Message;

    /**
        Advance channel time.
        Called by Connection::AdvanceTime for each channel configured on the connection.
     */

    fn AdvanceTime( &mut self, time: f64 );

    /**
        Get channel packet data for this channel.
        @param context The serialization context, from Client::GetContext or Server::GetContext. Passed through to the message serialize functions. May be NULL.
        @param packetData The channel packet data to be filled [out]
        @param packetSequence The sequence number of the packet being generated.
        @param availableBits The maximum number of bits of packet data the channel is allowed to write.
        @returns The number of bits of packet data written by the channel.
        @see ConnectionPacket
        @see Connection::GeneratePacket
     */

    fn GetPacketData( &mut self, context: *mut c_void, packetData: &mut ChannelPacketData, packetSequence: u16, availableBits: i32 ) -> i32;

    /**
        Process packet data included in a connection packet.
        @param packetData The channel packet data to process.
        @param packetSequence The sequence number of the connection packet that contains the channel packet data.
        @see ConnectionPacket
        @see Connection::ProcessPacket
     */

    fn ProcessPacketData( &mut self, packetData: &ChannelPacketData, packetSequence: u16 );

    /**
        Process a connection packet ack.
        Depending on the channel type:
            1. Acks messages and block fragments so they stop being included in outgoing connection packets (reliable-ordered channel),
            2. Does nothing at all (unreliable-unordered).
        @param sequence The sequence number of the connection packet that was acked.
     */

    fn ProcessAck( &mut self, sequence: u16 );

    /**
        Get the channel error level.
        @returns The channel error level.
     */

    fn GetErrorLevel( &self ) -> ChannelErrorLevel { self.base().GetErrorLevel() }

    /**
        Gets the channel index.
        @returns The channel index in [0,numChannels-1].
     */

    fn GetChannelIndex( &self ) -> i32 { self.base().GetChannelIndex() }

    /**
        Get a counter value.
        @param index The index of the counter to retrieve. See ChannelCounters.
        @returns The value of the counter.
        @see ResetCounters
     */

    fn GetCounter( &self, index: i32 ) -> u64 { self.base().GetCounter( index ) }

    /**
        Resets all counter values to zero.
     */

    fn ResetCounters( &mut self ) { self.base_mut().ResetCounters() }

    /**
        Set the channel error level.
        All errors go through this function to make debug logging easier.
     */

    fn SetErrorLevel( &mut self, errorLevel: ChannelErrorLevel ) { self.base_mut().SetErrorLevel( errorLevel ) }
}

// port: a null Channel * (see README, "Pointers and memory")
pub fn null_channel() -> *mut dyn Channel
{
    std::ptr::null_mut::<UnreliableUnorderedChannel>() as *mut dyn Channel
}
