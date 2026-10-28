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

use crate::*;
use crate::serialize::*;
use std::ffi::c_void;

// port: the queues, the sent packet buffer, the message id arrays and the block data are allocated from the channel's
// allocator and held as raw pointers, as upstream (see README.md, "Pointers and memory"). The channel owns them and
// frees them in Drop (upstream's destructor); every dereference is of one of those, or of a message the channel holds
// a reference to.

/**
    An entry in the send queue of the reliable-ordered channel.
    Messages stay into the send queue until acked. Each message is acked individually, so there can be "holes" in the message send queue.
 */

// port: the nested structs of ReliableOrderedChannel are top-level structs (Rust has no nested types)
#[derive(Clone, Copy)]
pub struct MessageSendQueueEntry
{
    pub message: *mut dyn Message,                                                  //< Pointer to the message. When inserted in the send queue the message has one reference. It is released when the message is acked and removed from the send queue.
    pub timeLastSent: f64,                                                          //< The time the message was last sent. Used to implement ChannelConfig::messageResendTime.
    pub measuredBits: u32,                                                          //< The number of bits the message takes up in a bit stream. port: upstream's 31-bit bitfield
    pub block: u32,                                                                 //< 1 if this is a block message. Block messages are treated differently to regular messages when sent over a reliable-ordered channel. port: upstream's 1-bit bitfield
}

// port: SequenceBuffer constructs its entries (see yojimbo_sequence_buffer.rs)
impl Default for MessageSendQueueEntry
{
    fn default() -> Self { MessageSendQueueEntry { message: null_message(), timeLastSent: 0.0, measuredBits: 0, block: 0 } }
}

/**
    An entry in the receive queue of the reliable-ordered channel.
 */

#[derive(Clone, Copy)]
pub struct MessageReceiveQueueEntry
{
    pub message: *mut dyn Message,                                                  //< The message pointer. Has at a reference count of at least 1 while in the receive queue. Ownership of the message is passed back to the caller when the message is dequeued.
}

impl Default for MessageReceiveQueueEntry
{
    fn default() -> Self { MessageReceiveQueueEntry { message: null_message() } }
}

/**
    Maps packet level acks to messages and fragments for the reliable-ordered channel.
 */

#[derive(Clone, Copy)]
pub struct SentPacketEntry
{
    pub timeSent: f64,                                                              //< The time the packet was sent. Used to estimate round trip time.
    pub messageIds: *mut u16,                                                       //< Pointer to an array of message ids. Dynamically allocated because the user can configure the maximum number of messages in a packet per-channel with ChannelConfig::maxMessagesPerPacket.
    pub numMessageIds: u32,                                                         //< The number of message ids in in the array. port: upstream's 16-bit bitfield
    pub acked: u32,                                                                 //< 1 if this packet has been acked. port: upstream's 1-bit bitfield
    pub block: u64,                                                                 //< 1 if this packet contains a fragment of a block message. port: upstream's 1-bit bitfield
    pub blockMessageId: u64,                                                        //< The block message id. Valid only if "block" is 1. port: upstream's 16-bit bitfield
    pub blockFragmentId: u64,                                                       //< The block fragment id. Valid only if "block" is 1. port: upstream's 16-bit bitfield
}

impl Default for SentPacketEntry
{
    fn default() -> Self { SentPacketEntry { timeSent: 0.0, messageIds: std::ptr::null_mut(), numMessageIds: 0, acked: 0, block: 0, blockMessageId: 0, blockFragmentId: 0 } }
}

/**
    Internal state for a block being sent across the reliable ordered channel.
    Stores the block data and tracks which fragments have been acked. The block send completes when all fragments have been acked.
    IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flights over the wire at a time.
 */

pub struct SendBlockData
{
    pub active: bool,                                                               //< True if we are currently sending a block.
    pub blockSize: i32,                                                             //< The size of the block (bytes).
    pub numFragments: i32,                                                          //< Number of fragments in the block being sent.
    pub numAckedFragments: i32,                                                     //< Number of acked fragments in the block being sent.
    pub blockMessageId: u16,                                                        //< The message id the block is attached to.
    pub ackedFragment: *mut BitArray,                                               //< Has fragment n been received?
    pub fragmentSendTime: *mut f64,                                                 //< Last time fragment was sent.

    m_allocator: *mut dyn Allocator,                                                //< Allocator used to create the block data.
}

impl SendBlockData
{
    pub fn new( allocator: *mut dyn Allocator, maxFragmentsPerBlock: i32 ) -> SendBlockData
    {
        let mut this = SendBlockData
        {
            active: false,
            blockSize: 0,
            numFragments: 0,
            numAckedFragments: 0,
            blockMessageId: 0,
            ackedFragment: std::ptr::null_mut(),
            fragmentSendTime: std::ptr::null_mut(),
            m_allocator: allocator,
        };
        this.ackedFragment = YOJIMBO_NEW!( allocator, BitArray, BitArray::new( allocator, maxFragmentsPerBlock ) );
        this.fragmentSendTime = YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<f64>() * maxFragmentsPerBlock as usize ) as *mut f64;
        yojimbo_assert!( !this.ackedFragment.is_null() );
        yojimbo_assert!( !this.fragmentSendTime.is_null() );
        this.Reset();
        this
    }

    pub fn Reset( &mut self )
    {
        self.active = false;
        self.numFragments = 0;
        self.numAckedFragments = 0;
        self.blockMessageId = 0;
        self.blockSize = 0;
    }
}

impl Drop for SendBlockData
{
    fn drop( &mut self )
    {
        YOJIMBO_DELETE!( self.m_allocator, BitArray, self.ackedFragment );
        YOJIMBO_FREE!( self.m_allocator, self.fragmentSendTime );
    }
}

/**
    Internal state for a block being received across the reliable ordered channel.
    Stores the fragments received over the network for the block, and completes once all fragments have been received.
    IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flight over the wire at a time.
 */

pub struct ReceiveBlockData
{
    pub active: bool,                                                               //< True if we are currently receiving a block.
    pub numFragments: i32,                                                          //< The number of fragments in this block
    pub numReceivedFragments: i32,                                                  //< The number of fragments received.
    pub messageId: u16,                                                             //< The message id corresponding to the block.
    pub messageType: i32,                                                           //< Message type of the block being received.
    pub blockSize: u32,                                                             //< Block size in bytes.
    pub receivedFragment: *mut BitArray,                                            //< Has fragment n been received?
    pub blockData: *mut u8,                                                         //< Block data for receive.
    pub blockDataBytes: i32,                                                        //< port addition: the size of blockData in bytes (maxBlockSize, or the current block's buffer with ChannelConfig::allocateBlocksOnDemand). The C# and TypeScript ports read it from the array's length.
    pub blockMessage: *mut dyn Message,                                             //< Block message (sent with fragment 0). port: a *mut dyn Message, not *mut BlockMessage, so it can be released and queued as the message it is

    m_allocator: *mut dyn Allocator,                                                //< Allocator used to free the data on shutdown.
}

impl ReceiveBlockData
{
    // port addition: with ChannelConfig::allocateBlocksOnDemand, blockData is allocated per block in
    // ReliableOrderedChannel::ProcessPacketFragment instead of here, and freed once the block is delivered

    pub fn new( allocator: *mut dyn Allocator, maxBlockSize: i32, maxFragmentsPerBlock: i32, allocateOnDemand: bool ) -> ReceiveBlockData
    {
        let mut this = ReceiveBlockData
        {
            active: false,
            numFragments: 0,
            numReceivedFragments: 0,
            messageId: 0,
            messageType: 0,
            blockSize: 0,
            receivedFragment: std::ptr::null_mut(),
            blockData: std::ptr::null_mut(),
            blockDataBytes: 0,
            blockMessage: null_message(),
            m_allocator: allocator,
        };
        this.receivedFragment = YOJIMBO_NEW!( allocator, BitArray, BitArray::new( allocator, maxFragmentsPerBlock ) );
        if !allocateOnDemand
        {
            this.blockData = YOJIMBO_ALLOCATE!( allocator, maxBlockSize as usize );
            this.blockDataBytes = if this.blockData.is_null() { 0 } else { maxBlockSize };
        }
        yojimbo_assert!( !this.receivedFragment.is_null() && ( allocateOnDemand || !this.blockData.is_null() ) );
        this.blockMessage = null_message();
        this.Reset();
        this
    }

    pub fn Reset( &mut self )
    {
        self.active = false;
        self.numFragments = 0;
        self.numReceivedFragments = 0;
        self.messageId = 0;
        self.messageType = 0;
        self.blockSize = 0;
    }
}

impl Drop for ReceiveBlockData
{
    fn drop( &mut self )
    {
        YOJIMBO_DELETE!( self.m_allocator, BitArray, self.receivedFragment );
        YOJIMBO_FREE!( self.m_allocator, self.blockData );
    }
}

/**
    Messages sent across this channel are guaranteed to arrive in the order they were sent.
    This channel type is best used for control messages and RPCs.
    Messages sent over this channel are included in connection packets until one of those packets is acked. Messages are acked individually and remain in the send queue until acked.
    Blocks attached to messages sent over this channel are split up into fragments. Each fragment of the block is included in a connection packet until one of those packets are acked. Eventually, all fragments are received on the other side, and block is reassembled and attached to the message.
    Only one message block may be in flight over the network at any time, so blocks stall out message delivery slightly. Therefore, only use blocks for large data that won't fit inside a single connection packet where you actually need the channel to split it up into fragments. If your block fits inside a packet, just serialize it inside your message serialize via serialize_bytes instead.
 */

pub struct ReliableOrderedChannel
{
    pub base: ChannelBase,                                                          //< port: the Channel base class's data members

    m_sendMessageId: u16,                                                           //< Id of the next message to be added to the send queue.
    m_receiveMessageId: u16,                                                        //< Id of the next message to be added to the receive queue.
    m_oldestUnackedMessageId: u16,                                                  //< Id of the oldest unacked message in the send queue.
    m_sentPackets: *mut SequenceBuffer<SentPacketEntry>,                            //< Stores information per sent connection packet about messages and block data included in each packet. Used to walk from connection packet level acks to message and data block fragment level acks.
    m_messageSendQueue: *mut SequenceBuffer<MessageSendQueueEntry>,                 //< Message send queue.
    m_messageReceiveQueue: *mut SequenceBuffer<MessageReceiveQueueEntry>,           //< Message receive queue.
    m_sentPacketMessageIds: *mut u16,                                               //< Array of n message ids per sent connection packet. Allows the maximum number of messages per-packet to be allocated dynamically.
    m_packetMessageIds: *mut u16,                                                   //< Scratch space for the message ids gathered for the packet currently being generated (maxMessagesPerPacket entries). Owned by the channel so stack usage doesn't scale with the config.
    m_sendBlock: *mut SendBlockData,                                                //< Data about the block being currently sent.
    m_receiveBlock: *mut ReceiveBlockData,                                          //< Data about the block being currently received.
}

impl ReliableOrderedChannel
{
    /**
        Reliable ordered channel constructor.
        @param allocator The allocator to use.
        @param messageFactory Message factory for creating and destroying messages.
        @param config The configuration for this channel.
        @param maxPacketSize The maximum packet size in bytes (see ConnectionConfig::maxPacketSize).
        @param channelIndex The channel index in [0,numChannels-1].
        @param time The current time in seconds. See Channel::AdvanceTime
     */

    // port: returns the channel by value (move it into YOJIMBO_NEW!); everything it allocates is held by pointer, so the move is safe
    pub fn new( allocator: *mut dyn Allocator, messageFactory: *mut dyn MessageFactory, config: &ChannelConfig, maxPacketSize: i32, channelIndex: i32, time: f64 ) -> ReliableOrderedChannel
    {
        let mut this = ReliableOrderedChannel
        {
            base: ChannelBase::new( allocator, messageFactory, config, maxPacketSize, channelIndex, time ),
            m_sendMessageId: 0,
            m_receiveMessageId: 0,
            m_oldestUnackedMessageId: 0,
            m_sentPackets: std::ptr::null_mut(),
            m_messageSendQueue: std::ptr::null_mut(),
            m_messageReceiveQueue: std::ptr::null_mut(),
            m_sentPacketMessageIds: std::ptr::null_mut(),
            m_packetMessageIds: std::ptr::null_mut(),
            m_sendBlock: std::ptr::null_mut(),
            m_receiveBlock: std::ptr::null_mut(),
        };

        yojimbo_assert!( config.r#type == CHANNEL_TYPE_RELIABLE_ORDERED );

        yojimbo_assert!( ( 65536 % config.sentPacketBufferSize ) == 0 );
        yojimbo_assert!( ( 65536 % config.messageSendQueueSize ) == 0 );
        yojimbo_assert!( ( 65536 % config.messageReceiveQueueSize ) == 0 );

        let a = this.base.m_allocator;
        let c = &this.base.m_config;

        this.m_sentPackets = YOJIMBO_NEW!( a, SequenceBuffer<SentPacketEntry>, SequenceBuffer::<SentPacketEntry>::new( a, c.sentPacketBufferSize ) );
        this.m_messageSendQueue = YOJIMBO_NEW!( a, SequenceBuffer<MessageSendQueueEntry>, SequenceBuffer::<MessageSendQueueEntry>::new( a, c.messageSendQueueSize ) );
        this.m_messageReceiveQueue = YOJIMBO_NEW!( a, SequenceBuffer<MessageReceiveQueueEntry>, SequenceBuffer::<MessageReceiveQueueEntry>::new( a, c.messageReceiveQueueSize ) );
        this.m_sentPacketMessageIds = YOJIMBO_ALLOCATE!( a, std::mem::size_of::<u16>() * c.maxMessagesPerPacket as usize * c.sentPacketBufferSize as usize ) as *mut u16;
        this.m_packetMessageIds = YOJIMBO_ALLOCATE!( a, std::mem::size_of::<u16>() * c.maxMessagesPerPacket as usize ) as *mut u16;

        if !config.disableBlocks
        {
            this.m_sendBlock = YOJIMBO_NEW!( a, SendBlockData, SendBlockData::new( a, c.GetMaxFragmentsPerBlock() ) );
            this.m_receiveBlock = YOJIMBO_NEW!( a, ReceiveBlockData, ReceiveBlockData::new( a, c.maxBlockSize, c.GetMaxFragmentsPerBlock(), c.allocateBlocksOnDemand ) );
        }
        else
        {
            this.m_sendBlock = std::ptr::null_mut();
            this.m_receiveBlock = std::ptr::null_mut();
        }

        this.Reset();

        this
    }
}

/**
    Reliable ordered channel destructor.
    Any messages still in the send or receive queues will be released.
 */

impl Drop for ReliableOrderedChannel
{
    fn drop( &mut self )
    {
        self.Reset();

        let a = self.base.m_allocator;

        YOJIMBO_DELETE!( a, SendBlockData, self.m_sendBlock );
        YOJIMBO_DELETE!( a, ReceiveBlockData, self.m_receiveBlock );
        YOJIMBO_DELETE!( a, SequenceBuffer<SentPacketEntry>, self.m_sentPackets );
        YOJIMBO_DELETE!( a, SequenceBuffer<MessageSendQueueEntry>, self.m_messageSendQueue );
        YOJIMBO_DELETE!( a, SequenceBuffer<MessageReceiveQueueEntry>, self.m_messageReceiveQueue );

        YOJIMBO_FREE!( a, self.m_sentPacketMessageIds );
        YOJIMBO_FREE!( a, self.m_packetMessageIds );

        self.m_sentPacketMessageIds = std::ptr::null_mut();
    }
}

// port: the Channel trait (below) forwards to these inherent methods, so the functions stay in upstream's order

impl ReliableOrderedChannel
{
    pub fn Reset( &mut self )
    {
        self.SetErrorLevel( CHANNEL_ERROR_NONE );

        self.m_sendMessageId = 0;
        self.m_receiveMessageId = 0;
        self.m_oldestUnackedMessageId = 0;

        unsafe
        {
            for i in 0..( *self.m_messageSendQueue ).GetSize()
            {
                let entry = ( *self.m_messageSendQueue ).GetAtIndex( i );
                if !entry.is_null() && !( *entry ).message.is_null()
                {
                    ( *self.base.m_messageFactory ).ReleaseMessage( ( *entry ).message );
                }
            }

            for i in 0..( *self.m_messageReceiveQueue ).GetSize()
            {
                let entry = ( *self.m_messageReceiveQueue ).GetAtIndex( i );
                if !entry.is_null() && !( *entry ).message.is_null()
                {
                    ( *self.base.m_messageFactory ).ReleaseMessage( ( *entry ).message );
                }
            }

            ( *self.m_sentPackets ).Reset();
            ( *self.m_messageSendQueue ).Reset();
            ( *self.m_messageReceiveQueue ).Reset();

            if !self.m_sendBlock.is_null()
            {
                ( *self.m_sendBlock ).Reset();
            }

            if !self.m_receiveBlock.is_null()
            {
                ( *self.m_receiveBlock ).Reset();
                if self.base.m_config.allocateBlocksOnDemand
                {
                    // port addition: an on-demand receive buffer only lives while its block is being received
                    YOJIMBO_FREE!( self.base.m_allocator, ( *self.m_receiveBlock ).blockData );
                    ( *self.m_receiveBlock ).blockDataBytes = 0;
                }
                if !( *self.m_receiveBlock ).blockMessage.is_null()
                {
                    ( *self.base.m_messageFactory ).ReleaseMessage( ( *self.m_receiveBlock ).blockMessage );
                    ( *self.m_receiveBlock ).blockMessage = null_message();
                }
            }
        }

        self.ResetCounters();
    }

    pub fn CanSendMessage( &self ) -> bool
    {
        yojimbo_assert!( !self.m_messageSendQueue.is_null() );
        unsafe { ( *self.m_messageSendQueue ).Available( self.m_sendMessageId ) }
    }

    pub fn SendMessage( &mut self, message: *mut dyn Message, context: *mut c_void )
    {
        yojimbo_assert!( !message.is_null() );

        yojimbo_assert!( self.CanSendMessage() );

        unsafe
        {
            if self.GetErrorLevel() != CHANNEL_ERROR_NONE
            {
                ( *self.base.m_messageFactory ).ReleaseMessage( message );
                return;
            }

            if !self.CanSendMessage()
            {
                // Increase your send queue size!
                self.SetErrorLevel( CHANNEL_ERROR_SEND_QUEUE_FULL );
                ( *self.base.m_messageFactory ).ReleaseMessage( message );
                return;
            }

            yojimbo_assert!( !( ( *message ).IsBlockMessage() && self.base.m_config.disableBlocks ) );

            if ( *message ).IsBlockMessage() && self.base.m_config.disableBlocks
            {
                // You tried to send a block message, but block messages are disabled for this channel!
                self.SetErrorLevel( CHANNEL_ERROR_BLOCKS_DISABLED );
                ( *self.base.m_messageFactory ).ReleaseMessage( message );
                return;
            }

            ( *message ).SetId( self.m_sendMessageId );

            let mut measureStream = MeasureStream::new();
            measureStream.SetContext( context );
            // port: the stream's allocator is a thin pointer; the fat *mut dyn Allocator's metadata is dropped
            measureStream.SetAllocator( ( *self.base.m_messageFactory ).GetAllocatorContext() );
            ( *message ).SerializeInternalMeasure( &mut measureStream );

            let measuredBits = measureStream.GetBitsProcessed() as i32;

            let isOverBudget = self.base.m_config.packetBudget > 0 && measuredBits > self.base.m_config.packetBudget * 8;
            let isOverPacketSize = measuredBits > self.base.m_maxPacketSize * 8;
            let isTooLarge = ( isOverBudget || isOverPacketSize ) && !( *message ).IsBlockMessage();

            yojimbo_assert!( !isTooLarge );

            if isTooLarge
            {
                // You tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message instead.
                self.SetErrorLevel( CHANNEL_ERROR_MESSAGE_TOO_LARGE );
                ( *self.base.m_messageFactory ).ReleaseMessage( message );
                return;
            }

            let entry = ( *self.m_messageSendQueue ).Insert( self.m_sendMessageId, false );

            yojimbo_assert!( !entry.is_null() );

            ( *entry ).block = ( *message ).IsBlockMessage() as u32;
            ( *entry ).message = message;
            ( *entry ).measuredBits = 0;
            ( *entry ).timeLastSent = -1.0;

            if ( *message ).IsBlockMessage()
            {
                // port: the cast to BlockMessage * is AsBlockMessage()
                yojimbo_assert!( ( *message ).AsBlockMessage().map_or( 0, |b| b.GetBlockSize() ) > 0 );
                yojimbo_assert!( ( *message ).AsBlockMessage().map_or( 0, |b| b.GetBlockSize() ) <= self.base.m_config.maxBlockSize );
            }

            ( *entry ).measuredBits = measuredBits as u32;
            self.base.m_counters[CHANNEL_COUNTER_MESSAGES_SENT as usize] += 1;
            self.m_sendMessageId = self.m_sendMessageId.wrapping_add( 1 );
        }
    }

    pub fn ReceiveMessage( &mut self ) -> *mut dyn Message
    {
        if self.GetErrorLevel() != CHANNEL_ERROR_NONE
        {
            return null_message();
        }

        unsafe
        {
            let entry = ( *self.m_messageReceiveQueue ).Find( self.m_receiveMessageId );
            if entry.is_null()
            {
                return null_message();
            }

            let message = ( *entry ).message;
            yojimbo_assert!( !message.is_null() );
            yojimbo_assert!( ( *message ).GetId() == self.m_receiveMessageId as i32 );
            ( *self.m_messageReceiveQueue ).Remove( self.m_receiveMessageId );
            self.base.m_counters[CHANNEL_COUNTER_MESSAGES_RECEIVED as usize] += 1;
            self.m_receiveMessageId = self.m_receiveMessageId.wrapping_add( 1 );

            message
        }
    }

    pub fn AdvanceTime( &mut self, time: f64 )
    {
        self.base.m_time = time;
    }

    pub fn GetPacketData( &mut self, context: *mut c_void, packetData: &mut ChannelPacketData, packetSequence: u16, availableBits: i32 ) -> i32
    {
        if !self.HasMessagesToSend()
        {
            return 0;
        }

        if self.SendingBlockMessage()
        {
            if self.base.m_config.blockFragmentSize * 8 > availableBits
            {
                return 0;
            }

            let mut messageId: u16 = 0;
            let mut fragmentId: u16 = 0;
            let mut fragmentBytes: i32 = 0;
            let mut numFragments: i32 = 0;
            let mut messageType: i32 = 0;

            let fragmentData = self.GetFragmentToSend( &mut messageId, &mut fragmentId, &mut fragmentBytes, &mut numFragments, &mut messageType );

            if !fragmentData.is_null()
            {
                let fragmentBits = self.GetFragmentPacketData( packetData, messageId, fragmentId, fragmentData, fragmentBytes, numFragments, messageType );
                self.AddFragmentPacketEntry( messageId, fragmentId, packetSequence );
                return fragmentBits;
            }
        }
        else
        {
            let mut numMessageIds: i32 = 0;
            let messageIds = self.m_packetMessageIds;
            let messageBits = self.GetMessagesToSend( messageIds, &mut numMessageIds, availableBits, context );

            if numMessageIds > 0
            {
                if !self.GetMessagePacketData( packetData, messageIds, numMessageIds )
                {
                    return 0;
                }
                self.AddMessagePacketEntry( messageIds, numMessageIds, packetSequence );
                return messageBits;
            }
        }

        0
    }

    /**
        Are there any unacked messages in the send queue?
        Messages are acked individually and remain in the send queue until acked.
        @returns True if there is at least one unacked message in the send queue.
     */

    pub fn HasMessagesToSend( &self ) -> bool
    {
        self.m_oldestUnackedMessageId != self.m_sendMessageId
    }

    /**
        Get messages to include in a packet.
        Messages are measured to see how many bits they take, and only messages that fit within the channel packet budget will be included. See ChannelConfig::packetBudget.
        Takes care not to send messages too rapidly by respecting ChannelConfig::messageResendTime for each message, and to only include messages that that the receiver is able to buffer in their receive queue. In other words, won't run ahead of the receiver.
        @param messageIds Array of message ids to be filled [out]. Fills up to ChannelConfig::maxMessagesPerPacket messages, make sure your array is at least this size.
        @param numMessageIds The number of message ids written to the array.
        @param remainingPacketBits Number of bits remaining in the packet. Considers this as a hard limit when determining how many messages can fit into the packet.
        @param context The serialization context, from Client::GetContext or Server::GetContext. Passed through to the message serialize functions when measuring them. May be NULL.
        @returns Estimate of the number of bits required to serialize the messages (upper bound).
        @see GetMessagePacketData
     */

    // port: messageIds is the channel's m_packetMessageIds scratch array (maxMessagesPerPacket entries), passed as upstream
    pub fn GetMessagesToSend( &mut self, messageIds: *mut u16, numMessageIds: &mut i32, mut availableBits: i32, context: *mut c_void ) -> i32
    {
        yojimbo_assert!( self.HasMessagesToSend() );

        *numMessageIds = 0;

        if self.base.m_config.packetBudget > 0
        {
            availableBits = yojimbo_min( self.base.m_config.packetBudget * 8, availableBits );
        }

        unsafe
        {
            let giveUpBits: i32 = 4 * 8;
            let messageTypeBits: i32 = bits_required( 0, ( ( *self.base.m_messageFactory ).GetNumTypes() - 1 ) as u32 ) as i32;
            let messageLimit: i32 = yojimbo_min( self.base.m_config.messageSendQueueSize, self.base.m_config.messageReceiveQueueSize );
            let mut previousMessageId: u16 = 0;
            let mut usedBits: i32 = ConservativeMessageHeaderBits;
            let mut giveUpCounter: i32 = 0;

            for i in 0..messageLimit
            {
                if availableBits - usedBits < giveUpBits
                {
                    break;
                }

                if giveUpCounter > self.base.m_config.messageSendQueueSize
                {
                    break;
                }

                let mut messageId: u16 = self.m_oldestUnackedMessageId.wrapping_add( i as u16 );
                let entry = ( *self.m_messageSendQueue ).Find( messageId );
                if entry.is_null()
                {
                    continue;
                }

                if ( *entry ).block != 0
                {
                    break;
                }

                // Messages that are too large to fit in a packet are rejected in SendMessage()
                yojimbo_assert!( ( self.base.m_config.packetBudget <= 0 || ( *entry ).measuredBits <= ( self.base.m_config.packetBudget * 8 ) as u32 ) && ( *entry ).measuredBits <= ( self.base.m_maxPacketSize * 8 ) as u32 );

                if ( *entry ).timeLastSent + self.base.m_config.messageResendTime as f64 <= self.base.m_time && availableBits >= ( *entry ).measuredBits as i32
                {
                    let mut messageBits: i32 = ( *entry ).measuredBits as i32 + messageTypeBits;

                    if *numMessageIds == 0
                    {
                        messageBits += 16;
                    }
                    else
                    {
                        let mut stream = MeasureStream::new();
                        stream.SetContext( context );
                        stream.SetAllocator( ( *self.base.m_messageFactory ).GetAllocatorContext() );
                        serialize_sequence_relative_internal( &mut stream, previousMessageId, &mut messageId );
                        messageBits += stream.GetBitsProcessed() as i32;
                    }

                    if usedBits + messageBits > availableBits
                    {
                        giveUpCounter += 1;
                        continue;
                    }

                    usedBits += messageBits;
                    *messageIds.add( *numMessageIds as usize ) = messageId;
                    *numMessageIds += 1;
                    previousMessageId = messageId;
                    ( *entry ).timeLastSent = self.base.m_time;
                }

                if *numMessageIds == self.base.m_config.maxMessagesPerPacket
                {
                    break;
                }
            }

            usedBits
        }
    }

    /**
        Fill channel packet data with messages.
        This is the payload function to fill packet data while sending regular messages (without blocks attached).
        Messages have references added to them when they are added to the packet. They also have a reference while they are stored in a send or receive queue. Messages are cleaned up when they are no longer in a queue, and no longer referenced by any packets.
        @param packetData The packet data to fill [out]
        @param messageIds Array of message ids identifying which messages to add to the packet from the message send queue.
        @param numMessageIds The number of message ids in the array.
        @see GetMessagesToSend
     */

    pub fn GetMessagePacketData( &mut self, packetData: &mut ChannelPacketData, messageIds: *const u16, numMessageIds: i32 ) -> bool
    {
        yojimbo_assert!( !messageIds.is_null() );

        packetData.Initialize();
        packetData.channelIndex = self.GetChannelIndex() as _;
        packetData.message.numMessages = numMessageIds;

        if numMessageIds == 0
        {
            return true;
        }

        unsafe
        {
            packetData.message.messages = YOJIMBO_ALLOCATE!( ( *self.base.m_messageFactory ).GetAllocator(), std::mem::size_of::<*mut dyn Message>() * numMessageIds as usize ) as *mut *mut dyn Message;

            if packetData.message.messages.is_null()
            {
                // Out of memory. Leave the arm empty (numMessages = 0) so packetData stays safe to
                // Free/serialize, and report failure so the caller drops this channel's data. We
                // haven't acquired any message references yet, so there is nothing to release.
                packetData.message.numMessages = 0;
                self.SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
                return false;
            }

            for i in 0..numMessageIds as usize
            {
                let entry = ( *self.m_messageSendQueue ).Find( *messageIds.add( i ) );
                yojimbo_assert!( !entry.is_null() );
                yojimbo_assert!( !( *entry ).message.is_null() );
                yojimbo_assert!( ( *( *entry ).message ).GetRefCount() > 0 );
                // port: write(), the array is fresh allocator memory
                packetData.message.messages.add( i ).write( ( *entry ).message );
                ( *self.base.m_messageFactory ).AcquireMessage( *packetData.message.messages.add( i ) );
            }
        }

        true
    }

    /**
        Add a packet entry for the set of messages included in a packet.
        This lets us look up the set of messages that were included in that packet later on when it is acked, so we can ack those messages individually.
        @param messageIds The set of message ids that were included in the packet.
        @param numMessageIds The number of message ids in the array.
        @param sequence The sequence number of the connection packet the messages were included in.
     */

    pub fn AddMessagePacketEntry( &mut self, messageIds: *const u16, numMessageIds: i32, sequence: u16 )
    {
        unsafe
        {
            let sentPacket = ( *self.m_sentPackets ).Insert( sequence, true );
            yojimbo_assert!( !sentPacket.is_null() );
            if !sentPacket.is_null()
            {
                ( *sentPacket ).acked = 0;
                ( *sentPacket ).block = 0;
                ( *sentPacket ).timeSent = self.base.m_time;
                ( *sentPacket ).messageIds = self.m_sentPacketMessageIds.add( ( ( sequence as i32 % self.base.m_config.sentPacketBufferSize ) * self.base.m_config.maxMessagesPerPacket ) as usize );
                ( *sentPacket ).numMessageIds = numMessageIds as u32;
                for i in 0..numMessageIds as usize
                {
                    *( *sentPacket ).messageIds.add( i ) = *messageIds.add( i );
                }
            }
        }
    }

    /**
        Process messages included in a packet.
        Any messages that have not already been received are added to the message receive queue. Messages that are added to the receive queue have a reference added. See Message::AddRef.
        @param numMessages The number of messages to process.
        @param messages Array of pointers to messages.
     */

    pub fn ProcessPacketMessages( &mut self, numMessages: i32, messages: *mut *mut dyn Message )
    {
        let minMessageId: u16 = self.m_receiveMessageId;
        let maxMessageId: u16 = self.m_receiveMessageId.wrapping_add( self.base.m_config.messageReceiveQueueSize as u16 ).wrapping_sub( 1 );

        unsafe
        {
            for i in 0..numMessages as usize
            {
                let message = *messages.add( i );

                yojimbo_assert!( !message.is_null() );

                let messageId: u16 = ( *message ).GetId() as u16;

                if yojimbo_sequence_less_than( messageId, minMessageId )
                {
                    continue;
                }

                if yojimbo_sequence_greater_than( messageId, maxMessageId )
                {
                    // Did you forget to dequeue messages on the receiver?
                    yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "sequence overflow: {} vs. [{},{}]\n", messageId, minMessageId, maxMessageId );
                    self.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                    return;
                }

                if !( *self.m_messageReceiveQueue ).Find( messageId ).is_null()
                {
                    continue;
                }

                yojimbo_assert!( ( *self.m_messageReceiveQueue ).GetAtIndex( ( *self.m_messageReceiveQueue ).GetIndex( messageId ) ).is_null() );

                let entry = ( *self.m_messageReceiveQueue ).Insert( messageId, false );
                if entry.is_null()
                {
                    // For some reason we can't insert the message in the receive queue
                    self.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                    return;
                }

                ( *entry ).message = message;

                ( *self.base.m_messageFactory ).AcquireMessage( message );
            }
        }
    }

    pub fn ProcessPacketData( &mut self, packetData: &ChannelPacketData, packetSequence: u16 )
    {
        if self.base.m_errorLevel != CHANNEL_ERROR_NONE
        {
            return;
        }

        if packetData.messageFailedToSerialize
        {
            // A message failed to serialize read for some reason, eg. mismatched read/write.
            self.SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
            return;
        }

        let _ = packetSequence;

        if packetData.blockMessage
        {
            self.ProcessPacketFragment( packetData.block.messageType as i32,
                                        packetData.block.messageId as u16,
                                        packetData.block.numFragments as i32,
                                        packetData.block.fragmentId as u16,
                                        packetData.block.fragmentData,
                                        packetData.block.fragmentSize as i32,
                                        packetData.block.message );
        }
        else
        {
            self.ProcessPacketMessages( packetData.message.numMessages, packetData.message.messages );
        }
    }

    pub fn ProcessAck( &mut self, ack: u16 )
    {
        unsafe
        {
            let sentPacketEntry = ( *self.m_sentPackets ).Find( ack );
            if sentPacketEntry.is_null()
            {
                return;
            }

            yojimbo_assert!( ( *sentPacketEntry ).acked == 0 );
            ( *sentPacketEntry ).acked = 1;

            for i in 0..( *sentPacketEntry ).numMessageIds as usize
            {
                let messageId: u16 = *( *sentPacketEntry ).messageIds.add( i );
                let sendQueueEntry = ( *self.m_messageSendQueue ).Find( messageId );
                if !sendQueueEntry.is_null()
                {
                    yojimbo_assert!( !( *sendQueueEntry ).message.is_null() );
                    yojimbo_assert!( ( *( *sendQueueEntry ).message ).GetId() == messageId as i32 );
                    ( *self.base.m_messageFactory ).ReleaseMessage( ( *sendQueueEntry ).message );
                    ( *self.m_messageSendQueue ).Remove( messageId );
                    self.UpdateOldestUnackedMessageId();
                }
            }

            if !self.base.m_config.disableBlocks && ( *sentPacketEntry ).block != 0 && ( *self.m_sendBlock ).active && ( *self.m_sendBlock ).blockMessageId as u64 == ( *sentPacketEntry ).blockMessageId
            {
                let messageId: i32 = ( *sentPacketEntry ).blockMessageId as i32;
                let fragmentId: i32 = ( *sentPacketEntry ).blockFragmentId as i32;

                if ( *( *self.m_sendBlock ).ackedFragment ).GetBit( fragmentId ) == 0
                {
                    ( *( *self.m_sendBlock ).ackedFragment ).SetBit( fragmentId );
                    ( *self.m_sendBlock ).numAckedFragments += 1;
                    if ( *self.m_sendBlock ).numAckedFragments == ( *self.m_sendBlock ).numFragments
                    {
                        ( *self.m_sendBlock ).active = false;
                        let sendQueueEntry = ( *self.m_messageSendQueue ).Find( messageId as u16 );
                        yojimbo_assert!( !sendQueueEntry.is_null() );
                        ( *self.base.m_messageFactory ).ReleaseMessage( ( *sendQueueEntry ).message );
                        ( *self.m_messageSendQueue ).Remove( messageId as u16 );
                        self.UpdateOldestUnackedMessageId();
                    }
                }
            }
        }
    }

    /**
        Track the oldest unacked message id in the send queue.
        Because messages are acked individually, the send queue is not a true queue and may have holes.
        Because of this it is necessary to periodically walk forward from the previous oldest unacked message id, to find the current oldest unacked message id.
        This lets us know our starting point for considering messages to include in the next packet we send.
        @see GetMessagesToSend
     */

    pub fn UpdateOldestUnackedMessageId( &mut self )
    {
        unsafe
        {
            let stopMessageId: u16 = ( *self.m_messageSendQueue ).GetSequence();

            loop
            {
                if self.m_oldestUnackedMessageId == stopMessageId || !( *self.m_messageSendQueue ).Find( self.m_oldestUnackedMessageId ).is_null()
                {
                    break;
                }
                self.m_oldestUnackedMessageId = self.m_oldestUnackedMessageId.wrapping_add( 1 );
            }

            yojimbo_assert!( !yojimbo_sequence_greater_than( self.m_oldestUnackedMessageId, stopMessageId ) );
        }
    }

    /**
        True if we are currently sending a block message.
        Block messages are treated differently to regular messages.
        Regular messages are small so we try to fit as many into the packet we can. See ReliableChannelData::GetMessagesToSend.
        Blocks attached to block messages are usually larger than the maximum packet size or channel budget, so they are split up fragments.
        While in the mode of sending a block message, each channel packet data generated has exactly one fragment from the current block in it. Fragments keep getting included in packets until all fragments of that block are acked.
        @returns True if currently sending a block message over the network, false otherwise.
        @see BlockMessage
        @see GetFragmentToSend
     */

    pub fn SendingBlockMessage( &mut self ) -> bool
    {
        yojimbo_assert!( self.HasMessagesToSend() );

        unsafe
        {
            let entry = ( *self.m_messageSendQueue ).Find( self.m_oldestUnackedMessageId );

            if !entry.is_null() { ( *entry ).block != 0 } else { false }
        }
    }

    /**
        Get the next block fragment to send.
        The next block fragment is selected by scanning left to right over the set of fragments in the block, skipping over any fragments that have already been acked or have been sent within ChannelConfig::fragmentResendTime.
        @param messageId The id of the message that the block is attached to [out].
        @param fragmentId The id of the fragment to send [out].
        @param fragmentBytes The size of the fragment in bytes.
        @param numFragments The total number of fragments in this block.
        @param messageType The type of message the block is attached to. See MessageFactory.
        @returns Pointer to the fragment data.
     */

    pub fn GetFragmentToSend( &mut self, messageId: &mut u16, fragmentId: &mut u16, fragmentBytes: &mut i32, numFragments: &mut i32, messageType: &mut i32 ) -> *mut u8
    {
        unsafe
        {
            let entry = ( *self.m_messageSendQueue ).Find( self.m_oldestUnackedMessageId );

            yojimbo_assert!( !entry.is_null() );
            yojimbo_assert!( ( *entry ).block != 0 );

            // port: the cast to BlockMessage * is AsBlockMessage(); the message stays a *mut dyn Message
            let message = ( *entry ).message;

            yojimbo_assert!( ( *message ).AsBlockMessage().is_some() );

            *messageId = ( *message ).GetId() as u16;

            let blockSize: i32 = ( *message ).AsBlockMessage().unwrap().GetBlockSize();

            let sendBlock = &mut *self.m_sendBlock;

            if !sendBlock.active
            {
                // start sending this block

                sendBlock.active = true;
                sendBlock.blockSize = blockSize;
                sendBlock.blockMessageId = *messageId;
                sendBlock.numFragments = ( blockSize as f32 / self.base.m_config.blockFragmentSize as f32 ).ceil() as i32;
                sendBlock.numAckedFragments = 0;

                let MaxFragmentsPerBlock: i32 = self.base.m_config.GetMaxFragmentsPerBlock();

                yojimbo_assert!( sendBlock.numFragments > 0 );
                yojimbo_assert!( sendBlock.numFragments <= MaxFragmentsPerBlock );

                ( *sendBlock.ackedFragment ).Clear();

                for i in 0..MaxFragmentsPerBlock as usize
                {
                    *sendBlock.fragmentSendTime.add( i ) = -1.0;
                }
            }

            *numFragments = sendBlock.numFragments;

            // find the next fragment to send (there may not be one)

            *fragmentId = 0xFFFF;

            for i in 0..sendBlock.numFragments
            {
                if ( *sendBlock.ackedFragment ).GetBit( i ) == 0 && *sendBlock.fragmentSendTime.add( i as usize ) + ( self.base.m_config.blockFragmentResendTime as f64 ) < self.base.m_time
                {
                    *fragmentId = i as u16;
                    break;
                }
            }

            if *fragmentId == 0xFFFF
            {
                return std::ptr::null_mut();
            }

            // allocate and return a copy of the fragment data

            *messageType = ( *message ).GetType();

            *fragmentBytes = self.base.m_config.blockFragmentSize;

            let fragmentRemainder: i32 = blockSize % self.base.m_config.blockFragmentSize;

            if fragmentRemainder != 0 && *fragmentId as i32 == sendBlock.numFragments - 1
            {
                *fragmentBytes = fragmentRemainder;
            }

            let fragmentData = YOJIMBO_ALLOCATE!( ( *self.base.m_messageFactory ).GetAllocator(), *fragmentBytes as usize );

            if !fragmentData.is_null()
            {
                let blockData = ( *message ).AsBlockMessage().unwrap().GetBlockData();
                std::ptr::copy_nonoverlapping( blockData.add( *fragmentId as usize * self.base.m_config.blockFragmentSize as usize ), fragmentData, *fragmentBytes as usize );

                *sendBlock.fragmentSendTime.add( *fragmentId as usize ) = self.base.m_time;
            }

            fragmentData
        }
    }

    /**
        Fill the packet data with block and fragment data.
        This is the payload function that fills the channel packet data while we are sending a block message.
        @param packetData The packet data to fill [out]
        @param messageId The id of the message that the block is attached to.
        @param fragmentId The id of the block fragment being sent.
        @param fragmentData The fragment data.
        @param fragmentSize The size of the fragment data (bytes).
        @param numFragments The number of fragments in the block.
        @param messageType The type of message the block is attached to.
        @returns An estimate of the number of bits required to serialize the block message and fragment data (upper bound).
     */

    pub fn GetFragmentPacketData( &mut self,
                                  packetData: &mut ChannelPacketData,
                                  messageId: u16,
                                  fragmentId: u16,
                                  fragmentData: *mut u8,
                                  fragmentSize: i32,
                                  numFragments: i32,
                                  messageType: i32 ) -> i32
    {
        packetData.Initialize();

        packetData.channelIndex = self.GetChannelIndex() as _;

        packetData.blockMessage = true;

        packetData.block.fragmentData = fragmentData;
        packetData.block.messageId = messageId as _;
        packetData.block.fragmentId = fragmentId as _;
        packetData.block.fragmentSize = fragmentSize as _;
        packetData.block.numFragments = numFragments as _;
        packetData.block.messageType = messageType;

        unsafe
        {
            let messageTypeBits: i32 = bits_required( 0, ( ( *self.base.m_messageFactory ).GetNumTypes() - 1 ) as u32 ) as i32;

            let mut fragmentBits: i32 = ConservativeFragmentHeaderBits + fragmentSize * 8;

            if fragmentId == 0
            {
                let entry = ( *self.m_messageSendQueue ).Find( packetData.block.messageId as u16 );

                yojimbo_assert!( !entry.is_null() );
                yojimbo_assert!( !( *entry ).message.is_null() );

                packetData.block.message = ( *entry ).message;

                ( *self.base.m_messageFactory ).AcquireMessage( packetData.block.message );

                fragmentBits += ( *entry ).measuredBits as i32 + messageTypeBits;
            }
            else
            {
                packetData.block.message = null_message();
            }

            fragmentBits
        }
    }

    /**
        Adds a packet entry for the fragment.
        This lets us look up the fragment that was in the packet later on when it is acked, so we can ack that block fragment.
        @param messageId The message id that the block was attached to.
        @param fragmentId The fragment id.
        @param sequence The sequence number of the packet the fragment was included in.
     */

    pub fn AddFragmentPacketEntry( &mut self, messageId: u16, fragmentId: u16, sequence: u16 )
    {
        unsafe
        {
            let sentPacket = ( *self.m_sentPackets ).Insert( sequence, true );
            yojimbo_assert!( !sentPacket.is_null() );
            if !sentPacket.is_null()
            {
                ( *sentPacket ).numMessageIds = 0;
                ( *sentPacket ).messageIds = std::ptr::null_mut();
                ( *sentPacket ).timeSent = self.base.m_time;
                ( *sentPacket ).acked = 0;
                ( *sentPacket ).block = 1;
                ( *sentPacket ).blockMessageId = messageId as u64;
                ( *sentPacket ).blockFragmentId = fragmentId as u64;
            }
        }
    }

    /**
        Process a packet fragment.
        The fragment is added to the set of received fragments for the block. When all packet fragments are received, that block is reconstructed, attached to the block message and added to the message receive queue.
        @param messageType The type of the message this block fragment is attached to. This is used to make sure this message type actually allows blocks to be attached to it.
        @param messageId The id of the message the block fragment belongs to.
        @param numFragments The number of fragments in the block.
        @param fragmentId The id of the fragment in [0,numFragments-1].
        @param fragmentData The fragment data.
        @param fragmentBytes The size of the fragment data in bytes.
        @param blockMessage Pointer to the block message. Passed this in only with the first fragment (0), pass NULL for all other fragments.
     */

    // port: fragmentData is the raw allocator pointer from ChannelPacketData (may be null); blockMessage is a *mut dyn Message
    pub fn ProcessPacketFragment( &mut self,
                                  messageType: i32,
                                  messageId: u16,
                                  numFragments: i32,
                                  fragmentId: u16,
                                  fragmentData: *const u8,
                                  fragmentBytes: i32,
                                  mut blockMessage: *mut dyn Message )
    {
        yojimbo_assert!( !self.base.m_config.disableBlocks );

        if !fragmentData.is_null()
        {
            unsafe
            {
                let expectedMessageId: u16 = ( *self.m_messageReceiveQueue ).GetSequence();
                if messageId != expectedMessageId
                {
                    return;
                }

                let receiveBlock = &mut *self.m_receiveBlock;

                // start receiving a new block

                if !receiveBlock.active
                {
                    yojimbo_assert!( numFragments >= 0 );
                    yojimbo_assert!( numFragments <= self.base.m_config.GetMaxFragmentsPerBlock() );

                    if self.base.m_config.allocateBlocksOnDemand
                    {
                        // port addition: allocate the receive buffer for this block now, sized to its fragments
                        let bufferBytes = yojimbo_min( numFragments as i64 * self.base.m_config.blockFragmentSize as i64, self.base.m_config.maxBlockSize as i64 ) as i32;
                        YOJIMBO_FREE!( self.base.m_allocator, receiveBlock.blockData );
                        receiveBlock.blockDataBytes = 0;
                        receiveBlock.blockData = YOJIMBO_ALLOCATE!( self.base.m_allocator, bufferBytes as usize );
                        if receiveBlock.blockData.is_null()
                        {
                            // Not enough memory to receive the block
                            self.SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
                            return;
                        }
                        receiveBlock.blockDataBytes = bufferBytes;
                    }

                    receiveBlock.active = true;
                    receiveBlock.numFragments = numFragments;
                    receiveBlock.numReceivedFragments = 0;
                    receiveBlock.messageId = messageId;
                    receiveBlock.blockSize = 0;
                    ( *receiveBlock.receivedFragment ).Clear();
                }

                // validate fragment

                if fragmentId as i32 >= receiveBlock.numFragments
                {
                    // The fragment id is out of range.
                    self.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                    return;
                }

                if numFragments != receiveBlock.numFragments
                {
                    // The number of fragments is out of range.
                    self.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                    return;
                }

                // Validate the fragment write against the receive buffer BEFORE copying.
                // blockData is allocated at maxBlockSize bytes, but when maxBlockSize is not a
                // multiple of blockFragmentSize the fragment count rounds up, so the final fragment
                // starts at an offset where a full blockFragmentSize write would run past the buffer.
                // fragmentBytes is attacker-controlled in [1,blockFragmentSize] (see SerializeBlockFragment),
                // so a peer can send an over-long final fragment. Reject anything that wouldn't fit
                // rather than overflowing the heap (the blockSize check below only runs after the copy).
                // port addition: also checked against the size of blockData, which is smaller than maxBlockSize with ChannelConfig::allocateBlocksOnDemand
                // port: 64-bit, as the C# port, so the offset can't overflow
                if fragmentId as i64 * self.base.m_config.blockFragmentSize as i64 + fragmentBytes as i64 > self.base.m_config.maxBlockSize as i64 ||
                   fragmentId as i64 * self.base.m_config.blockFragmentSize as i64 + fragmentBytes as i64 > receiveBlock.blockDataBytes as i64
                {
                    // The fragment would write past the end of the block buffer.
                    self.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                    return;
                }

                // receive the fragment

                if ( *receiveBlock.receivedFragment ).GetBit( fragmentId as i32 ) == 0
                {
                    ( *receiveBlock.receivedFragment ).SetBit( fragmentId as i32 );

                    std::ptr::copy_nonoverlapping( fragmentData, receiveBlock.blockData.add( fragmentId as usize * self.base.m_config.blockFragmentSize as usize ), fragmentBytes as usize );

                    if fragmentId == 0
                    {
                        receiveBlock.messageType = messageType;
                    }

                    if fragmentId as i32 == receiveBlock.numFragments - 1
                    {
                        receiveBlock.blockSize = ( ( receiveBlock.numFragments - 1 ) * self.base.m_config.blockFragmentSize + fragmentBytes ) as u32;

                        if receiveBlock.blockSize > self.base.m_config.maxBlockSize as u32
                        {
                            // The block size is outside range
                            self.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                            return;
                        }
                    }

                    receiveBlock.numReceivedFragments += 1;

                    if fragmentId == 0
                    {
                        // save block message (sent with fragment 0)
                        receiveBlock.blockMessage = blockMessage;
                        ( *self.base.m_messageFactory ).AcquireMessage( receiveBlock.blockMessage );
                    }

                    if receiveBlock.numReceivedFragments == receiveBlock.numFragments
                    {
                        // finished receiving block

                        if !( *self.m_messageReceiveQueue ).GetAtIndex( ( *self.m_messageReceiveQueue ).GetIndex( messageId ) ).is_null()
                        {
                            // Did you forget to dequeue messages on the receiver?
                            self.SetErrorLevel( CHANNEL_ERROR_DESYNC );
                            return;
                        }

                        blockMessage = receiveBlock.blockMessage;

                        yojimbo_assert!( !blockMessage.is_null() );

                        let blockData = YOJIMBO_ALLOCATE!( ( *self.base.m_messageFactory ).GetAllocator(), receiveBlock.blockSize as usize );

                        if blockData.is_null()
                        {
                            // Not enough memory to allocate block data
                            self.SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
                            return;
                        }

                        std::ptr::copy_nonoverlapping( receiveBlock.blockData, blockData, receiveBlock.blockSize as usize );

                        // port: the cast to BlockMessage * is AsBlockMessage()
                        ( *blockMessage ).AsBlockMessage().unwrap().AttachBlock( ( *self.base.m_messageFactory ).GetAllocator(), blockData, receiveBlock.blockSize as i32 );

                        ( *blockMessage ).SetId( messageId );

                        let entry = ( *self.m_messageReceiveQueue ).Insert( messageId, false );
                        yojimbo_assert!( !entry.is_null() );
                        ( *entry ).message = blockMessage;
                        receiveBlock.active = false;
                        receiveBlock.blockMessage = null_message();

                        if self.base.m_config.allocateBlocksOnDemand
                        {
                            // port addition: the block is delivered, so its receive buffer goes back to the allocator
                            YOJIMBO_FREE!( self.base.m_allocator, receiveBlock.blockData );
                            receiveBlock.blockDataBytes = 0;
                        }
                    }
                }
            }
        }
    }
}

impl Channel for ReliableOrderedChannel
{
    fn base( &self ) -> &ChannelBase { &self.base }
    fn base_mut( &mut self ) -> &mut ChannelBase { &mut self.base }

    fn Reset( &mut self ) { ReliableOrderedChannel::Reset( self ) }
    fn CanSendMessage( &self ) -> bool { ReliableOrderedChannel::CanSendMessage( self ) }
    fn HasMessagesToSend( &self ) -> bool { ReliableOrderedChannel::HasMessagesToSend( self ) }
    fn SendMessage( &mut self, message: *mut dyn Message, context: *mut c_void ) { ReliableOrderedChannel::SendMessage( self, message, context ) }
    fn ReceiveMessage( &mut self ) -> *mut dyn Message { ReliableOrderedChannel::ReceiveMessage( self ) }
    fn AdvanceTime( &mut self, time: f64 ) { ReliableOrderedChannel::AdvanceTime( self, time ) }
    fn GetPacketData( &mut self, context: *mut c_void, packetData: &mut ChannelPacketData, packetSequence: u16, availableBits: i32 ) -> i32 { ReliableOrderedChannel::GetPacketData( self, context, packetData, packetSequence, availableBits ) }
    fn ProcessPacketData( &mut self, packetData: &ChannelPacketData, packetSequence: u16 ) { ReliableOrderedChannel::ProcessPacketData( self, packetData, packetSequence ) }
    fn ProcessAck( &mut self, ack: u16 ) { ReliableOrderedChannel::ProcessAck( self, ack ) }
}
