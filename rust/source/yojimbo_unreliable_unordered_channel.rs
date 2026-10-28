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

// port: include/yojimbo_unreliable_unordered_channel.h + source/yojimbo_unreliable_unordered_channel.cpp

use crate::*;
use crate::serialize::*;
use std::ffi::c_void;

/**
    Messages sent across this channel are not guaranteed to arrive, and may be received in a different order than they were sent.
    This channel type is best used for time critical data like snapshots and object state.
 */

pub struct UnreliableUnorderedChannel
{
    pub base: ChannelBase,                                      //< port: the Channel base class's data members

    pub m_messageSendQueue: *mut Queue<*mut dyn Message>,       //< Message send queue.
    pub m_messageReceiveQueue: *mut Queue<*mut dyn Message>,    //< Message receive queue.
    pub m_packetMessages: *mut *mut dyn Message,                //< Scratch space for the messages gathered for the packet currently being generated (maxMessagesPerPacket entries). Owned by the channel so stack usage doesn't scale with the config.
}

impl UnreliableUnorderedChannel
{
    /**
        Unreliable unordered channel constructor.
        @param allocator The allocator to use.
        @param messageFactory Message factory for creating and destroying messages.
        @param config The configuration for this channel.
        @param maxPacketSize The maximum packet size in bytes (see ConnectionConfig::maxPacketSize).
        @param channelIndex The channel index in [0,numChannels-1].
        @param time The current time in seconds. See Channel::AdvanceTime
     */

    // port: returns the channel by value (move it into YOJIMBO_NEW!); everything it allocates is held by pointer, so the move is safe
    pub fn new( allocator: *mut dyn Allocator,
                messageFactory: *mut dyn MessageFactory,
                config: &ChannelConfig,
                maxPacketSize: i32,
                channelIndex: i32,
                time: f64 ) -> UnreliableUnorderedChannel
    {
        let mut this = UnreliableUnorderedChannel
        {
            base: ChannelBase::new( allocator,
                                    messageFactory,
                                    config,
                                    maxPacketSize,
                                    channelIndex,
                                    time ),
            m_messageSendQueue: std::ptr::null_mut(),
            m_messageReceiveQueue: std::ptr::null_mut(),
            m_packetMessages: std::ptr::null_mut(),
        };
        yojimbo_assert!( config.r#type == CHANNEL_TYPE_UNRELIABLE_UNORDERED );
        let m_allocator = this.base.m_allocator;
        this.m_messageSendQueue = YOJIMBO_NEW!( m_allocator, Queue<*mut dyn Message>, Queue::new( m_allocator, this.base.m_config.messageSendQueueSize ) );
        this.m_messageReceiveQueue = YOJIMBO_NEW!( m_allocator, Queue<*mut dyn Message>, Queue::new( m_allocator, this.base.m_config.messageReceiveQueueSize ) );
        this.m_packetMessages = YOJIMBO_ALLOCATE!( m_allocator, std::mem::size_of::<*mut dyn Message>() * this.base.m_config.maxMessagesPerPacket as usize ) as *mut *mut dyn Message;
        this.Reset();
        this
    }
}

/**
    Unreliable unordered channel destructor.
    Any messages still in the send or receive queues will be released.
 */

impl Drop for UnreliableUnorderedChannel
{
    fn drop( &mut self )
    {
        self.Reset();
        let m_allocator = self.base.m_allocator;
        YOJIMBO_DELETE!( m_allocator, Queue<*mut dyn Message>, self.m_messageSendQueue );
        YOJIMBO_DELETE!( m_allocator, Queue<*mut dyn Message>, self.m_messageReceiveQueue );
        YOJIMBO_FREE!( m_allocator, self.m_packetMessages );
    }
}

impl Channel for UnreliableUnorderedChannel
{
    fn base( &self ) -> &ChannelBase { &self.base }

    fn base_mut( &mut self ) -> &mut ChannelBase { &mut self.base }

    fn Reset( &mut self )
    {
        self.SetErrorLevel( CHANNEL_ERROR_NONE );

        unsafe
        {
            for i in 0..( *self.m_messageSendQueue ).GetNumEntries()
            {
                ( *self.base.m_messageFactory ).ReleaseMessage( ( &*self.m_messageSendQueue )[i] );
            }

            for i in 0..( *self.m_messageReceiveQueue ).GetNumEntries()
            {
                ( *self.base.m_messageFactory ).ReleaseMessage( ( &*self.m_messageReceiveQueue )[i] );
            }

            ( *self.m_messageSendQueue ).Clear();
            ( *self.m_messageReceiveQueue ).Clear();
        }

        self.ResetCounters();
    }

    fn CanSendMessage( &self ) -> bool
    {
        yojimbo_assert!( !self.m_messageSendQueue.is_null() );
        unsafe { !( *self.m_messageSendQueue ).IsFull() }
    }

    fn HasMessagesToSend( &self ) -> bool
    {
        yojimbo_assert!( !self.m_messageSendQueue.is_null() );
        unsafe { !( *self.m_messageSendQueue ).IsEmpty() }
    }

    fn SendMessage( &mut self, message: *mut dyn Message, context: *mut c_void )
    {
        yojimbo_assert!( !message.is_null() );
        yojimbo_assert!( self.CanSendMessage() );
        let _ = context;

        unsafe
        {
            if self.GetErrorLevel() != CHANNEL_ERROR_NONE
            {
                ( *self.base.m_messageFactory ).ReleaseMessage( message );
                return;
            }

            if !self.CanSendMessage()
            {
                self.SetErrorLevel( CHANNEL_ERROR_SEND_QUEUE_FULL );
                ( *self.base.m_messageFactory ).ReleaseMessage( message );
                return;
            }

            yojimbo_assert!( !( ( *message ).IsBlockMessage() && self.base.m_config.disableBlocks ) );

            if ( *message ).IsBlockMessage() && self.base.m_config.disableBlocks
            {
                self.SetErrorLevel( CHANNEL_ERROR_BLOCKS_DISABLED );
                ( *self.base.m_messageFactory ).ReleaseMessage( message );
                return;
            }

            if ( *message ).IsBlockMessage()
            {
                // port: the cast to BlockMessage * is AsBlockMessage()
                yojimbo_assert!( ( *message ).AsBlockMessage().map_or( 0, |b| b.GetBlockSize() ) > 0 );
                yojimbo_assert!( ( *message ).AsBlockMessage().map_or( 0, |b| b.GetBlockSize() ) <= self.base.m_config.maxBlockSize );
            }

            ( *self.m_messageSendQueue ).Push( message );
        }

        self.base.m_counters[CHANNEL_COUNTER_MESSAGES_SENT as usize] += 1;
    }

    fn ReceiveMessage( &mut self ) -> *mut dyn Message
    {
        if self.GetErrorLevel() != CHANNEL_ERROR_NONE
        {
            return null_message();
        }

        if unsafe { ( *self.m_messageReceiveQueue ).IsEmpty() }
        {
            return null_message();
        }

        self.base.m_counters[CHANNEL_COUNTER_MESSAGES_RECEIVED as usize] += 1;

        unsafe { ( *self.m_messageReceiveQueue ).Pop() }
    }

    fn AdvanceTime( &mut self, time: f64 )
    {
        let _ = time;
    }

    fn GetPacketData( &mut self, context: *mut c_void, packetData: &mut ChannelPacketData, packetSequence: u16, mut availableBits: i32 ) -> i32
    {
        let _ = packetSequence;

        unsafe
        {
            if ( *self.m_messageSendQueue ).IsEmpty()
            {
                return 0;
            }

            if self.base.m_config.packetBudget > 0
            {
                availableBits = yojimbo_min( self.base.m_config.packetBudget * 8, availableBits );
            }

            let giveUpBits: i32 = 4 * 8;

            let messageTypeBits = bits_required( 0, ( ( *self.base.m_messageFactory ).GetNumTypes() - 1 ) as u32 ) as i32;

            let mut usedBits = ConservativeMessageHeaderBits;
            let mut numMessages: i32 = 0;
            let messages = self.m_packetMessages;

            loop
            {
                if ( *self.m_messageSendQueue ).IsEmpty()
                {
                    break;
                }

                if availableBits - usedBits < giveUpBits
                {
                    break;
                }

                if numMessages == self.base.m_config.maxMessagesPerPacket
                {
                    break;
                }

                let message = ( *self.m_messageSendQueue ).Pop();

                yojimbo_assert!( !message.is_null() );

                let mut measureStream = MeasureStream::new();
                measureStream.SetContext( context );
                // port: the stream's allocator is a thin pointer; the fat *mut dyn Allocator's metadata is dropped
                measureStream.SetAllocator( ( *self.base.m_messageFactory ).GetAllocatorContext() );
                ( *message ).SerializeInternalMeasure( &mut measureStream );

                if ( *message ).IsBlockMessage()
                {
                    // port: the cast to BlockMessage * is AsBlockMessage()
                    let blockMessage = ( *message ).AsBlockMessage().unwrap() as *mut BlockMessage;
                    SerializeMessageBlock( &mut measureStream, self.base.m_messageFactory, blockMessage, self.base.m_config.maxBlockSize );
                }

                let messageBits = messageTypeBits + measureStream.GetBitsProcessed() as i32;

                let isOverBudget = self.base.m_config.packetBudget > 0 && messageBits > self.base.m_config.packetBudget * 8;
                let isOverPacketSize = messageBits > self.base.m_maxPacketSize * 8;
                let isTooLarge = isOverBudget || isOverPacketSize;

                yojimbo_assert!( !isTooLarge );

                if isTooLarge
                {
                    // You tried to send a message that is too large to ever fit into a packet for this channel. Large data should be sent as a block message over a reliable-ordered channel.
                    self.SetErrorLevel( CHANNEL_ERROR_MESSAGE_TOO_LARGE );
                    ( *self.base.m_messageFactory ).ReleaseMessage( message );
                    break;
                }

                if usedBits + messageBits > availableBits
                {
                    ( *self.base.m_messageFactory ).ReleaseMessage( message );
                    continue;
                }

                usedBits += messageBits;

                yojimbo_assert!( usedBits <= availableBits );

                messages.add( numMessages as usize ).write( message );
                numMessages += 1;
            }

            if numMessages == 0
            {
                return 0;
            }

            let allocator = ( *self.base.m_messageFactory ).GetAllocator();

            packetData.Initialize();
            packetData.channelIndex = self.GetChannelIndex() as u16;
            packetData.message.numMessages = numMessages;
            packetData.message.messages = YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<*mut dyn Message>() * numMessages as usize ) as *mut *mut dyn Message;

            if packetData.message.messages.is_null()
            {
                // Out of memory. These messages were already popped off the send queue, so this
                // channel owns the only reference to each: release them here or they leak. Leave the
                // arm empty (numMessages = 0) so packetData stays safe, and send no data this packet.
                for i in 0..numMessages as usize
                {
                    ( *self.base.m_messageFactory ).ReleaseMessage( *messages.add( i ) );
                }
                packetData.message.numMessages = 0;
                self.SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
                return 0;
            }

            for i in 0..numMessages as usize
            {
                // port: write(), the array is fresh allocator memory
                packetData.message.messages.add( i ).write( *messages.add( i ) );
            }

            usedBits
        }
    }

    fn ProcessPacketData( &mut self, packetData: &ChannelPacketData, packetSequence: u16 )
    {
        if self.base.m_errorLevel != CHANNEL_ERROR_NONE
        {
            return;
        }

        if packetData.messageFailedToSerialize
        {
            self.SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
            return;
        }

        // An unreliable-unordered channel never sends a top-level block fragment
        // (its block messages are serialized inline, see SerializeUnorderedMessages),
        // so packetData here must hold the message union member. If blockMessage is set
        // the packet is malformed: reading packetData.message would reinterpret the
        // block union member as a message-pointer array. Treat it as a serialize failure.
        if packetData.blockMessage
        {
            self.SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
            return;
        }

        unsafe
        {
            for i in 0..packetData.message.numMessages as usize
            {
                let message = *packetData.message.messages.add( i );
                yojimbo_assert!( !message.is_null() );
                ( *message ).SetId( packetSequence );
                if !( *self.m_messageReceiveQueue ).IsFull()
                {
                    ( *self.base.m_messageFactory ).AcquireMessage( message );
                    ( *self.m_messageReceiveQueue ).Push( message );
                }
            }
        }
    }

    fn ProcessAck( &mut self, ack: u16 )
    {
        let _ = ack;
    }
}
