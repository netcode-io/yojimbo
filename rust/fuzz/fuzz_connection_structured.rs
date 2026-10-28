/*
    Fuzz target: yojimbo::Connection round trip, driven by a structured script.

    Where fuzz_connection.rs feeds arbitrary bytes to ProcessPacket (great for malformed
    input, but random bytes rarely form a valid packet), this target interprets the fuzz input
    as a *script* of operations against a sender/receiver Connection pair:

        - send a message (fuzz picks type, channel, and contents) on the sender;
        - "tick": generate a packet from the sender and either deliver it to the receiver (and
          ack it) or drop it (fuzz-controlled loss), then advance time and drain the receiver.

    Every packet is produced by the real write path, so it is always structurally valid and the
    receiver never bails out early — which lets the fuzzer drive the reliable-ordered channel's
    reassembly and in-order delivery state machine (out-of-order arrival via loss + resend)
    under fuzzer-chosen message streams. ASan/UBSan/MSan then watch the receive side.

    Shares the config table (fuzz_config.rs) and message factory (fuzz_messages.rs) with
    fuzz_connection. Seeds: fuzz/corpus/fuzz_connection_structured.
*/

use yojimbo::*;

use crate::fuzz_messages::*;
use crate::fuzz_config::*;

// port: a C file static. The driver is single threaded.
static mut g_init: bool = false;

fn ensure_init()
{
    unsafe
    {
        if !g_init
        {
            // port: the driver has already called InitializeYojimbo (see the note in fuzz_connection.rs)
            yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );
            g_init = true;
        }
    }
}

// Minimal cursor over the fuzz input; out-of-data reads return 0.
struct Reader<'a>
{
    data: &'a [u8],
    size: usize,
    pos: usize,
}

impl<'a> Reader<'a>
{
    fn u8( &mut self ) -> u8 { if self.pos < self.size { let v = self.data[self.pos]; self.pos += 1; v } else { 0 } }
    fn u16( &mut self ) -> u16 { let a = self.u8() as u16; let b = self.u8() as u16; ( a | ( b << 8 ) ) as u16 }
    fn done( &self ) -> bool { self.pos >= self.size }
}

// Returns false if the message should be discarded rather than sent (e.g. a block message whose
// block couldn't be allocated - sending a zero-size block would trip a send-time assert; under
// allocation-fault injection that path is reachable).
fn fill_message( message: *mut dyn Message, r#type: i32, r: &mut Reader, config: &ConnectionConfig, channel: i32, allocator: *mut dyn Allocator ) -> bool
{
    match r#type
    {
        FUZZ_MESSAGE_PRIMITIVES =>
        {
            let m = unsafe { message_cast::<FuzzPrimitivesMessage>( message ) };
            m.i = ( r.u16() as i32 ) - 32768;
            m.bits = r.u16() as u32;
            m.flag = ( r.u8() & 1 ) != 0;
            m.f = ( r.u16() as i32 - 32768 ) as f32;
            m.d = ( r.u16() as i32 - 32768 ) as f64;
            m.cf = ( r.u8() % 101 ) as f32 / 100.0f32;   // [0,1]
            m.base = r.u16() as i32 % 900;
            m.rel = m.base + 1 + ( r.u8() as i32 % 100 );   // serialize_int_relative needs base < rel
        }
        FUZZ_MESSAGE_STRING =>
        {
            let m = unsafe { message_cast::<FuzzStringMessage>( message ) };
            let n = ( r.u8() as i32 % FuzzMaxString ) as usize;       // leave room for the terminator
            for i in 0..n
            {
                // masked to ASCII: the string payload is well-formed UTF-8 by the writer's
                // contract (serialize debug-asserts it, and asserts are live in this
                // harness), so this write-path target must generate conforming content —
                // exactly as serialize's own fuzzer does. Arbitrary bytes still reach the
                // reader's malformed-string refusal path via fuzz_connection's raw packets.
                let c = r.u8() & 0x7F;
                m.str[i] = if c != 0 { c } else { b' ' };   // no embedded NUL
            }
            m.str[n] = 0;
        }
        FUZZ_MESSAGE_BYTES =>
        {
            let m = unsafe { message_cast::<FuzzBytesMessage>( message ) };
            m.count = r.u16() as i32 % ( FuzzMaxBytes + 1 );
            for i in 0..m.count as usize
            {
                m.data[i] = r.u8();
            }
        }
        FUZZ_MESSAGE_BLOCK =>
        {
            let m = unsafe { message_cast::<FuzzBlockMessage>( message ) };
            m.sequence = r.u16();
            let maxBlock = config.channel[channel as usize].maxBlockSize;
            let blockSize = 1 + ( r.u16() as i32 % ( if maxBlock < 8192 { maxBlock } else { 8192 } ) );
            let block = YOJIMBO_ALLOCATE!( allocator, blockSize );
            if block.is_null()
            {
                return false;   // allocation failed (fault injection) -> don't send a blockless block message
            }
            let seed = r.u8();
            let blockSlice = unsafe { std::slice::from_raw_parts_mut( block, blockSize as usize ) };
            for i in 0..blockSize as usize
            {
                blockSlice[i] = ( i as u8 ).wrapping_add( seed );
            }
            m.base.AttachBlock( allocator, block, blockSize );
        }
        _ => {}
    }
    true
}

// Allocator used to fuzz allocation-failure paths. Delegates to malloc/free but can be told to
// fail the Nth upcoming allocation (then it disarms), driven by the fuzz input. Failures are only
// armed *after* construction, since the library allocates its fixed pools up front and treats
// those as infallible; every runtime allocation (packet generate/process, message create, block
// attach) is expected to handle NULL gracefully - that is exactly what this exercises.
struct FaultAllocator
{
    base: AllocatorBase,
    m_countdown: i32,
}

impl FaultAllocator
{
    fn new() -> FaultAllocator { FaultAllocator { base: AllocatorBase::new(), m_countdown: -1 } }
    fn FailIn( &mut self, n: i32 ) { self.m_countdown = n; }       // fail the n-th allocation from now, once
    fn Disarm( &mut self ) { self.m_countdown = -1; }
}

// port: malloc / free are std::alloc with a header in front of the block holding its size, as DefaultAllocator does
const FaultAllocatorHeaderBytes: usize = YOJIMBO_ALLOCATOR_ALIGNMENT;

fn fault_allocator_malloc( size: usize ) -> *mut u8
{
    let total = match size.checked_add( FaultAllocatorHeaderBytes ) { Some( total ) => total, None => return std::ptr::null_mut() };
    let layout = match std::alloc::Layout::from_size_align( total, YOJIMBO_ALLOCATOR_ALIGNMENT ) { Ok( layout ) => layout, Err( _ ) => return std::ptr::null_mut() };
    unsafe
    {
        let block = std::alloc::alloc( layout );
        if block.is_null()
        {
            return std::ptr::null_mut();
        }
        ( block as *mut usize ).write( size );
        block.add( FaultAllocatorHeaderBytes )
    }
}

fn fault_allocator_free( p: *mut u8 )
{
    unsafe
    {
        let block = p.sub( FaultAllocatorHeaderBytes );
        let size = ( block as *const usize ).read();
        let layout = std::alloc::Layout::from_size_align_unchecked( size + FaultAllocatorHeaderBytes, YOJIMBO_ALLOCATOR_ALIGNMENT );
        std::alloc::dealloc( block, layout );
    }
}

impl Allocator for FaultAllocator
{
    fn Allocate( &mut self, size: usize, file: &'static str, line: u32 ) -> *mut u8
    {
        if self.m_countdown == 0
        {
            self.m_countdown = -1;                      // one-shot: fail this allocation, then rearm off
            self.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return std::ptr::null_mut();
        }
        if self.m_countdown > 0
        {
            self.m_countdown -= 1;
        }
        let p = fault_allocator_malloc( size );
        if p.is_null()
        {
            self.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return std::ptr::null_mut();
        }
        self.TrackAlloc( p, size, file, line );
        p
    }

    fn Free( &mut self, p: *mut u8, file: &'static str, line: u32 )
    {
        if p.is_null()
        {
            return;
        }
        self.TrackFree( p, file, line );
        fault_allocator_free( p );
    }

    fn base( &self ) -> &AllocatorBase { &self.base }
    fn base_mut( &mut self ) -> &mut AllocatorBase { &mut self.base }
}

// Serialize just the connection-packet channel-entry count, matching ConnectionPacket::Serialize.
// (ConnectionPacket itself is internal; the per-entry body is written by the library below.)
fn write_channel_entry_count<S: Stream>( stream: &mut S, numChannelEntries: &mut i32, numChannels: i32 ) -> bool
{
    serialize_int!( stream, *numChannelEntries, 0, numChannels );
    true
}

// Feed the receiver a *hand-built* reliable-ordered block fragment whose header fields
// (numFragments / fragmentId / fragmentSize) are fuzz-chosen and deliberately out of spec - the
// thing the real write path never emits (e.g. a full-size final fragment). The wire bytes are
// produced by the library's own ChannelPacketData writer, so the format stays in sync; only the
// adversarial field *values* come from the fuzzer. advConfig uses a maxBlockSize that is not a
// multiple of blockFragmentSize, so this targets the block-reassembly bounds check directly. The
// receiver is Reset first so messageId 0 is the expected next block and the fragment reaches the
// reassembly memcpy.
// port: the factory is a pointer, since the receiver holds one to the same factory
fn inject_adversarial_fragment( receiver: &mut Connection, advConfig: &ConnectionConfig,
                                factory: *mut dyn MessageFactory, r: &mut Reader )
{
    let cc = &advConfig.channel[0];
    let maxFrags = cc.GetMaxFragmentsPerBlock();

    receiver.Reset();

    let mut channelData = ChannelPacketData::new();
    channelData.Initialize();
    channelData.channelIndex = 0;
    channelData.blockMessage = true;
    channelData.block.messageId = 0;

    let numFragments = if maxFrags > 1 { 1 + ( r.u8() as i32 % maxFrags ) } else { 1 };
    channelData.block.numFragments = numFragments as u16;

    let mut fragmentId = if numFragments > 1 { r.u8() as i32 % numFragments } else { 0 };
    if ( r.u8() & 1 ) != 0
    {
        fragmentId = numFragments - 1;              // bias toward the final fragment (overflow case)
    }
    channelData.block.fragmentId = fragmentId as u16;

    let mut fragmentSize = 1 + ( r.u16() as i32 % cc.blockFragmentSize );
    if ( r.u8() & 1 ) != 0
    {
        fragmentSize = cc.blockFragmentSize;        // bias toward a full-size (adversarial) fragment
    }
    channelData.block.fragmentSize = fragmentSize as u16;

    channelData.block.fragmentData = YOJIMBO_ALLOCATE!( unsafe { ( *factory ).GetAllocator() }, fragmentSize );
    if channelData.block.fragmentData.is_null()
    {
        channelData.Free( factory );
        return;
    }
    unsafe { std::ptr::write_bytes( channelData.block.fragmentData, r.u8(), fragmentSize as usize ); }
    channelData.block.messageType = FUZZ_MESSAGE_BLOCK;

    if fragmentId == 0
    {
        // Fragment 0 carries the block message; the writer serializes it after the fragment data.
        let bm = unsafe { ( *factory ).CreateMessage( FUZZ_MESSAGE_BLOCK ) };
        if bm.is_null()
        {
            channelData.Free( factory );
            return;
        }
        unsafe { message_cast::<FuzzBlockMessage>( bm ) }.sequence = r.u16();
        channelData.block.message = bm;
    }

    // Zero-initialized, with 8 bytes of slack past the write size. The serialize reader loads
    // a 64-bit window and reads up to 7 bytes past the packet data end (masked out of the
    // result, but MemorySanitizer sees the load), so the over-read must stay in-bounds and
    // initialized. Matches the padded buffer in fuzz_connection.
    let mut packet = [0u8; 8 * 1024 + 8];
    let mut packetBytes: i32 = 0;
    let written;
    {
        let mut stream = WriteStream::new( &mut packet, 8 * 1024 );
        let mut numChannelEntries: i32 = 1;
        written = write_channel_entry_count( &mut stream, &mut numChannelEntries, advConfig.numChannels ) &&
                  channelData.SerializeInternalWrite( &mut stream, factory, &advConfig.channel, advConfig.numChannels );
        if written
        {
            stream.Flush();
            packetBytes = stream.GetBytesProcessed() as i32;
        }
    }
    if written
    {
        channelData.Free( factory );                // release our write-side fragment data + message
        if packetBytes > 0
        {
            receiver.ProcessPacket( std::ptr::null_mut(), 0, &packet, packetBytes );
        }
    }
    else
    {
        channelData.Free( factory );
    }

    loop
    {
        let m = receiver.ReceiveMessage( 0 );
        if m.is_null()
        {
            break;
        }
        unsafe { ( *factory ).ReleaseMessage( m ); }
    }
}

pub fn LLVMFuzzerTestOneInput( data: &[u8], size: usize ) -> i32
{
    ensure_init();

    if size < 1
    {
        return 0;
    }

    let mut r = Reader { data, size, pos: 0 };

    // The fault allocator is declared first so it outlives (and its leak check runs after) the
    // factories and connections built on top of it.
    // port: the factories and connections keep pointers to the allocator (and the connections to their factories), so
    // the target reaches them through pointers too. Locals drop in reverse order of declaration, as in C++.
    let mut allocatorObject = FaultAllocator::new();
    let allocatorPtr: *mut FaultAllocator = &mut allocatorObject;
    let allocator: *mut dyn Allocator = allocatorPtr;

    let mut config = ConnectionConfig::new();
    fuzz_make_config( r.u8(), &mut config );

    let mut senderFactoryObject = FuzzMessageFactory::new( allocator );
    let senderFactory: *mut dyn MessageFactory = &mut senderFactoryObject;
    let mut receiverFactoryObject = FuzzMessageFactory::new( allocator );
    let receiverFactory: *mut dyn MessageFactory = &mut receiverFactoryObject;

    let mut time: f64 = 100.0;
    let mut sender = Connection::new( allocator, senderFactory, &config, time );
    let mut receiver = Connection::new( allocator, receiverFactory, &config, time );

    // A dedicated receiver + factory for adversarial block fragments, on a config whose
    // maxBlockSize is not a multiple of blockFragmentSize (the overflow-prone geometry).
    let mut advConfig = ConnectionConfig::new();
    advConfig.numChannels = 1;
    advConfig.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    advConfig.channel[0].maxBlockSize = 1100;
    advConfig.channel[0].blockFragmentSize = 500;
    let mut advFactoryObject = FuzzMessageFactory::new( allocator );
    let advFactory: *mut dyn MessageFactory = &mut advFactoryObject;
    let mut advReceiver = Connection::new( allocator, advFactory, &advConfig, time );

    // Zero-initialized with 8 bytes of slack past the generate size, for the reader's 64-bit
    // over-read window (see the note on the block-fragment packet buffer above).
    let mut packetData = [0u8; 8 * 1024 + 8];
    let mut sequence: u16 = 0;
    const MAX_OPS: i32 = 512;

    let mut op = 0;
    while op < MAX_OPS && !r.done()
    {
        let action = r.u8();

        // Occasionally schedule an allocation failure a few allocations out (one-shot). Armed only
        // here, inside the op loop, so it never disturbs the up-front pool allocations.
        if ( action & 0x20 ) != 0
        {
            let n = 1 + ( r.u8() as i32 % 12 );
            unsafe { ( *allocatorPtr ).FailIn( n ); }
        }

        // Occasionally feed the dedicated receiver an adversarial block fragment.
        if ( action & 0xC0 ) == 0xC0
        {
            inject_adversarial_fragment( &mut advReceiver, &advConfig, advFactory, &mut r );
        }

        if ( action & 3 ) != 0
        {
            // send a message
            let mut r#type = r.u8() as i32 % FUZZ_NUM_MESSAGE_TYPES;
            let channel = if config.numChannels > 1 { r.u8() as i32 % config.numChannels } else { 0 };

            // Block messages are only valid on a reliable-ordered channel with blocks enabled:
            // the unreliable channel serializes blocks inline and asserts if one won't fit a
            // single packet, and a disableBlocks channel asserts outright. Fall back otherwise.
            if r#type == FUZZ_MESSAGE_BLOCK &&
                 ( config.channel[channel as usize].r#type != CHANNEL_TYPE_RELIABLE_ORDERED ||
                   config.channel[channel as usize].disableBlocks )
            {
                r#type = FUZZ_MESSAGE_PRIMITIVES;
            }

            if sender.CanSendMessage( channel )
            {
                let message = unsafe { ( *senderFactory ).CreateMessage( r#type ) };
                if !message.is_null()
                {
                    if fill_message( message, r#type, &mut r, &config, channel, unsafe { ( *senderFactory ).GetAllocator() } )
                    {
                        sender.SendMessage( channel, message, std::ptr::null_mut() );
                    }
                    else
                    {
                        unsafe { ( *senderFactory ).ReleaseMessage( message ); }
                    }
                }
            }
        }
        else
        {
            // tick: generate a packet and deliver or drop it
            let mut packetBytes: i32 = 0;
            if sender.GeneratePacket( std::ptr::null_mut(), sequence, &mut packetData, 8 * 1024, &mut packetBytes ) && packetBytes > 0
            {
                let drop = ( action & 4 ) != 0;   // fuzz-controlled packet loss
                if !drop
                {
                    receiver.ProcessPacket( std::ptr::null_mut(), sequence, &packetData, packetBytes );
                    sender.ProcessAcks( &[sequence], 1 );
                }
            }

            time += 0.1;
            sender.AdvanceTime( time );
            receiver.AdvanceTime( time );
            sequence = sequence.wrapping_add( 1 );

            for ch in 0..config.numChannels
            {
                loop
                {
                    let m = receiver.ReceiveMessage( ch );
                    if m.is_null()
                    {
                        break;
                    }
                    unsafe { ( *receiverFactory ).ReleaseMessage( m ); }
                }
            }
        }

        op += 1;
    }

    // final drain
    for ch in 0..config.numChannels
    {
        loop
        {
            let m = receiver.ReceiveMessage( ch );
            if m.is_null()
            {
                break;
            }
            unsafe { ( *receiverFactory ).ReleaseMessage( m ); }
        }
    }

    0
}
