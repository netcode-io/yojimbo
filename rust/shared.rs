/*
    Shared Code for Tests and Examples.

    Copyright © 2016 - 2026, Más Bandwidth LLC

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

// port: shared.h. A bin includes it with `#[path = "shared.rs"] mod shared; use shared::*;` (the include guard has no
// Rust counterpart: a module is only compiled once per crate).

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_imports, unused_unsafe, static_mut_refs)]

use yojimbo::*;

pub const ProtocolId: u64 = 0x11223344556677;

pub const ClientPort: i32 = 30000;
pub const ServerPort: i32 = 40000;

pub fn GetNumBitsForMessage( sequence: u16 ) -> i32
{
    static messageBitsArray: [i32; 21] = [ 1, 320, 120, 4, 256, 45, 11, 13, 101, 100, 84, 95, 203, 2, 3, 8, 512, 5, 3, 7, 50 ];
    let modulus = messageBitsArray.len() as i32;
    let index = ( sequence as i32 ) % modulus;
    messageBitsArray[index as usize]
}

#[derive(Default)]
pub struct TestMessage
{
    pub base: MessageBase,
    pub sequence: u16,
}

impl TestMessage
{
    // port: TestMessage() { sequence = 0; } is #[derive(Default)]

    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_bits!( stream, self.sequence, 16 );

        let numBits = GetNumBitsForMessage( self.sequence );
        let numWords = numBits / 32;
        let mut dummy: u32 = 0;
        for _i in 0..numWords
        {
            serialize_bits!( stream, dummy, 32 );
        }
        let numRemainderBits = numBits - numWords * 32;
        if numRemainderBits > 0
        {
            serialize_bits!( stream, dummy, numRemainderBits );
        }

        true
    }
}

impl Serializable for TestMessage
{
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!();
}

YOJIMBO_MESSAGE!( TestMessage );

#[derive(Default)]
pub struct TestBlockMessage
{
    pub base: BlockMessage,
    pub sequence: u16,
}

impl TestBlockMessage
{
    // port: TestBlockMessage() { sequence = 0; } is #[derive(Default)]

    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_bits!( stream, self.sequence, 16 );
        true
    }
}

impl Serializable for TestBlockMessage
{
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!();
}

YOJIMBO_BLOCK_MESSAGE!( TestBlockMessage );

// port: the BlockMessage base class, so blockMessage.AttachBlock(), GetBlockData() and GetBlockSize() read as upstream
impl std::ops::Deref for TestBlockMessage
{
    type Target = BlockMessage;
    fn deref( &self ) -> &BlockMessage { &self.base }
}

impl std::ops::DerefMut for TestBlockMessage
{
    fn deref_mut( &mut self ) -> &mut BlockMessage { &mut self.base }
}

#[derive(Default)]
pub struct TestSerializeFailOnReadMessage
{
    pub base: MessageBase,
}

impl TestSerializeFailOnReadMessage
{
    pub fn Serialize<S: Stream>( &mut self, _stream: &mut S ) -> bool
    {
        !S::IsReading
    }
}

impl Serializable for TestSerializeFailOnReadMessage
{
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!();
}

YOJIMBO_MESSAGE!( TestSerializeFailOnReadMessage );

#[derive(Default)]
pub struct TestExhaustStreamAllocatorOnReadMessage
{
    pub base: MessageBase,
}

impl TestExhaustStreamAllocatorOnReadMessage
{
    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        if S::IsReading
        {
            const NumBuffers: usize = 100;

            let mut buffers: [*mut u8; NumBuffers] = [std::ptr::null_mut(); NumBuffers];

            // port: the stream's allocator context holds a pointer to a `*mut dyn Allocator` (AllocatorToContext)
            let allocator: *mut dyn Allocator = unsafe { AllocatorFromContext( stream.GetAllocator() ) };

            for i in 0..NumBuffers
            {
                buffers[i] = YOJIMBO_ALLOCATE!( allocator, 1024 * 1024 );
            }

            for i in 0..NumBuffers
            {
                YOJIMBO_FREE!( allocator, buffers[i] );
            }
        }

        true
    }
}

impl Serializable for TestExhaustStreamAllocatorOnReadMessage
{
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!();
}

YOJIMBO_MESSAGE!( TestExhaustStreamAllocatorOnReadMessage );

// enum TestMessageType
pub const TEST_MESSAGE: i32 = 0;
pub const TEST_BLOCK_MESSAGE: i32 = 1;
pub const TEST_SERIALIZE_FAIL_ON_READ_MESSAGE: i32 = 2;
pub const TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE: i32 = 3;
pub const NUM_TEST_MESSAGE_TYPES: i32 = 4;

YOJIMBO_MESSAGE_FACTORY_START!( TestMessageFactory, NUM_TEST_MESSAGE_TYPES,
    YOJIMBO_DECLARE_MESSAGE_TYPE( TEST_MESSAGE, TestMessage );
    YOJIMBO_DECLARE_MESSAGE_TYPE( TEST_BLOCK_MESSAGE, TestBlockMessage );
    YOJIMBO_DECLARE_MESSAGE_TYPE( TEST_SERIALIZE_FAIL_ON_READ_MESSAGE, TestSerializeFailOnReadMessage );
    YOJIMBO_DECLARE_MESSAGE_TYPE( TEST_EXHAUST_STREAM_ALLOCATOR_ON_READ_MESSAGE, TestExhaustStreamAllocatorOnReadMessage );
YOJIMBO_MESSAGE_FACTORY_FINISH() );

// enum SingleTestMessageType
pub const SINGLE_TEST_MESSAGE: i32 = 0;
pub const NUM_SINGLE_TEST_MESSAGE_TYPES: i32 = 1;

YOJIMBO_MESSAGE_FACTORY_START!( SingleTestMessageFactory, NUM_SINGLE_TEST_MESSAGE_TYPES,
    YOJIMBO_DECLARE_MESSAGE_TYPE( SINGLE_TEST_MESSAGE, TestMessage );
YOJIMBO_MESSAGE_FACTORY_FINISH() );

// enum SingleBlockTestMessageType
pub const SINGLE_BLOCK_TEST_MESSAGE: i32 = 0;
pub const NUM_SINGLE_BLOCK_TEST_MESSAGE_TYPES: i32 = 1;

YOJIMBO_MESSAGE_FACTORY_START!( SingleBlockTestMessageFactory, NUM_SINGLE_BLOCK_TEST_MESSAGE_TYPES,
    YOJIMBO_DECLARE_MESSAGE_TYPE( SINGLE_BLOCK_TEST_MESSAGE, TestBlockMessage );
YOJIMBO_MESSAGE_FACTORY_FINISH() );

pub struct TestAdapter;

impl Adapter for TestAdapter
{
    fn CreateMessageFactory( &mut self, allocator: *mut dyn Allocator ) -> *mut dyn MessageFactory
    {
        YOJIMBO_NEW!( allocator, TestMessageFactory, TestMessageFactory::new( allocator ) ) as *mut dyn MessageFactory
    }
}

// port: `static TestAdapter adapter;` is a static mut (single-threaded, as upstream). Pass it where upstream passes
// `adapter` with GetTestAdapter().
pub static mut adapter: TestAdapter = TestAdapter;

/// port addition: `adapter` as the `*mut dyn Adapter` the client and server constructors take
pub fn GetTestAdapter() -> *mut dyn Adapter
{
    unsafe { std::ptr::addr_of_mut!( adapter ) as *mut dyn Adapter }
}
