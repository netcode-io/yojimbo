/*
    Message types for the connection fuzz targets.

    The stock TestMessage only calls serialize_bits, so it exercises almost none of the
    serialize vocabulary. These messages deliberately drive the full set — int / bits / bool /
    float / double / compressed_float / int_relative / align, a bounded string, and a
    variable-length byte array — so fuzzing Connection::ProcessPacket reaches the read paths of
    each serialize helper (and their length/bounds checks, a classic bug surface). One block
    message type covers the reliable-ordered block path.

    Shared by fuzz_connection.rs, fuzz_connection_structured.rs, and the seed generator so the
    message-type indices line up between what writes the seeds and what reads them.
*/

// port: fuzz_messages.h. fuzz_standalone.rs declares it as a module (the include guard has no Rust counterpart)

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_imports, unused_unsafe, static_mut_refs)]

use yojimbo::*;

// enum FuzzMessageType
pub const FUZZ_MESSAGE_PRIMITIVES: i32 = 0;
pub const FUZZ_MESSAGE_STRING: i32 = 1;
pub const FUZZ_MESSAGE_BYTES: i32 = 2;
pub const FUZZ_MESSAGE_BLOCK: i32 = 3;
pub const FUZZ_NUM_MESSAGE_TYPES: i32 = 4;

pub const FuzzMaxBytes: i32 = 512;
pub const FuzzMaxString: i32 = 64;

// Every fixed-width serialize helper, including an odd bit width and a relative int.
#[derive(Default)]
pub struct FuzzPrimitivesMessage
{
    // port: the Message data members. Not named `base` as elsewhere, because upstream's `base` field is below
    pub message_base: MessageBase,
    pub i: i32,          // serialize_int with an asymmetric range
    pub bits: u32,       // serialize_bits, odd width
    pub flag: bool,      // serialize_bool
    pub f: f32,          // serialize_float
    pub d: f64,          // serialize_double
    pub cf: f32,         // serialize_compressed_float, [0,1]
    pub base: i32,       // serialize_int
    pub rel: i32,        // serialize_int_relative against base
}

impl FuzzPrimitivesMessage
{
    // port: FuzzPrimitivesMessage() : i( 0 ), bits( 0 ), ... is #[derive(Default)]

    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_int!( stream, self.i, -100000, 100000 );
        serialize_bits!( stream, self.bits, 17 );
        serialize_bool!( stream, self.flag );
        serialize_float!( stream, self.f );
        serialize_double!( stream, self.d );
        serialize_compressed_float!( stream, self.cf, 0.0f32, 1.0f32, 0.01f32 );
        serialize_align!( stream );
        serialize_int!( stream, self.base, 0, 1000 );
        serialize_int_relative!( stream, self.base, self.rel );
        true
    }
}

impl Serializable for FuzzPrimitivesMessage
{
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!();
}

// port: YOJIMBO_MESSAGE!( FuzzPrimitivesMessage ) written out, for the message_base member
impl Message for FuzzPrimitivesMessage
{
    fn base( &self ) -> &MessageBase { &self.message_base }
    fn base_mut( &mut self ) -> &mut MessageBase { &mut self.message_base }
}

// Bounded string: exercises serialize_string's length read + bounds check.
pub struct FuzzStringMessage
{
    pub base: MessageBase,
    pub str: [u8; FuzzMaxString as usize],
}

impl Default for FuzzStringMessage
{
    // port: FuzzStringMessage() { str[0] = '\0'; } (the rest of the buffer is zeroed too: Rust has no uninitialized arrays)
    fn default() -> Self
    {
        FuzzStringMessage { base: MessageBase::default(), str: [0; FuzzMaxString as usize] }
    }
}

impl FuzzStringMessage
{
    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_string!( stream, self.str, FuzzMaxString );         // port: sizeof( str )
        true
    }
}

impl Serializable for FuzzStringMessage
{
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!();
}

YOJIMBO_MESSAGE!( FuzzStringMessage );

// Variable-length byte array: a count then that many bytes — the read path where a bad count
// would over-read if unchecked.
pub struct FuzzBytesMessage
{
    pub base: MessageBase,
    pub count: i32,
    pub data: [u8; FuzzMaxBytes as usize],
}

impl Default for FuzzBytesMessage
{
    // port: FuzzBytesMessage() : count( 0 ) { memset( data, 0, sizeof( data ) ); }
    fn default() -> Self
    {
        FuzzBytesMessage { base: MessageBase::default(), count: 0, data: [0; FuzzMaxBytes as usize] }
    }
}

impl FuzzBytesMessage
{
    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_int!( stream, self.count, 0, FuzzMaxBytes );
        serialize_bytes!( stream, self.data, self.count );
        true
    }
}

impl Serializable for FuzzBytesMessage
{
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!();
}

YOJIMBO_MESSAGE!( FuzzBytesMessage );

// Block message for the reliable-ordered block path.
#[derive(Default)]
pub struct FuzzBlockMessage
{
    pub base: BlockMessage,
    pub sequence: u16,
}

impl FuzzBlockMessage
{
    // port: FuzzBlockMessage() : sequence( 0 ) {} is #[derive(Default)]

    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_bits!( stream, self.sequence, 16 );
        true
    }
}

impl Serializable for FuzzBlockMessage
{
    YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!();
}

YOJIMBO_BLOCK_MESSAGE!( FuzzBlockMessage );

YOJIMBO_MESSAGE_FACTORY_START!( FuzzMessageFactory, FUZZ_NUM_MESSAGE_TYPES,
    YOJIMBO_DECLARE_MESSAGE_TYPE( FUZZ_MESSAGE_PRIMITIVES, FuzzPrimitivesMessage );
    YOJIMBO_DECLARE_MESSAGE_TYPE( FUZZ_MESSAGE_STRING, FuzzStringMessage );
    YOJIMBO_DECLARE_MESSAGE_TYPE( FUZZ_MESSAGE_BYTES, FuzzBytesMessage );
    YOJIMBO_DECLARE_MESSAGE_TYPE( FUZZ_MESSAGE_BLOCK, FuzzBlockMessage );
YOJIMBO_MESSAGE_FACTORY_FINISH() );
