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

pub fn serialize_sequence_relative_internal<S: Stream>( stream: &mut S, sequence1: u16, sequence2: &mut u16 ) -> bool
{
    if S::IsWriting
    {
        let mut a: u32 = sequence1 as u32;
        let mut b: u32 = *sequence2 as u32 + ( if sequence1 > *sequence2 { 65536 } else { 0 } );
        serialize_int_relative!( stream, a, b );
    }
    else
    {
        let mut a: u32 = sequence1 as u32;
        let mut b: u32 = 0;
        serialize_int_relative!( stream, a, b );
        if b >= 65536
        {
            b -= 65536;
        }
        *sequence2 = b as u16;
    }

    true
}

/**
    Serialize a sequence number relative to another (read/write/measure).
    This is a helper macro to make writing unified serialize functions easier.
    Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
    IMPORTANT: This macro must be called inside a templated serialize function with template \<typename Stream\>. The serialize method must have a bool return value.
    @param stream The stream object. May be a read, write or measure stream.
    @param sequence1 The first sequence number to serialize relative to.
    @param sequence2 The second sequence number to be encoded relative to the first.
 */

// port: sequence1 is any integer expression and sequence2 any integer place (converted with `as`, like the serialize
// macros); upstream takes a uint16_t and a uint16_t &
#[macro_export]
macro_rules! serialize_sequence_relative {
    ( $stream:expr, $sequence1:expr, $sequence2:expr ) => {
        {
            let sequence1: u16 = ( $sequence1 ) as u16;
            let mut sequence2: u16 = ( $sequence2 ) as u16;
            if !$crate::serialize_sequence_relative_internal( $stream, sequence1, &mut sequence2 )
            {
                return false;
            }
            $sequence2 = sequence2 as _;
        }
    };
}

/**
    Interface for an object that knows how to read, write and measure how many bits it would take up in a bit stream.
    IMPORTANT: Instead of overriding the serialize virtual methods method directly, use the YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS macro in your derived class to override and redirect them to your templated serialize method.
    This way you can implement read and write for your messages in a single method and the C++ compiler takes care of generating specialized read, write and measure implementations for you.
    See shared.h for some examples of this.
    @see ReadStream
    @see WriteStream
    @see MeasureStream
 */

// port: the three SerializeInternal overloads get the suffix of the stream they take (README, "Names"); the virtual
// destructor is the trait object's drop
pub trait Serializable
{
    /**
        Virtual serialize function (read).
        Reads the object in from a bitstream.
        @param stream The stream to read from.
     */

    fn SerializeInternalRead( &mut self, stream: &mut ReadStream ) -> bool;

    /**
        Virtual serialize function (write).
        Writes the object to a bitstream.
        @param stream The stream to write to.
     */

    fn SerializeInternalWrite( &mut self, stream: &mut WriteStream ) -> bool;

    /**
        Virtual serialize function (measure).
        Quickly measures how many bits the object would take if it were written to a bit stream.
        @param stream The read stream.
     */

    fn SerializeInternalMeasure( &mut self, stream: &mut MeasureStream ) -> bool;
}

/**
    Helper macro to define virtual serialize functions for read, write and measure that call into the templated serialize function.
    This helps avoid writing boilerplate code, which is nice when you have lots of hand coded message types.
    See shared.h for examples of usage.
 */

// port: used inside `impl Serializable for X { YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!(); }`, where X has
// `fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool`
#[macro_export]
macro_rules! YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS {
    () => {
        fn SerializeInternalRead( &mut self, stream: &mut $crate::serialize::ReadStream ) -> bool { return self.Serialize( stream ); }
        fn SerializeInternalWrite( &mut self, stream: &mut $crate::serialize::WriteStream ) -> bool { return self.Serialize( stream ); }
        fn SerializeInternalMeasure( &mut self, stream: &mut $crate::serialize::MeasureStream ) -> bool { return self.Serialize( stream ); }
    };
}
