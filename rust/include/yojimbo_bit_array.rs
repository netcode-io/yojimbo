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

/**
    A simple bit array class.
    You can create a bit array with a number of bits, set, clear and test if each bit is set.
 */

pub struct BitArray
{
    m_allocator: *mut dyn Allocator,                    // Allocator passed in to the constructor.
    m_size: i32,                                        // The size of the bit array in bits.
    m_bytes: i32,                                       // The size of the bit array in bytes.
    m_data: *mut u64,                                   // The data backing the bit array is an array of 64 bit integer values.
}

// port: the private copy constructor and assignment operator: BitArray is neither Clone nor Copy

impl BitArray
{
    /**
        The bit array constructor.
        @param allocator The allocator to use.
        @param size The number of bits in the bit array.
        All bits are initially set to zero.
     */

    pub fn new( allocator: *mut dyn Allocator, size: i32 ) -> BitArray
    {
        yojimbo_assert!( size > 0 );
        let m_bytes = 8 * ( ( size / 64 ) + ( if ( size % 64 ) != 0 { 1 } else { 0 } ) );
        yojimbo_assert!( m_bytes > 0 );
        let mut this = BitArray
        {
            m_allocator: allocator,
            m_size: size,
            m_bytes,
            m_data: YOJIMBO_ALLOCATE!( allocator, m_bytes as usize ) as *mut u64,
        };
        this.Clear();
        this
    }

    /**
        Clear all bit values to zero.
     */

    pub fn Clear( &mut self )
    {
        yojimbo_assert!( !self.m_data.is_null() );
        unsafe { std::ptr::write_bytes( self.m_data as *mut u8, 0, self.m_bytes as usize ); }
    }

    /**
        Set a bit to 1.
        @param index The index of the bit.
     */

    pub fn SetBit( &mut self, index: i32 )
    {
        yojimbo_assert!( index >= 0 );
        yojimbo_assert!( index < self.m_size );
        let data_index = index >> 6;
        let bit_index = index & ( (1<<6) - 1 );
        yojimbo_assert!( bit_index >= 0 );
        yojimbo_assert!( bit_index < 64 );
        unsafe { *self.m_data.add( data_index as usize ) |= 1u64 << bit_index; }
    }

    /**
        Clear a bit to 0.
        @param index The index of the bit.
     */

    pub fn ClearBit( &mut self, index: i32 )
    {
        yojimbo_assert!( index >= 0 );
        yojimbo_assert!( index < self.m_size );
        let data_index = index >> 6;
        let bit_index = index & ( (1<<6) - 1 );
        unsafe { *self.m_data.add( data_index as usize ) &= !( 1u64 << bit_index ); }
    }

    /**
        Get the value of the bit.
        Returns 1 if the bit is set, 0 if the bit is not set.
        @param index The index of the bit.
     */

    pub fn GetBit( &self, index: i32 ) -> u64
    {
        yojimbo_assert!( index >= 0 );
        yojimbo_assert!( index < self.m_size );
        let data_index = index >> 6;
        let bit_index = index & ( (1<<6) - 1 );
        yojimbo_assert!( bit_index >= 0 );
        yojimbo_assert!( bit_index < 64 );
        unsafe { ( *self.m_data.add( data_index as usize ) >> bit_index ) & 1 }
    }

    /**
        Gets the size of the bit array, in number of bits.
        @returns The number of bits.
     */

    pub fn GetSize( &self ) -> i32
    {
        self.m_size
    }
}

impl Drop for BitArray
{
    /**
        The bit array destructor.
     */

    fn drop( &mut self )
    {
        yojimbo_assert!( !self.m_data.is_null() );
        yojimbo_assert!( !self.m_allocator.is_null() );
        YOJIMBO_FREE!( self.m_allocator, self.m_data );
        self.m_allocator = null_allocator();
    }
}
