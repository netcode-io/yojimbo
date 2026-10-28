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
    Data structure that stores data indexed by sequence number.
    Entries may or may not exist. If they don't exist the sequence value for the entry at that index is set to 0xFFFFFFFF.
    This provides a constant time lookup for an entry by sequence number. If the entry at sequence modulo buffer size doesn't have the same sequence number, that sequence number is not stored.
    This is incredibly useful and is used as the foundation of the packet level ack system and the reliable message send and receive queues.
    @see Connection
 */

// port: the entries array comes from the allocator, as upstream, but every entry holds a valid T for the buffer's
// whole life: the constructor writes T::default() into each one (upstream leaves the raw memory uninitialised) and the
// destructor drops them. Insert, Find and GetAtIndex return a pointer to the entry (null when there is none), as
// upstream; the caller fills it in.
pub struct SequenceBuffer<T>
{
    m_allocator: *mut dyn Allocator,                    // The allocator passed in to the constructor.
    m_size: i32,                                        // The size of the sequence buffer.
    m_sequence: u16,                                    // The most recent sequence number added to the buffer.
    m_entry_sequence: *mut u32,                         // Array of sequence numbers corresponding to each sequence buffer entry for fast lookup. Set to 0xFFFFFFFF if no entry exists at that index.
    m_entries: *mut T,                                  // The sequence buffer entries. This is where the data is stored per-entry. Separate from the sequence numbers for fast lookup (hot/cold split) when the data per-sequence number is relatively large.
}

// port: the private copy constructor and assignment operator: SequenceBuffer is neither Clone nor Copy

impl<T: Default> SequenceBuffer<T>
{
    /**
        Sequence buffer constructor.
        @param allocator The allocator to use.
        @param size The size of the sequence buffer.
     */

    pub fn new( allocator: *mut dyn Allocator, size: i32 ) -> SequenceBuffer<T>
    {
        yojimbo_assert!( size > 0 );
        yojimbo_assert!( std::mem::align_of::<T>() <= 16 );     // port: the allocator aligns to 16
        let mut this = SequenceBuffer
        {
            m_size: size,
            m_sequence: 0,
            m_allocator: allocator,
            m_entry_sequence: YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<u32>() * size as usize ) as *mut u32,
            m_entries: YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<T>() * size as usize ) as *mut T,
        };
        // port: construct the entries (see above)
        if !this.m_entries.is_null()
        {
            for i in 0..size as usize
            {
                unsafe { std::ptr::write( this.m_entries.add( i ), T::default() ); }
            }
        }
        this.Reset();
        this
    }

    /**
        Reset the sequence buffer.
        Removes all entries from the sequence buffer and restores it to initial state.
     */

    pub fn Reset( &mut self )
    {
        self.m_sequence = 0;
        unsafe { std::ptr::write_bytes( self.m_entry_sequence as *mut u8, 0xFF, std::mem::size_of::<u32>() * self.m_size as usize ); }
    }

    /**
        Insert an entry in the sequence buffer.
        IMPORTANT: If another entry exists at the sequence modulo buffer size, it is overwritten.
        @param sequence The sequence number.
        @param guaranteed_order Whether sequence is always the newest value (when sending) or can be out of order (when receiving).
        @returns The sequence buffer entry, which you must fill with your data. NULL if a sequence buffer entry could not be added for your sequence number (if the sequence number is too old for example).
     */

    // port: guaranteed_order has no default (upstream: = false); pass false
    pub fn Insert( &mut self, sequence: u16, guaranteed_order: bool ) -> *mut T
    {
        if yojimbo_sequence_greater_than( sequence.wrapping_add( 1 ), self.m_sequence ) || guaranteed_order
        {
            self.RemoveEntries( self.m_sequence as i32, sequence as i32 );
            self.m_sequence = sequence.wrapping_add( 1 );
        }
        else if yojimbo_sequence_less_than( sequence, ( self.m_sequence as i32 - self.m_size ) as u16 )
        {
            return std::ptr::null_mut();
        }
        let index = sequence as i32 % self.m_size;
        unsafe
        {
            *self.m_entry_sequence.add( index as usize ) = sequence as u32;
            self.m_entries.add( index as usize )
        }
    }

    /**
        Remove an entry from the sequence buffer.
        @param sequence The sequence number of the entry to remove.
     */

    pub fn Remove( &mut self, sequence: u16 )
    {
        unsafe { *self.m_entry_sequence.add( ( sequence as i32 % self.m_size ) as usize ) = 0xFFFFFFFF; }
    }

    /**
        Is the entry corresponding to the sequence number available? eg. Currently unoccupied.
        This works because older entries are automatically set back to unoccupied state as the sequence buffer advances forward.
        @param sequence The sequence number.
        @returns True if the sequence buffer entry is available, false if it is already occupied.
     */

    pub fn Available( &self, sequence: u16 ) -> bool
    {
        unsafe { *self.m_entry_sequence.add( ( sequence as i32 % self.m_size ) as usize ) == 0xFFFFFFFF }
    }

    /**
        Does an entry exist for a sequence number?
        @param sequence The sequence number.
        @returns True if an entry exists for this sequence number.
     */

    pub fn Exists( &self, sequence: u16 ) -> bool
    {
        unsafe { *self.m_entry_sequence.add( ( sequence as i32 % self.m_size ) as usize ) == sequence as u32 }
    }

    /**
        Get the entry corresponding to a sequence number.
        @param sequence The sequence number.
        @returns The entry if it exists. NULL if no entry is in the buffer for this sequence number.
     */

    // port: one method stands for the const and non-const overloads
    pub fn Find( &self, sequence: u16 ) -> *mut T
    {
        let index = sequence as i32 % self.m_size;
        unsafe
        {
            if *self.m_entry_sequence.add( index as usize ) == sequence as u32
                { self.m_entries.add( index as usize ) }
            else
                { std::ptr::null_mut() }
        }
    }

    /**
        Get the entry at the specified index.
        Use this to iterate across entries in the sequence buffer.
        @param index The entry index in [0,GetSize()-1].
        @returns The entry if it exists. NULL if no entry is in the buffer at the specified index.
     */

    // port: one method stands for the const and non-const overloads
    pub fn GetAtIndex( &self, index: i32 ) -> *mut T
    {
        yojimbo_assert!( index >= 0 );
        yojimbo_assert!( index < self.m_size );
        unsafe
        {
            if *self.m_entry_sequence.add( index as usize ) != 0xFFFFFFFF { self.m_entries.add( index as usize ) } else { std::ptr::null_mut() }
        }
    }

    /**
        Get the most recent sequence number added to the buffer.
        This sequence number can wrap around, so if you are at 65535 and add an entry for sequence 0, then 0 becomes the new "most recent" sequence number.
        @returns The most recent sequence number.
        @see yojimbo::sequence_greater_than
        @see yojimbo::sequence_less_than
     */

    pub fn GetSequence( &self ) -> u16
    {
        self.m_sequence
    }

    /**
        Get the entry index for a sequence number.
        This is simply the sequence number modulo the sequence buffer size.
        @param sequence The sequence number.
        @returns The sequence buffer index corresponding of the sequence number.
     */

    pub fn GetIndex( &self, sequence: u16 ) -> i32
    {
        sequence as i32 % self.m_size
    }

    /**
        Get the size of the sequence buffer.
        @returns The size of the sequence buffer (number of entries).
     */

    pub fn GetSize( &self ) -> i32
    {
        self.m_size
    }

    /**
        Helper function to remove entries.
        This is used to remove old entries as we advance the sequence buffer forward.
        Otherwise, if when entries are added with holes (eg. receive buffer for packets or messages, where not all sequence numbers are added to the buffer because we have high packet loss),
        and we are extremely unlucky, we can have old sequence buffer entries from the previous sequence # wrap around still in the buffer, which corrupts our internal connection state.
        This actually happened in the soak test at high packet loss levels (>90%). It took me days to track it down :)
     */

    // port: protected upstream
    fn RemoveEntries( &mut self, start_sequence: i32, finish_sequence: i32 )
    {
        let mut finish_sequence = finish_sequence;
        if finish_sequence < start_sequence
            { finish_sequence += 65535; }
        yojimbo_assert!( finish_sequence >= start_sequence );
        if finish_sequence - start_sequence < self.m_size
        {
            for sequence in start_sequence..=finish_sequence
                { unsafe { *self.m_entry_sequence.add( ( sequence % self.m_size ) as usize ) = 0xFFFFFFFF; } }
        }
        else
        {
            for i in 0..self.m_size
                { unsafe { *self.m_entry_sequence.add( i as usize ) = 0xFFFFFFFF; } }
        }
    }
}

impl<T> Drop for SequenceBuffer<T>
{
    /**
        Sequence buffer destructor.
     */

    fn drop( &mut self )
    {
        yojimbo_assert!( !self.m_allocator.is_null() );
        // port: drop the entries the constructor built
        if !self.m_entries.is_null()
        {
            for i in 0..self.m_size as usize
                { unsafe { std::ptr::drop_in_place( self.m_entries.add( i ) ); } }
        }
        YOJIMBO_FREE!( self.m_allocator, self.m_entries );
        YOJIMBO_FREE!( self.m_allocator, self.m_entry_sequence );
        self.m_allocator = null_allocator();
    }
}
