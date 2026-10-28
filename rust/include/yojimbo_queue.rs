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
    A simple templated queue.
    This is a FIFO queue. First entry in, first entry out.
 */

// port: the entries are raw memory from the allocator, as upstream. A slot holds a value from Push until Pop, Clear or
// the destructor: Push writes it in place (ptr::write), Pop moves it out (ptr::read), and Clear and the destructor drop
// the values still queued. Upstream copies POD values in and out (T is Message* or int), which is the same thing.
pub struct Queue<T>
{
    m_allocator: *mut dyn Allocator,                    // The allocator passed in to the constructor.
    m_entries: *mut T,                                  // Array of entries backing the queue (circular buffer).
    m_arraySize: i32,                                   // The size of the array, in number of entries. This is the "size" of the queue.
    m_startIndex: i32,                                  // The start index for the queue. This is the next value that gets popped off.
    m_numEntries: i32,                                  // The number of entries currently stored in the queue.
}

impl<T> Queue<T>
{
    /**
        Queue constructor.
        @param allocator The allocator to use.
        @param size The maximum number of entries in the queue.
     */

    pub fn new( allocator: *mut dyn Allocator, size: i32 ) -> Queue<T>
    {
        yojimbo_assert!( size > 0 );
        yojimbo_assert!( std::mem::align_of::<T>() <= 16 );     // port: the allocator aligns to 16
        let m_entries = YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<T>() * size as usize ) as *mut T;
        // port: memset( m_entries, 0, ... ). The bytes are zeroed as upstream, but a slot only holds a T once pushed.
        if !m_entries.is_null()
        {
            unsafe { std::ptr::write_bytes( m_entries as *mut u8, 0, std::mem::size_of::<T>() * size as usize ); }
        }
        Queue
        {
            m_arraySize: size,
            m_startIndex: 0,
            m_numEntries: 0,
            m_allocator: allocator,
            m_entries,
        }
    }

    /**
        Clear all entries in the queue and reset back to default state.
     */

    pub fn Clear( &mut self )
    {
        // port: drop the queued values (a no-op for the Copy types upstream queues)
        self.drop_entries();
        self.m_numEntries = 0;
        self.m_startIndex = 0;
    }

    /**
        Pop a value off the queue.
        IMPORTANT: This will assert if the queue is empty. Check Queue::IsEmpty or Queue::GetNumEntries first!
        @returns The value popped off the queue.
     */

    pub fn Pop( &mut self ) -> T
    {
        yojimbo_assert!( !self.IsEmpty() );
        let entry: T = unsafe { std::ptr::read( self.m_entries.add( self.m_startIndex as usize ) ) };
        self.m_startIndex = ( self.m_startIndex + 1 ) % self.m_arraySize;
        self.m_numEntries -= 1;
        entry
    }

    /**
        Push a value on to the queue.
        @param value The value to push onto the queue.
        IMPORTANT: Will assert if the queue is already full. Check Queue::IsFull before calling this!
     */

    // port: takes the value by move, for const T &
    pub fn Push( &mut self, value: T )
    {
        yojimbo_assert!( !self.IsFull() );
        let index = ( self.m_startIndex + self.m_numEntries ) % self.m_arraySize;
        unsafe { std::ptr::write( self.m_entries.add( index as usize ), value ); }
        self.m_numEntries += 1;
    }

    // port: the two operator [] overloads are the Index and IndexMut impls below

    /**
        Get the size of the queue.
        This is the maximum number of values that can be pushed on the queue.
        @returns The size of the queue.
     */

    pub fn GetSize( &self ) -> i32
    {
        self.m_arraySize
    }

    /**
        Is the queue currently full?
        @returns True if the queue is full. False otherwise.
     */

    pub fn IsFull( &self ) -> bool
    {
        self.m_numEntries == self.m_arraySize
    }

    /**
        Is the queue currently empty?
        @returns True if there are no entries in the queue.
     */

    pub fn IsEmpty( &self ) -> bool
    {
        self.m_numEntries == 0
    }

    /**
        Get the number of entries in the queue.
        @returns The number of entries in the queue in [0,GetSize()].
     */

    pub fn GetNumEntries( &self ) -> i32
    {
        self.m_numEntries
    }

    // port: drops the values still in the queue (Clear and the destructor)
    fn drop_entries( &mut self )
    {
        if std::mem::needs_drop::<T>()
        {
            for i in 0..self.m_numEntries
            {
                unsafe { std::ptr::drop_in_place( self.m_entries.add( ( ( self.m_startIndex + i ) % self.m_arraySize ) as usize ) ); }
            }
        }
    }
}

impl<T> std::ops::Index<i32> for Queue<T>
{
    type Output = T;

    /**
        Random access for entries in the queue (const version).
        @param index The index into the queue. 0 is the oldest entry, Queue::GetNumEntries() - 1 is the newest.
        @returns The value in the queue at the index.
     */

    fn index( &self, index: i32 ) -> &T
    {
        yojimbo_assert!( !self.IsEmpty() );
        yojimbo_assert!( index >= 0 );
        yojimbo_assert!( index < self.m_numEntries );
        unsafe { &*self.m_entries.add( ( ( self.m_startIndex + index ) % self.m_arraySize ) as usize ) }
    }
}

impl<T> std::ops::IndexMut<i32> for Queue<T>
{
    /**
        Random access for entries in the queue.
        @param index The index into the queue. 0 is the oldest entry, Queue::GetNumEntries() - 1 is the newest.
        @returns The value in the queue at the index.
     */

    fn index_mut( &mut self, index: i32 ) -> &mut T
    {
        yojimbo_assert!( !self.IsEmpty() );
        yojimbo_assert!( index >= 0 );
        yojimbo_assert!( index < self.m_numEntries );
        unsafe { &mut *self.m_entries.add( ( ( self.m_startIndex + index ) % self.m_arraySize ) as usize ) }
    }
}

impl<T> Drop for Queue<T>
{
    /**
        Queue destructor.
     */

    fn drop( &mut self )
    {
        yojimbo_assert!( !self.m_allocator.is_null() );

        self.drop_entries();     // port: drop the values still queued

        YOJIMBO_FREE!( self.m_allocator, self.m_entries );

        self.m_arraySize = 0;
        self.m_startIndex = 0;
        self.m_numEntries = 0;

        self.m_allocator = null_allocator();
    }
}
