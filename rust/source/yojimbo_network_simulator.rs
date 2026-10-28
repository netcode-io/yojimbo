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

// port: include/yojimbo_network_simulator.h + source/yojimbo_network_simulator.cpp

use crate::*;
use std::ptr;

/// A packet buffered in the network simulator.
// port: the C++ private nested struct NetworkSimulator::PacketEntry. All-zero bytes are a valid empty entry (the
// constructor memsets the array), so PacketEntry() is PacketEntry::new() and resetting an entry is `*entry = PacketEntry::new()`.
#[derive(Clone, Copy)]
struct PacketEntry
{
    to: i32,                                    // To index this packet should be sent to (for server -> client packets).
    deliveryTime: f64,                          // Delivery time for this packet (seconds).
    packetData: *mut u8,                        // Packet data (owns this pointer).
    packetBytes: i32,                           // Size of packet in bytes.
}

impl PacketEntry
{
    fn new() -> PacketEntry
    {
        PacketEntry { to: 0, deliveryTime: 0.0, packetData: ptr::null_mut(), packetBytes: 0 }
    }
}

/**
    Simulates packet loss, latency, jitter and duplicate packets.
    This is useful during development, so your game is tested and played under real world conditions, instead of ideal LAN conditions.
    This simulator works on packet send. This means that if you want 125ms of latency (round trip), you must to add 125/2 = 62.5ms of latency to each side.
 */

pub struct NetworkSimulator
{
    m_allocator: *mut dyn Allocator,            // The allocator passed in to the constructor. It's used to allocate and free packet data.
    m_latency: f32,                             // Latency in milliseconds
    m_jitter: f32,                              // Jitter in milliseconds +/-
    m_packetLoss: f32,                          // Packet loss percentage.
    m_duplicates: f32,                          // Duplicate packet percentage
    m_active: bool,                             // True if network simulator is active, eg. if any of the network settings above are enabled.

    m_time: f64,                                // Current time from last call to advance time.
    m_currentIndex: i32,                        // Current index in the packet entry array. New packets are inserted here.
    m_numPacketEntries: i32,                    // Number of elements in the packet entry array.
    m_packetEntries: *mut PacketEntry,          // Pointer to dynamically allocated packet entries. This is where buffered packets are stored.
}

impl NetworkSimulator
{
    /**
        Create a network simulator.
        Initial network conditions are set to:
            Latency: 0ms
            Jitter: 0ms
            Packet Loss: 0%
            Duplicates: 0%
        @param allocator The allocator to use.
        @param numPackets The maximum number of packets that can be stored in the simulator at any time.
        @param time The initial time value in seconds.
     */

    // port: the constructor. Upstream callers that do YOJIMBO_NEW( allocator, NetworkSimulator, ... ) write
    // YOJIMBO_NEW!( allocator, NetworkSimulator, NetworkSimulator::new( ... ) ); the destructor is Drop.
    pub fn new( allocator: *mut dyn Allocator, numPackets: i32, time: f64 ) -> NetworkSimulator
    {
        yojimbo_assert!( numPackets > 0 );
        let mut simulator = NetworkSimulator
        {
            m_allocator: allocator,
            m_latency: 0.0,
            m_jitter: 0.0,
            m_packetLoss: 0.0,
            m_duplicates: 0.0,
            m_active: false,
            m_time: 0.0,
            m_currentIndex: 0,
            m_numPacketEntries: 0,
            m_packetEntries: ptr::null_mut(),
        };
        simulator.m_allocator = allocator;
        simulator.m_currentIndex = 0;
        simulator.m_time = time;
        simulator.m_latency = 0.0;
        simulator.m_jitter = 0.0;
        simulator.m_packetLoss = 0.0;
        simulator.m_duplicates = 0.0;
        simulator.m_active = false;
        simulator.m_numPacketEntries = numPackets;
        simulator.m_packetEntries = YOJIMBO_ALLOCATE!( allocator, std::mem::size_of::<PacketEntry>() * numPackets as usize ) as *mut PacketEntry;
        yojimbo_assert!( !simulator.m_packetEntries.is_null() );
        // port: memset( m_packetEntries, 0, ... ) -- zero bytes are PacketEntry::new() (null pointer, zero numbers)
        if !simulator.m_packetEntries.is_null()
        {
            unsafe { ptr::write_bytes( simulator.m_packetEntries, 0, numPackets as usize ); }
        }
        simulator
    }
}

/**
    Network simulator destructor.
    Any packet data still in the network simulator is destroyed.
 */

impl Drop for NetworkSimulator
{
    fn drop( &mut self )
    {
        yojimbo_assert!( !self.m_allocator.is_null() );
        yojimbo_assert!( !self.m_packetEntries.is_null() );
        yojimbo_assert!( self.m_numPacketEntries > 0 );
        self.DiscardPackets();
        YOJIMBO_FREE!( self.m_allocator, self.m_packetEntries );
        self.m_numPacketEntries = 0;
        self.m_allocator = null_allocator();
    }
}

impl NetworkSimulator
{
    // port: the ring entry at `index`. The reference is not tied to &self (as C++'s PacketEntry &), so the allocator
    // can be used while it is held; the entries outlive every call.
    fn entry<'a>( &self, index: i32 ) -> &'a mut PacketEntry
    {
        yojimbo_assert!( index >= 0 && index < self.m_numPacketEntries );
        unsafe { &mut *self.m_packetEntries.add( index as usize ) }
    }

    /**
        Set the latency in milliseconds.
        This latency is added on packet send. To simulate a round trip time of 100ms, add 50ms of latency to both sides of the connection.
        @param milliseconds The latency to add in milliseconds.
     */

    pub fn SetLatency( &mut self, milliseconds: f32 )
    {
        self.m_latency = milliseconds;
        self.UpdateActive();
    }

    /**
        Set the packet jitter in milliseconds.
        Jitter is applied +/- this amount in milliseconds. To be truly effective, jitter must be applied together with some latency.
        @param milliseconds The amount of jitter to add in milliseconds (+/-).
     */

    pub fn SetJitter( &mut self, milliseconds: f32 )
    {
        self.m_jitter = milliseconds;
        self.UpdateActive();
    }

    /**
        Set the amount of packet loss to apply on send.
        @param percent The packet loss percentage. 0% = no packet loss. 100% = all packets are dropped.
     */

    pub fn SetPacketLoss( &mut self, percent: f32 )
    {
        self.m_packetLoss = percent;
        self.UpdateActive();
    }

    /**
        Set percentage chance of packet duplicates.
        If the duplicate chance succeeds, a duplicate packet is added to the queue with a random delay of up to 1 second.
        @param percent The percentage chance of a packet duplicate being sent. 0% = no duplicate packets. 100% = all packets have a duplicate sent.
     */

    pub fn SetDuplicates( &mut self, percent: f32 )
    {
        self.m_duplicates = percent;
        self.UpdateActive();
    }

    /**
        Is the network simulator active?
        The network simulator is active when packet loss, latency, duplicates or jitter are non-zero values.
        This is used by the transport to know whether it should shunt packets through the simulator, or send them directly to the network. This is a minor optimization.
     */

    pub fn IsActive( &self ) -> bool
    {
        self.m_active
    }

    /**
        Helper function to update the active flag whenever network settings are changed.
        Active is set to true if any of the network conditions are non-zero. This allows you to quickly check if the network simulator is active and would actually do something.
     */

    // port: C++ protected; private here
    fn UpdateActive( &mut self )
    {
        let previous = self.m_active;
        self.m_active = self.m_latency != 0.0 || self.m_jitter != 0.0 || self.m_packetLoss != 0.0 || self.m_duplicates != 0.0;
        if previous && !self.m_active
        {
            self.DiscardPackets();
        }
    }

    /**
        Queue a packet to send.
        IMPORTANT: Ownership of the packet data pointer is *not* transferred to the network simulator. It makes a copy of the data instead.
        @param to The slot index the packet should be sent to.
        @param packetData The packet data.
        @param packetBytes The packet size (bytes).
     */

    pub fn SendPacket( &mut self, to: i32, packetData: &[u8], packetBytes: i32 )
    {
        yojimbo_assert!( !self.m_allocator.is_null() );
        // port: yojimbo_assert( packetData ) -- a slice is never null
        yojimbo_assert!( packetBytes > 0 );

        if yojimbo_random_float( 0.0, 100.0 ) <= self.m_packetLoss
        {
            return;
        }

        let packetEntry: &mut PacketEntry = self.entry( self.m_currentIndex );

        if !packetEntry.packetData.is_null()
        {
            YOJIMBO_FREE!( self.m_allocator, packetEntry.packetData );
            *packetEntry = PacketEntry::new();
        }

        let mut delay: f64 = self.m_latency as f64 / 1000.0;

        if self.m_jitter > 0.0
        {
            delay += yojimbo_random_float( -self.m_jitter, self.m_jitter ) as f64 / 1000.0;
        }

        packetEntry.to = to;
        packetEntry.packetData = YOJIMBO_ALLOCATE!( self.m_allocator, packetBytes as usize );
        if packetEntry.packetData.is_null()
        {
            // The simulator is lossy by design, so on OOM just drop this packet (leaving an
            // empty slot, which ReceivePackets skips) rather than dereferencing NULL.
            *packetEntry = PacketEntry::new();
            return;
        }
        unsafe { ptr::copy_nonoverlapping( packetData.as_ptr(), packetEntry.packetData, packetBytes as usize ); }
        packetEntry.packetBytes = packetBytes;
        packetEntry.deliveryTime = self.m_time + delay;
        self.m_currentIndex = ( self.m_currentIndex + 1 ) % self.m_numPacketEntries;

        if yojimbo_random_float( 0.0, 100.0 ) <= self.m_duplicates
        {
            let nextPacketEntry: &mut PacketEntry = self.entry( self.m_currentIndex );
            if !nextPacketEntry.packetData.is_null()
            {
                YOJIMBO_FREE!( self.m_allocator, nextPacketEntry.packetData );
                *nextPacketEntry = PacketEntry::new();
            }
            nextPacketEntry.to = to;
            nextPacketEntry.packetData = YOJIMBO_ALLOCATE!( self.m_allocator, packetBytes as usize );
            if !nextPacketEntry.packetData.is_null()
            {
                unsafe { ptr::copy_nonoverlapping( packetData.as_ptr(), nextPacketEntry.packetData, packetBytes as usize ); }
                nextPacketEntry.packetBytes = packetBytes;
                nextPacketEntry.deliveryTime = self.m_time + delay + yojimbo_random_float( 0.0, 1.0 ) as f64;
                self.m_currentIndex = ( self.m_currentIndex + 1 ) % self.m_numPacketEntries;
            }
            else
            {
                // OOM on the duplicate copy: just skip the duplicate (leave an empty slot).
                *nextPacketEntry = PacketEntry::new();
            }
        }
    }

    /**
        Receive packets sent to any address.
        IMPORTANT: You take ownership of the packet data you receive and are responsible for freeing it. See NetworkSimulator::GetAllocator.
        @param maxPackets The maximum number of packets to receive.
        @param packetData Array of packet data pointers to be filled [out].
        @param packetBytes Array of packet sizes to be filled [out].
        @param to Array of to indices to be filled [out].
        @returns The number of packets received.
     */

    // port: the out arrays are slices (at least maxPackets long); `to` may be NULL upstream, so it is an Option.
    // Each returned packetData[i] is allocated from GetAllocator(); free it with YOJIMBO_FREE!( sim.GetAllocator(), p ).
    pub fn ReceivePackets( &mut self, maxPackets: i32, packetData: &mut [*mut u8], packetBytes: &mut [i32], mut to: Option<&mut [i32]> ) -> i32
    {
        if !self.IsActive()
        {
            return 0;
        }

        let mut numPackets: i32 = 0;

        // Scan the whole ring, but never return more than maxPackets. Packets are stored at
        // m_currentIndex across the entire buffer, so bounding the scan by maxPackets (rather
        // than the output count) would strand any packet held in a slot past that index.
        for i in 0..self.m_numPacketEntries
        {
            if numPackets >= maxPackets
            {
                break;
            }

            let packetEntry: &mut PacketEntry = self.entry( i );

            if packetEntry.packetData.is_null()
            {
                continue;
            }

            if packetEntry.deliveryTime < self.m_time
            {
                packetData[numPackets as usize] = packetEntry.packetData;
                packetBytes[numPackets as usize] = packetEntry.packetBytes;
                if let Some( to ) = to.as_mut()
                {
                    to[numPackets as usize] = packetEntry.to;
                }
                packetEntry.packetData = ptr::null_mut();
                numPackets += 1;
            }
        }

        numPackets
    }

    /**
        Discard all packets in the network simulator.
        This is useful if the simulator needs to be reset and used for another purpose.
     */

    pub fn DiscardPackets( &mut self )
    {
        for i in 0..self.m_numPacketEntries
        {
            let packetEntry: &mut PacketEntry = self.entry( i );
            if packetEntry.packetData.is_null()
            {
                continue;
            }
            YOJIMBO_FREE!( self.m_allocator, packetEntry.packetData );
            *packetEntry = PacketEntry::new();
        }
    }

    /**
        Discard packets sent to a particular client index.
        This is called when a client disconnects from the server.
     */

    pub fn DiscardClientPackets( &mut self, clientIndex: i32 )
    {
        for i in 0..self.m_numPacketEntries
        {
            let packetEntry: &mut PacketEntry = self.entry( i );
            if packetEntry.packetData.is_null() || packetEntry.to != clientIndex
            {
                continue;
            }
            YOJIMBO_FREE!( self.m_allocator, packetEntry.packetData );
            *packetEntry = PacketEntry::new();
        }
    }

    /**
        Advance network simulator time.
        You must pump this regularly otherwise the network simulator won't work.
        @param time The current time value. Please make sure you use double values for time so you retain sufficient precision as time increases.
     */

    pub fn AdvanceTime( &mut self, time: f64 )
    {
        self.m_time = time;
    }

    /**
        Get the allocator to use to free packet data.
        @returns The allocator that packet data is allocated with.
     */

    // port: inline in the header upstream
    pub fn GetAllocator( &self ) -> *mut dyn Allocator
    {
        yojimbo_assert!( !self.m_allocator.is_null() );
        self.m_allocator
    }
}
