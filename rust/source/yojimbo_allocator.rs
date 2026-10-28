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

use std::ffi::c_void;

/*
    Rust port of include/yojimbo_allocator.h + source/yojimbo_allocator.cpp (yojimbo 1.13.5).

    Port notes:
      - Allocator is a trait holding the virtual methods (Allocate, Free); its data members (m_errorLevel, m_debug) are
        in AllocatorBase, which every allocator embeds and returns from base() / base_mut(). The non-virtual and
        protected members (GetErrorLevel, ClearError, SetErrorLevel, TrackAlloc, TrackFree) are provided methods.
        ~Allocator (the leak check) is AllocatorBase's Drop, so it runs after the derived allocator's Drop, as in C++.
      - A reference or pointer to an allocator is `*mut dyn Allocator`; null_allocator() is the null one.
      - YOJIMBO_NEW! / YOJIMBO_DELETE! / YOJIMBO_ALLOCATE! / YOJIMBO_FREE! take `*mut dyn Allocator` (a `*mut T` or
        `&mut T` of a concrete allocator coerces) and pass file!() / line!() as the C++ macros pass __FILE__ / __LINE__.
      - Allocations are aligned to 16 bytes: DefaultAllocator over std::alloc (the size lives in a 16 byte header so
        Free can rebuild the layout), TLSF_Allocator by tlsf_memalign( m_tlsf, 16, size ) as upstream. YOJIMBO_NEW!
        refuses (at compile time) a type with an alignment above 16.
      - GetDefaultAllocator() is declared here upstream and defined in yojimbo.cpp; the port does the same (it is
        re-exported from here so both paths work).
*/

use crate::*;
use crate::tlsf::*;
use std::collections::BTreeMap;

pub use crate::yojimbo::GetDefaultAllocator;

/**
    Helper behind YOJIMBO_NEW. Allocates storage for a T and placement-constructs it, but
    only if the allocation succeeded — on failure it returns NULL instead of running the
    constructor on a NULL pointer (undefined behavior, and a crash the moment the constructor
    touches a member). Callers already NULL-check the result (e.g. MessageFactory::CreateMessage).
 */

// port: yojimbo_new<T>( allocator, file, line, args... ) is inlined into YOJIMBO_NEW!, so the value expression is
// only evaluated (the constructor only runs) once the allocation has succeeded, as upstream.

/// The alignment every yojimbo allocator guarantees (port: upstream relies on malloc's and tlsf_memalign's).
pub const YOJIMBO_ALLOCATOR_ALIGNMENT: usize = 16;

/// Macro for creating a new object instance with a yojimbo allocator.
/// `YOJIMBO_NEW!( allocator, T, value )`: allocates size_of::<T>() bytes, moves `value` in, returns `*mut T` (null on failure).
#[macro_export]
macro_rules! YOJIMBO_NEW {
    ( $allocator:expr, $T:ty, $value:expr ) => {{
        const { ::core::assert!( ::core::mem::align_of::<$T>() <= $crate::yojimbo_allocator::YOJIMBO_ALLOCATOR_ALIGNMENT, "YOJIMBO_NEW: type alignment above 16" ) };
        let __yojimbo_allocator: *mut dyn $crate::yojimbo_allocator::Allocator = $allocator;
        // port: at least one byte, as a C++ object is never zero-sized
        let __yojimbo_size = if ::core::mem::size_of::<$T>() > 0 { ::core::mem::size_of::<$T>() } else { 1 };
        let __yojimbo_memory = unsafe { (*__yojimbo_allocator).Allocate( __yojimbo_size, ::core::file!(), ::core::line!() ) } as *mut $T;
        if !__yojimbo_memory.is_null()
        {
            let __yojimbo_value: $T = $value;
            unsafe { ::core::ptr::write( __yojimbo_memory, __yojimbo_value ); }
        }
        __yojimbo_memory
    }};
}

/// Macro for deleting an object created with a yojimbo allocator.
/// `YOJIMBO_DELETE!( allocator, T, p )`: `p` is a place holding a `*mut T` or a `*mut dyn Trait`; drops the object in
/// place, frees it and sets `p` to null. T is the static type, as upstream (unused: drop goes through the pointer's type).
#[macro_export]
macro_rules! YOJIMBO_DELETE {
    ( $allocator:expr, $T:ty, $p:expr ) => {{
        if !( $p ).is_null()
        {
            let __yojimbo_allocator: *mut dyn $crate::yojimbo_allocator::Allocator = $allocator;
            unsafe
            {
                ::core::ptr::drop_in_place( $p );
                (*__yojimbo_allocator).Free( ( $p ) as *mut u8, ::core::file!(), ::core::line!() );
            }
            // port: null with the same pointer metadata, so this works for `*mut dyn Trait` as well as `*mut T`
            $p = ( $p ).wrapping_byte_sub( ( $p ) as *mut u8 as usize );
        }
    }};
}

/// Macro for allocating a block of memory with a yojimbo allocator. Returns `*mut u8`, null on failure.
#[macro_export]
macro_rules! YOJIMBO_ALLOCATE {
    ( $allocator:expr, $bytes:expr ) => {{
        let __yojimbo_allocator: *mut dyn $crate::yojimbo_allocator::Allocator = $allocator;
        unsafe { (*__yojimbo_allocator).Allocate( ( $bytes ) as usize, ::core::file!(), ::core::line!() ) }
    }};
}

/// Macro for freeing a block of memory created with a yojimbo allocator. Sets `p` to null.
#[macro_export]
macro_rules! YOJIMBO_FREE {
    ( $allocator:expr, $p:expr ) => {{
        if !( $p ).is_null()
        {
            let __yojimbo_allocator: *mut dyn $crate::yojimbo_allocator::Allocator = $allocator;
            unsafe { (*__yojimbo_allocator).Free( ( $p ) as *mut u8, ::core::file!(), ::core::line!() ); }
            $p = ( $p ).wrapping_byte_sub( ( $p ) as *mut u8 as usize );
        }
    }};
}

/// Allocator error level.
pub type AllocatorErrorLevel = i32;
pub const ALLOCATOR_ERROR_NONE: i32 = 0;                                //< No error. All is well.
pub const ALLOCATOR_ERROR_OUT_OF_MEMORY: i32 = 1;                       //< The allocator is out of memory!

/// Helper function to convert an allocator error to a user friendly string.
pub fn GetAllocatorErrorString( error: AllocatorErrorLevel ) -> &'static str
{
    match error
    {
        ALLOCATOR_ERROR_NONE => "none",
        ALLOCATOR_ERROR_OUT_OF_MEMORY => "out of memory",
        _ =>
        {
            yojimbo_assert!( false );
            "(unknown)"
        }
    }
}

/**
    Opaque debug-only leak tracking state for an Allocator.
    Defined and used entirely inside libyojimbo (yojimbo_allocator.cpp): the pointer to it is
    present in every build, so Allocator has one layout whatever NDEBUG a consumer compiles
    with, and it is only ever allocated when the library itself was built with
    YOJIMBO_DEBUG_MEMORY_LEAKS.
 */

// The leak tracker lives here, behind Allocator::m_debug, instead of in the public header.
// Allocator is a base class consumers derive from, so a member whose presence depends on
// NDEBUG gave the class two layouts: one for a debug build of the library and another for a
// release consumer that included the same header. One pointer, always present, one layout.
pub struct AllocatorDebugState
{
    alloc_map: BTreeMap<usize, AllocatorDebugStateEntry>,       // port: std::map<void*,Entry>, keyed by address
}

// port: AllocatorDebugState::Entry
#[derive(Clone, Copy)]
struct AllocatorDebugStateEntry
{
    size: usize,
    file: &'static str,
    line: u32,
}

/**
    Functionality common to all allocators.
    Extend this class to hook up your own allocator to yojimbo.
    IMPORTANT: This allocator is not yet thread safe. Only call it from one thread!
 */

// port: the data members of class Allocator. Embed one in your allocator and return it from base() / base_mut().
pub struct AllocatorBase
{
    pub m_errorLevel: AllocatorErrorLevel,                      //< The allocator error level.
    m_debug: Option<Box<AllocatorDebugState>>,                  //< Leak tracking state, or NULL. Present in every configuration so the class has one layout; only allocated in a debug library build.
}

impl AllocatorBase
{
    /**
        Allocator constructor.
        Sets the error level to ALLOCATOR_ERROR_NONE.
     */

    pub fn new() -> AllocatorBase
    {
        let m_errorLevel = ALLOCATOR_ERROR_NONE;
        let m_debug = if YOJIMBO_DEBUG_MEMORY_LEAKS
        {
            // The tracker's own std::map allocates from the global heap, and always did; the state
            // object joins it there rather than routing through the allocator being tracked.
            Some( Box::new( AllocatorDebugState { alloc_map: BTreeMap::new() } ) )
        }
        else
        {
            None
        };
        AllocatorBase { m_errorLevel, m_debug }
    }
}

impl Default for AllocatorBase
{
    fn default() -> Self { AllocatorBase::new() }
}

/**
    Allocator destructor.
    Make sure all allocations made from this allocator are freed before you destroy this allocator.
    In debug build, validates this is true walks the map of allocator entries. Any outstanding entries are considered memory leaks and printed to stdout.
 */

impl Drop for AllocatorBase
{
    fn drop( &mut self )
    {
        if YOJIMBO_DEBUG_MEMORY_LEAKS
        {
            yojimbo_assert!( self.m_debug.is_some() );
            if let Some( debug ) = self.m_debug.as_ref()
            {
                if debug.alloc_map.len() != 0
                {
                    yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "you leaked memory!\n\n" );
                    for ( p, entry ) in debug.alloc_map.iter()
                    {
                        let p = *p as *mut u8;
                        yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "leaked block {:p} ({} bytes) - {}:{}\n", p, entry.size as i32, entry.file, entry.line );
                    }
                    yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "\n" );
                    yojimbo_assert!( false /* && "Leaks detected, see log" */ );
                }
            }
        }
        self.m_debug = None;
    }
}

// port: class Allocator's virtual methods; the rest are provided methods
pub trait Allocator
{
    /**
        Allocate a block of memory.
        IMPORTANT: Don't call this directly. Use the YOJIMBO_NEW or YOJIMBO_ALLOCATE macros instead, because they automatically pass in the source filename and line number for you.
        @param size The size of the block of memory to allocate (bytes).
        @param file The source code filename that is performing the allocation. Used for tracking allocations and reporting on memory leaks.
        @param line The line number in the source code file that is performing the allocation.
        @returns A block of memory of the requested size, or NULL if the allocation could not be performed. If NULL is returned, the error level is set to ALLOCATION_ERROR_FAILED_TO_ALLOCATE.
        @see Allocator::Free
        @see Allocator::GetErrorLevel
     */

    fn Allocate( &mut self, size: usize, file: &'static str, line: u32 ) -> *mut u8;

    /**
        Free a block of memory.
        IMPORTANT: Don't call this directly. Use the YOJIMBO_DELETE or YOJIMBO_FREE macros instead, because they automatically pass in the source filename and line number for you.
        @param p Pointer to the block of memory to free. Must be non-NULL block of memory that was allocated with this allocator. Will assert otherwise.
        @param file The source code filename that is performing the free. Used for tracking allocations and reporting on memory leaks.
        @param line The line number in the source code file that is performing the free.
        @see Allocator::Allocate
        @see Allocator::GetErrorLevel
     */

    fn Free( &mut self, p: *mut u8, file: &'static str, line: u32 );

    /// port: the Allocator data members
    fn base( &self ) -> &AllocatorBase;

    /// port: the Allocator data members
    fn base_mut( &mut self ) -> &mut AllocatorBase;

    /**
        Get the allocator error level.
        Use this function to check if an allocation has failed. This is used in the client/server to disconnect a client with a failed allocation.
        @returns The allocator error level.
     */

    fn GetErrorLevel( &self ) -> AllocatorErrorLevel { self.base().m_errorLevel }

    /**
        Clear the allocator error level back to default.
     */

    fn ClearError( &mut self ) { self.base_mut().m_errorLevel = ALLOCATOR_ERROR_NONE; }

    // protected:

    /**
        Set the error level.
        For correct client/server behavior when an allocation fails, please make sure you call this method to set the error level to ALLOCATOR_ERROR_FAILED_TO_ALLOCATE.
        @param errorLevel The allocator error level to set.
     */

    fn SetErrorLevel( &mut self, errorLevel: AllocatorErrorLevel )
    {
        let base = self.base_mut();
        if base.m_errorLevel == ALLOCATOR_ERROR_NONE && errorLevel != ALLOCATOR_ERROR_NONE
        {
            yojimbo_printf!( YOJIMBO_LOG_LEVEL_ERROR, "allocator went into error state: {}\n", GetAllocatorErrorString( errorLevel ) );
        }
        base.m_errorLevel = errorLevel;
    }

    /**
        Call this function to track an allocation made by your derived allocator class.
        In debug build, tracked allocations are automatically checked for leaks when the allocator is destroyed.
        @param p Pointer to the memory that was allocated.
        @param size The size of the allocation in bytes.
        @param file The source code file that performed the allocation.
        @param line The line number in the source file where the allocation was performed.
     */

    fn TrackAlloc( &mut self, p: *mut u8, size: usize, file: &'static str, line: u32 )
    {
        if YOJIMBO_DEBUG_MEMORY_LEAKS
        {
            let base = self.base_mut();

            yojimbo_assert!( base.m_debug.is_some() );
            if let Some( debug ) = base.m_debug.as_mut()
            {
                yojimbo_assert!( !debug.alloc_map.contains_key( &( p as usize ) ) );

                let entry = AllocatorDebugStateEntry { size, file, line };
                debug.alloc_map.insert( p as usize, entry );
            }
        }
    }

    /**
        Call this function to track a free made by your derived allocator class.
        In debug build, any allocation tracked without a corresponding free is considered a memory leak when the allocator is destroyed.
        @param p Pointer to the memory that was allocated.
        @param file The source code file that is calling in to free the memory.
        @param line The line number in the source file where the free is being called from.
     */

    fn TrackFree( &mut self, p: *mut u8, file: &'static str, line: u32 )
    {
        if YOJIMBO_DEBUG_MEMORY_LEAKS
        {
            let base = self.base_mut();
            yojimbo_assert!( base.m_debug.is_some() );
            if let Some( debug ) = base.m_debug.as_mut()
            {
                yojimbo_assert!( debug.alloc_map.contains_key( &( p as usize ) ) );
                debug.alloc_map.remove( &( p as usize ) );
            }
        }
    }
}

/// port: a stream's allocator is a `void *` (serialize::BaseStream::SetAllocator), which can't hold a `*mut dyn Allocator`
/// (a fat pointer). Streams carry a pointer to the `*mut dyn Allocator` instead: `AllocatorToContext( &mut allocator )`
/// where upstream passes `&allocator`, and `AllocatorFromContext( stream.GetAllocator() )` where upstream casts back.
pub fn AllocatorToContext( allocator: &mut *mut ( dyn Allocator + 'static ) ) -> *mut c_void
{
    allocator as *mut *mut ( dyn Allocator + 'static ) as *mut c_void
}

/// port: see AllocatorToContext
pub unsafe fn AllocatorFromContext( context: *mut c_void ) -> *mut dyn Allocator
{
    if context.is_null() { return null_allocator(); }
    *( context as *mut *mut dyn Allocator )
}

/// port: a null `Allocator *` (test with .is_null())
pub fn null_allocator() -> *mut dyn Allocator
{
    std::ptr::null_mut::<DefaultAllocator>() as *mut dyn Allocator
}

/**
    The default allocator implementation based around malloc and free.
 */

pub struct DefaultAllocator
{
    pub base: AllocatorBase,
}

impl DefaultAllocator
{
    /**
        Default constructor.
     */

    pub fn new() -> DefaultAllocator
    {
        DefaultAllocator { base: AllocatorBase::new() }
    }
}

impl Default for DefaultAllocator
{
    fn default() -> Self { DefaultAllocator::new() }
}

// port: malloc / free are std::alloc with a header in front of the block holding its size (std::alloc::dealloc
// needs the layout back). The header is 16 bytes, so blocks stay 16-byte aligned.
const DefaultAllocatorHeaderBytes: usize = YOJIMBO_ALLOCATOR_ALIGNMENT;

impl Allocator for DefaultAllocator
{
    /**
        Allocates a block of memory using "malloc".
        IMPORTANT: Don't call this directly. Use the YOJIMBO_NEW or YOJIMBO_ALLOCATE macros instead, because they automatically pass in the source filename and line number for you.
        @param size The size of the block of memory to allocate (bytes).
        @param file The source code filename that is performing the allocation. Used for tracking allocations and reporting on memory leaks.
        @param line The line number in the source code file that is performing the allocation.
        @returns A block of memory of the requested size, or NULL if the allocation could not be performed. If NULL is returned, the error level is set to ALLOCATION_ERROR_FAILED_TO_ALLOCATE.
     */

    fn Allocate( &mut self, size: usize, file: &'static str, line: u32 ) -> *mut u8
    {
        // port: void * p = malloc( size );
        let mut p: *mut u8 = std::ptr::null_mut();
        if let Some( total ) = size.checked_add( DefaultAllocatorHeaderBytes )
        {
            if let Ok( layout ) = std::alloc::Layout::from_size_align( total, YOJIMBO_ALLOCATOR_ALIGNMENT )
            {
                let block = unsafe { std::alloc::alloc( layout ) };
                if !block.is_null()
                {
                    unsafe
                    {
                        ( block as *mut usize ).write( size );
                        p = block.add( DefaultAllocatorHeaderBytes );
                    }
                }
            }
        }

        if p.is_null()
        {
            self.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return std::ptr::null_mut();
        }

        self.TrackAlloc( p, size, file, line );

        p
    }

    /**
        Free a block of memory by calling "free".
        IMPORTANT: Don't call this directly. Use the YOJIMBO_DELETE or YOJIMBO_FREE macros instead, because they automatically pass in the source filename and line number for you.
        @param p Pointer to the block of memory to free. Must be non-NULL block of memory that was allocated with this allocator. Will assert otherwise.
        @param file The source code filename that is performing the free. Used for tracking allocations and reporting on memory leaks.
        @param line The line number in the source code file that is performing the free.
     */

    fn Free( &mut self, p: *mut u8, file: &'static str, line: u32 )
    {
        if p.is_null()
        {
            return;
        }

        self.TrackFree( p, file, line );

        // port: free( p );
        unsafe
        {
            let block = p.sub( DefaultAllocatorHeaderBytes );
            let size = ( block as *const usize ).read();
            let layout = std::alloc::Layout::from_size_align_unchecked( size + DefaultAllocatorHeaderBytes, YOJIMBO_ALLOCATOR_ALIGNMENT );
            std::alloc::dealloc( block, layout );
        }
    }

    fn base( &self ) -> &AllocatorBase { &self.base }
    fn base_mut( &mut self ) -> &mut AllocatorBase { &mut self.base }
}

// =============================================

fn AlignPointerUp( memory: *mut u8, align: i32 ) -> *mut u8
{
    yojimbo_assert!( ( align & ( align - 1 ) ) == 0 );
    let p = memory as usize;
    let align = align as usize;
    // port: as the uintptr_t arithmetic upstream, but keeping the pointer's provenance
    memory.wrapping_add( ( ( p + ( align - 1 ) ) & !( align - 1 ) ) - p )
}

fn AlignPointerDown( memory: *mut u8, align: i32 ) -> *mut u8
{
    yojimbo_assert!( ( align & ( align - 1 ) ) == 0 );
    let p = memory as usize;
    let align = align as usize;
    memory.wrapping_sub( p & ( align - 1 ) )
}

/**
    An allocator built on the TLSF allocator implementation by Matt Conte. Thanks Matt!
    This is a fast allocator that supports multiple heaps. It's used inside the yojimbo server to silo allocations for each client to their own heap.
    See https://github.com/mattconte/tlsf for details on this allocator implementation.
 */

pub struct TLSF_Allocator
{
    pub base: AllocatorBase,
    m_tlsf: tlsf_t,                                             //< The TLSF allocator instance backing this allocator.
    m_capacity: usize,                                          //< Port addition: bytes available to blocks, including their headers (see GetCapacityBytes).
    m_used: usize,                                              //< Port addition: bytes used by live blocks, including their headers (see GetUsedBytes).
}

impl TLSF_Allocator
{
    /**
        TLSF allocator constructor.
        If you want to integrate your own allocator with yojimbo for use with the client and server, this class is a good template to start from.
        Make sure your constructor has the same signature as this one, and it will work with the YOJIMBO_SERVER_ALLOCATOR and YOJIMBO_CLIENT_ALLOCATOR helper macros.
        @param memory Block of memory in which the allocator will work. This block must remain valid while this allocator exists. The allocator does not assume ownership of it, you must free it elsewhere, if necessary.
        @param bytes The size of the block of memory (bytes). The maximum amount of memory you can allocate will be less, due to allocator overhead.
     */

    pub fn new( memory: *mut u8, size: usize ) -> TLSF_Allocator
    {
        yojimbo_assert!( size > 0 );

        let mut allocator = TLSF_Allocator { base: AllocatorBase::new(), m_tlsf: std::ptr::null_mut(), m_capacity: 0, m_used: 0 };

        allocator.SetErrorLevel( ALLOCATOR_ERROR_NONE );

        // TLSF's own alignment (tlsf_align_size) is 8 bytes on 64 bit and 4 on 32 bit; blocks are aligned to 16 by
        // tlsf_memalign in Allocate.
        const AlignBytes: i32 = 8;

        let aligned_memory_start: *mut u8 = AlignPointerUp( memory, AlignBytes );
        let aligned_memory_finish: *mut u8 = AlignPointerDown( memory.wrapping_add( size ), AlignBytes );

        yojimbo_assert!( aligned_memory_start < aligned_memory_finish );

        let aligned_memory_size: usize = ( aligned_memory_finish as usize ).wrapping_sub( aligned_memory_start as usize );

        allocator.m_tlsf = unsafe { tlsf_create_with_pool( aligned_memory_start as *mut core::ffi::c_void, aligned_memory_size ) };

        // port addition: the pool's single free block, plus its header, is what blocks (and their headers) can use
        if !allocator.m_tlsf.is_null()
        {
            let pool_bytes = aligned_memory_size.wrapping_sub( tlsf_size() ).wrapping_sub( tlsf_pool_overhead() ) & !( tlsf_align_size() - 1 );
            allocator.m_capacity = pool_bytes + tlsf_alloc_overhead();
        }

        allocator
    }

    /// Bytes used by live blocks, including the per-block header (tlsf_block_size + tlsf_alloc_overhead).
    /// Port addition (as the C# and TypeScript ports), for tests and diagnostics.
    pub fn GetUsedBytes( &self ) -> i64
    {
        self.m_used as i64
    }

    /// Bytes available to blocks, including their headers: the heap less the TLSF control structure and pool overhead.
    /// Port addition (as the C# and TypeScript ports), for tests and diagnostics.
    pub fn GetCapacityBytes( &self ) -> i64
    {
        self.m_capacity as i64
    }
}

/**
    TLSF allocator destructor.
    Checks for memory leaks in debug build. Free all memory allocated by this allocator before destroying.
 */

impl Drop for TLSF_Allocator
{
    fn drop( &mut self )
    {
        unsafe { tlsf_destroy( self.m_tlsf ); }
        // port: ~Allocator (the leak check) runs next, as AllocatorBase's Drop
    }
}

impl Allocator for TLSF_Allocator
{
    /**
        Allocates a block of memory using TLSF.
        IMPORTANT: Don't call this directly. Use the YOJIMBO_NEW or YOJIMBO_ALLOCATE macros instead, because they automatically pass in the source filename and line number for you.
        @param size The size of the block of memory to allocate (bytes).
        @param file The source code filename that is performing the allocation. Used for tracking allocations and reporting on memory leaks.
        @param line The line number in the source code file that is performing the allocation.
        @returns A block of memory of the requested size, or NULL if the allocation could not be performed. If NULL is returned, the error level is set to ALLOCATION_ERROR_FAILED_TO_ALLOCATE.
     */

    fn Allocate( &mut self, size: usize, file: &'static str, line: u32 ) -> *mut u8
    {
        // port: a pool tlsf_create_with_pool refused (memory too small or too large) has no tlsf
        let p = if self.m_tlsf.is_null() { std::ptr::null_mut() } else { unsafe { tlsf_memalign( self.m_tlsf, 16, size ) as *mut u8 } };

        if p.is_null()
        {
            self.SetErrorLevel( ALLOCATOR_ERROR_OUT_OF_MEMORY );
            return std::ptr::null_mut();
        }

        self.m_used += unsafe { tlsf_block_size( p as *mut core::ffi::c_void ) } + tlsf_alloc_overhead();       // port addition

        self.TrackAlloc( p, size, file, line );

        p
    }

    /**
        Free a block of memory using TLSF.
        IMPORTANT: Don't call this directly. Use the YOJIMBO_DELETE or YOJIMBO_FREE macros instead, because they automatically pass in the source filename and line number for you.
        @param p Pointer to the block of memory to free. Must be non-NULL block of memory that was allocated with this allocator. Will assert otherwise.
        @param file The source code filename that is performing the free. Used for tracking allocations and reporting on memory leaks.
        @param line The line number in the source code file that is performing the free.
        @see Allocator::Allocate
        @see Allocator::GetError
     */

    fn Free( &mut self, p: *mut u8, file: &'static str, line: u32 )
    {
        if p.is_null()
        {
            return;
        }

        self.TrackFree( p, file, line );

        self.m_used -= unsafe { tlsf_block_size( p as *mut core::ffi::c_void ) } + tlsf_alloc_overhead();       // port addition

        unsafe { tlsf_free( self.m_tlsf, p as *mut core::ffi::c_void ); }
    }

    fn base( &self ) -> &AllocatorBase { &self.base }
    fn base_mut( &mut self ) -> &mut AllocatorBase { &mut self.base }
}
