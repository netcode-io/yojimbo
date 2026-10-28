
/*
** Two Level Segregated Fit memory allocator, version 3.1.
** Written by Matthew Conte
**	http://tlsf.baisoku.org
**
** Based on the original documentation by Miguel Masmano:
**	http://www.gii.upv.es/tlsf/main/docs
**
** This implementation was written to the specification
** of the document, therefore no GPL restrictions apply.
** 
** Copyright (c) 2006-2016, Matthew Conte
** All rights reserved.
** 
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the copyright holder nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
** 
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL MATTHEW CONTE BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
    Rust port of tlsf/tlsf.h + tlsf/tlsf.c (TLSF 3.1, as vendored by yojimbo 1.13.5).

    A real port of the algorithm: the control structure and the pool live inside the caller's memory block, and the
    block headers are written into it, exactly as upstream. The C# and TypeScript ports emulate TLSF; this one does not.

    Port notes:
      - tlsf_t / pool_t stay void pointers (*mut c_void). The functions that take or return raw memory are `unsafe fn`:
        the caller guarantees the pointers came from this allocator, as in C.
      - tlsf_ffs / tlsf_fls use u32::trailing_zeros / leading_zeros, in place of the per-compiler intrinsics
        (__builtin_ffs, _BitScanForward, __clz, ...) and the generic fallback.
      - TLSF_64BIT is cfg(target_pointer_width = "64").
      - tlsf_assert is debug_assert! (upstream: assert, compiled out by NDEBUG).
      - printf is print!.
      - Pointer arithmetic keeps provenance (wrapping_offset on the byte pointer) where C casts through ptrdiff_t.
      - test_ffs_fls runs in tlsf_create in debug builds (upstream: when _DEBUG is defined, ie. MSVC debug builds).
*/

use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::ptr;

/* tlsf_t: a TLSF structure. Can contain 1 to N pools. */
/* pool_t: a block of memory that TLSF can manage. */
pub type tlsf_t = *mut c_void;
pub type pool_t = *mut c_void;

/* Debugging. */
pub type tlsf_walker = fn( ptr: *mut c_void, size: usize, used: i32, user: *mut c_void );

/*
** Architecture-specific bit manipulation routines.
**
** TLSF achieves O(1) cost for malloc and free operations by limiting
** the search for a free block to a free list of guaranteed size
** adequate to fulfill the request, combined with efficient free list
** queries using bitmasks and architecture-specific bit-manipulation
** routines.
**
** Most modern processors provide instructions to count leading zeroes
** in a word, find the lowest and highest set bit, etc. These
** specific implementations will be used when available, falling back
** to a reasonably efficient generic implementation.
**
** NOTE: TLSF spec relies on ffs/fls returning value 0..31.
** ffs/fls return 1-32 by default, returning 0 for error.
*/

/*
** Detect whether or not we are building for a 32- or 64-bit (LP/LLP)
** architecture. There is no reliable portable method at compile-time.
*/
// port: #define TLSF_64BIT is cfg(target_pointer_width = "64")

// port: the per-compiler variants collapse into the Rust intrinsics
fn tlsf_ffs( word: u32 ) -> i32
{
    if word == 0 { -1 } else { word.trailing_zeros() as i32 }
}

fn tlsf_fls( word: u32 ) -> i32
{
    let bit: i32 = if word != 0 { 32 - word.leading_zeros() as i32 } else { 0 };
    bit - 1
}

/* Possibly 64-bit version of tlsf_fls. */
#[cfg(target_pointer_width = "64")]
fn tlsf_fls_sizet( size: usize ) -> i32
{
    let high: i32 = ( size >> 32 ) as i32;
    let bits: i32;
    if high != 0
    {
        bits = 32 + tlsf_fls( high as u32 );
    }
    else
    {
        bits = tlsf_fls( ( size as u32 ) & 0xffffffff );
    }
    bits
}

#[cfg(not(target_pointer_width = "64"))]
fn tlsf_fls_sizet( size: usize ) -> i32
{
    tlsf_fls( size as u32 )
}

/*
** Constants.
*/

/* Public constants: may be modified. */

/* log2 of number of linear subdivisions of block sizes. Larger
** values require more memory in the control structure. Values of
** 4 or 5 are typical.
*/
const SL_INDEX_COUNT_LOG2: i32 = 5;

/* Private constants: do not modify. */

#[cfg(target_pointer_width = "64")]
/* All allocation sizes and addresses are aligned to 8 bytes. */
const ALIGN_SIZE_LOG2: i32 = 3;
#[cfg(not(target_pointer_width = "64"))]
/* All allocation sizes and addresses are aligned to 4 bytes. */
const ALIGN_SIZE_LOG2: i32 = 2;

const ALIGN_SIZE: usize = 1 << ALIGN_SIZE_LOG2;

/*
** We support allocations of sizes up to (1 << FL_INDEX_MAX) bits.
** However, because we linearly subdivide the second-level lists, and
** our minimum size granularity is 4 bytes, it doesn't make sense to
** create first-level lists for sizes smaller than SL_INDEX_COUNT * 4,
** or (1 << (SL_INDEX_COUNT_LOG2 + 2)) bytes, as there we will be
** trying to split size ranges into more slots than we have available.
** Instead, we calculate the minimum threshold size, and place all
** blocks below that size into the 0th first-level list.
*/

#[cfg(target_pointer_width = "64")]
/*
** TODO: We can increase this to support larger sizes, at the expense
** of more overhead in the TLSF structure.
*/
const FL_INDEX_MAX: i32 = 32;
#[cfg(not(target_pointer_width = "64"))]
const FL_INDEX_MAX: i32 = 30;

const SL_INDEX_COUNT: i32 = 1 << SL_INDEX_COUNT_LOG2;
const FL_INDEX_SHIFT: i32 = SL_INDEX_COUNT_LOG2 + ALIGN_SIZE_LOG2;
const FL_INDEX_COUNT: i32 = FL_INDEX_MAX - FL_INDEX_SHIFT + 1;

const SMALL_BLOCK_SIZE: usize = 1 << FL_INDEX_SHIFT;

/*
** Cast and min/max macros.
*/

fn tlsf_min( a: usize, b: usize ) -> usize { if a < b { a } else { b } }
fn tlsf_max( a: usize, b: usize ) -> usize { if a > b { a } else { b } }

/*
** Set assert macro, if it has not been provided by the user.
*/
macro_rules! tlsf_assert {
    ( $x:expr, $msg:expr ) => { debug_assert!( $x, "{}", $msg ) };
    ( $x:expr ) => { debug_assert!( $x ) };
}

/*
** Static assertion mechanism.
*/

/* This code has been tested on 32- and 64-bit (LP/LLP) architectures. */
const _: () = assert!( size_of::<i32>() * 8 == 32 );
const _: () = assert!( size_of::<usize>() * 8 >= 32 );
const _: () = assert!( size_of::<usize>() * 8 <= 64 );

/* SL_INDEX_COUNT must be <= number of bits in sl_bitmap's storage type. */
const _: () = assert!( size_of::<u32>() * 8 >= SL_INDEX_COUNT as usize );

/* Ensure we've properly tuned our sizes. */
const _: () = assert!( ALIGN_SIZE == SMALL_BLOCK_SIZE / SL_INDEX_COUNT as usize );

/*
** Data structures and associated constants.
*/

/*
** Block header structure.
**
** There are several implementation subtleties involved:
** - The prev_phys_block field is only valid if the previous block is free.
** - The prev_phys_block field is actually stored at the end of the
**   previous block. It appears at the beginning of this structure only to
**   simplify the implementation.
** - The next_free / prev_free fields are only valid if the block is free.
*/
#[repr(C)]
struct block_header_t
{
    /* Points to the previous physical block. */
    prev_phys_block: *mut block_header_t,

    /* The size of this block, excluding the block header. */
    size: usize,

    /* Next and previous free blocks. */
    next_free: *mut block_header_t,
    prev_free: *mut block_header_t,
}

/*
** Since block sizes are always at least a multiple of 4, the two least
** significant bits of the size field are used to store the block status:
** - bit 0: whether block is busy or free
** - bit 1: whether previous block is busy or free
*/
const block_header_free_bit: usize = 1 << 0;
const block_header_prev_free_bit: usize = 1 << 1;

/*
** The size of the block header exposed to used blocks is the size field.
** The prev_phys_block field is stored *inside* the previous free block.
*/
const block_header_overhead: usize = size_of::<usize>();

/* User data starts directly after the size field in a used block. */
const block_start_offset: usize = offset_of!( block_header_t, size ) + size_of::<usize>();

/*
** A free block must be large enough to store its header minus the size of
** the prev_phys_block field, and no larger than the number of addressable
** bits for FL_INDEX.
*/
const block_size_min: usize = size_of::<block_header_t>() - size_of::<*mut block_header_t>();
const block_size_max: usize = ( 1 as usize ) << FL_INDEX_MAX;


/* The TLSF control structure. */
#[repr(C)]
struct control_t
{
    /* Empty lists point at this block to indicate they are free. */
    block_null: block_header_t,

    /* Bitmaps for free lists. */
    fl_bitmap: u32,
    sl_bitmap: [u32; FL_INDEX_COUNT as usize],

    /* Head of free lists. */
    blocks: [[*mut block_header_t; SL_INDEX_COUNT as usize]; FL_INDEX_COUNT as usize],
}

/* A type used for casting when doing pointer arithmetic. */
type tlsfptr_t = isize;

/*
** block_header_t member functions.
*/

unsafe fn block_size( block: *const block_header_t ) -> usize
{
    (*block).size & !( block_header_free_bit | block_header_prev_free_bit )
}

unsafe fn block_set_size( block: *mut block_header_t, size: usize )
{
    let oldsize = (*block).size;
    (*block).size = size | ( oldsize & ( block_header_free_bit | block_header_prev_free_bit ) );
}

unsafe fn block_is_last( block: *const block_header_t ) -> bool
{
    block_size( block ) == 0
}

unsafe fn block_is_free( block: *const block_header_t ) -> bool
{
    ( (*block).size & block_header_free_bit ) != 0
}

unsafe fn block_set_free( block: *mut block_header_t )
{
    (*block).size |= block_header_free_bit;
}

unsafe fn block_set_used( block: *mut block_header_t )
{
    (*block).size &= !block_header_free_bit;
}

unsafe fn block_is_prev_free( block: *const block_header_t ) -> bool
{
    ( (*block).size & block_header_prev_free_bit ) != 0
}

unsafe fn block_set_prev_free( block: *mut block_header_t )
{
    (*block).size |= block_header_prev_free_bit;
}

unsafe fn block_set_prev_used( block: *mut block_header_t )
{
    (*block).size &= !block_header_prev_free_bit;
}

fn block_from_ptr( ptr: *const c_void ) -> *mut block_header_t
{
    ( ptr as *mut u8 ).wrapping_sub( block_start_offset ) as *mut block_header_t
}

fn block_to_ptr( block: *const block_header_t ) -> *mut c_void
{
    ( block as *mut u8 ).wrapping_add( block_start_offset ) as *mut c_void
}

/* Return location of next block after block of given size. */
// port: size is a size_t upstream, and callers pass negative offsets through it; wrapping_offset does the same
fn offset_to_block( ptr: *const c_void, size: usize ) -> *mut block_header_t
{
    ( ptr as *mut u8 ).wrapping_offset( size as tlsfptr_t ) as *mut block_header_t
}

/* Return location of previous block. */
unsafe fn block_prev( block: *const block_header_t ) -> *mut block_header_t
{
    tlsf_assert!( block_is_prev_free( block ), "previous block must be free" );
    (*block).prev_phys_block
}

/* Return location of next existing block. */
unsafe fn block_next( block: *const block_header_t ) -> *mut block_header_t
{
    let next = offset_to_block( block_to_ptr( block ),
        block_size( block ).wrapping_sub( block_header_overhead ) );
    tlsf_assert!( !block_is_last( block ) );
    next
}

/* Link a new block with its physical neighbor, return the neighbor. */
unsafe fn block_link_next( block: *mut block_header_t ) -> *mut block_header_t
{
    let next = block_next( block );
    (*next).prev_phys_block = block;
    next
}

unsafe fn block_mark_as_free( block: *mut block_header_t )
{
    /* Link the block to the next block, first. */
    let next = block_link_next( block );
    block_set_prev_free( next );
    block_set_free( block );
}

unsafe fn block_mark_as_used( block: *mut block_header_t )
{
    let next = block_next( block );
    block_set_prev_used( next );
    block_set_used( block );
}

fn align_up( x: usize, align: usize ) -> usize
{
    tlsf_assert!( 0 == ( align & ( align - 1 ) ), "must align to a power of two" );
    x.wrapping_add( align - 1 ) & !( align - 1 )
}

fn align_down( x: usize, align: usize ) -> usize
{
    tlsf_assert!( 0 == ( align & ( align - 1 ) ), "must align to a power of two" );
    x - ( x & ( align - 1 ) )
}

fn align_ptr( ptr: *const c_void, align: usize ) -> *mut c_void
{
    let address = ptr as usize;
    let aligned = address.wrapping_add( align - 1 ) & !( align - 1 );
    tlsf_assert!( 0 == ( align & ( align - 1 ) ), "must align to a power of two" );
    ( ptr as *mut u8 ).wrapping_add( aligned - address ) as *mut c_void
}

/*
** Adjust an allocation size to be aligned to word size, and no smaller
** than internal minimum.
*/
fn adjust_request_size( size: usize, align: usize ) -> usize
{
    let mut adjust: usize = 0;
    if size != 0
    {
        let aligned = align_up( size, align );

        /* aligned sized must not exceed block_size_max or we'll go out of bounds on sl_bitmap */
        // port: and must not have wrapped around (C size_t arithmetic wraps the same way)
        if aligned < block_size_max && aligned >= size
        {
            adjust = tlsf_max( aligned, block_size_min );
        }
    }
    adjust
}

/*
** TLSF utility functions. In most cases, these are direct translations of
** the documentation found in the white paper.
*/

fn mapping_insert( size: usize, fli: &mut i32, sli: &mut i32 )
{
    let mut fl: i32;
    let sl: i32;
    if size < SMALL_BLOCK_SIZE
    {
        /* Store small blocks in first list. */
        fl = 0;
        sl = size as i32 / ( SMALL_BLOCK_SIZE / SL_INDEX_COUNT as usize ) as i32;
    }
    else
    {
        fl = tlsf_fls_sizet( size );
        sl = ( size >> ( fl - SL_INDEX_COUNT_LOG2 ) ) as i32 ^ ( 1 << SL_INDEX_COUNT_LOG2 );
        fl -= FL_INDEX_SHIFT - 1;
    }
    *fli = fl;
    *sli = sl;
}

/* This version rounds up to the next block size (for allocations) */
fn mapping_search( mut size: usize, fli: &mut i32, sli: &mut i32 )
{
    if size >= SMALL_BLOCK_SIZE
    {
        let round: usize = ( ( 1 as usize ) << ( tlsf_fls_sizet( size ) - SL_INDEX_COUNT_LOG2 ) ) - 1;
        size = size.wrapping_add( round );
    }
    mapping_insert( size, fli, sli );
}

unsafe fn search_suitable_block( control: *mut control_t, fli: &mut i32, sli: &mut i32 ) -> *mut block_header_t
{
    let mut fl: i32 = *fli;
    let mut sl: i32 = *sli;

    /*
    ** First, search for a block in the list associated with the given
    ** fl/sl index.
    */
    let mut sl_map: u32 = (*control).sl_bitmap[fl as usize] & ( !0u32 ).wrapping_shl( sl as u32 );
    if sl_map == 0
    {
        /* No block exists. Search in the next largest first-level list. */
        // port: wrapping_shl as the shift is never 32 here (fl + 1 <= FL_INDEX_COUNT < 32)
        let fl_map: u32 = (*control).fl_bitmap & ( !0u32 ).wrapping_shl( ( fl + 1 ) as u32 );
        if fl_map == 0
        {
            /* No free blocks available, memory has been exhausted. */
            return ptr::null_mut();
        }

        fl = tlsf_ffs( fl_map );
        *fli = fl;
        sl_map = (*control).sl_bitmap[fl as usize];
    }
    tlsf_assert!( sl_map != 0, "internal error - second level bitmap is null" );
    sl = tlsf_ffs( sl_map );
    *sli = sl;

    /* Return the first block in the free list. */
    (*control).blocks[fl as usize][sl as usize]
}

/* Remove a free block from the free list.*/
unsafe fn remove_free_block( control: *mut control_t, block: *mut block_header_t, fl: i32, sl: i32 )
{
    let prev = (*block).prev_free;
    let next = (*block).next_free;
    tlsf_assert!( !prev.is_null(), "prev_free field can not be null" );
    tlsf_assert!( !next.is_null(), "next_free field can not be null" );
    (*next).prev_free = prev;
    (*prev).next_free = next;

    /* If this block is the head of the free list, set new head. */
    if (*control).blocks[fl as usize][sl as usize] == block
    {
        (*control).blocks[fl as usize][sl as usize] = next;

        /* If the new head is null, clear the bitmap. */
        if next == ptr::addr_of_mut!( (*control).block_null )
        {
            (*control).sl_bitmap[fl as usize] &= !( 1u32 << sl );

            /* If the second bitmap is now empty, clear the fl bitmap. */
            if (*control).sl_bitmap[fl as usize] == 0
            {
                (*control).fl_bitmap &= !( 1u32 << fl );
            }
        }
    }
}

/* Insert a free block into the free block list. */
unsafe fn insert_free_block( control: *mut control_t, block: *mut block_header_t, fl: i32, sl: i32 )
{
    let current = (*control).blocks[fl as usize][sl as usize];
    tlsf_assert!( !current.is_null(), "free list cannot have a null entry" );
    tlsf_assert!( !block.is_null(), "cannot insert a null entry into the free list" );
    (*block).next_free = current;
    (*block).prev_free = ptr::addr_of_mut!( (*control).block_null );
    (*current).prev_free = block;

    tlsf_assert!( block_to_ptr( block ) == align_ptr( block_to_ptr( block ), ALIGN_SIZE ),
        "block not aligned properly" );
    /*
    ** Insert the new block at the head of the list, and mark the first-
    ** and second-level bitmaps appropriately.
    */
    (*control).blocks[fl as usize][sl as usize] = block;
    (*control).fl_bitmap |= 1u32 << fl;
    (*control).sl_bitmap[fl as usize] |= 1u32 << sl;
}

/* Remove a given block from the free list. */
unsafe fn block_remove( control: *mut control_t, block: *mut block_header_t )
{
    let mut fl: i32 = 0;
    let mut sl: i32 = 0;
    mapping_insert( block_size( block ), &mut fl, &mut sl );
    remove_free_block( control, block, fl, sl );
}

/* Insert a given block into the free list. */
unsafe fn block_insert( control: *mut control_t, block: *mut block_header_t )
{
    let mut fl: i32 = 0;
    let mut sl: i32 = 0;
    mapping_insert( block_size( block ), &mut fl, &mut sl );
    insert_free_block( control, block, fl, sl );
}

unsafe fn block_can_split( block: *mut block_header_t, size: usize ) -> bool
{
    block_size( block ) >= size_of::<block_header_t>() + size
}

/* Split a block into two, the second of which is free. */
unsafe fn block_split( block: *mut block_header_t, size: usize ) -> *mut block_header_t
{
    /* Calculate the amount of space left in the remaining block. */
    let remaining =
        offset_to_block( block_to_ptr( block ), size.wrapping_sub( block_header_overhead ) );

    let remain_size: usize = block_size( block ) - ( size + block_header_overhead );

    tlsf_assert!( block_to_ptr( remaining ) == align_ptr( block_to_ptr( remaining ), ALIGN_SIZE ),
        "remaining block not aligned properly" );

    tlsf_assert!( block_size( block ) == remain_size + size + block_header_overhead );
    block_set_size( remaining, remain_size );
    tlsf_assert!( block_size( remaining ) >= block_size_min, "block split with invalid size" );

    block_set_size( block, size );
    block_mark_as_free( remaining );

    remaining
}

/* Absorb a free block's storage into an adjacent previous free block. */
unsafe fn block_absorb( prev: *mut block_header_t, block: *mut block_header_t ) -> *mut block_header_t
{
    tlsf_assert!( !block_is_last( prev ), "previous block can't be last" );
    /* Note: Leaves flags untouched. */
    (*prev).size += block_size( block ) + block_header_overhead;
    block_link_next( prev );
    prev
}

/* Merge a just-freed block with an adjacent previous free block. */
unsafe fn block_merge_prev( control: *mut control_t, mut block: *mut block_header_t ) -> *mut block_header_t
{
    if block_is_prev_free( block )
    {
        let prev = block_prev( block );
        tlsf_assert!( !prev.is_null(), "prev physical block can't be null" );
        tlsf_assert!( block_is_free( prev ), "prev block is not free though marked as such" );
        block_remove( control, prev );
        block = block_absorb( prev, block );
    }

    block
}

/* Merge a just-freed block with an adjacent free block. */
unsafe fn block_merge_next( control: *mut control_t, mut block: *mut block_header_t ) -> *mut block_header_t
{
    let next = block_next( block );
    tlsf_assert!( !next.is_null(), "next physical block can't be null" );

    if block_is_free( next )
    {
        tlsf_assert!( !block_is_last( block ), "previous block can't be last" );
        block_remove( control, next );
        block = block_absorb( block, next );
    }

    block
}

/* Trim any trailing block space off the end of a block, return to pool. */
unsafe fn block_trim_free( control: *mut control_t, block: *mut block_header_t, size: usize )
{
    tlsf_assert!( block_is_free( block ), "block must be free" );
    if block_can_split( block, size )
    {
        let remaining_block = block_split( block, size );
        block_link_next( block );
        block_set_prev_free( remaining_block );
        block_insert( control, remaining_block );
    }
}

/* Trim any trailing block space off the end of a used block, return to pool. */
unsafe fn block_trim_used( control: *mut control_t, block: *mut block_header_t, size: usize )
{
    tlsf_assert!( !block_is_free( block ), "block must be used" );
    if block_can_split( block, size )
    {
        /* If the next block is free, we must coalesce. */
        let mut remaining_block = block_split( block, size );
        block_set_prev_used( remaining_block );

        remaining_block = block_merge_next( control, remaining_block );
        block_insert( control, remaining_block );
    }
}

unsafe fn block_trim_free_leading( control: *mut control_t, block: *mut block_header_t, size: usize ) -> *mut block_header_t
{
    let mut remaining_block = block;
    if block_can_split( block, size )
    {
        /* We want the 2nd block. */
        remaining_block = block_split( block, size - block_header_overhead );
        block_set_prev_free( remaining_block );

        block_link_next( block );
        block_insert( control, block );
    }

    remaining_block
}

unsafe fn block_locate_free( control: *mut control_t, size: usize ) -> *mut block_header_t
{
    let mut fl: i32 = 0;
    let mut sl: i32 = 0;
    let mut block: *mut block_header_t = ptr::null_mut();

    if size != 0
    {
        mapping_search( size, &mut fl, &mut sl );

        /*
        ** mapping_search can futz with the size, so for excessively large sizes it can sometimes wind up
        ** with indices that are off the end of the block array.
        ** So, we protect against that here, since this is the only callsite of mapping_search.
        ** Note that we don't need to check sl, since it comes from a modulo operation that guarantees it's always in range.
        */
        if fl < FL_INDEX_COUNT
        {
            block = search_suitable_block( control, &mut fl, &mut sl );
        }
    }

    if !block.is_null()
    {
        tlsf_assert!( block_size( block ) >= size );
        remove_free_block( control, block, fl, sl );
    }

    block
}

unsafe fn block_prepare_used( control: *mut control_t, block: *mut block_header_t, size: usize ) -> *mut c_void
{
    let mut p: *mut c_void = ptr::null_mut();
    if !block.is_null()
    {
        tlsf_assert!( size != 0, "size must be non-zero" );
        block_trim_free( control, block, size );
        block_mark_as_used( block );
        p = block_to_ptr( block );
    }
    p
}

/* Clear structure and point all empty lists at the null block. */
unsafe fn control_construct( control: *mut control_t )
{
    let block_null = ptr::addr_of_mut!( (*control).block_null );

    // port: the C struct is never zeroed; prev_phys_block and size of block_null are initialized for Rust's sake
    (*control).block_null.prev_phys_block = ptr::null_mut();
    (*control).block_null.size = 0;

    (*control).block_null.next_free = block_null;
    (*control).block_null.prev_free = block_null;

    (*control).fl_bitmap = 0;
    for i in 0..FL_INDEX_COUNT as usize
    {
        (*control).sl_bitmap[i] = 0;
        for j in 0..SL_INDEX_COUNT as usize
        {
            (*control).blocks[i][j] = block_null;
        }
    }
}

/*
** Debugging utilities.
*/

#[repr(C)]
struct integrity_t
{
    prev_status: i32,
    status: i32,
}

macro_rules! tlsf_insist {
    ( $status:ident, $x:expr, $msg:expr ) => {{ tlsf_assert!( $x, $msg ); if !( $x ) { $status -= 1; } }};
}

fn integrity_walker( ptr: *mut c_void, size: usize, used: i32, user: *mut c_void )
{
    unsafe
    {
        let block = block_from_ptr( ptr );
        let integ = user as *mut integrity_t;
        let this_prev_status: i32 = if block_is_prev_free( block ) { 1 } else { 0 };
        let this_status: i32 = if block_is_free( block ) { 1 } else { 0 };
        let this_block_size: usize = block_size( block );

        let mut status: i32 = 0;
        let _ = used;
        tlsf_insist!( status, (*integ).prev_status == this_prev_status, "prev status incorrect" );
        tlsf_insist!( status, size == this_block_size, "block size incorrect" );

        (*integ).prev_status = this_status;
        (*integ).status += status;
    }
}

/* Returns nonzero if any internal consistency check fails. */
pub unsafe fn tlsf_check( tlsf: tlsf_t ) -> i32
{
    let control = tlsf as *mut control_t;
    let mut status: i32 = 0;
    let block_null = ptr::addr_of_mut!( (*control).block_null );

    /* Check that the free lists and bitmaps are accurate. */
    for i in 0..FL_INDEX_COUNT
    {
        for j in 0..SL_INDEX_COUNT
        {
            let fl_map: u32 = (*control).fl_bitmap & ( 1u32 << i );
            let sl_list: u32 = (*control).sl_bitmap[i as usize];
            let sl_map: u32 = sl_list & ( 1u32 << j );
            let mut block: *mut block_header_t = (*control).blocks[i as usize][j as usize];

            /* Check that first- and second-level lists agree. */
            if fl_map == 0
            {
                tlsf_insist!( status, sl_map == 0, "second-level map must be null" );
            }

            if sl_map == 0
            {
                tlsf_insist!( status, block == block_null, "block list must be null" );
                continue;
            }

            /* Check that there is at least one free block. */
            tlsf_insist!( status, sl_list != 0, "no free blocks in second-level map" );
            tlsf_insist!( status, block != block_null, "block should not be null" );

            while block != block_null
            {
                let mut fli: i32 = 0;
                let mut sli: i32 = 0;
                tlsf_insist!( status, block_is_free( block ), "block should be free" );
                tlsf_insist!( status, !block_is_prev_free( block ), "blocks should have coalesced" );
                tlsf_insist!( status, !block_is_free( block_next( block ) ), "blocks should have coalesced" );
                tlsf_insist!( status, block_is_prev_free( block_next( block ) ), "block should be free" );
                tlsf_insist!( status, block_size( block ) >= block_size_min, "block not minimum size" );

                mapping_insert( block_size( block ), &mut fli, &mut sli );
                tlsf_insist!( status, fli == i && sli == j, "block size indexed in wrong list" );
                block = (*block).next_free;
            }
        }
    }

    status
}

fn default_walker( ptr: *mut c_void, size: usize, used: i32, user: *mut c_void )
{
    let _ = user;
    print!( "\t{:p} {} size: {:x} ({:p})\n", ptr, if used != 0 { "used" } else { "free" }, size as u32, block_from_ptr( ptr ) );
}

pub unsafe fn tlsf_walk_pool( pool: pool_t, walker: Option<tlsf_walker>, user: *mut c_void )
{
    let pool_walker: tlsf_walker = match walker { Some( w ) => w, None => default_walker };
    let mut block = offset_to_block( pool, ( -( block_header_overhead as i32 ) ) as isize as usize );

    while !block.is_null() && !block_is_last( block )
    {
        pool_walker(
            block_to_ptr( block ),
            block_size( block ),
            if !block_is_free( block ) { 1 } else { 0 },
            user );
        block = block_next( block );
    }
}

/* Returns internal block size, not original request size */
pub unsafe fn tlsf_block_size( ptr: *mut c_void ) -> usize
{
    let mut size: usize = 0;
    if !ptr.is_null()
    {
        let block = block_from_ptr( ptr );
        size = block_size( block );
    }
    size
}

pub unsafe fn tlsf_check_pool( pool: pool_t ) -> i32
{
    /* Check that the blocks are physically correct. */
    let mut integ = integrity_t { prev_status: 0, status: 0 };
    tlsf_walk_pool( pool, Some( integrity_walker ), ptr::addr_of_mut!( integ ) as *mut c_void );

    integ.status
}

/*
** Size of the TLSF structures in a given memory block passed to
** tlsf_create, equal to the size of a control_t
*/
pub fn tlsf_size() -> usize
{
    size_of::<control_t>()
}

pub fn tlsf_align_size() -> usize
{
    ALIGN_SIZE
}

pub fn tlsf_block_size_min() -> usize
{
    block_size_min
}

pub fn tlsf_block_size_max() -> usize
{
    block_size_max
}

/*
** Overhead of the TLSF structures in a given memory block passed to
** tlsf_add_pool, equal to the overhead of a free block and the
** sentinel block.
*/
pub fn tlsf_pool_overhead() -> usize
{
    2 * block_header_overhead
}

pub fn tlsf_alloc_overhead() -> usize
{
    block_header_overhead
}

/* Add/remove memory pools. */
pub unsafe fn tlsf_add_pool( tlsf: tlsf_t, mem: *mut c_void, bytes: usize ) -> pool_t
{
    let block: *mut block_header_t;
    let next: *mut block_header_t;

    let pool_overhead: usize = tlsf_pool_overhead();
    let pool_bytes: usize = align_down( bytes.wrapping_sub( pool_overhead ), ALIGN_SIZE );

    if ( ( mem as tlsfptr_t ) % ALIGN_SIZE as tlsfptr_t ) != 0
    {
        print!( "tlsf_add_pool: Memory must be aligned by {} bytes.\n",
            ALIGN_SIZE as u32 );
        return ptr::null_mut();
    }

    if pool_bytes < block_size_min || pool_bytes > block_size_max
    {
        #[cfg(target_pointer_width = "64")]
        print!( "tlsf_add_pool: Memory size must be between 0x{:x} and 0x{:x}00 bytes.\n",
            ( pool_overhead + block_size_min ) as u32,
            ( ( pool_overhead + block_size_max ) / 256 ) as u32 );
        #[cfg(not(target_pointer_width = "64"))]
        print!( "tlsf_add_pool: Memory size must be between {} and {} bytes.\n",
            ( pool_overhead + block_size_min ) as u32,
            ( pool_overhead + block_size_max ) as u32 );
        return ptr::null_mut();
    }

    /*
    ** Create the main free block. Offset the start of the block slightly
    ** so that the prev_phys_block field falls outside of the pool -
    ** it will never be used.
    */
    block = offset_to_block( mem, ( -( block_header_overhead as tlsfptr_t ) ) as usize );
    block_set_size( block, pool_bytes );
    block_set_free( block );
    block_set_prev_used( block );
    block_insert( tlsf as *mut control_t, block );

    /* Split the block to create a zero-size sentinel block. */
    next = block_link_next( block );
    block_set_size( next, 0 );
    block_set_used( next );
    block_set_prev_free( next );

    mem
}

pub unsafe fn tlsf_remove_pool( tlsf: tlsf_t, pool: pool_t )
{
    let control = tlsf as *mut control_t;
    let block = offset_to_block( pool, ( -( block_header_overhead as i32 ) ) as isize as usize );

    let mut fl: i32 = 0;
    let mut sl: i32 = 0;

    tlsf_assert!( block_is_free( block ), "block should be free" );
    tlsf_assert!( !block_is_free( block_next( block ) ), "next block should not be free" );
    tlsf_assert!( block_size( block_next( block ) ) == 0, "next block size should be zero" );

    mapping_insert( block_size( block ), &mut fl, &mut sl );
    remove_free_block( control, block, fl, sl );
}

/*
** TLSF main interface.
*/

// port: upstream compiles this under #if _DEBUG; it is pub so tests can run it
pub fn test_ffs_fls() -> i32
{
    /* Verify ffs/fls work properly. */
    let mut rv: i32 = 0;
    rv += if tlsf_ffs( 0 ) == -1 { 0 } else { 0x1 };
    rv += if tlsf_fls( 0 ) == -1 { 0 } else { 0x2 };
    rv += if tlsf_ffs( 1 ) == 0 { 0 } else { 0x4 };
    rv += if tlsf_fls( 1 ) == 0 { 0 } else { 0x8 };
    rv += if tlsf_ffs( 0x80000000 ) == 31 { 0 } else { 0x10 };
    rv += if tlsf_ffs( 0x80008000 ) == 15 { 0 } else { 0x20 };
    rv += if tlsf_fls( 0x80000008 ) == 31 { 0 } else { 0x40 };
    rv += if tlsf_fls( 0x7FFFFFFF ) == 30 { 0 } else { 0x80 };

    #[cfg(target_pointer_width = "64")]
    {
        rv += if tlsf_fls_sizet( 0x80000000 ) == 31 { 0 } else { 0x100 };
        rv += if tlsf_fls_sizet( 0x100000000 ) == 32 { 0 } else { 0x200 };
        rv += if tlsf_fls_sizet( 0xffffffffffffffff ) == 63 { 0 } else { 0x400 };
    }

    if rv != 0
    {
        print!( "test_ffs_fls: {:x} ffs/fls tests failed.\n", rv );
    }
    rv
}

/* Create/destroy a memory pool. */
pub unsafe fn tlsf_create( mem: *mut c_void ) -> tlsf_t
{
    if cfg!(debug_assertions)
    {
        if test_ffs_fls() != 0
        {
            return ptr::null_mut();
        }
    }

    if ( ( mem as tlsfptr_t ) % ALIGN_SIZE as tlsfptr_t ) != 0
    {
        print!( "tlsf_create: Memory must be aligned to {} bytes.\n",
            ALIGN_SIZE as u32 );
        return ptr::null_mut();
    }

    control_construct( mem as *mut control_t );

    mem as tlsf_t
}

pub unsafe fn tlsf_create_with_pool( mem: *mut c_void, bytes: usize ) -> tlsf_t
{
    let tlsf = tlsf_create( mem );
    // port: upstream adds the pool even when tlsf_create failed (a NULL tlsf); the port returns NULL instead, and
    // also when the pool is refused, so a caller can't write through a control structure that isn't there
    if tlsf.is_null() || bytes < tlsf_size()
    {
        return ptr::null_mut();
    }
    if tlsf_add_pool( tlsf, ( mem as *mut u8 ).add( tlsf_size() ) as *mut c_void, bytes - tlsf_size() ).is_null()
    {
        return ptr::null_mut();
    }
    tlsf
}

pub unsafe fn tlsf_destroy( tlsf: tlsf_t )
{
    /* Nothing to do. */
    let _ = tlsf;
}

pub unsafe fn tlsf_get_pool( tlsf: tlsf_t ) -> pool_t
{
    ( tlsf as *mut u8 ).wrapping_add( tlsf_size() ) as pool_t
}

/* malloc/memalign/realloc/free replacements. */
pub unsafe fn tlsf_malloc( tlsf: tlsf_t, size: usize ) -> *mut c_void
{
    let control = tlsf as *mut control_t;
    let adjust: usize = adjust_request_size( size, ALIGN_SIZE );
    let block = block_locate_free( control, adjust );
    block_prepare_used( control, block, adjust )
}

pub unsafe fn tlsf_memalign( tlsf: tlsf_t, align: usize, size: usize ) -> *mut c_void
{
    let control = tlsf as *mut control_t;
    let adjust: usize = adjust_request_size( size, ALIGN_SIZE );

    /*
    ** We must allocate an additional minimum block size bytes so that if
    ** our free block will leave an alignment gap which is smaller, we can
    ** trim a leading free block and release it back to the pool. We must
    ** do this because the previous physical block is in use, therefore
    ** the prev_phys_block field is not valid, and we can't simply adjust
    ** the size of that block.
    */
    let gap_minimum: usize = size_of::<block_header_t>();
    let size_with_gap: usize = adjust_request_size( adjust.wrapping_add( align ).wrapping_add( gap_minimum ), align );

    /*
    ** If alignment is less than or equals base alignment, we're done.
    ** If we requested 0 bytes, return null, as tlsf_malloc(0) does.
    */
    let aligned_size: usize = if adjust != 0 && align > ALIGN_SIZE { size_with_gap } else { adjust };

    let mut block = block_locate_free( control, aligned_size );

    /* This can't be a static assert. */
    tlsf_assert!( size_of::<block_header_t>() == block_size_min + block_header_overhead );

    if !block.is_null()
    {
        let ptr = block_to_ptr( block );
        let mut aligned = align_ptr( ptr, align );
        let mut gap: usize = ( aligned as tlsfptr_t - ptr as tlsfptr_t ) as usize;

        /* If gap size is too small, offset to next aligned boundary. */
        if gap != 0 && gap < gap_minimum
        {
            let gap_remain: usize = gap_minimum - gap;
            let offset: usize = tlsf_max( gap_remain, align );
            let next_aligned = ( aligned as *mut u8 ).wrapping_add( offset ) as *const c_void;

            aligned = align_ptr( next_aligned, align );
            gap = ( aligned as tlsfptr_t - ptr as tlsfptr_t ) as usize;
        }

        if gap != 0
        {
            tlsf_assert!( gap >= gap_minimum, "gap size too small" );
            block = block_trim_free_leading( control, block, gap );
        }
    }

    block_prepare_used( control, block, adjust )
}

pub unsafe fn tlsf_free( tlsf: tlsf_t, ptr: *mut c_void )
{
    /* Don't attempt to free a NULL pointer. */
    if !ptr.is_null()
    {
        let control = tlsf as *mut control_t;
        let mut block = block_from_ptr( ptr );
        tlsf_assert!( !block_is_free( block ), "block already marked as free" );
        block_mark_as_free( block );
        block = block_merge_prev( control, block );
        block = block_merge_next( control, block );
        block_insert( control, block );
    }
}

/*
** The TLSF block information provides us with enough information to
** provide a reasonably intelligent implementation of realloc, growing or
** shrinking the currently allocated block as required.
**
** This routine handles the somewhat esoteric edge cases of realloc:
** - a non-zero size with a null pointer will behave like malloc
** - a zero size with a non-null pointer will behave like free
** - a request that cannot be satisfied will leave the original buffer
**   untouched
** - an extended buffer size will leave the newly-allocated area with
**   contents undefined
*/
pub unsafe fn tlsf_realloc( tlsf: tlsf_t, ptr: *mut c_void, size: usize ) -> *mut c_void
{
    let control = tlsf as *mut control_t;
    let mut p: *mut c_void = ptr::null_mut();

    /* Zero-size requests are treated as free. */
    if !ptr.is_null() && size == 0
    {
        tlsf_free( tlsf, ptr );
    }
    /* Requests with NULL pointers are treated as malloc. */
    else if ptr.is_null()
    {
        p = tlsf_malloc( tlsf, size );
    }
    else
    {
        let block = block_from_ptr( ptr );
        let next = block_next( block );

        let cursize: usize = block_size( block );
        let combined: usize = cursize + block_size( next ) + block_header_overhead;
        let adjust: usize = adjust_request_size( size, ALIGN_SIZE );

        tlsf_assert!( !block_is_free( block ), "block already marked as free" );

        /*
        ** If the next block is used, or when combined with the current
        ** block, does not offer enough space, we must reallocate and copy.
        */
        if adjust > cursize && ( !block_is_free( next ) || adjust > combined )
        {
            p = tlsf_malloc( tlsf, size );
            if !p.is_null()
            {
                let minsize: usize = tlsf_min( cursize, size );
                ptr::copy_nonoverlapping( ptr as *const u8, p as *mut u8, minsize );
                tlsf_free( tlsf, ptr );
            }
        }
        else
        {
            /* Do we need to expand to the next block? */
            if adjust > cursize
            {
                block_merge_next( control, block );
                block_mark_as_used( block );
            }

            /* Trim the resulting block and return the original pointer. */
            block_trim_used( control, block, adjust );
            p = ptr;
        }
    }

    p
}
