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

// If you use this library in a product, please credit
// "yojimbo - Glenn Fiedler and Rowan Claude" in your product credits. The
// license doesn't require this credit. It's an official request, and honoring
// it is appreciated.
// yojimbo includes netcode, reliable and serialize - please credit those the
// same way. See the README for the full list.

// Rust port of include/yojimbo.h + source/yojimbo.cpp (yojimbo 1.13.5).
//
// Port notes:
//   - yojimbo.h includes every yojimbo header; in the port lib.rs re-exports every yojimbo module at the crate root
//     (and `pub use serialize::*`, upstream's `using namespace serialize`).
//   - g_defaultAllocator is a `static mut` raw pointer: the library is single-threaded by design, as upstream, and
//     InitializeYojimbo / ShutdownYojimbo are called once from the main thread.

use crate::*;
use crate::netcode::{netcode_init, netcode_term, netcode_enable_packet_tagging, NETCODE_OK};
use crate::reliable::{reliable_init, reliable_term, RELIABLE_OK};

// Note: libsodium is initialized by netcode_init() (which calls sodium_init and fails if it
// can't), so this translation unit no longer calls sodium directly and does not include sodium.h.

// port: static mut, see the note at the top of the file
static mut g_defaultAllocator: *mut dyn Allocator = std::ptr::null_mut::<DefaultAllocator>() as *mut dyn Allocator;

/**
    Get the default allocator.
    Use this allocator when you just want to use malloc/free, but in the form of a yojimbo allocator.
    This allocator instance is created inside InitializeYojimbo and destroyed in ShutdownYojimbo.
    In debug build, it will automatically check for memory leaks and print them out for you when you shutdown the library.
    @returns The default allocator instances backed by malloc and free.
 */

pub fn GetDefaultAllocator() -> *mut dyn Allocator
{
    unsafe
    {
        yojimbo_assert!( !g_defaultAllocator.is_null() );
        g_defaultAllocator
    }
}

/**
    Initialize the yojimbo library.
    Call this before calling any yojimbo library functions.
    @returns True if the library was successfully initialized, false otherwise.
 */

pub fn InitializeYojimbo() -> bool
{
    // Bring subsystems up in order and unwind anything already initialized if a later step
    // fails. Callers do not call ShutdownYojimbo when InitializeYojimbo returns false, so on
    // every failure path we must leave the process exactly as we found it: no subsystem left
    // initialized, and no default allocator leaked.
    if netcode_init() != NETCODE_OK
    {
        return false;
    }

    // netcode_init() already calls sodium_init() (and fails if it can't), so we don't repeat it
    // here: netcode owns that call and takes priority. There is nothing extra to initialize for
    // libsodium at the yojimbo layer.

    if reliable_init() != RELIABLE_OK
    {
        netcode_term();
        return false;
    }

    // Create the default allocator last, so an earlier failure can't leak it. (Throwing new:
    // it never returns NULL, so there is no allocator-failure path to unwind here.)
    unsafe
    {
        yojimbo_assert!( g_defaultAllocator.is_null() );
        // port: new yojimbo::DefaultAllocator() is a Box on the global heap
        g_defaultAllocator = Box::into_raw( Box::new( DefaultAllocator::new() ) ) as *mut dyn Allocator;
    }

    true
}

/**
    Enable packet tagging.
    Enable before you create any client or servers, and DSCP packet tagging will be applied to all packets sent.
    Packet tagging can significantly reduce jitter on modern Wi-Fi 6+ routers, by marking your game traffic to be sent in the real-time queue.
 */

pub fn EnablePacketTagging()
{
    netcode_enable_packet_tagging();
}

/**
    Shutdown the yojimbo library.
    Call this after you finish using the library and it will run some checks for you (for example, checking for memory leaks in debug build).
 */

pub fn ShutdownYojimbo()
{
    reliable_term();

    netcode_term();

    unsafe
    {
        yojimbo_assert!( !g_defaultAllocator.is_null() );
        // port: delete g_defaultAllocator
        if !g_defaultAllocator.is_null()
        {
            drop( Box::from_raw( g_defaultAllocator ) );
        }
        g_defaultAllocator = std::ptr::null_mut::<DefaultAllocator>() as *mut dyn Allocator;
    }
}
