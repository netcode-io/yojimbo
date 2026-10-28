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

/*
    Rust port of include/yojimbo_platform.h + source/yojimbo_platform.cpp (yojimbo 1.13.5).

    Port notes:
      - yojimbo_printf! takes a Rust format string (upstream: printf format); the function behind it,
        yojimbo_printf, takes the format_args!. The printf hook is fn( &str ) and receives the formatted text.
      - yojimbo_assert! is active in debug builds (cfg(debug_assertions), upstream's YOJIMBO_DEBUG / !NDEBUG). Like
        upstream it calls the assert hook, then exits the process with status 1. The default handler prints as upstream
        and panics (upstream: __builtin_trap / __debugbreak).
      - The globals (log level, printf and assert hooks) are an atomic and mutexes; the library is single-threaded by
        design, as upstream.
      - Time is std::time::Instant and sleep is std::thread::sleep (see README.md, "Platform"), in place of the
        per-platform mach_absolute_time / clock_gettime / QueryPerformanceCounter and usleep / Sleep paths.
*/

use crate::*;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// port: yojimbo_sleep and yojimbo_time, declared here upstream, are defined at the end of the file

pub const YOJIMBO_LOG_LEVEL_NONE: i32 = 0;
pub const YOJIMBO_LOG_LEVEL_ERROR: i32 = 1;
pub const YOJIMBO_LOG_LEVEL_INFO: i32 = 2;
pub const YOJIMBO_LOG_LEVEL_DEBUG: i32 = 3;

/**
    Printf function used by yojimbo to emit logs.
    This function internally calls the printf callback set by the user.
    @see yojimbo_set_printf_function
 */

#[macro_export]
macro_rules! yojimbo_printf {
    ( $level:expr, $($arg:tt)* ) => {
        $crate::yojimbo_platform::yojimbo_printf( ( $level ) as i32, ::core::format_args!( $($arg)* ) )
    };
}

/// port: the name of the enclosing function, for yojimbo_assert! (upstream: __FUNCTION__)
#[doc(hidden)]
#[macro_export]
macro_rules! yojimbo_function_name {
    () => {{
        fn __yojimbo_f() {}
        let name = ::core::any::type_name_of_val( &__yojimbo_f );
        &name[..name.len() - "::__yojimbo_f".len()]
    }};
}

/**
    Assert function used by yojimbo.
    This assert function lets the user override the assert presentation.
    @see yojimbo_set_assert_function
 */

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! yojimbo_assert {
    ( $condition:expr ) => {{
        if !( $condition ) {
            $crate::yojimbo_platform::yojimbo_assert_function_call( ::core::stringify!( $condition ), $crate::yojimbo_function_name!(), ::core::file!(), ::core::line!() as i32 );
            ::std::process::exit( 1 );
        }
    }};
}

// port: in release the condition is not compiled, as upstream's ((void)0)
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! yojimbo_assert {
    ( $condition:expr ) => {{}};
}

fn default_assert_handler( condition: &str, function: &str, file: &str, line: i32 )
{
    // We use YOJIMBO_LOG_LEVEL_NONE because it's lower than YOJIMBO_LOG_LEVEL_ERROR, so even if you suppress errors (by setting
    // yojimbo_log_level(YOJIMBO_LOG_LEVEL_NONE)), this will still be logged.
    yojimbo_printf!( YOJIMBO_LOG_LEVEL_NONE, "assert failed: ( {} ), function {}, file {}, line {}\n", condition, function, file, line );
    // port: __builtin_trap() / __debugbreak()
    panic!( "assert failed: ( {} ), function {}, file {}, line {}", condition, function, file, line );
}

static log_level: AtomicI32 = AtomicI32::new( 0 );

// port: upstream's printf; the hook receives the formatted text
fn printf( s: &str )
{
    print!( "{}", s );
}

static printf_function: Mutex<fn( &str )> = Mutex::new( printf );

/// port: upstream's `extern void (*yojimbo_assert_function)(...)`, behind a mutex. Call it with yojimbo_assert_function_call.
pub static yojimbo_assert_function: Mutex<fn( &str, &str, &str, i32 )> = Mutex::new( default_assert_handler );

/// port: calls the current assert function (upstream calls the yojimbo_assert_function pointer directly)
pub fn yojimbo_assert_function_call( condition: &str, function: &str, file: &str, line: i32 )
{
    let function_ptr = *yojimbo_assert_function.lock().unwrap_or_else( |e| e.into_inner() );
    function_ptr( condition, function, file, line );
}

/**
    Set the yojimbo log level.
    Valid log levels are: YOJIMBO_LOG_LEVEL_NONE, YOJIMBO_LOG_LEVEL_ERROR, YOJIMBO_LOG_LEVEL_INFO and YOJIMBO_LOG_LEVEL_DEBUG
    @param level The log level to set. Initially set to YOJIMBO_LOG_LEVEL_NONE.
 */

pub fn yojimbo_log_level( level: i32 )
{
    log_level.store( level, Ordering::Relaxed );
    crate::netcode::netcode_log_level( level );
    crate::reliable::reliable_log_level( level );
}

/**
    Call this to set the printf function to use for logging.
    @param function The printf callback function.
 */

pub fn yojimbo_set_printf_function( function: fn( &str ) )
{
    // port: yojimbo_assert( function ) -- a Rust fn pointer is never null
    *printf_function.lock().unwrap_or_else( |e| e.into_inner() ) = function;
    crate::netcode::netcode_set_printf_function( function );
    crate::reliable::reliable_set_printf_function( function );
}

/**
    Call this to set the function to call when an assert triggers.
    @param function The assert callback function.
 */

pub fn yojimbo_set_assert_function( function: fn( &str, &str, &str, i32 ) )
{
    *yojimbo_assert_function.lock().unwrap_or_else( |e| e.into_inner() ) = function;
    crate::netcode::netcode_set_assert_function( function );
    crate::reliable::reliable_set_assert_function( function );
}

/// port: the function behind yojimbo_printf!; takes the format_args! in place of a printf format and varargs
// port: #if YOJIMBO_ENABLE_LOGGING is a const test (YOJIMBO_ENABLE_LOGGING is a const in yojimbo_config.rs)
pub fn yojimbo_printf( level: i32, args: std::fmt::Arguments )
{
    if !YOJIMBO_ENABLE_LOGGING
    {
        return;
    }
    if level > log_level.load( Ordering::Relaxed )
    {
        return;
    }
    // port: no 4k buffer, so long messages are not truncated
    let buffer = std::fmt::format( args );
    let function = *printf_function.lock().unwrap_or_else( |e| e.into_inner() );
    function( &buffer );
}

// ===============================
//      Time (all platforms)
// ===============================

// port: upstream has a MacOS (mach_absolute_time), Unix (clock_gettime) and Windows (QueryPerformanceCounter) version;
// std::time::Instant is the monotonic clock of each of those platforms.

/**
    Sleep for approximately this number of seconds.
    @param time number of seconds to sleep for.
 */

#[cfg(windows)]
pub fn yojimbo_sleep( time: f64 )
{
    let milliseconds = ( time * 1000.0 ) as i32;
    // port: Sleep( milliseconds )
    if milliseconds > 0
    {
        std::thread::sleep( Duration::from_millis( milliseconds as u64 ) );
    }
}

#[cfg(not(windows))]
pub fn yojimbo_sleep( time: f64 )
{
    // port: usleep( (int) ( time * 1000000 ) )
    let microseconds = ( time * 1000000.0 ) as i32;
    if microseconds > 0
    {
        std::thread::sleep( Duration::from_micros( microseconds as u64 ) );
    }
}

static start: OnceLock<Instant> = OnceLock::new();

/**
    Get a high precision time in seconds since the application has started.
    Please store time in doubles so you retain sufficient precision as time increases.
    @returns Time value in seconds.
 */

pub fn yojimbo_time() -> f64
{
    let mut first = false;
    let start_time = *start.get_or_init( || { first = true; Instant::now() } );
    if first
    {
        return 0.0;
    }
    let current = Instant::now();
    // port: Instant is monotonic, so current < start (clamped upstream) cannot happen; saturating_duration_since keeps the clamp
    current.saturating_duration_since( start_time ).as_secs_f64()
}
