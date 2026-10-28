/*
    Yojimbo Client Example (insecure)

    Copyright © 2016 - 2026, Más Bandwidth LLC

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

// port: the program keeps upstream's names (README, "Names")
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_imports, unused_unsafe, static_mut_refs)]
#![allow(clippy::all)]

// port: #include "yojimbo.h" is the crate, and <stdio.h>, <stdlib.h>, <stdint.h>, <inttypes.h> and <time.h> are std
use yojimbo::*;
use std::sync::atomic::{AtomicI32, Ordering};

#[path = "shared.rs"]
mod shared;
use shared::*;

// port: `static volatile int quit` is an atomic: on Windows the Ctrl-C handler runs on a console control thread
static quit: AtomicI32 = AtomicI32::new( 0 );

extern "C" fn interrupt_handler( _dummy: i32 )
{
    quit.store( 1, Ordering::SeqCst );
}

// port: <signal.h>. signal( SIGINT, handler ) is a few lines of FFI per platform: the C library's signal() on unix,
// SetConsoleCtrlHandler on Windows (where the C runtime's SIGINT is Ctrl-C, CTRL_C_EVENT)
const SIGINT: i32 = 2;

#[cfg(unix)]
fn signal( signum: i32, handler: extern "C" fn( i32 ) )
{
    extern "C"
    {
        #[link_name = "signal"]
        fn c_signal( signum: i32, handler: extern "C" fn( i32 ) ) -> usize;
    }
    unsafe { c_signal( signum, handler ); }
}

#[cfg(windows)]
fn signal( signum: i32, handler: extern "C" fn( i32 ) )
{
    #[link(name = "kernel32")]
    extern "system"
    {
        fn SetConsoleCtrlHandler( handlerRoutine: Option<extern "system" fn( u32 ) -> i32>, add: i32 ) -> i32;
    }
    static SIGINT_HANDLER: std::sync::OnceLock<extern "C" fn( i32 )> = std::sync::OnceLock::new();
    extern "system" fn console_ctrl_handler( ctrlType: u32 ) -> i32
    {
        const CTRL_C_EVENT: u32 = 0;
        match SIGINT_HANDLER.get()
        {
            Some( handler ) if ctrlType == CTRL_C_EVENT => { handler( SIGINT ); 1 }
            _ => 0,
        }
    }
    if signum == SIGINT && SIGINT_HANDLER.set( handler ).is_ok()
    {
        unsafe { SetConsoleCtrlHandler( Some( console_ctrl_handler ), 1 ); }
    }
}

#[cfg(not(any(unix, windows)))]
fn signal( _signum: i32, _handler: extern "C" fn( i32 ) )
{
}

fn ClientMain( argc: i32, argv: &[String] ) -> i32
{
    print!( "\nconnecting client (insecure)\n" );

    let mut time: f64 = 100.0;

    let mut clientId: u64 = 0;
    // port: yojimbo_random_bytes( (uint8_t*) &clientId, 8 ) fills the bytes of the u64 in memory order
    let mut clientIdBytes = [0u8; 8];
    yojimbo_random_bytes( &mut clientIdBytes, 8 );
    clientId = u64::from_ne_bytes( clientIdBytes );
    print!( "client id is {:016x}\n", clientId );

    let config = ClientServerConfig::new();

    // port: Client::new returns the client boxed (it must not move while connected); GetTestAdapter() is `adapter`
    let mut client = Client::new( GetDefaultAllocator(), &Address::from_string( "0.0.0.0" ), &config, GetTestAdapter(), time );

    let mut serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    if argc == 2
    {
        let mut commandLineAddress = Address::from_string( &argv[1] );
        if commandLineAddress.IsValid()
        {
            if commandLineAddress.GetPort() == 0
            {
                commandLineAddress.SetPort( ServerPort as u16 );
            }
            serverAddress = commandLineAddress;
        }
    }

    // port: memset( privateKey, 0, KeyBytes ) is the zero initializer
    let privateKey = [0u8; KeyBytes as usize];

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    // port: Address::ToString returns a String (README, "Strings"), so char addressString[256] is gone
    let addressString = client.GetAddress().ToString();
    print!( "client address is {}\n", addressString );

    const deltaTime: f64 = 0.01f32 as f64;

    signal( SIGINT, interrupt_handler );

    while quit.load( Ordering::SeqCst ) == 0
    {
        client.SendPackets();

        client.ReceivePackets();

        if client.IsDisconnected()
        {
            break;
        }

        time += deltaTime;

        client.AdvanceTime( time );

        if client.ConnectionFailed()
        {
            break;
        }

        yojimbo_sleep( deltaTime );
    }

    client.Disconnect();

    // Why did we end up disconnected? Deliberate disconnect (ctrl-c), kicked by the server,
    // connect failure (eg. no server running), timeout etc. See ClientDisconnectReason.
    print!( "client disconnected: {}\n", GetClientDisconnectReasonString( client.GetDisconnectReason() ) );

    0
}

fn main()
{
    // port: int main( int argc, char * argv[] ); the result is the process exit code
    let argv: Vec<String> = std::env::args().collect();
    let argc = argv.len() as i32;

    if !InitializeYojimbo()
    {
        print!( "error: failed to initialize Yojimbo!\n" );
        std::process::exit( 1 );
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_INFO );

    // port: srand( (unsigned int) time( NULL ) ) seeds yojimbo_rand, the generator behind yojimbo_random_int
    yojimbo_srand( std::time::SystemTime::now().duration_since( std::time::UNIX_EPOCH ).map( |d| d.as_secs() ).unwrap_or( 0 ) as u32 );

    let result = ClientMain( argc, &argv );

    ShutdownYojimbo();

    print!( "\n" );

    std::process::exit( result );
}
