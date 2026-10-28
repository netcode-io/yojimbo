/*
    Yojimbo Server Example (insecure)

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

// port: #include "yojimbo.h" is the crate, and <time.h>, <stdio.h> and <stdlib.h> are std
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

// Adapter that logs when clients connect and disconnect. The disconnect reason is recorded
// before OnServerClientDisconnected is called, so it can be queried inside the callback.
// port: `class ServerAdapter : public TestAdapter` embeds the TestAdapter as `base` and calls through it for
// TestAdapter::CreateMessageFactory
struct ServerAdapter
{
    base: TestAdapter,
    server: *mut Server,
}

impl ServerAdapter
{
    fn new() -> ServerAdapter
    {
        ServerAdapter { base: TestAdapter, server: std::ptr::null_mut() }
    }
}

impl Adapter for ServerAdapter
{
    fn CreateMessageFactory( &mut self, allocator: *mut dyn Allocator ) -> *mut dyn MessageFactory
    {
        self.base.CreateMessageFactory( allocator )
    }

    fn OnServerClientConnected( &mut self, clientIndex: i32 )
    {
        print!( "client {} connected\n", clientIndex );
    }

    fn OnServerClientDisconnected( &mut self, clientIndex: i32 )
    {
        yojimbo_assert!( !self.server.is_null() );
        print!( "client {} disconnected: {}\n", clientIndex, GetServerClientDisconnectReasonString( unsafe { ( *self.server ).GetClientDisconnectReason( clientIndex ) } ) );
    }
}

fn ServerMain() -> i32
{
    print!( "started server on port {} (insecure)\n", ServerPort );

    let mut time: f64 = 100.0;

    let config = ClientServerConfig::new();

    // port: memset( privateKey, 0, KeyBytes ) is the zero initializer
    let privateKey = [0u8; KeyBytes as usize];

    let mut serverAdapter = ServerAdapter::new();

    // port: the server holds the adapter by pointer, as upstream holds it by reference; the program reaches the
    // adapter through that same pointer afterwards
    let serverAdapterPointer: *mut ServerAdapter = std::ptr::addr_of_mut!( serverAdapter );

    // port: Server::new returns the server boxed (it must not move while running)
    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &Address::from_string_port( "127.0.0.1", ServerPort as u16 ), &config, serverAdapterPointer as *mut dyn Adapter, time );

    unsafe { ( *serverAdapterPointer ).server = &mut *server; }

    server.Start( MaxClients );

    // port: Address::ToString returns a String (README, "Strings"), so char addressString[256] is gone
    let addressString = server.GetAddress().ToString();
    print!( "server address is {}\n", addressString );

    const deltaTime: f64 = 0.01f32 as f64;

    signal( SIGINT, interrupt_handler );

    while quit.load( Ordering::SeqCst ) == 0
    {
        server.SendPackets();

        server.ReceivePackets();

        time += deltaTime;

        server.AdvanceTime( time );

        if !server.IsRunning()
        {
            break;
        }

        yojimbo_sleep( deltaTime );
    }

    server.Stop();

    0
}

fn main()
{
    print!( "\n" );

    if !InitializeYojimbo()
    {
        print!( "error: failed to initialize Yojimbo!\n" );
        std::process::exit( 1 );
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_INFO );

    // port: srand( (unsigned int) time( NULL ) ) seeds yojimbo_rand, the generator behind yojimbo_random_int
    yojimbo_srand( std::time::SystemTime::now().duration_since( std::time::UNIX_EPOCH ).map( |d| d.as_secs() ).unwrap_or( 0 ) as u32 );

    let result = ServerMain();

    ShutdownYojimbo();

    print!( "\n" );

    // port: the result of main is the process exit code
    std::process::exit( result );
}
