/*
    Yojimbo Soak Test.

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

// port: #include "shared.h" brings in yojimbo.h, which is the crate; <stdio.h>, <stdlib.h> and <math.h> are std
use yojimbo::*;
use std::sync::atomic::{AtomicI32, Ordering};

#[path = "shared.rs"]
mod shared;
use shared::*;

const MaxPacketSize: i32 = 16 * 1024;
const MaxSnapshotSize: i32 = 8 * 1024;
const MaxBlockSize: i32 = 10 * 1024;

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

// port: the C library's rand() / srand() are yojimbo_rand() / yojimbo_srand(), the generator behind yojimbo_random_int
// (see yojimbo_utils.rs), so one seed reproduces a run
fn rand() -> i32
{
    yojimbo_rand()
}

fn srand( seed: u32 )
{
    yojimbo_srand( seed );
}

const UNRELIABLE_UNORDERED_CHANNEL: i32 = 0;
const RELIABLE_ORDERED_CHANNEL: i32 = 1;

fn SoakMain( iterations: i32 ) -> i32
{
    let mut config = ClientServerConfig::new();
    config.maxPacketSize = MaxPacketSize;
    // maxPacketFragments was derived from the default maxPacketSize in the ClientServerConfig
    // constructor. We just doubled maxPacketSize, so recompute it or packets larger than
    // packetFragmentSize * maxPacketFragments can't be fragmented (config.Validate() catches this).
    config.maxPacketFragments = ( config.maxPacketSize as f64 / config.packetFragmentSize as f64 ).ceil() as i32;
    config.clientMemory = 100 * 1024 * 1024;
    config.serverGlobalMemory = 10 * 1024 * 1024;
    config.serverPerClientMemory = 100 * 1024 * 1024;
    config.numChannels = 2;
    config.channel[UNRELIABLE_UNORDERED_CHANNEL as usize].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    config.channel[UNRELIABLE_UNORDERED_CHANNEL as usize].maxBlockSize = MaxSnapshotSize;
    config.channel[RELIABLE_ORDERED_CHANNEL as usize].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[RELIABLE_ORDERED_CHANNEL as usize].maxBlockSize = MaxBlockSize;
    config.channel[RELIABLE_ORDERED_CHANNEL as usize].blockFragmentSize = 1024;

    // port: memset( privateKey, 0, KeyBytes ) is the zero initializer
    let privateKey = [0u8; KeyBytes as usize];

    let mut time: f64 = 0.0;

    let serverAddress = Address::from_string_port( "127.0.0.1", ServerPort as u16 );

    // port: Server::new and Client::new return the object boxed (it must not move while in use); GetTestAdapter()
    // is `adapter`
    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &serverAddress, &config, GetTestAdapter(), time );

    server.Start( 1 );

    server.SetLatency( 1000.0 );
    server.SetJitter( 100.0 );
    server.SetPacketLoss( 25.0 );
    server.SetDuplicates( 25.0 );

    let mut clientId: u64 = 0;
    // port: yojimbo_random_bytes( (uint8_t*) &clientId, 8 ) fills the bytes of the u64 in memory order
    let mut clientIdBytes = [0u8; 8];
    yojimbo_random_bytes( &mut clientIdBytes, 8 );
    clientId = u64::from_ne_bytes( clientIdBytes );

    let mut client = Client::new( GetDefaultAllocator(), &Address::from_string( "0.0.0.0" ), &config, GetTestAdapter(), time );

    client.InsecureConnect( &privateKey, clientId, &serverAddress );

    client.SetLatency( 1000.0 );
    client.SetJitter( 100.0 );
    client.SetPacketLoss( 25.0 );
    client.SetDuplicates( 25.0 );

    let mut numMessagesSentToServer: u64 = 0;
    let mut numMessagesSentToClient: u64 = 0;
    let mut numMessagesReceivedFromClient: u64 = 0;
    let mut numMessagesReceivedFromServer: u64 = 0;

    signal( SIGINT, interrupt_handler );

    let mut clientConnected = false;
    let mut serverConnected = false;

    let mut timeForNextClientMessage: f64 = 0.0;
    let mut timeForNextServerMessage: f64 = 0.0;

    // iterations <= 0 runs until interrupted (SIGINT); a positive count time-boxes the
    // run so it exits cleanly — used by CI to soak under sanitizers for a bounded time.
    let mut iteration: i32 = 0;

    while quit.load( Ordering::SeqCst ) == 0 && ( iterations <= 0 || iteration < iterations )
    {
        iteration += 1;

        client.SendPackets();
        server.SendPackets();

        client.ReceivePackets();
        server.ReceivePackets();

        if client.ConnectionFailed()
        {
            print!( "error: client connect failed!\n" );
            break;
        }

        time += 0.1f32 as f64;

        if client.IsConnected()
        {
            if ( rand() % 100000 ) == 0
            {
                print!( "client reconnect\n" );
                client.Disconnect();
                client.InsecureConnect( &privateKey, clientId, &serverAddress );
                clientConnected = false;
                numMessagesSentToServer = 0;
                numMessagesSentToClient = 0;
                numMessagesReceivedFromClient = 0;
                numMessagesReceivedFromServer = 0;
            }
        }

        if client.IsConnected()
        {
            clientConnected = true;

            if timeForNextClientMessage < time && ( rand() % 1000 ) == 0
            {
                timeForNextClientMessage = time + yojimbo_random_int( 1, 1000 ) as f64;
            }

            if timeForNextClientMessage <= time
            {
                let messagesToSend = yojimbo_random_int( 0, 64 );

                for i in 0..messagesToSend
                {
                    if !client.CanSendMessage( RELIABLE_ORDERED_CHANNEL )
                    {
                        break;
                    }

                    if rand() % 100 != 0
                    {
                        // port: (TestMessage*) client.CreateMessage( TEST_MESSAGE ) stays a `*mut dyn Message`;
                        // message_cast reaches the TestMessage fields
                        let message = client.CreateMessage( TEST_MESSAGE );
                        if !message.is_null()
                        {
                            unsafe { message_cast::<TestMessage>( message ) }.sequence = numMessagesSentToServer as u16;
                            client.SendMessage( RELIABLE_ORDERED_CHANNEL, message );
                            numMessagesSentToServer += 1;
                        }
                    }
                    else
                    {
                        let numBlocks = yojimbo_random_int( 1, 3 );

                        for k in 0..numBlocks
                        {
                            if !client.CanSendMessage( RELIABLE_ORDERED_CHANNEL )
                            {
                                break;
                            }

                            let blockMessage = client.CreateMessage( TEST_BLOCK_MESSAGE );
                            if !blockMessage.is_null()
                            {
                                unsafe { message_cast::<TestBlockMessage>( blockMessage ) }.sequence = numMessagesSentToServer as u16;
                                let blockSize = 1 + ( ( numMessagesSentToServer as i32 ).wrapping_mul( 33 ) ) % MaxBlockSize;
                                let blockData = client.AllocateBlock( blockSize );
                                if !blockData.is_null()
                                {
                                    // port: the block is a raw allocation of blockSize bytes; written through a slice
                                    let block = unsafe { std::slice::from_raw_parts_mut( blockData, blockSize as usize ) };
                                    for j in 0..blockSize
                                    {
                                        block[j as usize] = numMessagesSentToServer.wrapping_add( j as u64 ) as u8;
                                    }
                                    client.AttachBlockToMessage( blockMessage, blockData, blockSize );
                                    client.SendMessage( RELIABLE_ORDERED_CHANNEL, blockMessage );
                                    numMessagesSentToServer += 1;
                                }
                                else
                                {
                                    client.ReleaseMessage( blockMessage );
                                }
                            }
                        }
                    }
                }
            }

            let clientIndex = client.GetClientIndex();

            if timeForNextServerMessage < time && ( rand() % 1000 ) == 0
            {
                let delay = yojimbo_random_int( 1, 1000 );

                timeForNextServerMessage = time + delay as f64;
            }

            if server.IsClientConnected( clientIndex )
            {
                serverConnected = true;

                if timeForNextServerMessage <= time
                {
                    let messagesToSend = yojimbo_random_int( 0, 64 );

                    for i in 0..messagesToSend
                    {
                        if !server.CanSendMessage( clientIndex, RELIABLE_ORDERED_CHANNEL )
                        {
                            break;
                        }

                        if rand() % 100 != 0
                        {
                            let message = server.CreateMessage( clientIndex, TEST_MESSAGE );
                            if !message.is_null()
                            {
                                unsafe { message_cast::<TestMessage>( message ) }.sequence = numMessagesSentToClient as u16;
                                server.SendMessage( clientIndex, RELIABLE_ORDERED_CHANNEL, message );
                                numMessagesSentToClient += 1;
                            }
                        }
                        else
                        {
                            let numBlocks = yojimbo_random_int( 1, 3 );

                            for k in 0..numBlocks
                            {
                                if !server.CanSendMessage( clientIndex, RELIABLE_ORDERED_CHANNEL )
                                {
                                    break;
                                }

                                let blockMessage = server.CreateMessage( clientIndex, TEST_BLOCK_MESSAGE );
                                if !blockMessage.is_null()
                                {
                                    unsafe { message_cast::<TestBlockMessage>( blockMessage ) }.sequence = numMessagesSentToClient as u16;
                                    let blockSize = 1 + ( ( numMessagesSentToClient as i32 ).wrapping_mul( 33 ) ) % MaxBlockSize;
                                    let blockData = server.AllocateBlock( clientIndex, blockSize );
                                    if !blockData.is_null()
                                    {
                                        // port: the block is a raw allocation of blockSize bytes; written through a slice
                                        let block = unsafe { std::slice::from_raw_parts_mut( blockData, blockSize as usize ) };
                                        for j in 0..blockSize
                                        {
                                            block[j as usize] = numMessagesSentToClient.wrapping_add( j as u64 ) as u8;
                                        }
                                        server.AttachBlockToMessage( clientIndex, blockMessage, blockData, blockSize );
                                        server.SendMessage( clientIndex, RELIABLE_ORDERED_CHANNEL, blockMessage );
                                        numMessagesSentToClient += 1;
                                    }
                                    else
                                    {
                                        server.ReleaseMessage( clientIndex, blockMessage );
                                    }
                                }
                            }
                        }
                    }
                }

                loop
                {
                    let message = server.ReceiveMessage( clientIndex, RELIABLE_ORDERED_CHANNEL );
                    if message.is_null()
                    {
                        break;
                    }

                    yojimbo_assert!( unsafe { ( *message ).GetId() } == numMessagesReceivedFromClient as u16 as i32 );

                    match unsafe { ( *message ).GetType() }
                    {
                        TEST_MESSAGE =>
                        {
                            let testMessage = unsafe { message_cast::<TestMessage>( message ) };
                            yojimbo_assert!( testMessage.sequence == numMessagesReceivedFromClient as u16 );
                            print!( "server received message {}\n", testMessage.sequence );
                            server.ReleaseMessage( clientIndex, message );
                            numMessagesReceivedFromClient += 1;
                        }

                        TEST_BLOCK_MESSAGE =>
                        {
                            let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
                            yojimbo_assert!( blockMessage.sequence == numMessagesReceivedFromClient as u16 );
                            let blockSize = blockMessage.GetBlockSize();
                            let expectedBlockSize = 1 + ( ( numMessagesReceivedFromClient as i32 ).wrapping_mul( 33 ) ) % MaxBlockSize;
                            if blockSize != expectedBlockSize
                            {
                                print!( "error: block size mismatch. expected {}, got {}\n", expectedBlockSize, blockSize );
                                return 1;
                            }
                            let blockData = blockMessage.GetBlockData();
                            yojimbo_assert!( !blockData.is_null() );
                            // port: the block is a raw allocation of blockSize bytes; read through a slice
                            let block = unsafe { std::slice::from_raw_parts( blockData, blockSize as usize ) };
                            for i in 0..blockSize
                            {
                                if block[i as usize] != numMessagesReceivedFromClient.wrapping_add( i as u64 ) as u8
                                {
                                    print!( "error: block data mismatch. expected {}, but blockData[{}] = {}\n", numMessagesReceivedFromClient.wrapping_add( i as u64 ) as u8, i, block[i as usize] );
                                    return 1;
                                }
                            }
                            print!( "server received message {}\n", numMessagesReceivedFromClient as u16 );
                            server.ReleaseMessage( clientIndex, message );
                            numMessagesReceivedFromClient += 1;
                        }

                        _ => {}
                    }
                }
            }

            loop
            {
                let message = client.ReceiveMessage( RELIABLE_ORDERED_CHANNEL );

                if message.is_null()
                {
                    break;
                }

                yojimbo_assert!( unsafe { ( *message ).GetId() } == numMessagesReceivedFromServer as u16 as i32 );

                match unsafe { ( *message ).GetType() }
                {
                    TEST_MESSAGE =>
                    {
                        let testMessage = unsafe { message_cast::<TestMessage>( message ) };
                        yojimbo_assert!( testMessage.sequence == numMessagesReceivedFromServer as u16 );
                        print!( "client received message {}\n", testMessage.sequence );
                        client.ReleaseMessage( message );
                        numMessagesReceivedFromServer += 1;
                    }

                    TEST_BLOCK_MESSAGE =>
                    {
                        let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
                        yojimbo_assert!( blockMessage.sequence == numMessagesReceivedFromServer as u16 );
                        let blockSize = blockMessage.GetBlockSize();
                        let expectedBlockSize = 1 + ( ( numMessagesReceivedFromServer as i32 ).wrapping_mul( 33 ) ) % MaxBlockSize;
                        if blockSize != expectedBlockSize
                        {
                            print!( "error: block size mismatch. expected {}, got {}\n", expectedBlockSize, blockSize );
                            return 1;
                        }
                        let blockData = blockMessage.GetBlockData();
                        yojimbo_assert!( !blockData.is_null() );
                        // port: the block is a raw allocation of blockSize bytes; read through a slice
                        let block = unsafe { std::slice::from_raw_parts( blockData, blockSize as usize ) };
                        for i in 0..blockSize
                        {
                            if block[i as usize] != numMessagesReceivedFromServer.wrapping_add( i as u64 ) as u8
                            {
                                print!( "error: block data mismatch. expected {}, but blockData[{}] = {}\n", numMessagesReceivedFromServer.wrapping_add( i as u64 ) as u8, i, block[i as usize] );
                                return 1;
                            }
                        }
                        print!( "client received message {}\n", numMessagesReceivedFromServer as u16 );
                        client.ReleaseMessage( message );
                        numMessagesReceivedFromServer += 1;
                    }

                    _ => {}
                }
            }

            if clientConnected && !client.IsConnected()
            {
                break;
            }

            if serverConnected && server.GetNumConnectedClients() == 0
            {
                break;
            }
        }

        client.AdvanceTime( time );
        server.AdvanceTime( time );
    }

    if quit.load( Ordering::SeqCst ) != 0
    {
        print!( "\nstopped\n" );
    }

    client.Disconnect();

    server.Stop();

    0
}

// port: atoi; like atoi, a leading integer is parsed and anything else is zero
fn atoi( s: &str ) -> i32
{
    let s = s.trim_start();
    let end = s.char_indices().find( |&( i, c )| !( c.is_ascii_digit() || ( i == 0 && ( c == '-' || c == '+' ) ) ) ).map( |( i, _ )| i ).unwrap_or( s.len() );
    s[..end].parse::<i64>().map( |v| v as i32 ).unwrap_or( 0 )
}

fn main()
{
    print!( "\nsoak\n" );

    // port: int main( int argc, char ** argv ); the result is the process exit code
    let argv: Vec<String> = std::env::args().collect();
    let argc = argv.len() as i32;

    // Optional iteration count: `soak [iterations]`. Zero or absent runs until Ctrl-C.
    let iterations = if argc > 1 { atoi( &argv[1] ) } else { 0 };

    if !InitializeYojimbo()
    {
        print!( "error: failed to initialize Yojimbo!\n" );
        std::process::exit( 1 );
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_INFO );

    // port: time( NULL )
    srand( std::time::SystemTime::now().duration_since( std::time::UNIX_EPOCH ).map( |d| d.as_secs() ).unwrap_or( 0 ) as u32 );

    let result = SoakMain( iterations );

    ShutdownYojimbo();

    print!( "\n" );

    std::process::exit( result );
}
