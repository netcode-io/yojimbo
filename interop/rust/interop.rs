/*
    Cross-implementation interop test (Rust side). Mirrors interop/interop.cpp line for line; see that file for
    the protocol. Any pairing of the C++, C#, TypeScript and Rust sides can be run:

        cargo run --release --manifest-path interop/rust/Cargo.toml -- server [port]
        cargo run --release --manifest-path interop/rust/Cargo.toml -- client [port]
*/

// port: the program keeps upstream's names (rust/README.md, "Names")
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_imports, unused_unsafe, static_mut_refs)]
#![allow(clippy::all)]

// port: #include "yojimbo.h" is the crate; #include "shared.h" is rust/shared.rs, pulled in by path as
// interop/cs/interop.csproj pulls in cs/shared.cs
use yojimbo::*;
use std::io::Write;

#[path = "../../rust/shared.rs"]
mod shared;
use shared::*;

const NumMessages: i32 = 1000;
const BlockEvery: i32 = 8;
const TimeoutSeconds: f64 = 60.0;

fn BlockSizeFor( sequence: i32 ) -> i32 { 1 + ( sequence * 977 ) % 5000 }

fn BlockByte( sequence: i32, i: i32 ) -> u8 { ( ( sequence * 31 + i * 7 ) & 0xFF ) as u8 }

// port: InitConfig( ClientServerConfig & config ) fills in the caller's config
fn InitConfig( config: &mut ClientServerConfig )
{
    config.protocolId = ProtocolId;
    config.numChannels = 2;
    config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[1].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
}

// port: printf + fflush( stdout )
macro_rules! printf {
    ( $($arg:tt)* ) => {{
        print!( $($arg)* );
        let _ = std::io::stdout().flush();
    }};
}

fn ServerMain( port: i32 ) -> i32
{
    let mut config = ClientServerConfig::new();
    InitConfig( &mut config );

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    let mut time: f64 = 100.0;
    let deltaTime: f64 = 0.01;

    // port: a Box (Server::new), not a stack object; it is dropped at the end of this function, as upstream's is
    let mut server = Server::new( GetDefaultAllocator(), &privateKey, &Address::from_string_port( "127.0.0.1", port as u16 ), &config, GetTestAdapter(), time );
    if !server.Start( MaxClients )
    {
        printf!( "server: failed to start\n" );
        return 1;
    }
    printf!( "server: listening on 127.0.0.1:{}\n", port );

    let mut hadClient = false;
    let mut idleSince = time;
    loop
    {
        server.SendPackets();
        server.ReceivePackets();
        time += deltaTime;
        server.AdvanceTime( time );

        let mut anyConnected = false;
        for clientIndex in 0..MaxClients
        {
            if !server.IsClientConnected( clientIndex )
            {
                continue;
            }
            anyConnected = true;
            hadClient = true;
            for channel in 0..config.numChannels
            {
                loop
                {
                    let message = server.ReceiveMessage( clientIndex, channel );
                    if message.is_null()
                    {
                        break;
                    }
                    if !server.CanSendMessage( clientIndex, channel )
                    {
                        server.ReleaseMessage( clientIndex, message );
                        continue;
                    }
                    let messageType = unsafe { ( *message ).GetType() };
                    if messageType == TEST_BLOCK_MESSAGE
                    {
                        let r#in = unsafe { message_cast::<TestBlockMessage>( message ) };
                        let out = server.CreateMessage( clientIndex, TEST_BLOCK_MESSAGE );
                        unsafe { message_cast::<TestBlockMessage>( out ) }.sequence = r#in.sequence;
                        let block = server.AllocateBlock( clientIndex, r#in.GetBlockSize() );
                        unsafe { std::ptr::copy_nonoverlapping( r#in.GetBlockData(), block, r#in.GetBlockSize() as usize ) };
                        server.AttachBlockToMessage( clientIndex, out, block, r#in.GetBlockSize() );
                        server.SendMessage( clientIndex, channel, out );
                    }
                    else if messageType == TEST_MESSAGE
                    {
                        let out = server.CreateMessage( clientIndex, TEST_MESSAGE );
                        unsafe { message_cast::<TestMessage>( out ) }.sequence = unsafe { message_cast::<TestMessage>( message ) }.sequence;
                        server.SendMessage( clientIndex, channel, out );
                    }
                    server.ReleaseMessage( clientIndex, message );
                }
            }
        }

        // exit once the client has come and gone, or nobody shows up
        if anyConnected
        {
            idleSince = time;
        }
        else if hadClient && time - idleSince > 1.0
        {
            break;
        }
        else if !hadClient && time - idleSince > TimeoutSeconds
        {
            printf!( "server: no client connected\n" );
            server.Stop();
            return 1;
        }

        yojimbo_sleep( deltaTime );
    }

    server.Stop();
    printf!( "server: done\n" );
    0
}

fn ClientMain( port: i32 ) -> i32
{
    let mut config = ClientServerConfig::new();
    InitConfig( &mut config );

    let mut privateKey = [0u8; KeyBytes as usize];
    privateKey.fill( 0 );

    // port: yojimbo_random_bytes( (uint8_t*) &clientId, 8 ) fills the bytes of the integer (little endian, as on
    // every platform upstream runs on)
    let mut clientIdBytes = [0u8; 8];
    yojimbo_random_bytes( &mut clientIdBytes, 8 );
    let clientId: u64 = u64::from_le_bytes( clientIdBytes );

    let mut time: f64 = 100.0;
    let deltaTime: f64 = 0.01;

    // port: a Box (Client::new), not a stack object; it is dropped at the end of this function, as upstream's is
    let mut client = Client::new( GetDefaultAllocator(), &Address::from_string( "0.0.0.0" ), &config, GetTestAdapter(), time );
    client.InsecureConnect( &privateKey, clientId, &Address::from_string_port( "127.0.0.1", port as u16 ) );

    let mut numSent: i32 = 0;
    let mut numReceived: i32 = 0;
    let mut numUnreliableEchoes: i32 = 0;
    let mut unreliableSequence: u16 = 0;
    let start = time;
    let mut result: i32 = 1;

    loop
    {
        client.SendPackets();
        client.ReceivePackets();
        time += deltaTime;
        client.AdvanceTime( time );

        if client.ConnectionFailed() || ( client.IsDisconnected() && time - start > 1.0 )
        {
            printf!( "client: connection failed ({})\n", GetClientDisconnectReasonString( client.GetDisconnectReason() ) );
            break;
        }

        if time - start > TimeoutSeconds
        {
            printf!( "client: timed out with {}/{} echoes\n", numReceived, NumMessages );
            break;
        }

        if client.IsConnected()
        {
            while numSent < NumMessages && client.CanSendMessage( 0 )
            {
                if numSent % BlockEvery == 0
                {
                    let message = client.CreateMessage( TEST_BLOCK_MESSAGE );
                    unsafe { message_cast::<TestBlockMessage>( message ) }.sequence = numSent as u16;
                    let blockSize = BlockSizeFor( numSent );
                    let block = client.AllocateBlock( blockSize );
                    // port: the uint8_t * block from the allocator, written through a slice over it
                    let blockSlice = unsafe { std::slice::from_raw_parts_mut( block, blockSize as usize ) };
                    for i in 0..blockSize
                    {
                        blockSlice[i as usize] = BlockByte( numSent, i );
                    }
                    client.AttachBlockToMessage( message, block, blockSize );
                    client.SendMessage( 0, message );
                }
                else
                {
                    let message = client.CreateMessage( TEST_MESSAGE );
                    unsafe { message_cast::<TestMessage>( message ) }.sequence = numSent as u16;
                    client.SendMessage( 0, message );
                }
                numSent += 1;
            }

            if client.CanSendMessage( 1 )
            {
                let message = client.CreateMessage( TEST_MESSAGE );
                unsafe { message_cast::<TestMessage>( message ) }.sequence = unreliableSequence;
                unreliableSequence = unreliableSequence.wrapping_add( 1 );
                client.SendMessage( 1, message );
            }

            loop
            {
                let message = client.ReceiveMessage( 0 );
                if message.is_null()
                {
                    break;
                }
                let expected = numReceived;
                let mut ok: bool;
                let messageType = unsafe { ( *message ).GetType() };
                if expected % BlockEvery == 0
                {
                    ok = messageType == TEST_BLOCK_MESSAGE && unsafe { message_cast::<TestBlockMessage>( message ) }.sequence == expected as u16;
                    if ok
                    {
                        let blockMessage = unsafe { message_cast::<TestBlockMessage>( message ) };
                        ok = blockMessage.GetBlockSize() == BlockSizeFor( expected );
                        let mut i = 0;
                        while ok && i < blockMessage.GetBlockSize()
                        {
                            ok = unsafe { *blockMessage.GetBlockData().add( i as usize ) } == BlockByte( expected, i );
                            i += 1;
                        }
                    }
                }
                else
                {
                    ok = messageType == TEST_MESSAGE && unsafe { message_cast::<TestMessage>( message ) }.sequence == expected as u16;
                }
                client.ReleaseMessage( message );
                if !ok
                {
                    printf!( "client: echo {} is wrong\n", expected );
                    client.Disconnect();
                    return 1;
                }
                numReceived += 1;
            }

            loop
            {
                let message = client.ReceiveMessage( 1 );
                if message.is_null()
                {
                    break;
                }
                numUnreliableEchoes += 1;
                client.ReleaseMessage( message );
            }

            if numReceived == NumMessages
            {
                printf!( "client: {} reliable echoes verified ({} blocks), {} unreliable echoes\n", numReceived, ( NumMessages + BlockEvery - 1 ) / BlockEvery, numUnreliableEchoes );
                result = if numUnreliableEchoes > 0 { 0 } else { 1 };
                if result != 0
                {
                    printf!( "client: no unreliable echoes\n" );
                }
                break;
            }
        }

        yojimbo_sleep( deltaTime );
    }

    client.Disconnect();
    result
}

// port: int main( int argc, char * argv[] ), with the exit code passed to std::process::exit
fn main()
{
    std::process::exit( interop_main() );
}

fn interop_main() -> i32
{
    let argv: Vec<String> = std::env::args().collect();
    let argc = argv.len();

    if argc < 2 || ( argv[1] != "server" && argv[1] != "client" )
    {
        printf!( "usage: interop server|client [port]\n" );
        return 1;
    }

    // port: atoi, which yields 0 for a string that is not a number
    let port: i32 = if argc >= 3 { argv[2].trim().parse::<i32>().unwrap_or( 0 ) } else { ServerPort };

    if !InitializeYojimbo()
    {
        printf!( "error: failed to initialize yojimbo\n" );
        return 1;
    }

    yojimbo_log_level( YOJIMBO_LOG_LEVEL_ERROR );

    // port: srand( (unsigned int) time( NULL ) ) seeds yojimbo_rand, the port's rand()
    let now = std::time::SystemTime::now().duration_since( std::time::UNIX_EPOCH ).map( |d| d.as_secs() ).unwrap_or( 0 );
    yojimbo_srand( now as u32 );

    let result = if argv[1] == "server" { ServerMain( port ) } else { ClientMain( port ) };

    ShutdownYojimbo();

    printf!( "{}\n", if result == 0 { "PASS" } else { "FAIL" } );

    result
}
