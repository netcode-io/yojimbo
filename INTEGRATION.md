# Integrating yojimbo

How to use the C#, TypeScript and Rust ports of yojimbo in a game or service. The examples below were built and run against this repository. Run them as written and change them from there.

## Pick a port

| You are building | Use |
|---|---|
| a .NET game client or dedicated server (.NET 10, Godot C#, Unity and anything else that takes .NET Standard 2.1) | `cs/`, the `yojimbo` NuGet package (`net10.0` and `netstandard2.1`) |
| a Node game server, tools or bots | `ts/` on Node 24+ (native UDP), the `yojimbo2` npm package |
| a browser client | `yojimbo2` in the browser, over WebRTC to a server running `yojimbo2/webrtc/server` (on Node, or in another browser page) |
| a Rust game client or dedicated server, tools or bots | `rust/`, the `yojimbo` crate (std only, no dependencies; Rust 1.80+) |

All four implementations interoperate: C++, C#, TypeScript and Rust speak the same wire protocol (`NETCODE 1.02`), so any client can connect to any server. `interop/run.sh` checks all sixteen pairings. A mixed deployment works as long as both sides agree on the things listed in [What both ends must agree on](#what-both-ends-must-agree-on).

Install:

- **C#:** `dotnet add package yojimbo`, then `using networkprotocol; using static networkprotocol.yojimbo;`. Or reference the source: `<ProjectReference Include="path/to/cs/yojimbo.csproj" />`.
- **TypeScript:** `npm install yojimbo2`, then `import { ... } from 'yojimbo2'`. Plain `yojimbo` is a different package on npm. Subpaths: `yojimbo2/webrtc/client`, `yojimbo2/webrtc/server`, `yojimbo2/webrtc/server-http` (Node), `yojimbo2/webrtc/token`, `yojimbo2/netcode`, `yojimbo2/reliable`, `yojimbo2/serialize`, `yojimbo2/sodium`. The package is ES modules with type definitions and works with Node 24+ and with browser bundlers. TypeScript consumers need TypeScript 5.0 or later; the declarations are checked against 5.0 and the latest release. To work from the source instead, import `path/to/ts/source/yojimbo.ts`: Node 24 runs the `.ts` files directly.
- **Rust:** `cargo add yojimbo` (or `yojimbo = "1.13"` under `[dependencies]`), then `use yojimbo::*;`, which brings in the yojimbo API and its macros. The libraries underneath are modules: `yojimbo::netcode`, `yojimbo::reliable`, `yojimbo::serialize`, `yojimbo::sodium`, `yojimbo::tlsf`. Or depend on the source: `yojimbo = { path = "path/to/rust" }`. A dependency is built with your package's profiles, not its own, so copy the crate's one debug setting into your `Cargo.toml`. It turns overflow checks off, a safety net for the wrapping C arithmetic the port follows (release builds have them off already):

  ```toml
  [profile.dev.package.yojimbo]
  overflow-checks = false
  ```

All three packages share one version, which follows upstream yojimbo with the port's revision folded into the patch. `1.13.500` is the port of upstream 1.13.5, `1.13.501` is the first port-only fix on top of it, and `1.13.600` is the port of upstream 1.13.6.

The examples below use the packages. To build against the repository sources instead, import from `path/to/ts/source/yojimbo.ts` and `path/to/ts/webrtc/*.ts` (TypeScript); the C# and Rust code is the same either way.

## The model

- **One server, many clients** (up to `MaxClients` = 64). The server holds a slot per client (`clientIndex`).
- **Connect tokens** authorize clients. Your backend (matchmaker, web service) and your game servers share a 32-byte **private key** and a 64-bit **protocol id**:
  - The backend issues a token (client id, server addresses, expiry), encrypted with that key.
  - The client passes the token to `Connect`.
  - Tokens are single use, and they expire.
- **Messages** are classes (structs in Rust) you define, with one `Serialize` method used for writing, reading and measuring. They travel on **channels**:
  - **reliable-ordered:** resent until acked, delivered in order;
  - **unreliable-unordered:** sent once, may be lost or reordered.

  A message can carry a **block** (a byte array of up to `maxBlockSize`, 256 KB by default) that is split into fragments for you.
- **You own the loop.** Each frame, call `SendPackets`, then `ReceivePackets`, then `AdvanceTime(now)`, then read and write messages. Nothing runs in the background. The library is single threaded, so use each client or server from one thread.
- **The adapter** is your hook into the library: it creates your message factory, receives server connect/disconnect callbacks, and optionally replaces the UDP transport (custom packet I/O, which is how WebRTC is done).

## C#

```csharp
using System;
using networkprotocol;
using static networkprotocol.yojimbo;

// 1. a message: Serialize runs for write, read and measure. propagate every failure
class ChatMessage : Message
{
    public int playerId;
    public string text = "";

    public override bool Serialize(BaseStream stream)
    {
        if (!stream.serialize_int(ref playerId, 0, 63)) return false;
        if (!stream.serialize_string(ref text, 256)) return false;
        return true;
    }
}

enum GameMessageType { CHAT_MESSAGE, NUM_GAME_MESSAGE_TYPES }

// 2. the factory maps type ids to classes, in the same order on every peer
class GameMessageFactory : MESSAGE_FACTORY_START
{
    public GameMessageFactory(Allocator allocator) : base(allocator, (int)GameMessageType.NUM_GAME_MESSAGE_TYPES)
    {
        DECLARE_MESSAGE_TYPE((int)GameMessageType.CHAT_MESSAGE, typeof(ChatMessage));
        MESSAGE_FACTORY_FINISH();
    }
}

// 3. the adapter creates the factory and hears about server connects/disconnects
class GameAdapter : Adapter
{
    public override MessageFactory CreateMessageFactory(Allocator allocator) =>
        YOJIMBO_NEW(allocator, () => new GameMessageFactory(allocator));

    public override void OnServerClientConnected(int clientIndex) { }
    public override void OnServerClientDisconnected(int clientIndex) { }
}

static ClientServerConfig CreateConfig()
{
    var config = new ClientServerConfig();
    config.protocolId = 0x1122334455667788UL;              // must match on client and server
    config.numChannels = 2;
    config.channel[0].type = ChannelType.CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[1].type = ChannelType.CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    return config;
}
```

Server:

```csharp
InitializeYojimbo();                                        // once per process; ShutdownYojimbo() at exit

var server = new Server(GetDefaultAllocator(), privateKey, new Address("0.0.0.0", 40000), CreateConfig(), new GameAdapter(), yojimbo.time());
if (!server.Start(MaxClients)) throw new Exception("server failed to start");

while (running)
{
    server.SendPackets();
    server.ReceivePackets();
    server.AdvanceTime(yojimbo.time());

    for (var clientIndex = 0; clientIndex < MaxClients; ++clientIndex)
    {
        if (!server.IsClientConnected(clientIndex)) continue;
        Message message;
        while ((message = server.ReceiveMessage(clientIndex, 0)) != null)
        {
            // handle message (switch on message.Type)
            server.ReleaseMessage(clientIndex, ref message);  // always release what you receive
        }
    }
    sleep(1.0 / 60.0);
}

server.Stop();
server.Dispose();
```

Client:

```csharp
var client = new Client(GetDefaultAllocator(), new Address("0.0.0.0"), CreateConfig(), new GameAdapter(), yojimbo.time());
client.Connect(clientId, connectToken);                    // token from your backend (see Connect tokens)

while (!client.IsDisconnected)
{
    client.SendPackets();
    client.ReceivePackets();
    client.AdvanceTime(yojimbo.time());
    if (client.ConnectionFailed) break;                    // GetDisconnectReason() says why

    if (client.IsConnected && client.CanSendMessage(0))
    {
        var message = (ChatMessage)client.CreateMessage((int)GameMessageType.CHAT_MESSAGE);
        message.playerId = client.ClientIndex;
        message.text = "hello";
        client.SendMessage(0, message);                    // the library owns it now
    }
    sleep(1.0 / 60.0);
}
client.Disconnect();
client.Dispose();
```

## TypeScript (Node)

```ts
import {
    InitializeYojimbo, GetDefaultAllocator, yojimbo_time, yojimbo_sleep, Address, Client, Server, ClientServerConfig,
    MaxClients, CHANNEL_TYPE_RELIABLE_ORDERED, CHANNEL_TYPE_UNRELIABLE_UNORDERED,
    Message, Adapter, Allocator, MessageFactory, BaseStream, serialize_int, serialize_string,
    YOJIMBO_MESSAGE_FACTORY, YOJIMBO_NEW,
} from 'yojimbo2';

// 1. a message: serialize_* take (stream, object, 'field', ...) and return false on failure. propagate it
class ChatMessage extends Message
{
    playerId = 0;
    text = '';

    Serialize( stream: BaseStream ): boolean
    {
        if ( !serialize_int( stream, this, 'playerId', 0, 63 ) ) return false;
        if ( !serialize_string( stream, this, 'text', 256 ) ) return false;
        return true;
    }
}

const CHAT_MESSAGE = 0;
const NUM_GAME_MESSAGE_TYPES = 1;

// 2. the factory maps type ids to classes, in the same order on every peer
const GameMessageFactory = YOJIMBO_MESSAGE_FACTORY( NUM_GAME_MESSAGE_TYPES, [ [ CHAT_MESSAGE, ChatMessage ] ] );

// 3. the adapter
class GameAdapter extends Adapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new GameMessageFactory( allocator ) );
    }
}

function CreateConfig(): ClientServerConfig
{
    const config = new ClientServerConfig();
    config.protocolId = 0x1122334455667788n;               // 64-bit values are bigint
    config.numChannels = 2;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[1].type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    return config;
}

InitializeYojimbo();

const server = new Server( GetDefaultAllocator(), privateKey, new Address( '0.0.0.0', 40000 ), CreateConfig(), new GameAdapter(), yojimbo_time() );
if ( !server.Start( MaxClients ) ) throw new Error( 'server failed to start' );

while ( running )
{
    server.SendPackets();
    server.ReceivePackets();
    server.AdvanceTime( yojimbo_time() );

    for ( let clientIndex = 0; clientIndex < MaxClients; ++clientIndex )
    {
        if ( !server.IsClientConnected( clientIndex ) ) continue;
        let message;
        while ( ( message = server.ReceiveMessage( clientIndex, 0 ) ) !== null )
        {
            // handle message (switch on message.GetType())
            server.ReleaseMessage( clientIndex, message );
        }
    }
    await yojimbo_sleep( 1 / 60 );                          // REQUIRED: packets only arrive while the event loop runs
}
```

The client mirrors the C# client: `new Client( ... )`, `client.Connect( clientId, connectToken )`, then the same loop with `client.IsConnected()`, `client.CreateMessage( CHAT_MESSAGE ) as ChatMessage`, `client.SendMessage( 0, message )` and `client.ReceiveMessage( 0 )`. Always `await yojimbo_sleep(...)` between frames. A loop that never yields receives nothing.

## Browser clients (WebRTC)

Browsers can't send UDP, so browser clients reach the server over WebRTC data channels configured to behave like UDP (unordered, no retransmits). The channels carry the same encrypted netcode packets. A Node server accepts WebRTC peers and native UDP clients (Node, C#, Rust, C++) at the same time; a server can also run in a browser page (WebRTC only, see below).

**Server (Node, needs `npm install node-datachannel`):**

```ts
import { WebRTCServerAdapter, ListenSignaling, ShutdownWebRTC } from 'yojimbo2/webrtc/server-http';

class GameServerAdapter extends WebRTCServerAdapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new GameMessageFactory( allocator ) );
    }
}

const adapter = new GameServerAdapter( { address: '203.0.113.10:40000', privateKey, protocolId: 0x1122334455667788n } );
await adapter.open();                                       // also binds UDP on that address for native clients
const server = new Server( GetDefaultAllocator(), privateKey, adapter.address, CreateConfig(), adapter, yojimbo_time() );
server.Start( MaxClients );
adapter.attachServer( server );
await ListenSignaling( adapter, 8080, { path: '/signal' } ); // or route POST /signal to HandleSignal( adapter, req, res )
// ... the usual server loop ...
adapter.close();                                            // also closes the signaling server
await ShutdownWebRTC();                                     // otherwise node-datachannel keeps the process alive
```

`yojimbo2/webrtc/server-http` is the Node HTTP layer (`ListenSignaling`, `HandleSignal`, with the HTTP options `cors`, `clientIp`, `maxBodyBytes`, `bodyTimeoutMs`) and re-exports everything in `yojimbo2/webrtc/server`.

**Browser:**

```ts
import { WebRTCClientAdapter } from 'yojimbo2/webrtc/client';

class GameClientAdapter extends WebRTCClientAdapter
{
    override CreateMessageFactory( allocator: Allocator ): MessageFactory | null
    {
        return YOJIMBO_NEW( allocator, () => new GameMessageFactory( allocator ) );
    }
}

const adapter = new GameClientAdapter( { iceServers: [ { urls: 'stun:stun.example.com:3478' } ] } );
await adapter.connect( 'https://game.example.com/signal', connectToken );   // one POST: SDP offer + token
const client = new Client( GetDefaultAllocator(), new Address( '0.0.0.0' ), CreateConfig(), adapter, yojimbo_time() );
client.Connect( clientId, connectToken );                   // same token
// ... the usual client loop, awaiting yojimbo_sleep each frame (or driven by requestAnimationFrame) ...
```

**Your own signaling.** Signaling is one offer and one answer, and HTTP is only the default way to carry them. Give `connect` a function instead of a URL, and on the server hand the offer to `adapter.accept()`, the gate every transport goes through:

```ts
import { type WebRTCSignal } from 'yojimbo2/webrtc/client';
import { SignalError } from 'yojimbo2/webrtc/server';

// client: send the offer however you like (WebSocket, your lobby's message bus, ...); resolve with the answer
const signal: WebRTCSignal = async ( offer, abort ) => lobby.request( 'webrtc-offer', offer, { abort } );   // → { sdp }
await adapter.connect( connectToken, signal );

// server: wherever the offer arrives
try
{
    const answer = await serverAdapter.accept( { sdp: offer.sdp, connectToken: offer.connectToken, ip: playerId } );
    reply( answer );                                        // { sdp }
}
catch ( error )
{
    reply( { error: ( error as SignalError ).status } );    // 400 / 403 / 429 / 503: reject the client's signal promise
}
```

`connect( url, token )` is the same as `connect( token, HttpSignal( url ) )`. If the signal function rejects, `connect()` fails as it does on an HTTP error (`state` is `'failed'`). `accept()` takes the token as bytes (`Uint8Array`), not base64.

**A server in a browser page.** `WebRTCServerAdapter` runs in a page too, on the browser's own `RTCPeerConnection`, for player-hosted games, peer hosts or a host in an Electron/WebView shell. It is WebRTC only (no UDP in a browser), so give it an address with an explicit port; nothing binds it, it is just the identity connect tokens name. Signal into `accept()` with your own transport (your game's WebSocket relay; a `BroadcastChannel` between tabs of one origin, which is what the repository's browser test does). `yojimbo2/webrtc/server` has no Node code, so it bundles for the browser as is.

```ts
import { WebRTCServerAdapter } from 'yojimbo2/webrtc/server';

const adapter = new GameServerAdapter( { address: '10.0.0.1:40000', privateKey: sessionKey, protocolId } );   // sessionKey: from your backend
await adapter.open();                                       // the page's RTCPeerConnection; no UDP
const server = new Server( GetDefaultAllocator(), sessionKey, adapter.address, CreateConfig(), adapter, yojimbo_time() );
server.Start( MaxClients );
adapter.attachServer( server );
relay.onOffer = async ( offer, from ) => adapter.accept( { sdp: offer.sdp, connectToken: offer.connectToken, ip: from } );
setInterval( () => { server.SendPackets(); server.ReceivePackets(); server.AdvanceTime( yojimbo_time() ); /* game */ }, 16 );
```

- **The host page holds the server private key.** Anyone with that page (or its devtools) can mint tokens for it. So the backend must mint a fresh private key for each hosted session, give it only to that host, issue client tokens for that session only (its address and that key), and never reuse a game-wide key in a page.
- **Per-IP caps need an identity.** `accept()` keys its per-IP caps on `request.ip`, which can be any stable per-caller string (a player or session id from your relay). Without one only the global caps apply, so a relay that can't tell callers apart should authenticate them first.
- **Keep the host tab visible.** Browsers throttle timers in hidden tabs (Chrome: at most once a second, and less after a few minutes), so a hidden host stops pumping its server and clients time out. A visible tab, or a window the browser does not background (an Electron/WebView host with throttling off), is needed.
- **No `RTCPeerConnection` in workers.** Browsers expose WebRTC only on the page's main thread, so both the server adapter and the client adapter run there. Keep the frame work light, or move game simulation (not the adapter) into a worker.

What to know:

- **The token gates signaling.** The server decrypts and checks the connect token before it creates a peer connection, so unauthenticated offers cost almost nothing. It also caps peers per IP and globally and reaps peers that stall; all of this is `accept()`, whatever the transport. The HTTP layer adds body size, content type and method checks. The limits are `WebRTCServerAdapter` options (HTTP ones are `ListenSignaling`/`HandleSignal` options).
- **Deployment:**
  - Serve `/signal` over HTTPS, and set `cors` if the page is on another origin.
  - Give clients STUN, and TURN for networks that block UDP.
  - A server behind NAT needs `iceServers` and open ICE ports (`rtcConfig.portRangeBegin`/`portRangeEnd`, or `enableIceUdpMux`).
- **Reconnecting needs a fresh token.** Each WebRTC peer gets a new synthetic address, and netcode won't reuse a token from a different address.
- **Background tabs throttle timers,** so a hidden tab's loop runs slowly. Expect timeouts if the tab stays hidden longer than `config.timeout`.
- **Demo and docs:** see `ts/README.md` and `ts/webrtc/demo/` for a working page and server (`npm run demo:webrtc`).

## Rust

The Rust port keeps upstream's names and its object model: a C++ class with virtual methods is a trait, and the objects the library hands you are raw pointers, created and released through the client or server as in C++.

```rust
#![allow(non_snake_case)]                                   // the API keeps upstream's names (playerId, clientIndex)

use yojimbo::*;

// 1. a message: Serialize runs for write, read and measure. each serialize_* macro returns false on failure
pub struct ChatMessage
{
    pub base: MessageBase,                                  // every message embeds MessageBase as `base`
    pub playerId: i32,
    pub text: [u8; 256],                                    // NUL-terminated, as upstream's char[256]
}

impl Default for ChatMessage                                // the factory creates messages with Default::default()
{
    fn default() -> ChatMessage { ChatMessage { base: MessageBase::default(), playerId: 0, text: [0; 256] } }
}

impl ChatMessage
{
    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_int!( stream, self.playerId, 0, 63 );
        serialize_string!( stream, self.text, 256 );
        true
    }
}

impl Serializable for ChatMessage { YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!(); }  // read, write and measure call Serialize
YOJIMBO_MESSAGE!( ChatMessage );                            // implements Message through `base`

pub const CHAT_MESSAGE: i32 = 0;
pub const NUM_GAME_MESSAGE_TYPES: i32 = 1;

// 2. the factory maps type ids to structs, in the same order on every peer
YOJIMBO_MESSAGE_FACTORY!( GameMessageFactory, NUM_GAME_MESSAGE_TYPES, {
    CHAT_MESSAGE => ChatMessage,
} );

// 3. the adapter creates the factory and hears about server connects/disconnects
pub struct GameAdapter;

impl Adapter for GameAdapter
{
    fn CreateMessageFactory( &mut self, allocator: *mut dyn Allocator ) -> *mut dyn MessageFactory
    {
        YOJIMBO_NEW!( allocator, GameMessageFactory, GameMessageFactory::new( allocator ) ) as *mut dyn MessageFactory
    }

    fn OnServerClientConnected( &mut self, _clientIndex: i32 ) { }
    fn OnServerClientDisconnected( &mut self, _clientIndex: i32 ) { }
}

pub fn CreateConfig() -> ClientServerConfig
{
    let mut config = ClientServerConfig::new();
    config.protocolId = 0x1122334455667788;                 // must match on client and server
    config.numChannels = 2;
    config.channel[0].r#type = CHANNEL_TYPE_RELIABLE_ORDERED;   // `type` is a keyword, so the field is r#type
    config.channel[1].r#type = CHANNEL_TYPE_UNRELIABLE_UNORDERED;
    config
}
```

Server:

```rust
InitializeYojimbo();                                        // once per process; ShutdownYojimbo() at exit

let mut adapter = GameAdapter;                              // the server keeps a pointer to it: it must outlive the server and not move
let mut server = Server::new( GetDefaultAllocator(), &privateKey, &Address::from_string_port( "203.0.113.10", 40000 ), &CreateConfig(), &mut adapter, yojimbo_time() );
if !server.Start( MaxClients ) { panic!( "server failed to start" ); }

while running
{
    server.SendPackets();
    server.ReceivePackets();
    server.AdvanceTime( yojimbo_time() );

    for clientIndex in 0..MaxClients
    {
        if !server.IsClientConnected( clientIndex ) { continue; }
        loop
        {
            let message = server.ReceiveMessage( clientIndex, 0 );  // *mut dyn Message, null when there are no more
            if message.is_null() { break; }
            if unsafe { ( *message ).GetType() } == CHAT_MESSAGE
            {
                let chat = unsafe { message_cast::<ChatMessage>( message ) };   // the C++ cast: check GetType() first
                let text = std::ffi::CStr::from_bytes_until_nul( &chat.text ).unwrap_or_default();
                println!( "client {} says {:?}", chat.playerId, text );
            }
            server.ReleaseMessage( clientIndex, message );  // always release what you receive
        }
    }
    yojimbo_sleep( 1.0 / 60.0 );
}

server.Stop();                                              // before the server drops, and before ShutdownYojimbo()
ShutdownYojimbo();
```

Client:

```rust
let mut adapter = GameAdapter;                              // as on the server: outlives the client, doesn't move
let mut client = Client::new( GetDefaultAllocator(), &Address::from_string( "0.0.0.0" ), &CreateConfig(), &mut adapter, yojimbo_time() );
client.Connect( clientId, &connectToken );                  // token from your backend (see Connect tokens)

while !client.IsDisconnected()
{
    client.SendPackets();
    client.ReceivePackets();
    client.AdvanceTime( yojimbo_time() );
    if client.ConnectionFailed() { break; }                 // GetDisconnectReason() says why

    if client.IsConnected() && client.CanSendMessage( 0 )
    {
        let message = client.CreateMessage( CHAT_MESSAGE ); // *mut dyn Message
        let chat = unsafe { message_cast::<ChatMessage>( message ) };
        chat.playerId = client.GetClientIndex();
        chat.text[..5].copy_from_slice( b"hello" );
        client.SendMessage( 0, message );                   // the library owns it now
    }
    yojimbo_sleep( 1.0 / 60.0 );
}
client.Disconnect();                                        // before the client drops, and before ShutdownYojimbo()
```

The client receives as the server does: `client.ReceiveMessage( 0 )` until it returns null, and `client.ReleaseMessage( message )` for each one.

**Blocks.** A block message embeds `BlockMessage` instead of `MessageBase` and uses `YOJIMBO_BLOCK_MESSAGE!`. This factory uses the other spelling of the factory macro, upstream's three macros as one invocation:

```rust
#[derive(Default)]
pub struct SnapshotMessage
{
    pub base: BlockMessage,                                 // a block message embeds BlockMessage as `base`
    pub tick: u32,
}

impl SnapshotMessage
{
    pub fn Serialize<S: Stream>( &mut self, stream: &mut S ) -> bool
    {
        serialize_bits!( stream, self.tick, 32 );           // the block itself is serialized for you
        true
    }
}

impl Serializable for SnapshotMessage { YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!(); }
YOJIMBO_BLOCK_MESSAGE!( SnapshotMessage );

pub const CHAT_MESSAGE: i32 = 0;
pub const SNAPSHOT_MESSAGE: i32 = 1;
pub const NUM_GAME_MESSAGE_TYPES: i32 = 2;

YOJIMBO_MESSAGE_FACTORY_START!( GameMessageFactory, NUM_GAME_MESSAGE_TYPES,
    YOJIMBO_DECLARE_MESSAGE_TYPE( CHAT_MESSAGE, ChatMessage );
    YOJIMBO_DECLARE_MESSAGE_TYPE( SNAPSHOT_MESSAGE, SnapshotMessage );
YOJIMBO_MESSAGE_FACTORY_FINISH() );
```

Send a block from a byte buffer, and read it back on the other side:

```rust
let message = client.CreateMessage( SNAPSHOT_MESSAGE );
unsafe { message_cast::<SnapshotMessage>( message ) }.tick = tick;
let block = client.AllocateBlock( snapshot.len() as i32 );      // *mut u8 from the client's allocator, null if it is out of memory
unsafe { std::ptr::copy_nonoverlapping( snapshot.as_ptr(), block, snapshot.len() ); }
client.AttachBlockToMessage( message, block, snapshot.len() as i32 );   // the message owns the block now
client.SendMessage( 0, message );
```

```rust
if unsafe { ( *message ).GetType() } == SNAPSHOT_MESSAGE
{
    let snapshotMessage = unsafe { message_cast::<SnapshotMessage>( message ) };
    let data = unsafe { std::slice::from_raw_parts( snapshotMessage.base.GetBlockData(), snapshotMessage.base.GetBlockSize() as usize ) };
    // use data before ReleaseMessage, which frees the block with the message
}
```

What to know:

- **`use yojimbo::*;`** brings in everything, macros included. `ClientInterface` and `ServerInterface` are traits, so a client or server method is not found without that import (or `use yojimbo::{ ClientInterface, ServerInterface };`).
- **Names:** upstream's spelling throughout (`SendPackets`, `numChannels`, `CHANNEL_TYPE_RELIABLE_ORDERED`). C++ enums are `i32` constants. Put `#![allow(non_snake_case)]` at the top of files that use the same style.
- **`Client::new` and `Server::new` return `Box<Client>` / `Box<Server>`.** netcode and reliable hold raw pointers to the object while it is connected or running, so keep it in that box: moving the `Box` is fine, moving the value out of it is not.
- **The adapter is a `*mut dyn Adapter`.** Pass `&mut adapter` and it coerces. The client or server keeps the pointer, and the compiler does not check its lifetime, so the adapter must outlive them and not move: declare it before them, or `Box::leak` it. An adapter that needs the server (to call `GetClientDisconnectReason` from `OnServerClientDisconnected`, say) holds a `*mut Server` set after `Server::new`, as `rust/server.rs` does. Custom packet I/O is the adapter's `UseCustomPacketIO`, `SendPacket` and `ReceivePacket` (see `rust/custom_packet_io_test.rs`).
- **Messages are `*mut dyn Message`.** Create them through the client or server (`CreateMessage`), so the factory and its allocator own them. `message_cast::<T>( message )` turns one into your struct, as the C++ cast does. Release each one you receive with `ReleaseMessage`. The compiler doesn't stop you using a `message_cast` reference after `SendMessage` or `ReleaseMessage`, so the ownership rules under [Pitfalls](#pitfalls) are yours to keep, as in C++. `Message` methods (`GetType`, `GetId`) are called through the pointer: `( *message ).GetType()`.
- **The message macros:**
  - `YOJIMBO_MESSAGE!( T )` implements `Message` for a struct with `base: MessageBase`.
  - `YOJIMBO_BLOCK_MESSAGE!( T )` does the same for one with `base: BlockMessage`.
  - `YOJIMBO_VIRTUAL_SERIALIZE_FUNCTIONS!()` goes inside `impl Serializable for T`. It routes the read, write and measure streams to your `fn Serialize<S: Stream>`.
  - `YOJIMBO_MESSAGE_FACTORY!` or `YOJIMBO_MESSAGE_FACTORY_START!` defines the factory struct with `new( allocator )`. Message types are any `i32` expressions.
  - Every message struct implements `Default`: the factory builds messages with it.
- **The `serialize_*!` macros** (`serialize_int!`, `serialize_bits!`, `serialize_bool!`, `serialize_float!`, `serialize_string!`, `serialize_bytes!`, ...) work only inside a function that returns `bool`. On failure they `return false` from it, so a failure always propagates. `S::IsWriting` and `S::IsReading` are constants for code that differs by direction.
- **`unsafe` marks raw pointer use:**
  - dereferencing a message pointer (`( *message ).GetType()`);
  - `message_cast`, which trusts that the message really is a `T` (check `GetType()` first; debug builds assert the size);
  - reading or writing block memory (`AllocateBlock`, `GetBlockData`).

  Building, connecting, pumping and sending need none.
- **Teardown order:** `Disconnect()` the client and `Stop()` the server before they drop (debug builds assert it) and before `ShutdownYojimbo()`: both free memory back to the default allocator, which `ShutdownYojimbo()` destroys. Dropping the box afterwards, at the end of `main`, is fine.
- **Debug builds** turn on upstream's checks: asserts, memory and message leak tracking, and the packet budget. A message you never released asserts when its client disconnects or its server stops.

## Connect tokens

Issue tokens on a trusted backend, never in the client. The backend needs the private key, the protocol id, the client id, and the server addresses the client may use.

- **C#:**

  ```csharp
  var connectToken = new byte[ConnectTokenBytes];
  netcode.generate_connect_token(1, new[] { "203.0.113.10:40000" }, new[] { "203.0.113.10:40000" },
      expireSeconds, DEFAULT_TIMEOUT, clientId, protocolId, privateKey, userData /* 256 bytes */, connectToken);
  ```
- **TypeScript:**

  ```ts
  GenerateConnectToken( { privateKey, protocolId, clientId, serverAddresses: [ '203.0.113.10:40000' ], expireSeconds } )
  ```

  `GenerateConnectToken` comes from `yojimbo2/webrtc/token` and also works for UDP servers.
- **Rust:**

  ```rust
  use yojimbo::netcode::{ netcode_generate_connect_token, NETCODE_OK };

  let mut connectToken = [0u8; ConnectTokenBytes as usize];
  let userData = [0u8; 256];
  if netcode_generate_connect_token( 1, &[ "203.0.113.10:40000" ], &[ "203.0.113.10:40000" ],
      expireSeconds, YOJIMBO_DEFAULT_TIMEOUT, clientId, protocolId, &privateKey, &userData, &mut connectToken ) != NETCODE_OK
  {
      panic!( "failed to generate connect token" );
  }
  ```
- **C++ backends:** use `netcode_generate_connect_token`. Tokens from any implementation work on any server.

Rules the server enforces:

- **Expiry:** the token is rejected once it has expired.
- **Single use:** a token can't be used from a second address.
- **Server start:** a token issued before the server started is refused. Set `ClientServerConfig.maxConnectTokenLifetime` on the server to the lifetime your backend uses (`expireSeconds`, 30 by default) so this check works.

For local development, `client.InsecureConnect(privateKey, clientId, serverAddress)` (Rust: `client.InsecureConnect( &privateKey, clientId, &serverAddress )`) makes its own token. Never ship it: the client would need the private key.

## What both ends must agree on

- `protocolId` and the private key.
- The channel layout: `numChannels` and each channel's `type`, plus `maxBlockSize` and `blockFragmentSize` when blocks are used.
- The message types, the same ids in the same order, and every `Serialize` producing the same bits. The C++, C#, TypeScript and Rust serialize primitives are bit-identical, so the same sequence of `serialize_*` calls with the same ranges interoperates.
- `maxPacketSize` and the fragment settings, if you change them from the defaults.

## Pitfalls

- **Message ownership:**
  - Release every message you receive (`ReleaseMessage`).
  - Don't touch a message after `SendMessage`.
  - Don't send or release a message twice.
  - Check `CanSendMessage(channel)` before creating a message on a channel. A full send queue is a channel error that disconnects the client.
- **Serialize:** every `serialize_*` call must have its result checked, and the function must `return false` on failure. Skipping that turns malformed packets into exceptions. The Rust `serialize_*!` macros do both for you.
- **Time:** pass the same monotonic clock (seconds, as a double) to `AdvanceTime` every frame: `yojimbo.time()` or `yojimbo_time()`. Don't use wall-clock time.
- **Node sockets need the event loop.** UDP and WebRTC packets arrive only while it runs. On Windows, Node reads one datagram per socket per event-loop turn, so a busy server should sleep a real frame each tick, not spin.
- **Threads:** keep each client or server on one thread or event loop.
- **.NET Standard 2.1** (Unity and similar):
  - The 128-bit serialize primitives (`serialize_int128`, `serialize_uint128`, 128-bit fixed point) are not available there, because `Int128` needs .NET 7.
  - IPv6 packet tagging needs .NET 5+, so on Unity's Mono, `EnablePacketTagging` makes IPv6 socket creation fail; leave tagging off there.
  - The full test suite passes against the `netstandard2.1` build on .NET. Unity itself is not covered by CI.
- **Block memory:** by default, as upstream, every reliable-ordered channel reserves a `maxBlockSize` receive buffer per connection when it's created. A 64-client server with the default 256 KB reserves 16 MB per reliable channel; at 4 MB it would be 256 MB. Set `config.channel[i].allocateBlocksOnDemand = true` (a port addition, not in upstream C++) to allocate the buffer only while a block is arriving, sized to that block, and free it once delivered. If that allocation fails, the client is disconnected with `CHANNEL_ERROR_OUT_OF_MEMORY`. It's local to each end, so it doesn't need to match the other side.
- **Message sizes:** messages larger than the channel allows are rejected (`CHANNEL_ERROR_MESSAGE_TOO_LARGE`). Send large payloads as blocks, or raise `maxPacketSize`/fragment settings on both ends.
- **Disconnect reasons:** `client.GetDisconnectReason()` and `server.GetClientDisconnectReason(clientIndex)`, with the `Get*DisconnectReasonString` helpers, tell you why a connection ended. `GetNetworkInfo` gives RTT, jitter, packet loss and bandwidth.

## More

- [README.md](README.md): layout, build and test commands, interop and CI.
- [ts/README.md](ts/README.md): TypeScript conventions and WebRTC deployment details.
- [rust/README.md](rust/README.md): Rust conventions (names, pointers and memory, macros).
- Upstream [USAGE.md](cpp/USAGE.md) and [STATE-MACHINE.md](cpp/STATE-MACHINE.md): the C++ API docs. The ports keep the same names, and they apply here.
