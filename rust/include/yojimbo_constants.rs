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

// Rust port of include/yojimbo_constants.h (yojimbo 1.13.5).

use crate::*;

pub const MaxClients: i32 = 64;                                     //< The maximum number of clients supported by this library. You can increase this if you want, but this library is designed around patterns that work best for [2,64] player games. If your game has less than 64 clients, reducing this will save memory.

pub const MaxChannels: i32 = 64;                                    //< The maximum number of message channels supported by this library. If you need less than 64 channels per-packet, reducing this will save memory. Minimum is 2.

pub const KeyBytes: i32 = 32;                                       //< Size of encryption key for dedicated client/server in bytes. Must be equal to key size for libsodium encryption primitive. Do not change.

pub const ConnectTokenBytes: i32 = 2048;                            //< Size of the encrypted connect token data return from the matchmaker. Must equal size of NETCODE_CONNECT_TOKEN_BYTE (2048).

pub const DefaultMaxConnectTokenLifetime: i32 = 30;                 //< Default for ClientServerConfig::maxConnectTokenLifetime (seconds). Must equal NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME (30). The matcher under matcher/ issues 45 second connect tokens, so a deployment running it as-is sets maxConnectTokenLifetime to 45.

pub const InsecureConnectTokenExpirySeconds: i32 = 60;              //< Expiry for insecure connect tokens (seconds). Kept well above the connection timeout so a failed insecure connect reports "connection request timed out" like a secure connect token from a matchmaker would, rather than hitting token expiry first.

pub const ConservativeMessageHeaderBits: i32 = 32;                  //< Conservative number of bits per-message header.

pub const ConservativeFragmentHeaderBits: i32 = 64;                 //< Conservative number of bits per-fragment header.

pub const ConservativeChannelHeaderBits: i32 = 32;                  //< Conservative number of bits per-channel header.

pub const ConservativePacketHeaderBits: i32 = 16;                   //< Conservative number of bits per-packet header.

pub const MaxAddressLength: i32 = 256;                              //< The maximum length of an address when converted to a string (includes terminating NULL). @see Address::ToString
