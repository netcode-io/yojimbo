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

// Rust port of include/yojimbo_network_info.h (yojimbo 1.13.5).

use crate::*;

/**
    Network information for a connection.
    Contains statistics like round trip time (RTT), packet loss %, bandwidth estimates, number of packets sent, received and acked.
 */

#[derive(Clone, Copy, Default, Debug)]
pub struct NetworkInfo
{
    pub RTT: f32,                                   //< Round trip time estimate (milliseconds). Exponentially smoothed average tracking most recent RTT value.
    pub minRTT: f32,                                //< Minimum RTT seen over the last n samples (see rtt_history_size in reliable config). This is a more stable and accurate RTT value under typical Wi-Fi jitter.
    pub maxRTT: f32,                                //< Maximum RTT seen over the last n samples.
    pub averageRTT: f32,                            //< Average RTT seen over the last n samples.
    pub averageJitter: f32,                         //< Average jitter relative to min RTT over the last n samples.
    pub maxJitter: f32,                             //< Max jitter relative to min RTT seen over the last n samples.
    pub stddevJitter: f32,                          //< One standard deviation of jitter relative to average RTT over the last n samples.
    pub packetLoss: f32,                            //< Packet loss percent.
    pub sentBandwidth: f32,                         //< Sent bandwidth (kbps).
    pub receivedBandwidth: f32,                     //< Received bandwidth (kbps).
    pub ackedBandwidth: f32,                        //< Acked bandwidth (kbps).
    pub numPacketsSent: u64,                        //< Number of packets sent.
    pub numPacketsReceived: u64,                    //< Number of packets received.
    pub numPacketsAcked: u64,                       //< Number of packets acked.
}
