/*
    Yojimbo Client/Server Network Library (Rust port).

    The crate root: the module list, mirroring cpp/ file for file (see README.md). The yojimbo files form one
    namespace, as upstream's `namespace yojimbo`: each is re-exported here and starts with `use crate::*;`.
*/

// port: the port keeps upstream's names and C-style structure (see README.md, "Conventions")
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_imports, unused_unsafe, static_mut_refs)]
#![allow(clippy::all)]

#[path = "sodium/sodium.rs"]
pub mod sodium;
#[path = "tlsf/tlsf.rs"]
pub mod tlsf;
#[path = "serialize/serialize.rs"]
pub mod serialize;
#[path = "netcode/netcode.rs"]
pub mod netcode;
#[path = "reliable/reliable.rs"]
pub mod reliable;

#[path = "include/yojimbo_constants.rs"]
pub mod yojimbo_constants;
#[path = "source/yojimbo_platform.rs"]
pub mod yojimbo_platform;
#[path = "source/yojimbo_config.rs"]
pub mod yojimbo_config;
#[path = "source/yojimbo_utils.rs"]
pub mod yojimbo_utils;
#[path = "source/yojimbo_allocator.rs"]
pub mod yojimbo_allocator;
#[path = "include/yojimbo_serialize.rs"]
pub mod yojimbo_serialize;
#[path = "include/yojimbo_bit_array.rs"]
pub mod yojimbo_bit_array;
#[path = "include/yojimbo_queue.rs"]
pub mod yojimbo_queue;
#[path = "include/yojimbo_sequence_buffer.rs"]
pub mod yojimbo_sequence_buffer;
#[path = "source/yojimbo_address.rs"]
pub mod yojimbo_address;
#[path = "source/yojimbo_message.rs"]
pub mod yojimbo_message;
#[path = "source/yojimbo_channel.rs"]
pub mod yojimbo_channel;
#[path = "source/yojimbo_reliable_ordered_channel.rs"]
pub mod yojimbo_reliable_ordered_channel;
#[path = "source/yojimbo_unreliable_unordered_channel.rs"]
pub mod yojimbo_unreliable_unordered_channel;
#[path = "source/yojimbo_connection.rs"]
pub mod yojimbo_connection;
#[path = "source/yojimbo_network_simulator.rs"]
pub mod yojimbo_network_simulator;
#[path = "include/yojimbo_adapter.rs"]
pub mod yojimbo_adapter;
#[path = "include/yojimbo_network_info.rs"]
pub mod yojimbo_network_info;
#[path = "include/yojimbo_client_interface.rs"]
pub mod yojimbo_client_interface;
#[path = "source/yojimbo_base_client.rs"]
pub mod yojimbo_base_client;
#[path = "source/yojimbo_client.rs"]
pub mod yojimbo_client;
#[path = "include/yojimbo_server_interface.rs"]
pub mod yojimbo_server_interface;
#[path = "source/yojimbo_base_server.rs"]
pub mod yojimbo_base_server;
#[path = "source/yojimbo_server.rs"]
pub mod yojimbo_server;
// private: a public module named `yojimbo` would make `use yojimbo::*;` ambiguous in the bins and in consumers
#[path = "source/yojimbo.rs"]
mod yojimbo;

pub use yojimbo_constants::*;
pub use yojimbo_platform::*;
pub use yojimbo_config::*;
pub use yojimbo_utils::*;
pub use yojimbo_allocator::*;
pub use yojimbo_serialize::*;
pub use yojimbo_bit_array::*;
pub use yojimbo_queue::*;
pub use yojimbo_sequence_buffer::*;
pub use yojimbo_address::*;
pub use yojimbo_message::*;
pub use yojimbo_channel::*;
pub use yojimbo_reliable_ordered_channel::*;
pub use yojimbo_unreliable_unordered_channel::*;
pub use yojimbo_connection::*;
pub use yojimbo_network_simulator::*;
pub use yojimbo_adapter::*;
pub use yojimbo_network_info::*;
pub use yojimbo_client_interface::*;
pub use yojimbo_base_client::*;
pub use yojimbo_client::*;
pub use yojimbo_server_interface::*;
pub use yojimbo_base_server::*;
pub use yojimbo_server::*;
pub use self::yojimbo::*;
// upstream's yojimbo namespace does `using namespace serialize`
pub use serialize::*;
