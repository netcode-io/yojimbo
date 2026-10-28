/*
    Shared parameters for the netcode fuzz target and its seed generator.

    The generator (tools/gen_seed_corpus) must write packets with the same protocol id
    and keys the harness reads with, or the seeds won't decrypt and would be no better
    than random bytes. Keeping the constants here means the two can't drift apart.

    The harness reads with all-zero packet and private keys, so the generator writes with
    the same zero key.
*/

// port: fuzz_netcode_params.h. The #defines are consts

pub const FUZZ_PROTOCOL_ID: u64 = 0x1122334455667788u64;
pub const FUZZ_TIMESTAMP: u64 = 1000000u64;
