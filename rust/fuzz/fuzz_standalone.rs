/*
    Minimal standalone driver for the fuzz targets.

    libFuzzer isn't always available (notably Apple clang doesn't ship it), so each
    target can also be built with -DFUZZ_STANDALONE to get an ordinary executable:

      - with file arguments, it replays those inputs through the target;
      - otherwise it feeds pseudo-random buffers (set FUZZ_ITERS to change the count).

    Build it with -fsanitize=address,undefined to shake out crashes locally; CI runs
    the same targets under real libFuzzer on Linux. The target defines
    LLVMFuzzerTestOneInput above its #include of this header.
*/

/*
    port: upstream each target is its own libFuzzer binary, with this driver as the fallback where libFuzzer isn't
    available. The Rust port has no libFuzzer, so all five targets share one program (the `fuzz` bin), as in the C#
    port, and with no arguments it runs as a regression test:

      1. replays every seed in cpp/fuzz/corpus/<target> through its target, and checks the seeds still decode where
         the seed generators guarantee they do (every netcode packet type decrypts, connect tokens parse, reliable
         packets deliver, connection seeds read back without error) - so the Rust readers are checked against bytes
         the C code wrote;
      2. a seeded mutation pass over that corpus (bit flips, byte sets, inserts, deletes, duplicates, truncation,
         splices between seeds of the same target);
      3. pseudo-random buffers, from the same generator upstream's standalone driver uses (below, in main).

    Any panic (a slice out of bounds, an unwrap), and any yojimbo / netcode / reliable / serialize assert (asserts are
    live in a debug build), is a failure: the input is written to crash-<target>-<sha1> in the current directory and
    the program exits non-zero. Library log output for the failing input is printed with the report.

    usage:
        fuzz [seed]                     run the regression
        fuzz <target> <file>...         replay files through one target, eg. a crash file

    environment:
        FUZZ_ITERS          mutations per seed (default 200)
        FUZZ_RANDOM_ITERS   pseudo-random inputs per target (default 1000)
        FUZZ_CORPUS         corpus root (default: cpp/fuzz/corpus, found by walking up from the program and the crate)
*/

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_imports, unused_unsafe, static_mut_refs)]

#[path = "fuzz_config.rs"]
mod fuzz_config;
#[path = "fuzz_messages.rs"]
mod fuzz_messages;
#[path = "fuzz_netcode_params.rs"]
mod fuzz_netcode_params;
#[path = "fuzz_connection.rs"]
mod fuzz_connection;
#[path = "fuzz_connection_structured.rs"]
mod fuzz_connection_structured;
#[path = "fuzz_netcode.rs"]
mod fuzz_netcode;
#[path = "fuzz_netcode_connect_token.rs"]
mod fuzz_netcode_connect_token;
#[path = "fuzz_reliable.rs"]
mod fuzz_reliable;

use yojimbo::*;

use std::io::Write;
use std::path::{ Path, PathBuf };
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Instant;

// port: print! that ignores a closed stdout (print! panics on one, which the panic hook would report against the input)
macro_rules! out {
    ( $($arg:tt)* ) => {{
        let mut stdout = std::io::stdout().lock();
        let _ = write!( stdout, $($arg)* );
        let _ = stdout.flush();
    }};
}

struct Target
{
    name: &'static str,
    run: fn( &[u8], usize ) -> i32,
    reset: Option<fn()>,                                    // drop long-lived target state before a corpus replay
    checkSeed: Option<fn( &[u8] ) -> Option<String>>,       // None if the seed decoded as the generator guarantees, else why not
    checkCorpus: Option<fn() -> Option<String>>,            // None if the corpus as a whole decoded as guaranteed, else why not
}

static netcodePacketTypesSeen: Mutex<[bool; fuzz_netcode::FUZZ_NETCODE_NUM_PACKET_TYPES as usize]> = Mutex::new( [false; fuzz_netcode::FUZZ_NETCODE_NUM_PACKET_TYPES as usize] );

fn netcode_reset()
{
    *netcodePacketTypesSeen.lock().unwrap() = [false; fuzz_netcode::FUZZ_NETCODE_NUM_PACKET_TYPES as usize];
}

fn netcode_check_seed( _seed: &[u8] ) -> Option<String>
{
    let packet_type = fuzz_netcode::fuzz_netcode_last_packet_type.load( Ordering::Relaxed );
    if packet_type < 0
    {
        return Some( "seed failed to decrypt and read back".to_string() );
    }
    netcodePacketTypesSeen.lock().unwrap()[packet_type as usize] = true;
    None
}

fn netcode_check_corpus() -> Option<String>
{
    if netcodePacketTypesSeen.lock().unwrap().iter().all( |seen| *seen ) { None } else { Some( "not every netcode packet type has a seed that reads back".to_string() ) }
}

fn connection_check_seed( _seed: &[u8] ) -> Option<String>
{
    if fuzz_connection::g_all_packets_accepted.load( Ordering::Relaxed ) { None } else { Some( "a seed packet failed to read back".to_string() ) }
}

fn connect_token_check_seed( _seed: &[u8] ) -> Option<String>
{
    if fuzz_netcode_connect_token::fuzz_netcode_connect_token_last_result.load( Ordering::Relaxed ) == netcode::NETCODE_OK { None } else { Some( "seed failed to parse".to_string() ) }
}

// the small packet delivers directly and the large one delivers once reassembled
fn reliable_check_corpus() -> Option<String>
{
    let received = fuzz_reliable::g_received.load( Ordering::Relaxed );
    if received >= 2 { None } else { Some( format!( "seeds delivered {} packets, expected at least 2", received ) ) }
}

static targets: [Target; 5] =
[
    Target { name: "fuzz_connection", run: fuzz_connection::LLVMFuzzerTestOneInput, reset: None, checkSeed: Some( connection_check_seed ), checkCorpus: None },
    Target { name: "fuzz_connection_structured", run: fuzz_connection_structured::LLVMFuzzerTestOneInput, reset: None, checkSeed: None, checkCorpus: None },
    Target { name: "fuzz_netcode", run: fuzz_netcode::LLVMFuzzerTestOneInput, reset: Some( netcode_reset ), checkSeed: Some( netcode_check_seed ), checkCorpus: Some( netcode_check_corpus ) },
    Target { name: "fuzz_netcode_connect_token", run: fuzz_netcode_connect_token::LLVMFuzzerTestOneInput, reset: None, checkSeed: Some( connect_token_check_seed ), checkCorpus: None },
    Target { name: "fuzz_reliable", run: fuzz_reliable::LLVMFuzzerTestOneInput, reset: Some( fuzz_reliable::reset ), checkSeed: None, checkCorpus: Some( reliable_check_corpus ) },
];

// ---------------------------------------------------------------------------------------------------------------
// failure reporting

// the input being run, for the panic hook
struct Current
{
    name: &'static str,
    input: Vec<u8>,
    origin: String,
    reported: bool,
}

static current: Mutex<Option<Current>> = Mutex::new( None );

// library log output for the current input, printed with a failure report
static captured_log: Mutex<String> = Mutex::new( String::new() );

fn capture_printf( s: &str )
{
    if let Ok( mut log ) = captured_log.lock()
    {
        log.push_str( s );
    }
}

// an assert inside a target is a finding: panic, so the driver can report the input
fn fuzz_assert_function( condition: &str, function: &str, file: &str, line: i32 )
{
    panic!( "assert failed: ( {} ), function {}, file {}, line {}", condition, function, file, line );
}

// writes the current input to crash-<target>-<sha1> and prints the report (once per input)
fn report( reason: &str )
{
    // try_lock: a panic while the lock is held must not deadlock the hook
    let mut guard = match current.try_lock() { Ok( guard ) => guard, Err( _ ) => return };
    let Some( c ) = guard.as_mut() else { return };
    if c.reported
    {
        return;
    }
    c.reported = true;

    let name = format!( "crash-{}-{}", c.name, sha1_hex( &c.input ) );
    let _ = std::fs::write( &name, &c.input );
    let full = std::path::absolute( &name ).unwrap_or_else( |_| PathBuf::from( &name ) );
    let log = captured_log.try_lock().map( |log| log.clone() ).unwrap_or_default();
    let log = if log.is_empty() { String::new() } else { format!( "\nlog:\n{}", log ) };
    out!( "\nFAIL {}: {}\n{}\n{}\ninput ({} bytes) written to {}\nreproduce: fuzz {} {}\n",
            c.name, c.origin, reason, log, c.input.len(), full.display(), c.name, name );
}

fn fail( reason: &str ) -> !
{
    report( reason );
    std::process::exit( 1 );
}

fn panic_hook( info: &std::panic::PanicHookInfo )
{
    let message = if let Some( s ) = info.payload().downcast_ref::<&str>() { s.to_string() }
                  else if let Some( s ) = info.payload().downcast_ref::<String>() { s.clone() }
                  else { "panic".to_string() };
    let location = info.location().map( |l| format!( "{}:{}:{}", l.file(), l.line(), l.column() ) ).unwrap_or_default();
    let backtrace = std::backtrace::Backtrace::capture();
    let backtrace = if backtrace.status() == std::backtrace::BacktraceStatus::Captured { format!( "\n{}", backtrace ) } else { String::new() };
    let reason = format!( "panicked at {}:\n{}{}", location, message, backtrace );
    if current.try_lock().map( |c| c.is_some() ).unwrap_or( true )
    {
        report( &reason );
    }
    else
    {
        out!( "\n{}\n", reason );
    }
}

fn run_one( target: &'static Target, input: Vec<u8>, origin: String )
{
    captured_log.lock().unwrap().clear();
    *current.lock().unwrap() = Some( Current { name: target.name, input, origin, reported: false } );

    // port: the input stays owned by `current` for the hook, so the target gets a copy
    let data = current.lock().unwrap().as_ref().unwrap().input.clone();
    let run = target.run;
    let result = std::panic::catch_unwind( std::panic::AssertUnwindSafe( || { run( &data, data.len() ); } ) );
    if result.is_err()
    {
        // the panic hook has written the report
        std::process::exit( 1 );
    }
}

fn set_origin( origin: String )
{
    if let Some( c ) = current.lock().unwrap().as_mut()
    {
        c.origin = origin;
    }
}

// ---------------------------------------------------------------------------------------------------------------

fn env_int( name: &str, defaultValue: i32 ) -> i32
{
    match std::env::var( name )
    {
        Ok( value ) if !value.is_empty() => value.trim().parse().unwrap_or_else( |_| { out!( "error: {} is not an integer\n", name ); std::process::exit( 1 ) } ),
        _ => defaultValue,
    }
}

fn find_corpus() -> Option<PathBuf>
{
    if let Ok( corpus ) = std::env::var( "FUZZ_CORPUS" )
    {
        if !corpus.is_empty()
        {
            return Some( PathBuf::from( corpus ) );
        }
    }
    // port: walk up from the program (as the C# port), then from this source file and the crate (cargo run puts the
    // program under a target directory that may be outside the repo)
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok( exe ) = std::env::current_exe()
    {
        if let Some( dir ) = exe.parent() { starts.push( dir.to_path_buf() ); }
    }
    let manifest = Path::new( env!( "CARGO_MANIFEST_DIR" ) );
    if let Some( dir ) = manifest.join( file!() ).parent() { starts.push( dir.to_path_buf() ); }
    starts.push( manifest.to_path_buf() );
    for start in starts
    {
        let mut dir: Option<&Path> = Some( &start );
        while let Some( d ) = dir
        {
            let candidate = d.join( "cpp" ).join( "fuzz" ).join( "corpus" );
            if candidate.is_dir()
            {
                return Some( candidate );
            }
            dir = d.parent();
        }
    }
    None
}

// port: C#'s System.Random, which has no std counterpart: splitmix64. The mutations differ from the C# port's, the
// coverage of the mutation kinds does not.
struct Random
{
    state: u64,
}

impl Random
{
    fn new( seed: i32 ) -> Random { Random { state: seed as u32 as u64 } }

    fn next_u64( &mut self ) -> u64
    {
        self.state = self.state.wrapping_add( 0x9E3779B97F4A7C15 );
        let mut z = self.state;
        z = ( z ^ ( z >> 30 ) ).wrapping_mul( 0xBF58476D1CE4E5B9 );
        z = ( z ^ ( z >> 27 ) ).wrapping_mul( 0x94D049BB133111EB );
        z ^ ( z >> 31 )
    }

    // a value in [0,n)
    fn Next( &mut self, n: usize ) -> usize
    {
        if n == 0 { 0 } else { ( self.next_u64() % n as u64 ) as usize }
    }
}

fn mutate( random: &mut Random, seed: &[u8], seeds: &[Vec<u8>] ) -> Vec<u8>
{
    let mut data: Vec<u8> = seed.to_vec();
    let numMutations = 1 + random.Next( 4 );
    for _m in 0..numMutations
    {
        match random.Next( 8 )
        {
            0 => // flip a bit
            {
                if data.len() > 0
                {
                    let at = random.Next( data.len() );
                    data[at] ^= 1u8 << random.Next( 8 );
                }
            }

            1 => // set a random byte
            {
                if data.len() > 0
                {
                    let at = random.Next( data.len() );
                    data[at] = random.Next( 256 ) as u8;
                }
            }

            2 => // set an interesting value
            {
                const interesting: [u8; 5] = [ 0x00, 0x01, 0x7F, 0x80, 0xFF ];
                if data.len() > 0
                {
                    let at = random.Next( data.len() );
                    data[at] = interesting[random.Next( interesting.len() )];
                }
            }

            3 => // insert random bytes
            {
                let count = 1 + random.Next( 8 );
                let at = random.Next( data.len() + 1 );
                for _i in 0..count
                {
                    data.insert( at, random.Next( 256 ) as u8 );
                }
            }

            4 => // delete a range
            {
                if data.len() > 0
                {
                    let at = random.Next( data.len() );
                    let count = 1 + random.Next( std::cmp::min( 16, data.len() - at ) );
                    data.drain( at..at + count );
                }
            }

            5 => // duplicate a range
            {
                if data.len() > 0
                {
                    let at = random.Next( data.len() );
                    let count = 1 + random.Next( std::cmp::min( 32, data.len() - at ) );
                    let range: Vec<u8> = data[at..at + count].to_vec();
                    let to = random.Next( data.len() + 1 );
                    data.splice( to..to, range );
                }
            }

            6 => // truncate
            {
                if data.len() > 0
                {
                    let keep = random.Next( data.len() );
                    data.truncate( keep );
                }
            }

            _ => // splice in the tail of another seed of the same target
            {
                let other = &seeds[random.Next( seeds.len() )];
                let at = random.Next( data.len() + 1 );
                let from = random.Next( other.len() + 1 );
                data.truncate( at );
                data.extend_from_slice( &other[from..] );
            }
        }
    }
    data
}

// a per-target RNG seed that is the same in every run (as the C# port's StableHash)
fn StableHash( s: &str ) -> i32
{
    let mut hash: i32 = 17;
    for c in s.encode_utf16()
    {
        hash = hash.wrapping_mul( 31 ).wrapping_add( c as i32 );
    }
    hash
}

// ---------------------------------------------------------------------------------------------------------------
// SHA-1 (FIPS 180-4), for the crash file names

fn sha1( data: &[u8] ) -> [u8; 20]
{
    let mut h: [u32; 5] = [ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 ];

    let mut message = data.to_vec();
    let bit_length = ( data.len() as u64 ).wrapping_mul( 8 );
    message.push( 0x80 );
    while message.len() % 64 != 56
    {
        message.push( 0 );
    }
    message.extend_from_slice( &bit_length.to_be_bytes() );

    for chunk in message.chunks( 64 )
    {
        let mut w = [0u32; 80];
        for i in 0..16
        {
            w[i] = u32::from_be_bytes( [ chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3] ] );
        }
        for i in 16..80
        {
            w[i] = ( w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16] ).rotate_left( 1 );
        }

        let ( mut a, mut b, mut c, mut d, mut e ) = ( h[0], h[1], h[2], h[3], h[4] );
        for i in 0..80
        {
            let ( f, k ) = match i
            {
                0..=19 => ( ( b & c ) | ( !b & d ), 0x5A827999u32 ),
                20..=39 => ( b ^ c ^ d, 0x6ED9EBA1u32 ),
                40..=59 => ( ( b & c ) | ( b & d ) | ( c & d ), 0x8F1BBCDCu32 ),
                _ => ( b ^ c ^ d, 0xCA62C1D6u32 ),
            };
            let temp = a.rotate_left( 5 ).wrapping_add( f ).wrapping_add( e ).wrapping_add( k ).wrapping_add( w[i] );
            e = d;
            d = c;
            c = b.rotate_left( 30 );
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add( a );
        h[1] = h[1].wrapping_add( b );
        h[2] = h[2].wrapping_add( c );
        h[3] = h[3].wrapping_add( d );
        h[4] = h[4].wrapping_add( e );
    }

    let mut digest = [0u8; 20];
    for i in 0..5
    {
        digest[i * 4..i * 4 + 4].copy_from_slice( &h[i].to_be_bytes() );
    }
    digest
}

fn sha1_hex( data: &[u8] ) -> String
{
    sha1( data ).iter().map( |b| format!( "{:02x}", b ) ).collect()
}

// ---------------------------------------------------------------------------------------------------------------

fn main()
{
    std::process::exit( run_main() );
}

fn run_main() -> i32
{
    let args: Vec<String> = std::env::args().skip( 1 ).collect();

    let parsedSeed = if args.len() == 1 { args[0].parse::<u32>().ok() } else { None };
    let seedArgument = parsedSeed.is_some();

    // the sha-1 used for crash names is self-checked, so a crash file is always named by its real hash
    if sha1_hex( b"abc" ) != "a9993e364706816aba3e25717850c26c9cd0d89d" || sha1_hex( b"" ) != "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    {
        out!( "error: sha-1 self test failed\n" );
        return 1;
    }

    if !InitializeYojimbo()
    {
        out!( "error: failed to initialize yojimbo\n" );
        return 1;
    }

    // an assert inside a target is a finding: it panics, so the driver can report the input
    yojimbo_set_assert_function( fuzz_assert_function );
    serialize::serialize_set_assert_function( fuzz_assert_function );
    yojimbo_set_printf_function( capture_printf );
    std::panic::set_hook( Box::new( panic_hook ) );

    if args.len() > 0 && !seedArgument
    {
        // replay files through one target
        let Some( target ) = targets.iter().find( |t| t.name == args[0] ) else
        {
            let names: Vec<&str> = targets.iter().map( |t| t.name ).collect();
            out!( "error: unknown target '{}'. targets: {}\n", args[0], names.join( ", " ) );
            return 1;
        };
        for file in &args[1..]
        {
            let input = match std::fs::read( file )
            {
                Ok( input ) => input,
                Err( e ) => { out!( "error: can't read {}: {}\n", file, e ); return 1; }
            };
            run_one( target, input, file.clone() );
        }
        out!( "{}: {} inputs ok\n", target.name, args.len() - 1 );
        fuzz_reliable::reset();
        ShutdownYojimbo();
        return 0;
    }

    let Some( corpusRoot ) = find_corpus().filter( |c| c.is_dir() ) else
    {
        out!( "error: fuzz corpus not found. check out the cpp submodule (git submodule update --init) or set FUZZ_CORPUS\n" );
        return 1;
    };

    let seed: i32 = match parsedSeed { Some( s ) => s as i32, None => 1 };
    let mutationsPerSeed = env_int( "FUZZ_ITERS", 200 );
    let randomIters = env_int( "FUZZ_RANDOM_ITERS", 1000 );

    let corpusDisplay = std::path::absolute( &corpusRoot ).unwrap_or( corpusRoot.clone() );
    out!( "fuzz random seed {}, {} mutations per seed, {} random inputs per target\ncorpus {}\n\n", seed as u32, mutationsPerSeed, randomIters, corpusDisplay.display() );

    let total = Instant::now();

    for target in targets.iter()
    {
        let stopwatch = Instant::now();

        let dir = corpusRoot.join( target.name );
        let mut files: Vec<PathBuf> = match std::fs::read_dir( &dir )
        {
            Ok( entries ) => entries.filter_map( |e| e.ok() ).map( |e| e.path() ).filter( |p| p.is_file() ).collect(),
            Err( _ ) => Vec::new(),
        };
        files.sort();
        if files.len() == 0
        {
            out!( "error: no seeds for {} in {}\n", target.name, dir.display() );
            return 1;
        }
        let seeds: Vec<Vec<u8>> = files.iter().map( |f| std::fs::read( f ).unwrap_or_else( |e| { out!( "error: can't read {}: {}\n", f.display(), e ); std::process::exit( 1 ) } ) ).collect();

        // 1. corpus replay
        if let Some( reset ) = target.reset
        {
            reset();
        }
        for i in 0..files.len()
        {
            let origin = format!( "seed {}", files[i].display() );
            run_one( target, seeds[i].clone(), origin );
            if let Some( checkSeed ) = target.checkSeed
            {
                if let Some( reason ) = checkSeed( &seeds[i] )
                {
                    fail( &reason );
                }
            }
        }
        if let Some( checkCorpus ) = target.checkCorpus
        {
            if let Some( reason ) = checkCorpus()
            {
                set_origin( format!( "corpus {}", dir.display() ) );
                fail( &reason );
            }
        }

        // 2. mutations, seeded per target so a target's inputs don't depend on the targets before it
        let mut random = Random::new( seed ^ StableHash( target.name ) );
        let mut mutations = 0;
        for i in 0..seeds.len()
        {
            for j in 0..mutationsPerSeed
            {
                let input = mutate( &mut random, &seeds[i], &seeds );
                run_one( target, input, format!( "mutation {} of seed {} (fuzz random seed {})", j, files[i].display(), seed as u32 ) );
                mutations += 1;
            }
        }

        // 3. pseudo-random buffers, as upstream's standalone driver generates them
        let mut lcg: u32 = 0x1234567u32;
        for it in 0..randomIters
        {
            const bufSize: usize = 4096;
            lcg = lcg.wrapping_mul( 1103515245u32 ).wrapping_add( 12345u32 );
            let n = ( ( lcg >> 8 ) as usize ) % ( bufSize + 1 );
            let mut buf = vec![0u8; n];
            for j in 0..n
            {
                lcg = lcg.wrapping_mul( 1103515245u32 ).wrapping_add( 12345u32 );
                buf[j] = ( lcg >> 16 ) as u8;
            }
            run_one( target, buf, format!( "random input {}", it ) );
        }

        out!( "{:<28} {:>2} seeds ok, {} mutations, {} random inputs ({:.1}s)\n", target.name, seeds.len(), mutations, randomIters, stopwatch.elapsed().as_secs_f64() );
    }

    *current.lock().unwrap() = None;

    fuzz_reliable::reset();

    ShutdownYojimbo();

    out!( "\n*** ALL FUZZ TARGETS PASS *** ({:.1}s)\n\n", total.elapsed().as_secs_f64() );

    0
}
