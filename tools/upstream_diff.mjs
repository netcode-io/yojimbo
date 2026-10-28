#!/usr/bin/env node
/*
    Upstream change report for the ports.

    Lists the upstream yojimbo commits past the cpp/ submodule pin and the upstream files they change, maps each
    file onto the C#, TypeScript and Rust files that mirror it (PORTS and MAP below are the one place the mirroring
    rules live) and prints a Markdown report: the commits, a checklist per port of the files to update with the
    upstream diff stat behind each, the upstream files with no port counterpart, and the vendored library versions
    when they move.

        node tools/upstream_diff.mjs                       fetch upstream's default branch and diff the pin against it
        node tools/upstream_diff.mjs --to v1.14.0          fetch and diff a branch, tag or commit instead
        node tools/upstream_diff.mjs --from 5b563a6 --to 272153a --no-fetch
                                                           diff two commits already in cpp/ (here: the old port's base to 1.13.5)
        node tools/upstream_diff.mjs --out report.md       write the report to a file instead of stdout

    Needs the cpp/ submodule checked out with history (git submodule update --init). Fetching only adds objects
    to cpp/'s repository; its checkout is left alone. With GITHUB_OUTPUT set (in Actions) it also writes
    behind=<commits past the pin>, from=<sha> and to=<sha> there.
*/

import child_process from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const root = path.resolve( path.dirname( url.fileURLToPath( import.meta.url ) ), '..' );
const UPSTREAM = 'mas-bandwidth/yojimbo';
const UPSTREAM_URL = `https://github.com/${UPSTREAM}.git`;
const REPORT_LIMIT = 60000;             // characters: a GitHub issue body holds 65536
const LIST_LIMIT = 20;                  // entries shown per group of files with no port work

// the ports, in report order: id is the key MAP rules use, title heads the port's report section
const PORTS = [
    { id: 'cs', title: 'C# (`cs/`)' },
    { id: 'ts', title: 'TypeScript (`ts/`)' },
    { id: 'rs', title: 'Rust (`rust/`)' },
];

/*
    Upstream path -> port files. The first rule whose pattern matches wins; $1.. are the pattern's groups.
    A ported rule names every port in PORTS by its id, as one of:
        'path'              the mirroring file
        { file, note }      the mirroring file, with a note on how it mirrors the upstream file
        null                no counterpart in that port (the rule's note says why)
    The rule's note goes on every port's file when no port is null, and only on the null ports otherwise. A rule
    with only a note is informational: the file has no port counterpart by design. `ifUpstream` makes a rule apply
    only when that upstream file exists (a header with a source collapses into the source's file).
*/
const TLSF_EMULATED = 'the TLSF heap is emulated as a byte budget; check its overheads still match';
const MAP = [
    { from: /^\.github\/|(^|\/)\.[^/]+$/, note: 'upstream CI and repo config' },
    { from: /^include\/(yojimbo\w*)\.h$/, ifUpstream: 'source/$1.cpp', cs: 'cs/source/$1.cs', ts: 'ts/source/$1.ts', rs: 'rust/source/$1.rs' },
    { from: /^include\/(yojimbo\w*)\.h$/, cs: 'cs/include/$1.cs', ts: 'ts/include/$1.ts', rs: 'rust/include/$1.rs' },
    { from: /^source\/(yojimbo\w*)\.cpp$/, cs: 'cs/source/$1.cs', ts: 'ts/source/$1.ts', rs: 'rust/source/$1.rs' },
    { from: /^source\/yojimbo_address_conversion\.h$/, cs: 'cs/source/yojimbo_address.cs', ts: 'ts/source/yojimbo_client.ts', rs: 'rust/source/yojimbo_address.rs', note: 'the conversion helpers live in these files' },
    { from: /^(netcode|reliable)\/\1\.[ch]$/, cs: 'cs/$1/$1.cs', ts: 'ts/$1/$1.ts', rs: 'rust/$1/$1.rs' },
    { from: /^serialize\/serialize\.h$/, cs: 'cs/serialize/serialize.cs', ts: 'ts/serialize/serialize.ts', rs: 'rust/serialize/serialize.rs' },
    { from: /^sodium\/sodium\.[ch]$/, cs: null, ts: 'ts/sodium/sodium.ts', rs: 'rust/sodium/sodium.rs', note: 'C# uses BouncyCastle' },
    { from: /^fuzz\/(fuzz_\w+)\.(c|cpp|h)$/, cs: 'cs/fuzz/$1.cs', ts: null, rs: 'rust/fuzz/$1.rs', note: 'TypeScript has no fuzz port' },
    { from: /^(test|client|server|soak|loopback|custom_packet_io_test)\.cpp$/, cs: 'cs/$1.cs', ts: 'ts/$1.ts', rs: 'rust/$1.rs' },
    { from: /^shared\.h$/, cs: 'cs/shared.cs', ts: 'ts/shared.ts', rs: 'rust/shared.rs' },
    // Rust ports the TLSF allocator itself; C# and TypeScript emulate it inside their allocator file
    { from: /^tlsf\//, cs: { file: 'cs/source/yojimbo_allocator.cs', note: TLSF_EMULATED }, ts: { file: 'ts/source/yojimbo_allocator.ts', note: TLSF_EMULATED }, rs: 'rust/tlsf/tlsf.rs' },
    { from: /^fuzz\/corpus\//, note: 'fuzz corpus: cs/fuzz and rust/fuzz replay it straight from cpp/, so rerun `fuzz`' },
    { from: /^(fuzz\/dict\/|fuzz\/README\.md$)/, note: 'libFuzzer support files' },
    { from: /^test_layout_\w+\.cpp$/, note: 'C++ ABI layout check' },
    { from: /^(STANDARD|STATE-MACHINE)\.md$/, note: 'protocol spec: read for behaviour changes' },
    { from: /(^|\/)[^/]+\.md$|^LICENCE$|^doxygen\.config$/, note: 'docs' },
    { from: /^(CMakeLists\.txt|cmake\/|dependencies\.manifest$)/, note: 'C++ build' },
    { from: /^(matcher|tools)\//, note: 'upstream tooling, not ported' },
];

// a ported rule names every port, so adding a port means deciding its counterpart in every rule
for ( const rule of MAP )
{
    const missing = PORTS.filter( ( port ) => rule[port.id] === undefined );
    if ( missing.length > 0 && missing.length < PORTS.length )
        throw new Error( `MAP rule ${rule.from} has no entry for ${missing.map( ( port ) => port.id ).join( ', ' )}` );
}

function mapFile( file, upstreamFiles )
{
    for ( const rule of MAP )
    {
        const match = rule.from.exec( file );
        if ( !match )
            continue;
        const fill = ( template ) => template.replace( /\$(\d)/g, ( _, i ) => match[+i] );
        if ( rule.ifUpstream && !upstreamFiles.has( fill( rule.ifUpstream ) ) )
            continue;
        if ( rule[PORTS[0].id] === undefined )
            return { ported: false, note: rule.note };
        // a note on a ported file explains the mapping, or why a port has no counterpart
        const partial = PORTS.some( ( port ) => rule[port.id] === null );
        const targets = {};
        for ( const { id } of PORTS )
        {
            const value = rule[id];
            if ( value === null )
                targets[id] = { file: null, note: rule.note };
            else if ( typeof value === 'string' )
                targets[id] = { file: fill( value ), note: partial ? undefined : rule.note };
            else
                targets[id] = { file: fill( value.file ), note: value.note };
        }
        return { ported: true, targets };
    }
    return null;
}

function git( ...args )
{
    const options = { encoding: 'utf8', maxBuffer: 1 << 28, stdio: [ 'ignore', 'pipe', 'pipe' ] };
    return child_process.execFileSync( 'git', [ '-C', path.join( root, 'cpp' ), ...args ], options ).trimEnd();
}

function tryGit( ...args )
{
    try { return git( ...args ); } catch { return null; }
}

function parseArgs( argv )
{
    const options = { to: null, from: null, fetch: true, out: null, url: UPSTREAM_URL };
    for ( let i = 0; i < argv.length; i++ )
    {
        const arg = argv[i];
        const value = () => { if ( i + 1 >= argv.length ) throw new Error( `${arg} needs a value` ); return argv[++i]; };
        if ( arg === '--to' ) options.to = value();
        else if ( arg === '--from' ) options.from = value();
        else if ( arg === '--url' ) options.url = value();
        else if ( arg === '--out' ) options.out = value();
        else if ( arg === '--no-fetch' ) options.fetch = false;
        else throw new Error( `unknown argument ${arg}\nusage: node tools/upstream_diff.mjs [--to <ref>] [--from <commit>] [--no-fetch] [--url <repo>] [--out <file>]` );
    }
    return options;
}

// the commit the superproject pins cpp/ at (the gitlink in HEAD, not whatever cpp/ has checked out)
function readPin()
{
    const entry = child_process.execFileSync( 'git', [ '-C', root, 'ls-tree', 'HEAD', 'cpp' ], { encoding: 'utf8' } );
    const match = /^160000 commit ([0-9a-f]{40})\tcpp$/m.exec( entry );
    if ( !match )
        throw new Error( 'no cpp submodule entry in HEAD' );
    return match[1];
}

function resolveTarget( options )
{
    if ( !options.fetch )
        return { sha: git( 'rev-parse', '--verify', `${options.to ?? 'HEAD'}^{commit}` ), name: options.to ?? 'HEAD' };
    if ( git( 'rev-parse', '--is-shallow-repository' ) === 'true' )
        git( 'fetch', '--quiet', '--unshallow', options.url );
    let name = options.to;
    if ( name === null )
    {
        // upstream's default branch, by name, for the report
        const symref = /^ref: refs\/heads\/(\S+)\tHEAD$/m.exec( git( 'ls-remote', '--symref', options.url, 'HEAD' ) );
        name = symref ? symref[1] : 'HEAD';
    }
    // by URL, not cpp/'s remote: a submodule clone's origin can be an old name of the repository or a fork
    git( 'fetch', '--quiet', options.url, name );
    return { sha: git( 'rev-parse', '--verify', 'FETCH_HEAD^{commit}' ), name };
}

function readVersions( commit )
{
    const show = ( file ) => tryGit( 'show', `${commit}:${file}` ) ?? '';
    const pick = ( text, pattern ) => { const m = pattern.exec( text ); return m ? m[1] : null; };
    const triple = ( text, prefix ) =>
    {
        const parts = [ 'MAJOR', 'MINOR', 'PATCH' ].map( ( part ) => pick( text, new RegExp( `#define\\s+${prefix.replace( '%', part )}\\s+(\\d+)` ) ) );
        return parts.includes( null ) ? null : parts.join( '.' );
    };
    return {
        yojimbo: triple( show( 'include/yojimbo_config.h' ), 'YOJIMBO_%_VERSION' ),
        netcode: triple( show( 'netcode/netcode.h' ), 'NETCODE_VERSION_%' ),
        reliable: triple( show( 'reliable/reliable.h' ), 'RELIABLE_VERSION_%' ),
        serialize: triple( show( 'serialize/serialize.h' ), 'SERIALIZE_VERSION_%' ),
    };
}

// commit subjects in code spans: no @mentions, and no #123 that GitHub would link to this repository's issues
const quote = ( text ) => '`' + text.replace( /`/g, "'" ) + '`';
const short = ( sha ) => sha.slice( 0, 7 );
const stat = ( s ) => s.binary ? 'binary' : `+${s.added} −${s.removed}`;

function report( options )
{
    const target = resolveTarget( options );
    const to = target.sha;
    const from = tryGit( 'rev-parse', '--verify', '--quiet', `${options.from ?? readPin()}^{commit}` );
    if ( from === null )
        throw new Error( options.from ? `commit ${options.from} is not in cpp/` : `the pinned commit ${readPin()} is not in cpp/ (run git submodule update --init)` );
    const web = `https://github.com/${UPSTREAM}`;

    const base = tryGit( 'merge-base', from, to );
    const behind = Number( git( 'rev-list', '--count', `${from}..${to}` ) );
    const ahead = Number( git( 'rev-list', '--count', `${to}..${from}` ) );

    const lines = [];
    const out = ( line = '' ) => lines.push( line );
    out( `<!-- upstream-diff from=${from} to=${to} -->` );
    out( `# Upstream yojimbo since the cpp/ pin` );
    out();
    out( `${options.from ? 'From' : 'Pin'}: [\`${short( from )}\`](${web}/commit/${from}) · upstream ${quote( target.name )}: [\`${short( to )}\`](${web}/commit/${to}) · [compare](${web}/compare/${from}...${to})` );
    out();
    if ( behind === 0 )
    {
        out( ahead === 0 ? 'The pin is at upstream. Nothing to port.' : `The pin is ${ahead} commit(s) ahead of upstream ${quote( target.name )} and has nothing to port from it.` );
        return { text: lines.join( '\n' ) + '\n', behind, from, to };
    }
    if ( ahead > 0 )
        out( `> The pin is not on upstream ${quote( target.name )}: ${ahead} pinned commit(s) are missing from it. File changes below are from the merge base \`${short( base ?? from )}\`.\n` );

    // versions
    const before = readVersions( from ), after = readVersions( to );
    const moved = Object.keys( after ).filter( ( name ) => before[name] !== after[name] );
    out( `**${behind} commit(s)** past the pin.` );
    out();
    if ( moved.length > 0 )
    {
        out( '## Versions' );
        out();
        out( '| | pin | upstream |' );
        out( '|---|---|---|' );
        for ( const name of moved )
            out( `| ${name} | ${before[name] ?? '—'} | **${after[name] ?? '—'}** |` );
        out();
        if ( moved.includes( 'yojimbo' ) && after.yojimbo )
            out( `Upstream yojimbo is now ${after.yojimbo}: after porting, \`node tools/version.mjs set ${after.yojimbo}\` and update the in-code version constants.` );
        const vendored = moved.filter( ( name ) => name !== 'yojimbo' );
        if ( vendored.length > 0 )
            out( `Vendored ${vendored.join( ', ' )} moved: update their in-code version constants and the versions in README.md, and run \`interop/run.sh\`.` );
        out();
    }

    // files
    const diffBase = base ?? from;
    const upstreamFiles = new Set( git( 'ls-tree', '-r', '--name-only', to ).split( '\n' ) );
    const stats = new Map();
    for ( const line of git( 'diff', '--numstat', '--no-renames', diffBase, to ).split( '\n' ).filter( Boolean ) )
    {
        const [ added, removed, file ] = line.split( '\t' );
        stats.set( file, { added, removed, binary: added === '-' } );
    }
    const statuses = new Map();
    for ( const line of git( 'diff', '--name-status', '--no-renames', diffBase, to ).split( '\n' ).filter( Boolean ) )
    {
        const [ status, file ] = line.split( '\t' );
        statuses.set( file, status[0] );
    }

    const ports = Object.fromEntries( PORTS.map( ( port ) => [ port.id, new Map() ] ) );     // port file -> { sources, note }
    const notPorted = [];                                // a port with no counterpart for a ported file
    const informational = new Map();                     // note -> [ upstream files ]
    const unmapped = [];
    const oldFiles = new Set( git( 'ls-tree', '-r', '--name-only', diffBase ).split( '\n' ) );
    for ( const [ file, status ] of statuses )
    {
        const mapped = mapFile( file, status === 'D' ? oldFiles : upstreamFiles );
        const entry = { file, status, stat: stats.get( file ) };
        if ( mapped === null )
            unmapped.push( entry );
        else if ( !mapped.ported )
        {
            if ( !informational.has( mapped.note ) )
                informational.set( mapped.note, [] );
            informational.get( mapped.note ).push( entry );
        }
        else
        {
            for ( const { id: port } of PORTS )
            {
                const target = mapped.targets[port];
                if ( target.file === null )
                {
                    notPorted.push( { ...entry, port, note: target.note } );
                    continue;
                }
                if ( !ports[port].has( target.file ) )
                    ports[port].set( target.file, { sources: [], note: target.note } );
                ports[port].get( target.file ).sources.push( entry );
            }
        }
    }

    const list = ( entries ) => entries.slice( 0, LIST_LIMIT ).map( describe ).join( ', ' ) + ( entries.length > LIST_LIMIT ? `, and ${entries.length - LIST_LIMIT} more` : '' );
    const describe = ( e ) => `${quote( e.file )} (${e.status === 'A' ? 'new, ' : e.status === 'D' ? 'deleted, ' : ''}${e.stat ? stat( e.stat ) : 'mode'})`;
    for ( const { id: port, title } of PORTS )
    {
        out( `## ${title}` );
        out();
        if ( ports[port].size === 0 )
            out( 'Nothing to port.' );
        for ( const [ target, { sources, note } ] of [ ...ports[port] ].sort( ( a, b ) => a[0].localeCompare( b[0] ) ) )
        {
            const exists = fs.existsSync( path.join( root, target ) );
            const gone = sources.every( ( s ) => s.status === 'D' );
            const flag = gone ? ' — **upstream deleted its sources**' : exists ? '' : ' — **new file**';
            out( `- [ ] \`${target}\`${flag} ← ${sources.map( describe ).join( ', ' )}${note ? ` _(${note})_` : ''}` );
        }
        const skipped = notPorted.filter( ( e ) => e.port === port );
        for ( const note of new Set( skipped.map( ( e ) => e.note ) ) )
            out( `- not in this port (${note}): ${list( skipped.filter( ( e ) => e.note === note ) )}` );
        out();
    }

    if ( unmapped.length > 0 )
    {
        out( '## No port counterpart' );
        out();
        out( 'These upstream files match no mirroring rule (`MAP` in `tools/upstream_diff.mjs`). Decide where each belongs and add a rule.' );
        out();
        // one line per top-level directory, so a removed vendor tree doesn't flood the report
        const groups = Map.groupBy( unmapped, ( e ) => e.file.includes( '/' ) ? e.file.slice( 0, e.file.indexOf( '/' ) + 1 ) : e.file );
        for ( const [ group, entries ] of groups )
            out( entries.length === 1 ? `- [ ] ${describe( entries[0] )}` : `- [ ] ${quote( group )} (${entries.length} files): ${list( entries )}` );
        out();
    }

    if ( informational.size > 0 )
    {
        out( '## Informational (not ported)' );
        out();
        for ( const [ note, entries ] of informational )
            out( `- **${note}**: ${list( entries )}` );
        out();
    }

    const syncing = [
        '## Syncing',
        '',
        `Port each checked file side by side with its upstream diff (\`git -C cpp diff ${short( diffBase )} ${short( to )} -- <file>\`), then move the \`cpp\` pin to \`${short( to )}\` and run the C#, TypeScript and Rust tests and \`interop/run.sh\`. See "Tracking upstream" in README.md.`,
    ];

    // the commits go last and get whatever room the report has left, newest last
    out( '## Commits' );
    out();
    const log = git( 'log', '--no-merges', '--reverse', '--format=%H%x09%as%x09%an%x09%s', `${from}..${to}` ).split( '\n' ).filter( Boolean );
    const merges = behind - log.length;
    let room = REPORT_LIMIT - [ ...lines, ...syncing ].join( '\n' ).length - 500;
    let shown = 0;
    for ( const line of log )
    {
        const [ sha, date, author, subject ] = line.split( '\t' );
        const entry = `- [\`${short( sha )}\`](${web}/commit/${sha}) ${date} ${quote( subject )} (${quote( author )})`;
        if ( ( room -= entry.length + 1 ) < 0 )
            break;
        out( entry );
        shown++;
    }
    if ( shown < log.length )
        out( `- … and ${log.length - shown} more: see the [compare view](${web}/compare/${from}...${to})` );
    if ( merges > 0 )
        out( `\n${merges} merge commit(s) not listed.` );
    out();
    lines.push( ...syncing );
    return { text: lines.join( '\n' ) + '\n', behind, from, to };
}

try
{
    const options = parseArgs( process.argv.slice( 2 ) );
    const result = report( options );
    if ( options.out )
        fs.writeFileSync( options.out, result.text );
    else
        process.stdout.write( result.text );
    if ( process.env.GITHUB_OUTPUT )
        fs.appendFileSync( process.env.GITHUB_OUTPUT, `behind=${result.behind}\nfrom=${result.from}\nto=${result.to}\n` );
}
catch ( error )
{
    console.error( `error: ${error.message}` );
    process.exitCode = 1;
}
