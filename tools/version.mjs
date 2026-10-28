#!/usr/bin/env node
/*
    Package versions for the ports.

    The ports mirror the upstream yojimbo version they implement (cpp/include/yojimbo_config.h), plus a port
    revision for fixes made here between upstream releases. All the packages (NuGet yojimbo, npm yojimbo2, crates.io
    yojimbo) use one version that folds the revision into the patch: MAJOR.MINOR.(PATCH * 100 + REVISION).

        1.13.500    the port of upstream 1.13.5
        1.13.501    the first port-only fix on top of it
        1.13.600    the port of upstream 1.13.6

    VERSION at the repo root holds it; release tags are v<VERSION>.

        node tools/version.mjs                     print the version and the upstream version it ports
        node tools/version.mjs check [tag]         verify VERSION, cs/yojimbo.csproj, ts/package.json, rust/Cargo.toml
                                                   and rust/Cargo.lock if present (and a v<VERSION> tag)
        node tools/version.mjs set 1.13.501        write VERSION, cs/yojimbo.csproj, ts/package.json and its lockfile,
                                                   rust/Cargo.toml and the yojimbo entry of each Cargo.lock present
        node tools/version.mjs set 1.13.5.1        the same, given as upstream version plus revision
*/

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const root = path.resolve( path.dirname( url.fileURLToPath( import.meta.url ) ), '..' );
const file = ( relative ) => path.join( root, relative );

// accepts the package form (1.13.500, 1.13.501) or upstream plus revision (1.13.5, 1.13.5.1)
function parse( version )
{
    const match = /^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$/.exec( version.trim() );
    if ( !match )
        throw new Error( `bad version "${version}": expected MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH.REVISION` );
    const [ , major, minor, patch, revision ] = match;
    if ( revision !== undefined || +patch < 100 )
    {
        const v = { major: +major, minor: +minor, patch: +patch, revision: revision === undefined ? 0 : +revision };
        if ( v.revision > 99 )
            throw new Error( `port revision ${v.revision} is over 99, which the version can't hold` );
        return v;
    }
    return { major: +major, minor: +minor, patch: Math.floor( +patch / 100 ), revision: +patch % 100 };
}

const upstreamOf = ( v ) => `${v.major}.${v.minor}.${v.patch}`;
const packageOf = ( v ) => `${v.major}.${v.minor}.${v.patch * 100 + v.revision}`;

function readUpstream()
{
    const header = fs.readFileSync( file( 'cpp/include/yojimbo_config.h' ), 'utf8' );
    const get = ( name ) =>
    {
        const match = new RegExp( `#define\\s+YOJIMBO_${name}_VERSION\\s+(\\d+)` ).exec( header );
        if ( !match )
            throw new Error( `YOJIMBO_${name}_VERSION not found in cpp/include/yojimbo_config.h (is the cpp submodule checked out?)` );
        return match[1];
    };
    return `${get( 'MAJOR' )}.${get( 'MINOR' )}.${get( 'PATCH' )}`;
}

const readVersion = () => fs.readFileSync( file( 'VERSION' ), 'utf8' ).trim();

function readCsproj()
{
    const match = /<Version>([^<]+)<\/Version>/.exec( fs.readFileSync( file( 'cs/yojimbo.csproj' ), 'utf8' ) );
    if ( !match )
        throw new Error( 'no <Version> in cs/yojimbo.csproj' );
    return match[1];
}

const readPackageJson = () => JSON.parse( fs.readFileSync( file( 'ts/package.json' ), 'utf8' ) ).version;

// the version key of Cargo.toml's [package] table (no '[' between the table header and the key)
const CARGO_TOML_VERSION = /(^\[package\][^[]*?^version\s*=\s*")([^"]*)(")/m;
// the yojimbo entry of a Cargo.lock: the crate itself in rust/, the path dependency in interop/rust/
const CARGO_LOCK_VERSION = /(^\[\[package\]\]\r?\nname = "yojimbo"\r?\nversion = ")([^"]*)(")/m;
const CARGO_LOCKS = [ 'rust/Cargo.lock', 'interop/rust/Cargo.lock' ];

function readCargo( name, pattern )
{
    const match = pattern.exec( fs.readFileSync( file( name ), 'utf8' ) );
    if ( !match )
        throw new Error( `no yojimbo package version in ${name}` );
    return match[2];
}

const readCargoToml = () => readCargo( 'rust/Cargo.toml', CARGO_TOML_VERSION );

function check( tag )
{
    const problems = [];
    const version = readVersion();
    const v = parse( version );
    if ( version !== packageOf( v ) )
        problems.push( `VERSION ${version} is not in package form (expected ${packageOf( v )})` );
    const upstream = readUpstream();
    if ( upstreamOf( v ) !== upstream )
        problems.push( `VERSION ${version} ports upstream ${upstreamOf( v )}, but cpp/ is upstream ${upstream}` );
    if ( readCsproj() !== packageOf( v ) )
        problems.push( `cs/yojimbo.csproj has ${readCsproj()}, expected ${packageOf( v )}` );
    if ( readPackageJson() !== packageOf( v ) )
        problems.push( `ts/package.json has ${readPackageJson()}, expected ${packageOf( v )}` );
    if ( readCargoToml() !== packageOf( v ) )
        problems.push( `rust/Cargo.toml has ${readCargoToml()}, expected ${packageOf( v )}` );
    if ( fs.existsSync( file( 'rust/Cargo.lock' ) ) && readCargo( 'rust/Cargo.lock', CARGO_LOCK_VERSION ) !== packageOf( v ) )
        problems.push( `rust/Cargo.lock has ${readCargo( 'rust/Cargo.lock', CARGO_LOCK_VERSION )}, expected ${packageOf( v )}` );
    if ( tag !== undefined && tag.replace( /^refs\/tags\//, '' ) !== `v${packageOf( v )}` )
        problems.push( `tag ${tag} does not match VERSION (expected v${packageOf( v )})` );
    for ( const problem of problems )
        console.error( `error: ${problem}` );
    if ( problems.length === 0 )
        console.log( `ok: ${packageOf( v )} (upstream ${upstream}, port revision ${v.revision})` );
    return problems.length === 0;
}

function set( version )
{
    const v = parse( version );
    const packageVersion = packageOf( v );
    readCargoToml();        // fails before anything is written when rust/Cargo.toml has no [package] version
    fs.writeFileSync( file( 'VERSION' ), packageVersion + '\n' );

    const csproj = fs.readFileSync( file( 'cs/yojimbo.csproj' ), 'utf8' );
    fs.writeFileSync( file( 'cs/yojimbo.csproj' ), csproj.replace( /<Version>[^<]+<\/Version>/, `<Version>${packageVersion}</Version>` ) );

    for ( const name of [ 'ts/package.json', 'ts/package-lock.json' ] )
    {
        if ( !fs.existsSync( file( name ) ) )
            continue;
        const json = JSON.parse( fs.readFileSync( file( name ), 'utf8' ) );
        json.version = packageVersion;
        if ( json.packages?.[''] )
            json.packages[''].version = packageVersion;
        fs.writeFileSync( file( name ), JSON.stringify( json, null, 2 ) + '\n' );
    }

    for ( const [ name, pattern ] of [ [ 'rust/Cargo.toml', CARGO_TOML_VERSION ], ...CARGO_LOCKS.map( ( lock ) => [ lock, CARGO_LOCK_VERSION ] ) ] )
    {
        if ( name !== 'rust/Cargo.toml' && !fs.existsSync( file( name ) ) )
            continue;
        readCargo( name, pattern );         // throws when the version is missing, rather than writing the file unchanged
        fs.writeFileSync( file( name ), fs.readFileSync( file( name ), 'utf8' ).replace( pattern, `$1${packageVersion}$3` ) );
    }
    console.log( `set: ${packageVersion} (upstream ${upstreamOf( v )}, port revision ${v.revision})` );
}

const [ command, argument ] = process.argv.slice( 2 );
if ( command === 'set' && argument )
    set( argument );
else if ( command === 'check' )
    process.exitCode = check( argument ) ? 0 : 1;
else if ( command === undefined )
{
    const v = parse( readVersion() );
    console.log( `${packageOf( v )} (upstream ${upstreamOf( v )}, port revision ${v.revision}; cpp/ is upstream ${readUpstream()})` );
}
else
{
    console.error( 'usage: node tools/version.mjs [check [tag] | set <MAJOR.MINOR.PATCH[.REVISION]>]' );
    process.exitCode = 1;
}
