#!/bin/bash
# Runs every server/client pairing of the C++, C#, TypeScript and Rust implementations against each other (16 pairings).
# usage: interop/run.sh [port]      (builds the C++, C# and Rust sides first; exit code is the number of failed pairings)
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${1:-45000}
"$HERE/build_cpp.sh" > /dev/null || exit 1
dotnet build "$HERE/cs/interop.csproj" -c Release -v q -nologo > /dev/null || exit 1
cargo build --release --quiet --manifest-path "$HERE/rust/Cargo.toml" || exit 1
CPP="$HERE/bin/cpp/interop"
CS="dotnet $HERE/cs/bin/Release/net10.0/interop.dll"
TS="node $HERE/ts/interop.ts"
RS="$HERE/rust/target/release/interop"
failed=0
run() {
    local name=$1 server=$2 client=$3
    $server server $PORT > /tmp/interop_server.$$ 2>&1 &
    local pid=$!
    sleep 1
    $client client $PORT > /tmp/interop_client.$$ 2>&1
    local client_result=$?
    wait $pid; local server_result=$?
    if [ $client_result -eq 0 ] && [ $server_result -eq 0 ]; then
        echo "PASS  $name   $(grep 'echoes verified' /tmp/interop_client.$$)"
    else
        echo "FAIL  $name"; sed 's/^/      client: /' /tmp/interop_client.$$; sed 's/^/      server: /' /tmp/interop_server.$$
        failed=$((failed + 1))
    fi
    rm -f /tmp/interop_server.$$ /tmp/interop_client.$$
}
impl() { case $1 in c++) echo "$CPP";; c#) echo "$CS";; ts) echo "$TS";; rs) echo "$RS";; esac; }
for server in c++ c# ts rs; do
    for client in c++ c# ts rs; do
        run "$(printf '%-3s server <-> %-3s client' $server $client)" "$(impl $server)" "$(impl $client)"
    done
done
exit $failed
