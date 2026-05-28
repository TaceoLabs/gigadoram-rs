#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
    echo "usage: $0 PARTY_ID PARTY0_HOST[:PORT] PARTY1_HOST[:PORT] PARTY2_HOST[:PORT] [benchmark args...]" >&2
    echo "example: $0 0 10.0.0.10 10.0.0.11 10.0.0.12 --num-queries 5000 --log-address-space 20 --num-levels 4 --log-amp-factor 4 --build-bottom-level-at-startup false" >&2
    exit 2
fi

party_id=$1
shift
hosts=("$1" "$2" "$3")
shift 3

if [[ ! "$party_id" =~ ^[0-2]$ ]]; then
    echo "PARTY_ID must be 0, 1, or 2" >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_port="${DORAM_BENCH_BASE_PORT:-10000}"
bind_host="${DORAM_BENCH_BIND_HOST:-0.0.0.0}"
results_dir="${DORAM_BENCH_RESULTS_DIR:-$repo_root/multi_server_results}"
config_dir="${DORAM_BENCH_CONFIG_DIR:-$results_dir/configs}"
config="$config_dir/party${party_id}.toml"
log="$results_dir/party${party_id}.log"

endpoint() {
    local host=$1
    local party=$2
    if [[ "$host" == *:* ]]; then
        echo "$host"
    else
        echo "$host:$((base_port + party))"
    fi
}

mkdir -p "$config_dir" "$results_dir"
{
    echo "[network]"
    echo "my_id = $party_id"
    echo "bind_addr = \"$bind_host:$((base_port + party_id))\""
    echo "timeout = \"30min\""
    echo "max_frame_length = 1073741824"

    for other in 0 1 2; do
        echo "[[network.parties]]"
        echo "id = $other"
        echo "dns_name = \"$(endpoint "${hosts[$other]}" "$other")\""
    done
} >"$config"

cd "$repo_root"
RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native" \
    cargo build --release -p doram --bin multi_server_benchmarks

{
    echo "---------"
    echo "Data from"
    date
    echo "---------"
    echo "Party: $party_id"
    echo "Config: $config"
    echo "Hosts: ${hosts[*]}"
} >>"$log"

"$repo_root/target/release/multi_server_benchmarks" \
    --network "$config" \
    "$@" 2>&1 | tee -a "$log"
