#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 LATENCY BANDWIDTH [benchmark args...]" >&2
    echo "example: $0 100us 10Gbit --num-queries 5000 --log-address-space 20 --num-levels 4 --log-amp-factor 4 --build-bottom-level-at-startup false" >&2
    exit 2
fi

latency=$1
bandwidth=$2
shift 2

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
base_port="${DORAM_BENCH_BASE_PORT:-10000}"
results_dir="${DORAM_BENCH_RESULTS_DIR:-$repo_root/single_server_results}"
pids=()

cleanup() {
    status=$?
    if ((${#pids[@]})); then
        kill "${pids[@]}" 2>/dev/null || true
    fi
    sudo tc qdisc del dev lo root 2>/dev/null || true
    rm -rf "$tmpdir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

write_config() {
    local party=$1
    local port=$((base_port + party))
    local config="$tmpdir/party${party}.toml"

    {
        echo "my_id = $party"
        echo "bind_addr = \"0.0.0.0:$port\""
        echo "timeout = \"30min\""
        echo "max_frame_length = 1073741824"

        for other in 0 1 2; do
            echo "[[parties]]"
            echo "id = $other"
            echo "dns_name = \"127.0.0.1:$((base_port + other))\""
        done
    } >"$config"
}

command -v cargo >/dev/null || {
    echo "cargo not found; run this script as your normal user, not with sudo bash" >&2
    exit 1
}
sudo -v

mkdir -p "$results_dir"
for party in 0 1 2; do
    write_config "$party"
done

cd "$repo_root"
echo "building multi_server_benchmarks..." >&2
RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native" \
    cargo build --release -p doram --bin multi_server_benchmarks

echo "applying tc: delay=$latency rate=$bandwidth" >&2
sudo tc qdisc replace dev lo root netem delay "$latency" rate "$bandwidth"

echo "running three local TCP parties..." >&2
for party in 0 1 2; do
    "$repo_root/target/release/multi_server_benchmarks" \
        --network "$tmpdir/party${party}.toml" \
        "$@" >"$tmpdir/party${party}.log" 2>&1 &
    pids+=("$!")
done

failed=0
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        failed=1
    fi
done
pids=()

for party in 0 1 2; do
    report="$results_dir/doram_timing_report$((party + 1)).txt"
    {
        echo "---------"
        echo "Data from"
        date
        echo "---------"
        echo "Latency: $latency"
        echo "Bandwidth: $bandwidth"
        cat "$tmpdir/party${party}.log"
    } >>"$report"
done

if [[ "$failed" -ne 0 ]]; then
    for party in 0 1 2; do
        echo "----- party $party log -----" >&2
        cat "$tmpdir/party${party}.log" >&2
    done
    exit 1
fi

cat "$tmpdir/party0.log"
