# gigadoram-rs

A Rust implementation of **GigaDORAM**, a hierarchical Distributed Oblivious RAM (DORAM) for honest-majority, three-party computation (Rep3 replicated secret sharing).

A DORAM lets three parties jointly read and write a large secret-shared array while keeping the access pattern hidden from every party. GigaDORAM keeps the per-access communication and round complexity low enough to scale to very large address spaces by organizing storage as a hierarchy of oblivious hash tables that are periodically rebuilt.

This crate is a Rust port of the original **GigaDORAM C++ reference implementation**. The construction comes from the paper:

> *GigaDORAM: Breaking the Billion Address Barrier* — Brett Hemenway Falk, Rafail Ostrovsky, Matan Shtepel, Jacob Zhang (USENIX Security).

The MPC backend (replicated secret sharing, networking, garbled circuits) comes from [co-snarks](https://github.com/TaceoLabs/co-snarks) (`mpc-core`, `mpc-net`).

## Full address space via dummy-address reassignment

The original GigaDORAM reserves address `0` as a special marker for dummy elements in its hierarchical ORAM design. This is inconvenient for applications that need to access address `0`, since they must introduce address offsets, an operation that is costly in MPC.

We modify GigaDORAM to enable the use of the full address space `{0, …, 2^N − 1}` for `N`-bit addresses by reassigning the dummy marker from `0` to `2^N`. Beyond enabling the full address space, this change improves protocol performance by eliminating costly zero-checks, which require multiple rounds of communication. Concretely, we make the following changes:

- **SpeedCache query.** When an element is found in the SpeedCache, its address is overwritten with the dummy address. We modify the `xy_if_xs_equal_circuit` to obliviously overwrite the found value with `2^N` instead of `0`.
- **Rebuild (upper levels).** Dummy elements inherited from upper levels are detected and relabeled by checking whether the address is `0` or its MSB is set (i.e. the address lies in `[2^N, 2^(N+1) − 1]`). With the new encoding, only the MSB check is needed, so the zero-check is eliminated.
- **Rebuild (bottom level).** Dummies are detected and cleansed via the same procedure as for the upper levels, again eliminating the zero-check.

### Correctness and security implications

The choice of dummy marker does not impact the correctness or obliviousness of the protocol, as long as it does not collide with the real address space. For an `N`-bit address space, real elements live in `[0, 2^N − 1]` while dummies live in `[2^N, 2^(N+1) − 1]`. The value `2^N` also serves as the initial dummy marker assigned to newly created dummy elements before their first relabeling.

Relabeling is necessary because the `OhTable` build uses a PRF on the element addresses, and without unique addresses multiple dummies would collide to the same table slot. Relabeling assigns unique addresses to every dummy that is part of an `OhTable` build before they are ever used as PRF inputs, so overlapping the initial dummy marker with the dummy space after relabeling is not an issue.

Increasing the address space by `1` increases the number of real elements in the bottom level by `1`, to `2^N` elements. This means a maximum of `2^N` dummy addresses are needed for the relabel operation, for which there is sufficient space; upper levels require fewer.

## Workspace layout

The repository is a Cargo workspace with four crates:

| Crate | Path | Contents |
| --- | --- | --- |
| `primitives` | `crates/primitives` | Shared share types (`X`, `Y`, `Block`, …) and helpers: public promotion, casts, oblivious array shuffle, RNG/utilities. |
| `circuits` | `crates/circuits` | MPC circuits: Batcher sorting network, LowMC PRF, CHT lookup, and the SpeedCache equality/select circuits. |
| `data-structures` | `crates/data-structures` | The building blocks: the linear `SpeedCache`, the oblivious hash table (`OhTable`), and the cuckoo hash table (`cht`). |
| `doram` | `crates/doram` | The top-level `GigaDoram` hierarchy and its `GigaDoramConfig`, plus the benchmark binaries. |
```

## Running the tests

```bash
cargo test                       # whole workspace
cargo test -p doram              # just the DORAM integration tests
cargo test -p doram --test gigadoram test_overwrite   # a single test
```

The tests run all three parties in a single process: `run_parties` spawns one thread per party connected over an in-memory `LocalNetwork`, so no setup or network configuration is required. The e2e correctness and invariant tests live in [`crates/doram/tests/gigadoram.rs`](crates/doram/tests/gigadoram.rs).

## Benchmarks

Two binaries in the `doram` crate drive a configurable workload of random reads/writes and report timing and bytes sent. Both share the same flags (run with `--help` for the full list); the ones used most often are:

```
--num-queries                     number of operations to run
--log-address-space               log2 of the address space size
--num-levels                      number of hierarchy levels
--log-amp-factor                  log2 of the per-level amplification factor
--build-bottom-level-at-startup   pre-populate the bottom level instead of filling lazily
--seed                            RNG seed for reproducible workloads
```

### Single-process (all three parties locally)

```bash
cargo run --release -p doram --bin local_benchmarks -- \
    --num-queries 5000 --log-address-space 20 --num-levels 4 --log-amp-factor 4
```

### Three real TCP processes

`multi_server_benchmarks` runs one process per party and connects them over TCP using a small TOML network config (`--network party<id>.toml`). Two helper scripts generate the configs and launch the parties for you:

- **All on one machine, with simulated network latency/bandwidth** (uses `tc netem`, so it needs `sudo`):

  ```bash
  ./scripts/local_benchmarks.sh 100us 10Gbit \
      --num-queries 5000 --log-address-space 20 --num-levels 4 --log-amp-factor 4
  ```

  Results are appended under `single_server_results/`.

- **Across separate machines** run once per party, pointing each at the three hosts:

  ```bash
  # on each host, with PARTY_ID in {0,1,2}
  ./scripts/multi_server_benchmarks.sh PARTY_ID HOST0 HOST1 HOST2 \
      --num-queries 5000 --log-address-space 20 --num-levels 4 --log-amp-factor 4
  ```

  Configs and logs are written under `multi_server_results/`.