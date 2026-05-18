# gigadoram-rs

Rust workspace for a GigaDORAM implementation.

## Layout

- `primitives`: shared types, circuits, PRF, permutation, and CHT scaffolding.
- `data-structures`: SpeedCache, oblivious hash table, and rebuild buffer scaffolding.
- `core`: config, context, DORAM orchestration, MPC engine bindings, and timing types.
- `test`: executable and integration-test harnesses for mock flows.

## Getting started

```bash
cargo test
```
