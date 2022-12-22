# Spartan-Wasm

An attempt to run [Spartan](https://github.com/microsoft/Spartan) prover in browser.

## Compile prover to wasm

```
sh ./scripts/build_wasm.sh
```

## Compile Circom R1CS to serialized Spartan circuit instance

```
cargo run --bin gen_spartan_inst
```

## Run compiled wasm in browser

### Get into browser_benchmark dir

```
cd ./browser_benchmark
```

### Install dependencies

```
yarn
```

### Start server

```
yarn dev
```

## Build

Switch to nightly Rust using `rustup`:

```text
rustup default nightly
```

build

```
cargo build
```
