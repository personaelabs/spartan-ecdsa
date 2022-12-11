# Spartan-Wasm

An attempt to run [Spartan](https://github.com/microsoft/Spartan) prover in browser.

## Compile to Wasm

```
sh ./scripts/build_wasm.sh
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
