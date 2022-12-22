# Spartan-Wasm

An attempt to run [Spartan](https://github.com/microsoft/Spartan) prover in browser.

**Todos**

- [x] Circom compiler that can compile to the scalar field of curve25519.

- [x] A compiler to generate a Spartan circuit from Circom R1CS. The compiler uses [Nova Scotia](https://github.com/nalinbhardwaj/Nova-Scotia) at its core.
- [x] Spartan prover in wasm.
- [x] Right-field ECDSA verification + membership proving circuit written in Circom.

- [ ] Circom compiler that can compile to the scalar field of secp256k1.

- [ ] Spartan implementation over secq256k1.

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
