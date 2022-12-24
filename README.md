# Spartan-Wasm

An attempt to run [Spartan](https://github.com/microsoft/Spartan) prover in browser.

**Todos**

- [x] Circom compiler that can compile to the scalar field of curve25519.

- [x] A compiler to generate a Spartan circuit from Circom R1CS. The compiler uses [Nova Scotia](https://github.com/nalinbhardwaj/Nova-Scotia) at its core.
- [x] Spartan prover in wasm.
- [x] Right-field ECDSA verification + membership proving circuit written in Circom.

- [ ] Circom compiler that can compile to the scalar field of secq256k1.

- [ ] Spartan implementation over secq256k1.

## Browser proving benchmarks

We use circuits with varying number of Poseidon hash instance (e.g. poseidon5.circom has 5 instances of Poseidon hashes).

**Prover**

- MacBook Pro (M1 Pro)
- Internet download speed: 170Mbps
- Browser: Brave

Spartan NIZK

| Circuit     | Constraints | Full proving time | Circuit (i.e. proving key ) size | Circuit download time | Proof size |
| ----------- | ----------- | ----------------- | -------------------------------- | --------------------- | ---------- |
| poseidon5   | 3045        | 1s                | 6.8 MB                           | 320ms                 | 12.9KB     |
| poseidon32  | 19488       | 4.5s              | 43.2 MB                          | 2s                    | 17.4KB     |
| poseidon256 | 155904      | 31s               | 345.9 MB                         | 16s                   | 32.8KB     |

Groth16

| Circuit     | Constraints | Full proving time | Zkey size |
| ----------- | ----------- | ----------------- | --------- |
| poseidon5   | 3045        | 950ms             | 4.6 MB    |
| poseidon32  | 19488       | 3.7s              | 29.8 MB   |
| poseidon256 | 155904      | 24s               | 238.1 MB  |

- We don't present the zkey download time for Groth16 due benchmarking processes inside snarkjs being nontrivial.

- The time required to download the circuit (i.e. proving key) is a major contributor to the full proving time. For mobile applications, we could download the circuit at app installation, relieving the burden of downloading the circuit at proving time.
- Spartan NIZK circuit serialization is not optimized; which is why Spartan NIZK has larger “proving keys”.

## Compile prover to wasm

```
sh ./scripts/build_wasm.sh
```

## Compile Circom R1CS to serialized Spartan circuit instance

```
cargo run --release --bin gen_spartan_inst
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
