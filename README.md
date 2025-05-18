# This is a fork of the original spartan-ecdsa repo developed by personaelabs

The build was not working off of the main branch code, so we made the following changes:

1. Before running yarn build, have to manually add packages in the root directory

```
yarn add circomlib -W
yarn add @typescript-eslint/parser -W
yarn add @personaelabs/spartan-ecdsa -W
```

2. Inside of packages/lib, we made the following changes

- Moved test folder inside of src (with path updates)
- Changed `tsconfig.json` to include `"rootDir": "src"` (to flatten the builds in dist/) so that paths to type files in package.json were correct:
  `"main": "./dist/index.js",
"types": "./dist/index.d.ts"`
- Changed all "@src/" in non-config files in packages/lib/src to the right paths (relative to the actual files) — “./” manually (would not be recognized/path would not be resolved in resulting js compilations)

3. In packages/benchmark/web/pages/index.tsx, we made the following changes to fix static type errors:

- Wrapped arguments of prover.prove() and verifier.verify with `{}` so that number of arguments is correct
- Added `publicInputSer` argument to all instances of `verifier.verify()`, to become
  ````verifier.verify({
    proof,
    publicInputSer: publicInput.serialize()
  });```
  ````

# Spartan-ecdsa

Spartan-ecdsa (which to our knowledge) is the fastest open-source method to verify ECDSA (secp256k1) signatures in zero-knowledge. It can prove ECDSA group membership 10 times faster than [efficient-zk-ecdsa](https://github.com/personaelabs/efficient-zk-ecdsa), our previous implementation of fast ECDSA signature proving. Please refer to [this blog post](https://personaelabs.org/posts/spartan-ecdsa/) for further information.

## Constraint breakdown

spartan-ecdsa achieves the phenomenal result of **hashing becoming the bottleneck instead of ECC operations** for the `pubkey_membership.circom` circuit. In particular, there are **3,039** constraints for efficient ECDSA signature verification, and **5,037** constraints for a depth 20 merkle tree membership check + 1 Poseidon hash of the ECDSA public key. The drop from the original 1.5 million constraints of [circom-ecdsa](https://github.com/0xPARC/circom-ecdsa) comes primarily from doing right-field arithmetic with secq and avoiding SNARK-unfriendly range checks and big integer math.

We also use [efficient ECDSA signatures](https://personaelabs.org/posts/efficient-ecdsa-1/) instead of standard ECDSA siagnatures to save an additional **14,505** constraints. To review, the standard ECDSA signature consists of $(r, s)$ for a public key $Q_a$ and message $m$, where $r$ is the x-coordinate of a random elliptic curve point $R$. Standard ECDSA signature verification checks if

```math
R == m s ^{-1} * G + r s ^{-1} * Q_a
```

where $G$ is the generator point of the curve. The efficient ECDSA signature consists of $s$ as well as $T = r^{-1} * R$ and $U = -r^{-1} * m * G$, which can both be computed outside of the SNARK without breaking correctness. Efficient ECDSA signature verification checks if

```math
s * T + U == Q_a
```

Thus, verifying a standard ECDSA signature instead of the efficient ECDSA signature requires (1) computing $s^{-1}$, $r \* s^{-1}$, $m \* s^{-1}$, and (2) an extra ECC scalar multiply to compute $m s ^{-1} * G$. The former computations happen in the scalar field of secp, which is unequal to the scalar field of secq, and so we incur 11,494 additional constraints for the wrong-field math. The latter can use the `Secp256k1Mul` subroutine and incurs 3,011 additional constraints.

## Benchmarks

Proving membership to a group of ECDSA public keys

|          Benchmark           |   #   |
| :--------------------------: | :---: |
|         Constraints          | 8,076 |
|   Proving time in browser    |  4s   |
|   Proving time in Node.js    |  2s   |
| Verification time in browser |  1s   |
| Verification time in Node.js | 300ms |
|          Proof size          | 16kb  |

- Measured on a M1 MacBook Pro with 80Mbps internet speed.
- Both proving and verification time in browser includes the time to download the circuit.

## Disclaimers

- Spartan-ecdsa is unaudited. Please use it at your own risk.
- Usage on mobile browsers isn’t currently supported.

## Install

```jsx
yarn add @personaelabs/spartan-ecdsa
```

## Development

### Node.js

v18 or later

### Build

1. Install Circom with secq256k1 support

```
git clone https://github.com/DanTehrani/circom-secq
cd circom-secq && cargo build --release && cargo install --path circom
```

2. Install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

3. Install dependencies & Build all packages

```jsx
yarn && yarn build
```
