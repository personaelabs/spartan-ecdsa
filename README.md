# Spartan-ecdsa

Spartan-ecdsa (which to our knowledge) is the fastest open-source method to verify ECDSA (secp256k1) signatures in zero-knowledge. It can prove ECDSA group membership 10 times faster than [efficient-zk-ecdsa](https://github.com/personaelabs/efficient-zk-ecdsa), our previous implementation of fast ECDSA signature proving. Please refer to [this blog post](https://personaelabs.org/posts/spartan-ecdsa/) for further information.

## Constraint breakdown

Using right-field arithmetic and tricks from [Efficient ECDSA](https://personaelabs.org/posts/efficient-ecdsa-1/#take-computation-out-of-the-snark), spartan-ecdsa achieves the phenomenal result of **hashing becoming the bottleneck instead of ECC operations** for the `pubkey_membership.circom` circuit. In particular, there are **3,039** constraints for efficient ECDSA signature verification, and **5,037** constraints for a depth 20 merkle tree membership check + 1 Poseidon hash of the ECDSA public key.

We save 11,494 constraints by using efficient ECDSA signatures instead of standard ECDSA signatures. This is because verifying a standard ECDSA signature requires math in the scalar field of secp to compute s^-1, r \* s^-1, and m \* s^-1. As the scalar field of secp is not equal to the scalar field of secq, we need to do _wrong-field math_ with big integers to compute these values. In efficient ECDSA however, we do the wrong-field math outside of the circuit in a way that doesn't break privacy or correctness!

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

### Install dependencies & Build all packages

```jsx
yarn && yarn build
```
