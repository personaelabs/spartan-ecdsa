# Spartan-ecdsa

Spartan-ecdsa (which to our knowledge) is the fastest open-source method to verify ECDSA (secp256k1) signatures in zero-knowledge. It can prove ECDSA group membership 10 times faster than [efficient-zk-ecdsa](https://github.com/personaelabs/efficient-zk-ecdsa), our previous implementation of fast ECDSA signature proving. Please refer to [this blog post](https://personaelabs.org/posts/spartan-ecdsa/) for further information.

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
