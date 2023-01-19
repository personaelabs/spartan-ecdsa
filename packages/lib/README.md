# Spartan-ecdsa

## Usage example

```typescript
import { EffECDSAProver, EffECDSAVerifier } from "spartan-ecdsa";
import { ecsign, hashPersonalMessage } from "@ethereumjs/util";

const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
const msg = Buffer.from("harry potter");
const msgHash = hashPersonalMessage(msg);

const { v, r, s } = ecsign(msg, privKey);
const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

const prover = new EffECDSAProver();

const { proof, publicInput } = await prover.prove(sig, msgHash);

const verifier = new EffECDSAVerifier();

const verified = await verifier.verify(proof.proof, proof.publicInput);
console.log("Verified?", verified);
```

## Development

### Install dependencies

```
yarn
```

### Run tests

```
yarn jest
```

### Build

```
yarn build
```
