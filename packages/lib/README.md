# Spartan-ecdsa

## Usage example

### Proving membership to a group of public keys

```typescript
// Setup
const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
const msg = Buffer.from("harry potter");
const msgHash = hashPersonalMessage(msg);

const { v, r, s } = ecsign(msgHash, privKey);
const pubKey = ecrecover(msgHash, v, r, s);
const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

let wasm = new SpartanWasm(defaultWasmConfig);

// Init the Poseidon hash
const poseidon = new Poseidon();
await poseidon.initWasm(wasm);

const treeDepth = 20;
const tree = new Tree(treeDepth, poseidon);

// Get the prover public key hash
const proverPubkeyHash = poseidon.hashPubKey(pubKey);

// Insert prover public key hash into the tree
tree.insert(proverPubkeyHash);

// Insert other members into the tree
for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
  const pubKey = privateToPublic(
    Buffer.from("".padStart(16, member), "utf16le")
  );
  tree.insert(poseidon.hashPubKey(pubKey));
}

// Compute the merkle proof
const index = tree.indexOf(proverPubkeyHash);
const merkleProof = tree.createProof(index);

// Init the prover
const prover = new MembershipProver(defaultPubkeyMembershipConfig);
await prover.initWasm(wasm);

// Prove membership
await prover.prove(sig, msgHash, merkleProof);
```

### Proving membership to a group of addresses

```typescript
import {
  hashPersonalMessage,
  privateToAddress,
  ecsign
} from "@ethereumjs/util";
import {
  SpartanWasm,
  Tree,
  Poseidon,
  MembershipProver,
  defaultAddressMembershipConfig,
  defaultWasmConfig
} from "spartan-ecdsa";

const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
const msg = Buffer.from("harry potter");
const msgHash = hashPersonalMessage(msg);

const { v, r, s } = ecsign(msgHash, privKey);
const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

let wasm = new SpartanWasm(defaultWasmConfig);

// Init the Poseidon hash
const poseidon = new Poseidon();
await poseidon.initWasm(wasm);

const treeDepth = 20;
const tree = new Tree(treeDepth, poseidon);

// Get the prover address
const proverAddress = BigInt("0x" + privateToAddress(privKey).toString("hex"));

// Insert prover address into the tree
tree.insert(proverAddress);

// Insert other members into the tree
for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
  const address = BigInt(
    "0x" +
      privateToAddress(
        Buffer.from("".padStart(16, member), "utf16le")
      ).toString("hex")
  );
  tree.insert(address);
}

// Compute the merkle proof
const index = tree.indexOf(proverAddress);
const merkleProof = tree.createProof(index);

// Init the prover
const prover = new MembershipProver(defaultAddressMembershipConfig);
await prover.initWasm(wasm);

// Prove membership
await prover.prove(sig, msgHash, merkleProof);
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
