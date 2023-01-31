# Spartan-ecdsa

## Usage example

### Proving membership to a group of public keys

```typescript
import {
  MembershipProver,
  MembershipVerifier,
  Poseidon,
  Tree,
  defaultPubkeyMembershipPConfig,
  defaultPubkeyMembershipVConfig
} from "@personaelabs/spartan-ecdsa";
import { hashPersonalMessage } from "@ethereumjs/util";

// Init the Poseidon hash
const poseidon = new Poseidon();
await poseidon.initWasm();

const treeDepth = 20;
const tree = new Tree(treeDepth, poseidon);

const proverPubKey = Buffer.from("...");
// Get the prover public key hash
const proverPubkeyHash = poseidon.hashPubKey(proverPubKey);

// Insert prover public key hash into the tree
tree.insert(proverPubkeyHash);

// Insert other members into the tree
for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
  tree.insert(
    poseidon.hashPubKey(Buffer.from("".padStart(16, member), "utf16le"))
  );
}

// Compute the merkle proof
const index = tree.indexOf(proverPubkeyHash);
const merkleProof = tree.createProof(index);

// Init the prover
const prover = new MembershipProver(defaultPubkeyMembershipPConfig);
await prover.initWasm();

const sig = "0x...";
const msgHash = hashPersonalMessage(Buffer.from("harry potter"));
// Prove membership
const { proof, publicInput } = await prover.prove(sig, msgHash, merkleProof);

// Init verifier
const verifier = new MembershipVerifier(defaultPubkeyMembershipVConfig);
await verifier.initWasm();

// Verify proof
await verifier.verify(proof, publicInput);
```

### Proving membership to a group of addresses

```typescript
import {
  MembershipProver,
  MembershipVerifier,
  Poseidon,
  Tree,
  defaultAddressMembershipPConfig,
  defaultAddressMembershipVConfig
} from "@personaelabs/spartan-ecdsa";
import { hashPersonalMessage } from "@ethereumjs/util";

// Init the Poseidon hash
const poseidon = new Poseidon();
await poseidon.initWasm();

const treeDepth = 20;
const tree = new Tree(treeDepth, poseidon);

// Get the prover public key hash
const proverAddress = BigInt("0x...");

// Insert prover public key hash into the tree
tree.insert(proverAddress);

// Insert other members into the tree
for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
  tree.insert(
    BigInt(
      "0x" + Buffer.from("".padStart(16, member), "utf16le").toString("hex")
    )
  );
}

// Compute the merkle proof
const index = tree.indexOf(proverAddress);
const merkleProof = tree.createProof(index);

// Init the prover
const prover = new MembershipProver(defaultAddressMembershipPConfig);
await prover.initWasm();

const sig = "0x...";
const msgHash = hashPersonalMessage(Buffer.from("harry potter"));
// Prove membership
const { proof, publicInput } = await prover.prove(sig, msgHash, merkleProof);

// Init verifier
const verifier = new MembershipVerifier(defaultAddressMembershipVConfig);
await verifier.initWasm();

// Verify proof
await verifier.verify(proof, publicInput);
```

## Circuit downloads

- Public key membership
  | circuit | https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.circuit |
  | --- | --- |
  | witnessGenWasm | https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.wasm |

- Ethereum address membership
  | circuit | https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.circuit |
  | --- | --- |
  | witnessGenWasm | https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.wasm |

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
