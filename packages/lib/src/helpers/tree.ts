import { IncrementalMerkleTree } from "@zk-kit/incremental-merkle-tree";
import { Poseidon } from "./poseidon";
import { MerkleProof } from "../types";
import { bytesToBigInt } from "./utils";

export class Tree {
  depth: number;
  poseidon: Poseidon;
  private treeInner!: IncrementalMerkleTree;

  constructor(depth: number, poseidon: Poseidon) {
    this.depth = depth;

    this.poseidon = poseidon;
    const hash = poseidon.hash.bind(poseidon);
    this.treeInner = new IncrementalMerkleTree(hash, this.depth, BigInt(0));
  }

  private hashPubKey(pubKey: Buffer): bigint {
    const pubKeyX = BigInt("0x" + pubKey.toString("hex").slice(0, 64));
    const pubKeyY = BigInt("0x" + pubKey.toString("hex").slice(64, 128));

    const pubKeyHash = this.poseidon.hash([pubKeyX, pubKeyY]);
    return pubKeyHash;
  }

  hashAndInsert(pubKey: Buffer) {
    this.insert(this.hashPubKey(pubKey));
  }

  insert(leaf: bigint) {
    this.treeInner.insert(leaf);
  }

  root(): bigint {
    return this.treeInner.root;
  }

  indexOf(pubKey: Buffer): number {
    return this.treeInner.indexOf(this.hashPubKey(pubKey));
  }

  createProof(index: number): MerkleProof {
    const proof = this.treeInner.createProof(index);

    const siblings = proof.siblings.map(s =>
      typeof s[0] === "bigint" ? s : bytesToBigInt(s[0])
    );

    return {
      siblings,
      pathIndices: proof.pathIndices,
      root: proof.root
    };
  }

  // TODO: Add more functions that expose the IncrementalMerkleTree API
}
