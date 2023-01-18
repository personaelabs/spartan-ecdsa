// The same structure as MerkleProof in @zk-kit/incremental-merkle-tree.
// Not directly using MerkleProof defined in @zk-kit/incremental-merkle-tree so
// library users can choose whatever merkle tree management method they want.
export interface MerkleProof {
  root: any;
  leaf: any;
  siblings: any[];
  pathIndices: number[];
}

export interface Proof {
  proof: Uint8Array;
  publicInput: Uint8Array;
}

export interface ProveOptions {
  proverWasm?: string;
  witnessGenWasm?: string;
  circuit?: string;
  spartanWasm?: string;
  enableProfiler?: boolean;
}

export interface VerifyOptions {
  circuit?: string;
  spartanWasm?: string;
  enableProfiler?: boolean;
}
