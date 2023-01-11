// The same structure as MerkleProof in @zk-kit/incremental-merkle-tree. 
// Not directly using MerkleProof defined in @zk-kit/incremental-merkle-tree so 
// library users can choose whatever merkle tree management method they want.
export interface MerkleProof {
    root: any;
    leaf: any;
    siblings: any[];
    pathIndices: number[];
}