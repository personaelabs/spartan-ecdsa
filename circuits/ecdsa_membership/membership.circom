pragma circom 2.1.2;

include "./ecdsa.circom";
include "./tree.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template Membership(nLevels) {
    signal input s;
    signal input msg;
    signal input rInv;
    signal input rX;
    signal input rXSquared;
    signal input rY;
    signal input rYSquared;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];
    signal output root;

    component ecdsa = ECDSA();
    ecdsa.msg <== msg;
    ecdsa.rInv <== rInv;
    ecdsa.rX <== rX;
    ecdsa.rXSquared <== rXSquared;
    ecdsa.rY <== rY;
    ecdsa.rYSquared <== rYSquared;
    ecdsa.s <== s;

    component pubKeyHash = Poseidon(2);
    pubKeyHash.inputs[0] <== ecdsa.pubKeyX;
    pubKeyHash.inputs[1] <== ecdsa.pubKeyY;

    component merkleProof = MerkleTreeInclusionProof(nLevels);
    merkleProof.leaf <== pubKeyHash.out;

    for (var i = 0; i < nLevels; i++) {
        merkleProof.pathIndices[i] <== pathIndices[i];
        merkleProof.siblings[i] <== siblings[i];
    }

    root <== merkleProof.root;
}

component main = Membership(20);