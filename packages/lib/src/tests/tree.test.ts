import { Tree, Poseidon } from "../";

describe("Merkle tree prove and verify", () => {
  let poseidon: Poseidon;
  let tree: Tree;
  const members = new Array(10).fill(0).map((_, i) => BigInt(i));

  beforeAll(async () => {
    // Init Poseidon
    poseidon = new Poseidon();
    await poseidon.initWasm();
    const treeDepth = 20;

    tree = new Tree(treeDepth, poseidon);
    for (const member of members) {
      tree.insert(member);
    }
  });

  it("should prove and verify a valid Merkle proof", async () => {
    const proof = tree.createProof(0);
    expect(tree.verifyProof(proof, members[0])).toBe(true);
  });

  it("should assert an invalid Merkle proof", async () => {
    const proof = tree.createProof(0);
    proof.siblings[0][0] = proof.siblings[0][0] += BigInt(1);
    expect(tree.verifyProof(proof, members[0])).toBe(false);
    proof.siblings[0][0] = proof.siblings[0][0] -= BigInt(1);
  });
});
