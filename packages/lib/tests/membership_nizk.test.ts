import * as path from "path";
import { MembershipProver, Tree, Poseidon } from "../src/lib";
import { hashPersonalMessage, ecsign, privateToPublic } from "@ethereumjs/util";
var EC = require("elliptic").ec;
const ec = new EC("secp256k1");

//! Still doesn't pass. Need to fix.
describe("membership prove and verify", () => {
  // Init prover
  const treeDepth = 10;

  const privKeys = ["1", "a", "bb", "ccc", "dddd", "ffff"].map(val =>
    Buffer.from(val.padStart(64, "0"), "hex")
  );

  // Sign (Use privKeys[0] for proving)
  const proverIndex = 0;
  const proverPrivKey = privKeys[proverIndex];

  let msg = Buffer.from("harry potter");
  const msgHash = hashPersonalMessage(msg);

  const { v, r, s } = ecsign(msgHash, proverPrivKey);
  const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

  let poseidon: Poseidon;
  let tree: Tree;
  let prover: MembershipProver;
  beforeAll(async () => {
    // Init Poseidon
    poseidon = new Poseidon();
    await poseidon.init();

    tree = new Tree(treeDepth, poseidon);

    const CIRCUIT = path.join(
      __dirname,
      "/../../circuits/build/membership/membership.circuit"
    );

    const WITNESS_GEN_WASM = path.join(
      __dirname,
      "/../../circuits/build/membership/membership_js/membership.wasm"
    );

    prover = new MembershipProver(treeDepth, {
      circuit: CIRCUIT,
      witnessGenWasm: WITNESS_GEN_WASM
    });

    // Insert the members into the tree
    for (const privKey of privKeys) {
      const pubKey = privateToPublic(privKey);
      tree.hashAndInsert(pubKey);
    }
  });

  it("should prove and verify valid signature and merkle proof", async () => {
    const index = tree.indexOf(privateToPublic(proverPrivKey));
    const merkleProof = tree.createProof(proverIndex);

    const { proof, publicInput } = await prover.prove(
      sig,
      msgHash,
      merkleProof
    );

    // TODO: Verify the proof
  });
});
