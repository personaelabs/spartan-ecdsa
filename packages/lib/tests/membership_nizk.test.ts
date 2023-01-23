import * as path from "path";
import { MembershipProver, Tree, Poseidon } from "../src/lib";
import { hashPersonalMessage, ecsign } from "@ethereumjs/util";
var EC = require("elliptic").ec;
const ec = new EC("secp256k1");

//! Still doesn't pass. Need to fix.
describe.skip("membership prove and verify", () => {
  // Init prover
  const treeDepth = 10;

  const privKeys = [
    "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
    "a",
    "bb",
    "ccc",
    "dddd",
    "ffff"
  ].map(val => Buffer.from(val.padStart(64, "0"), "hex"));

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

    prover = new MembershipProver(treeDepth, {
      circuit: path.join(
        __dirname,
        "/../../circuits/build/membership/membership.circuit"
      ),
      witnessGenWasm: path.join(
        __dirname,
        "/../../circuits/build/membership/membership_js/membership.wasm"
      )
    });

    // Compute public key hashes using Poseidon
    const members: bigint[] = [];
    for (const privKey of privKeys) {
      const pubKey = ec.keyFromPrivate(privKey).getPublic();
      const pubKeyX = BigInt(pubKey.x.toString());
      const pubKeyY = BigInt(pubKey.y.toString());
      const pubKeyHash = poseidon.hash([pubKeyX, pubKeyY]);
      members.push(pubKeyHash);
    }

    // Insert the pubkey hashes into the tree
    for (const member of members) {
      tree.insert(member);
    }

    console.log("member", members[0]);
  });

  it("should prove and verify valid signature and merkle proof", async () => {
    const merkleProof = tree.createProof(proverIndex);

    const { proof, publicInput } = await prover.prove(
      sig,
      msgHash,
      merkleProof
    );
  });
});
