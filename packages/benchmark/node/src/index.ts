import { MembershipProver, Poseidon, Tree } from "spartan-ecdsa";
import {
  hashPersonalMessage,
  ecsign,
  ecrecover,
  privateToPublic
} from "@ethereumjs/util";

const main = async () => {
  const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
  const msg = Buffer.from("harry potter");
  const msgHash = hashPersonalMessage(msg);

  const { v, r, s } = ecsign(msgHash, privKey);
  const pubKey = ecrecover(msgHash, v, r, s);
  const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

  const poseidon = new Poseidon();
  await poseidon.init();
  const treeDepth = 10;
  const tree = new Tree(treeDepth, poseidon);

  // Insert prover public key into the tree
  tree.hashAndInsert(pubKey);

  // Insert other members into the tree
  for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
    const pubKey = privateToPublic(
      Buffer.from("".padStart(16, member), "utf16le")
    );
    tree.hashAndInsert(pubKey);
  }

  const index = tree.indexOf(pubKey);
  const merkleProof = tree.createProof(index);

  const prover = new MembershipProver(treeDepth);
  await prover.prove(sig, msgHash, merkleProof);

  // TODO: Verify the proof
};

main();
