import {
  MembershipProver,
  Poseidon,
  Tree,
  SpartanWasm,
  defaultWasmConfig,
  defaultPubkeyMembershipConfig
} from "spartan-ecdsa";
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

  let wasm = new SpartanWasm(defaultWasmConfig);

  const poseidon = new Poseidon();
  await poseidon.initWasm(wasm);

  const treeDepth = 20;
  const tree = new Tree(treeDepth, poseidon);

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

  const index = tree.indexOf(proverPubkeyHash);
  const merkleProof = tree.createProof(index);

  const prover = new MembershipProver(defaultPubkeyMembershipConfig);
  await prover.initWasm(wasm);

  await prover.prove(sig, msgHash, merkleProof);

  // TODO: Verify the proof
};

main();
