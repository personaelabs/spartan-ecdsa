import {
  hashPersonalMessage,
  privateToAddress,
  ecsign
} from "@ethereumjs/util";
import {
  Tree,
  Poseidon,
  MembershipProver,
  defaultAddressMembershipConfig
} from "@personaelabs/spartan-ecdsa";

const benchAddrMembership = async () => {
  const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
  const msg = Buffer.from("harry potter");
  const msgHash = hashPersonalMessage(msg);

  const { v, r, s } = ecsign(msgHash, privKey);
  const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

  // Init the Poseidon hash
  const poseidon = new Poseidon();
  await poseidon.initWasm();

  const treeDepth = 20;
  const tree = new Tree(treeDepth, poseidon);

  // Get the prover public key hash
  const proverAddress = BigInt(
    "0x" + privateToAddress(privKey).toString("hex")
  );

  // Insert prover public key hash into the tree
  tree.insert(proverAddress);

  // Insert other members into the tree
  for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
    const address = BigInt(
      "0x" +
        privateToAddress(
          Buffer.from("".padStart(16, member), "utf16le")
        ).toString("hex")
    );
    tree.insert(address);
  }

  // Compute the merkle proof
  const index = tree.indexOf(proverAddress);
  const merkleProof = tree.createProof(index);

  // Init the prover
  const prover = new MembershipProver({
    ...defaultAddressMembershipConfig,
    enableProfiler: true
  });
  await prover.initWasm();

  // Prove membership
  await prover.prove(sig, msgHash, merkleProof);
};

export default benchAddrMembership;
