import { useState } from "react";
import { MembershipProver, Tree, Poseidon } from "spartan-ecdsa";
import {
  ecrecover,
  ecsign,
  hashPersonalMessage,
  privateToPublic
} from "@ethereumjs/util";

export default function Home() {
  const [proof, setProof] = useState<any | undefined>();

  const prove = async () => {
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

    console.log("Proving...");
    console.time("Full proving time");

    const prover = new MembershipProver(treeDepth, {
      enableProfiler: true
    });

    const { proof, publicInput } = await prover.prove(
      sig,
      msgHash,
      merkleProof
    );

    console.timeEnd("Full proving time");
    console.log(
      "Raw proof size (excluding public input)",
      proof.length,
      "bytes"
    );
    setProof({ proof, publicInput });
  };

  /*
  const verify = async () => {
    if (!proof) {
      console.log("No proof yet!");
    } else {
      const verifier = new EffECDSAVerifier({
        enableProfiler: true
      });

      const verified = await verifier.verify(proof.proof, proof.publicInput);
      console.log("Verified?", verified);
    }
  };
  */

  return (
    <div>
      <button onClick={prove}>Prove</button>
    </div>
  );
}
