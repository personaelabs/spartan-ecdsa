import { useState } from "react";
import {
  MembershipProver,
  Tree,
  Poseidon,
  SpartanWasm,
  defaultAddressMembershipConfig,
  defaultWasmConfig,
  defaultPubkeyMembershipConfig
} from "spartan-ecdsa";
import {
  ecrecover,
  ecsign,
  hashPersonalMessage,
  privateToAddress,
  privateToPublic,
  pubToAddress
} from "@ethereumjs/util";

export default function Home() {
  const [proof, setProof] = useState<any | undefined>();

  const provePubKeyMembership = async () => {
    const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
    const msg = Buffer.from("harry potter");
    const msgHash = hashPersonalMessage(msg);

    const { v, r, s } = ecsign(msgHash, privKey);
    const pubKey = ecrecover(msgHash, v, r, s);
    const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

    const wasm = new SpartanWasm(defaultWasmConfig);
    const poseidon = new Poseidon();
    await poseidon.initWasm(wasm);

    const treeDepth = 20;
    const pubKeyTree = new Tree(treeDepth, poseidon);

    const proverPubKeyHash = poseidon.hashPubKey(pubKey);

    pubKeyTree.insert(proverPubKeyHash);

    // Insert other members into the tree
    for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
      const pubKey = privateToPublic(
        Buffer.from("".padStart(16, member), "utf16le")
      );
      pubKeyTree.insert(poseidon.hashPubKey(pubKey));
    }

    const index = pubKeyTree.indexOf(proverPubKeyHash);
    const merkleProof = pubKeyTree.createProof(index);

    console.log("Proving...");
    console.time("Full proving time");

    const prover = new MembershipProver(defaultPubkeyMembershipConfig);

    prover.initWasm(wasm);

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

  const proverAddressMembership = async () => {
    const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
    const msg = Buffer.from("harry potter");
    const msgHash = hashPersonalMessage(msg);

    const { v, r, s } = ecsign(msgHash, privKey);
    const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

    const wasm = new SpartanWasm(defaultWasmConfig);
    const poseidon = new Poseidon();
    await poseidon.initWasm(wasm);

    const treeDepth = 20;
    const addressTree = new Tree(treeDepth, poseidon);

    const proverAddress = BigInt(
      "0x" + privateToAddress(privKey).toString("hex")
    );
    addressTree.insert(proverAddress);

    // Insert other members into the tree
    for (const member of ["🕵️", "🥷", "👩‍🔬"]) {
      const pubKey = privateToPublic(
        Buffer.from("".padStart(16, member), "utf16le")
      );
      const address = BigInt("0x" + pubToAddress(pubKey).toString("hex"));
      addressTree.insert(address);
    }

    const index = addressTree.indexOf(proverAddress);
    const merkleProof = addressTree.createProof(index);

    console.log("Proving...");
    console.time("Full proving time");

    const prover = new MembershipProver({
      ...defaultAddressMembershipConfig,
      enableProfiler: true
    });

    prover.initWasm(wasm);

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
      <button onClick={provePubKeyMembership}>
        Prove Public Key Membership
      </button>
      <button onClick={proverAddressMembership}>
        Prove Address Membership
      </button>
    </div>
  );
}
