import { useState } from "react";
import { EffECDSAProver, EffECDSAVerifier } from "spartan-ecdsa";
import { ecsign, hashPersonalMessage } from "@ethereumjs/util";

export default function Home() {
  const [proof, setProof] = useState<any | undefined>();

  const prove = async () => {
    const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
    const msg = Buffer.from("harry potter");
    const msgHash = hashPersonalMessage(msg);

    const { v, r, s } = ecsign(msg, privKey);
    const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

    console.log("Proving...");
    console.time("Full proving time");
    const prover = new EffECDSAProver({
      enableProfiler: true
    });
    const { proof, publicInput } = await prover.prove(sig, msgHash);
    console.timeEnd("Full proving time");
    console.log(
      "Raw proof size (excluding public input)",
      proof.length,
      "bytes"
    );
    setProof({ proof, publicInput });
  };

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

  return (
    <div>
      <button onClick={prove}>Prove</button>
      <button onClick={verify}>Verify</button>
    </div>
  );
}
