import { useState } from "react";
import { proveSig, verifyProof, Proof } from "spartan-ecdsa";
import { ecsign } from "@ethereumjs/util";

export default function Home() {
  const [proof, setProof] = useState<Proof | undefined>();

  const prove = async () => {
    const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
    let msg = Buffer.from("harry potter");

    const { v, r, s } = ecsign(msg, privKey);
    const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

    console.log("Proving...");
    console.time("Full proving time");
    const { proof, publicInput } = await proveSig(sig, msg);
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
      const verified = await verifyProof(proof.proof, proof.publicInput);
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
