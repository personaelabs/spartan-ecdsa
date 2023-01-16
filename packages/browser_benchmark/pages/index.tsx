import { proveSig } from "spartan-ecdsa";
import { ecsign } from "@ethereumjs/util";

export default function Home() {
  const prove = async () => {
    const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
    let msg = Buffer.from("harry potter");

    const { v, r, s } = ecsign(msg, privKey);
    const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

    console.log("Proving...");
    console.time("Full proving time");
    const { proof, publicInputs } = await proveSig(sig, msg);
    console.timeEnd("Full proving time");
    console.log(
      "Raw proof size (excluding public input)",
      proof.length,
      "bytes"
    );
  };

  return (
    <div>
      <button onClick={prove}>Prove with lib</button>
    </div>
  );
}
