import { EffECDSAProver, EffECDSAVerifier } from "spartan-ecdsa";
import { hashPersonalMessage, ecsign } from "@ethereumjs/util";

const main = async () => {
    const privKey = Buffer.from("".padStart(16, "🧙"), "utf16le");
    const msg = Buffer.from("Hello World", "utf8");
    const { v, r, s } = ecsign(msg, privKey);
    const sig = "0x" + r.toString("hex") + s.toString("hex") + v.toString(16);

    const prover = new EffECDSAProver({
        witnessGenWasm: "../../circuits/build/eff_ecdsa/eff_ecdsa_js/eff_ecdsa.wasm",
        enableProfiler: true,
    });

    const msgHash = hashPersonalMessage(Buffer.from(msg));
    const { proof, publicInput } = await prover.prove(sig, msgHash);

    const verifier = new EffECDSAVerifier({
        enableProfiler: true,
    });

    await verifier.verify(proof, publicInput)
}

main()