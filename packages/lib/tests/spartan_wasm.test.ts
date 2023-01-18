import { proveSig, verifyProof, EffEcdsaPubInput } from "../src/lib";
import { hashPersonalMessage, ecsign } from "@ethereumjs/util";
import * as path from "path";

describe("ecdsa_verify prove and verify", () => {
  const privKey = Buffer.from(
    "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
    "hex"
  );
  let msg = Buffer.from("harry potter");
  const msgHash = hashPersonalMessage(msg);

  const { v, r, s } = ecsign(msgHash, privKey);
  const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

  it("should prove and verify valid signature", async () => {
    const { proof, publicInput } = await proveSig(sig, msgHash, {
      witnessGenWasm: path.join(
        __dirname,
        "/../../circuits/build/eff_ecdsa/eff_ecdsa_js/eff_ecdsa.wasm"
      )
    });

    const result = await verifyProof(proof, publicInput);
    expect(result).toBe(true);
  });

  it("verifier should return false when the proof is invalid", async () => {
    const { proof, publicInput } = await proveSig(sig, msgHash, {
      witnessGenWasm: path.join(
        __dirname,
        "/../../circuits/build/eff_ecdsa/eff_ecdsa_js/eff_ecdsa.wasm"
      )
    });
    proof[0] = proof[0] + 1;

    const result = await verifyProof(proof, publicInput);
    expect(result).toBe(false);
  });

  it("verifier should return false when the public input is invalid", async () => {
    const { proof, publicInput } = await proveSig(sig, msgHash, {
      witnessGenWasm: path.join(
        __dirname,
        "/../../circuits/build/eff_ecdsa/eff_ecdsa_js/eff_ecdsa.wasm"
      )
    });
    publicInput[0] = publicInput[0] + 1;

    const result = await verifyProof(proof, publicInput);
    expect(result).toBe(false);
  });
});
