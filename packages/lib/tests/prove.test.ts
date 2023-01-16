import { proveSig, verifyProof } from "../src/index";
const { hashPersonalMessage, ecsign } = require("@ethereumjs/util");
import * as path from "path";

describe.skip("nizk wasm", () => {
  it("should work", async () => {
    const privKey = Buffer.from(
      "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
      "hex"
    );
    let msg = Buffer.from("harry potter");

    const msgHash = hashPersonalMessage(msg);
    const { v, r, s } = ecsign(msgHash, privKey);

    const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

    const { proof, publicInput } = await proveSig(sig, msg, {
      witnessGenWasm: path.join(
        __dirname,
        "/../../circuits/build/eff_ecdsa/eff_ecdsa_js/eff_ecdsa.wasm"
      )
    });
    console.log("proof", proof.length);
    console.log("publicInput", publicInput.length);

    const result = await verifyProof(proof, publicInput);
    expect(result).toBe(true);
  });

  it("should fail when the signature is invalid", () => {});
  it("should fail when the merkle proof is invalid", () => {});
});
