const wasm_tester = require("circom_tester").wasm;
import * as path from "path";

describe("poseidon", () => {
  it("should output correct hash", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/poseidon_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    // Using the same inputs as test_poseidon in wasm.rs
    const input = {
      inputs: [
        "115792089237316195423570985008687907853269984665640564039457584007908834671663",
        "115792089237316195423570985008687907853269984665640564039457584007908834671662"
      ]
    };
    const w = await circuit.calculateWitness(input, true);

    await circuit.assertOut(w, {
      out: "55864140790032987462805271262840606862500777900572169165625301625084550490622"
    });

    await circuit.checkConstraints(w);
  });
});
