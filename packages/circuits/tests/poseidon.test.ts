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

    const input = {
      inputs: [1234567, 109987]
    };
    const w = await circuit.calculateWitness(input, true);

    await circuit.assertOut(w, {
      out: "62534806623609037682792088280062396003670079411844818423566523365109509144887"
    });

    await circuit.checkConstraints(w);
  });
});
