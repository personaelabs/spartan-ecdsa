const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
import { getEffEcdsaCircuitInput } from "./test_utils";

const ec = new EC("secp256k1");

describe("ecdsa", () => {
  it("should verify valid message", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/eff_ecdsa_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    const privKey = Buffer.from(
      "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
      "hex"
    );
    const pubKey = ec.keyFromPrivate(privKey.toString("hex")).getPublic();
    const msg = Buffer.from("hello world");
    const circuitInput = getEffEcdsaCircuitInput(privKey, msg);

    const w = await circuit.calculateWitness(circuitInput, true);

    await circuit.assertOut(w, {
      pubKeyX: pubKey.x.toString(),
      pubKeyY: pubKey.y.toString()
    });

    await circuit.checkConstraints(w);
  });

  // TODO - add more tests
});
