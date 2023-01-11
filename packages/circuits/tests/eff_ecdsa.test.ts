const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
import { genEffEcdsaInput } from "./test_utils";

const ec = new EC("secp256k1");

describe("ecdsa", () => {
  it("should verify valid message", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/eff_ecdsa_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    const privKey = BigInt(
      "0xf5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f"
    );
    const msg = Buffer.from("hello world");

    const input = genEffEcdsaInput(privKey, msg);
    const pubKey = ec.keyFromPrivate(privKey.toString(16)).getPublic();

    const witness = await circuit.calculateWitness(input, true);

    await circuit.assertOut(witness, {
      pubKeyX: pubKey.x.toString(),
      pubKeyY: pubKey.y.toString()
    });
  });
});
