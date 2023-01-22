const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
import { getEffEcdsaCircuitInput } from "./test_utils";
import { privateToAddress } from "@ethereumjs/util";

const ec = new EC("secp256k1");

describe("eff_ecdsa_to_addr", () => {
  it("should output correct address", async () => {
    const privKey = Buffer.from(
      "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
      "hex"
    );
    const pubKey = ec.keyFromPrivate(privKey.toString("hex")).getPublic();
    const addr = BigInt(
      "0x" + privateToAddress(privKey).toString("hex")
    ).toString(10);

    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/eff_ecdsa_to_addr_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    const msg = Buffer.from("hello world");
    const circuitInput = getEffEcdsaCircuitInput(privKey, msg);

    const w = await circuit.calculateWitness(circuitInput, true);

    await circuit.assertOut(w, {
      addr
    });

    await circuit.checkConstraints(w);
  });

  // TODO - add more tests
});
