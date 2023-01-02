const wasm_tester = require("circom_tester").wasm;
const { hashPersonalMessage, ecsign } = require("@ethereumjs/util");
var EC = require("elliptic").ec;
import * as path from "path";
const BN = require("bn.js");

const ec = new EC("secp256k1");

describe.skip("ecdsa", () => {
  const privKey = BigInt(
    "0xf5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f"
  );
  const msgHash = hashPersonalMessage(Buffer.from("hello world"));
  const SECP256K1_N = new BN(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    16
  );

  it("should verify valid message", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/ecdsa_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    const { v, r, s } = ecsign(msgHash, privKey);
    const pubKey = ec.keyFromPrivate(privKey.toString(16)).getPublic();

    const isYOdd = (v - BigInt(27)) % BigInt(2);
    const rPoint = ec.keyFromPublic(
      ec.curve.pointFromX(new BN(r), isYOdd).encode("hex"),
      "hex"
    );

    const rInv = new BN(r).invm(SECP256K1_N);

    const input = {
      s: BigInt("0x" + s.toString("hex")),
      msg: BigInt("0x" + msgHash.toString("hex")),
      rX: rPoint.getPublic().x.toString(),
      rY: rPoint.getPublic().y.toString(),
      rInv
    };

    const w = await circuit.calculateWitness(input, true);

    await circuit.assertOut(w, {
      pubKeyX: pubKey.x.toString(),
      pubKeyY: pubKey.y.toString()
    });
  });
});
