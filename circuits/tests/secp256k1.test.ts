const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";

const ec = new EC("secp256k1");

describe("secp256k1", () => {
  it("Secp256k1Add", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/add_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    const p1 = ec.keyFromPrivate(BigInt("1")).getPublic();
    const p2 = ec.keyFromPrivate(BigInt("2")).getPublic();
    const p3 = p1.add(p2);

    const input = {
      p1X: p1.x.toString(),
      p1Y: p1.y.toString(),
      p2X: p2.x.toString(),
      p2Y: p2.y.toString(),
      isP2Identity: 0
    };

    const w = await circuit.calculateWitness(input, true);

    await circuit.assertOut(w, {
      outX: p3.x.toString(),
      outY: p3.y.toString()
    });

    await circuit.checkConstraints(w);
  });

  it("Secp256k1Double", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/double_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    const p = ec.g;
    const expected = p.mul(BigInt("2"));

    const input = {
      pX: p.x.toString(),
      pY: p.y.toString()
    };

    const w = await circuit.calculateWitness(input, true);

    await circuit.assertOut(w, {
      outX: expected.x.toString(),
      outY: expected.y.toString()
    });

    await circuit.checkConstraints(w);
  });

  it("Secp256k1Mul", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/mul_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    const p1 = ec.keyFromPrivate(BigInt("5")).getPublic();

    const scalar = BigInt("424242");

    let scalarArray = scalar
      .toString(2)
      .split("")
      .join("")
      .padStart(256, "0")
      .split("");

    scalarArray.reverse();

    const p2 = p1.mul(Number(scalar));

    const input = {
      pX: p1.x.toString(),
      pY: p1.y.toString(),
      scalar: scalarArray
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.assertOut(w, {
      outX: p2.x.toString(),
      outY: p2.y.toString()
    });

    await circuit.checkConstraints(w);
  });
});
