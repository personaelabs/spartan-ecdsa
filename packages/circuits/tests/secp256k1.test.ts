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
      xP: p1.x.toString(),
      yP: p1.y.toString(),
      xQ: p2.x.toString(),
      yQ: p2.y.toString(),
      isP2Identity: 0
    };

    const w = await circuit.calculateWitness(input, true);

    await circuit.assertOut(w, {
      outX: p3.x.toString(),
      outY: p3.y.toString()
    });

    await circuit.checkConstraints(w);
  });

  describe("Secp256k1AddComplete", () => {
    let circuit;
    const p1 = ec.keyFromPrivate(Buffer.from("🪄", "utf16le")).getPublic();
    const p2 = ec.keyFromPrivate(Buffer.from("🧙", "utf16le")).getPublic();

    beforeAll(async () => {
      circuit = await wasm_tester(
        path.join(__dirname, "./circuits/add_complete_test.circom"),
        {
          prime: "secq256k1"
        }
      );
    });

    it("should work when P = Q", async () => {
      const expected = p1.add(p1);

      const input = {
        xP: p1.x.toString(),
        yP: p1.y.toString(),
        xQ: p1.x.toString(),
        yQ: p1.y.toString()
      };

      const w = await circuit.calculateWitness(input, true);

      await circuit.assertOut(w, {
        outX: expected.x.toString(),
        outY: expected.y.toString()
      });

      await circuit.checkConstraints(w);
    });

    it("should work when P != Q", async () => {
      const expected = p1.add(p2);

      const input = {
        xP: p1.x.toString(),
        yP: p1.y.toString(),
        xQ: p2.x.toString(),
        yQ: p2.y.toString()
      };

      const w = await circuit.calculateWitness(input, true);

      await circuit.assertOut(w, {
        outX: expected.x.toString(),
        outY: expected.y.toString()
      });

      await circuit.checkConstraints(w);
    });

    it("should work when xP = 0 and xQ != 0", async () => {
      const input = {
        xP: 0,
        yP: 0,
        xQ: p1.x.toString(),
        yQ: p1.y.toString()
      };

      const w = await circuit.calculateWitness(input, true);

      await circuit.assertOut(w, {
        outX: p1.x.toString(),
        outY: p1.y.toString()
      });

      await circuit.checkConstraints(w);
    });

    it("should work when xP != 0 and xQ = 0", async () => {
      const input = {
        xP: p1.x.toString(),
        yP: p1.y.toString(),
        xQ: 0,
        yQ: 0
      };

      const w = await circuit.calculateWitness(input, true);

      await circuit.assertOut(w, {
        outX: p1.x.toString(),
        outY: p1.y.toString()
      });

      await circuit.checkConstraints(w);
    });

    it("should work when xP = xQ and yP = -yQ", async () => {
      const p1Neg = p1.neg();

      // Sanity check
      expect(p1.add(p1Neg).inf).toStrictEqual(true);

      const input = {
        xP: p1.x.toString(),
        yP: p1.y.toString(),
        xQ: p1Neg.x.toString(),
        yQ: p1Neg.y.toString()
      };

      const w = await circuit.calculateWitness(input, true);

      await circuit.assertOut(w, {
        outX: 0,
        outY: 0
      });

      await circuit.checkConstraints(w);
    });

    it("should work when xP = 0 and xQ = 0", async () => {
      const input = {
        xP: 0,
        yP: 0,
        xQ: 0,
        yQ: 0
      };

      const w = await circuit.calculateWitness(input, true);

      await circuit.assertOut(w, {
        outX: 0,
        outY: 0
      });

      await circuit.checkConstraints(w);
    });
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
      xP: p.x.toString(),
      yP: p.y.toString()
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
      xP: p1.x.toString(),
      yP: p1.y.toString(),
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
