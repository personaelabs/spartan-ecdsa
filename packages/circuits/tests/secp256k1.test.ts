const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
const ec = new EC("secp256k1");

describe("secp256k1", () => {
  it("Secp256k1AddIncomplete", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/add_incomplete_test.circom"),
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
      yQ: p2.y.toString()
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

  describe("mul", () => {
    describe("K", () => {
      let circuit;
      const q = BigInt(
        "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
      );
      const tQ = BigInt(
        "115792089237316195423570985008687907852405143892509244725752742275123193348738"
      );
      beforeAll(async () => {
        circuit = await wasm_tester(
          path.join(__dirname, "./circuits/k_test.circom"),
          {
            prime: "secq256k1"
          }
        );
      });

      it("should work when (s + tQ) > q (i.e. quotient = 1 for s + tQ / q)", async () => {
        const s = q - tQ + BigInt(1);

        // Sanity check
        expect(s + tQ).toBeGreaterThan(q);

        const k = (s + tQ) % q;

        const kBitsArr = k.toString(2).split("").reverse();
        const kBits = kBitsArr.join("").padEnd(256, "0").split("");

        const input = {
          s
        };

        const w = await circuit.calculateWitness(input, true);

        await circuit.assertOut(w, {
          out: kBits
        });

        await circuit.checkConstraints(w);
      });

      it("should work when (s + tQ) < q (i.e. quotient = 0 for s + tQ / q)", async () => {
        const s = q - tQ - BigInt(1);

        // Sanity check
        expect(s + tQ).toBeLessThanOrEqual(q);

        const k = (s + tQ) % q;

        const kBitsArr = k.toString(2).split("").reverse();
        const kBits = kBitsArr.join("").padEnd(256, "0").split("");

        const input = {
          s
        };

        const w = await circuit.calculateWitness(input, true);

        await circuit.assertOut(w, {
          out: kBits
        });

        await circuit.checkConstraints(w);
      });
    });

    describe("Secp256k1Mul", () => {
      let circuit;
      beforeAll(async () => {
        circuit = await wasm_tester(
          path.join(__dirname, "./circuits/mul_test.circom"),
          {
            prime: "secq256k1"
          }
        );
      });

      it("should work when scalar = q - 1", async () => {
        const p1 = ec.g;

        const largest =
          "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";

        const p2 = p1.mul(largest);

        const input = {
          xP: p1.x.toString(),
          yP: p1.y.toString(),
          scalar: BigInt("0x" + largest)
        };

        const w = await circuit.calculateWitness(input, true);
        await circuit.assertOut(w, {
          outX: p2.x.toString(),
          outY: p2.y.toString()
        });

        await circuit.checkConstraints(w);
      });

      it("should work when scalar < q - 1", async () => {
        const p1 = ec.g;

        const scalars = [
          "1",
          "2",
          "3",
          "ff",
          "100",
          "101",
          "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139"
        ];

        for (const scalar of scalars) {
          const p2 = p1.mul(scalar);

          const input = {
            xP: p1.x.toString(),
            yP: p1.y.toString(),
            scalar: BigInt("0x" + scalar)
          };

          const w = await circuit.calculateWitness(input, true);
          await circuit.assertOut(w, {
            outX: p2.x.toString(),
            outY: p2.y.toString()
          });

          await circuit.checkConstraints(w);
        }
      });
    });
  });
});
