var EC = require("elliptic").ec;
const BN = require("bn.js");

import { bytesToBigInt, bigIntToBytes } from "./utils";

const ec = new EC("secp256k1");

const SECP256K1_N = new BN(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  16
);

/**
 * Public inputs that are passed into the efficient ECDSA circuit
 * This doesn't include the other public values, which are the group element R and the msgHash.
 */
export class EffEcdsaCircuitPubInput {
  Tx: bigint;
  Ty: bigint;
  Ux: bigint;
  Uy: bigint;

  constructor(Tx: bigint, Ty: bigint, Ux: bigint, Uy: bigint) {
    this.Tx = Tx;
    this.Ty = Ty;
    this.Ux = Ux;
    this.Uy = Uy;
  }

  static computeFromSig(
    r: bigint,
    v: bigint,
    msgHash: Buffer
  ): EffEcdsaCircuitPubInput {
    const isYOdd = (v - BigInt(27)) % BigInt(2);
    const rPoint = ec.keyFromPublic(
      ec.curve.pointFromX(new BN(r), isYOdd).encode("hex"),
      "hex"
    );

    // Get the group element: -(m * r^−1 * G)
    const rInv = new BN(r).invm(SECP256K1_N);

    // w = -(r^-1 * msg)
    const w = rInv.mul(new BN(msgHash)).neg().umod(SECP256K1_N);
    // U = -(w * G) = -(r^-1 * msg * G)
    const U = ec.curve.g.mul(w);

    // T = r^-1 * R
    const T = rPoint.getPublic().mul(rInv);

    return new EffEcdsaCircuitPubInput(
      BigInt(T.getX().toString()),
      BigInt(T.getY().toString()),
      BigInt(U.getX().toString()),
      BigInt(U.getY().toString())
    );
  }

  serialize(): Uint8Array {
    let serialized = new Uint8Array(32 * 4);

    serialized.set(bigIntToBytes(this.Tx, 32), 0);
    serialized.set(bigIntToBytes(this.Ty, 32), 32);
    serialized.set(bigIntToBytes(this.Ux, 32), 64);
    serialized.set(bigIntToBytes(this.Uy, 32), 96);

    return serialized;
  }
}

/**
 * Public values of efficient ECDSA
 */
export class EffEcdsaPubInput {
  r: bigint;
  rV: bigint;
  msgHash: Buffer;
  circuitPubInput: EffEcdsaCircuitPubInput;

  constructor(
    r: bigint,
    v: bigint,
    msgHash: Buffer,
    circuitPubInput: EffEcdsaCircuitPubInput
  ) {
    this.r = r;
    this.rV = v;
    this.msgHash = msgHash;
    this.circuitPubInput = circuitPubInput;
  }

  /**
   * Serialize the public input into a Uint8Array
   * @returns the serialized public input
   */
  serialize(): Uint8Array {
    let serialized = new Uint8Array(32 * 6 + 1);

    serialized.set(bigIntToBytes(this.r, 32), 0);
    serialized.set(bigIntToBytes(this.rV, 1), 32);
    serialized.set(this.msgHash, 33);
    serialized.set(bigIntToBytes(this.circuitPubInput.Tx, 32), 65);
    serialized.set(bigIntToBytes(this.circuitPubInput.Ty, 32), 97);
    serialized.set(bigIntToBytes(this.circuitPubInput.Ux, 32), 129);
    serialized.set(bigIntToBytes(this.circuitPubInput.Uy, 32), 161);

    return serialized;
  }

  /**
   * Instantiate EffEcdsaPubInput from a serialized Uint8Array
   * @param serialized Uint8Array serialized by the serialize() function
   * @returns EffEcdsaPubInput
   */
  static deserialize(serialized: Uint8Array): EffEcdsaPubInput {
    const r = bytesToBigInt(serialized.slice(0, 32));
    const rV = bytesToBigInt(serialized.slice(32, 33));
    const msg = serialized.slice(33, 65);
    const Tx = bytesToBigInt(serialized.slice(65, 97));
    const Ty = bytesToBigInt(serialized.slice(97, 129));
    const Ux = bytesToBigInt(serialized.slice(129, 161));
    const Uy = bytesToBigInt(serialized.slice(161, 193));

    return new EffEcdsaPubInput(
      r,
      rV,
      Buffer.from(msg),
      new EffEcdsaCircuitPubInput(Tx, Ty, Ux, Uy)
    );
  }
}

/**
 * Verify the public values of the efficient ECDSA circuit
 */
export const verifyEffEcdsaPubInput = (pubInput: EffEcdsaPubInput): boolean => {
  const expectedCircuitInput = EffEcdsaCircuitPubInput.computeFromSig(
    pubInput.r,
    pubInput.rV,
    pubInput.msgHash
  );

  const circuitPubInput = pubInput.circuitPubInput;

  const isValid =
    expectedCircuitInput.Tx === circuitPubInput.Tx &&
    expectedCircuitInput.Ty === circuitPubInput.Ty &&
    expectedCircuitInput.Ux === circuitPubInput.Ux &&
    expectedCircuitInput.Uy === circuitPubInput.Uy;

  return isValid;
};
