const { hashPersonalMessage, ecsign } = require("@ethereumjs/util");
var EC = require("elliptic").ec;
const BN = require("bn.js");

const ec = new EC("secp256k1");

const SECP256K1_N = new BN(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  16
);

export const genEffEcdsaInput = (privKey: bigint, msg: Buffer) => {
  const msgHash = hashPersonalMessage(msg);
  const { v, r, s } = ecsign(msgHash, privKey);

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

  return {
    s: BigInt("0x" + s.toString("hex")),
    Tx: T.x.toString(),
    Ty: T.y.toString(),
    Ux: U.x.toString(),
    Uy: U.y.toString()
  };
};

export const bytesToBigInt = (bytes: Uint8Array): bigint =>
  BigInt("0x" + Buffer.from(bytes).toString("hex"));
