import { hashPersonalMessage, fromRpcSig } from "@ethereumjs/util";
var EC = require("elliptic").ec;
const BN = require("bn.js");

const ec = new EC("secp256k1");

const SECP256K1_N = new BN(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  16
);

export const genEffEcdsaInput = (sig: string, msg: Buffer) => {
  const msgHash = hashPersonalMessage(msg);

  const { v, r, s } = fromRpcSig(sig);

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

export const fetchCircuit = async (url: string): Promise<Uint8Array> => {
  const response = await fetch(url);

  const circuit = await response.arrayBuffer();

  return new Uint8Array(circuit);
};

export const bigIntToBytes = (n: bigint, size: number): Uint8Array => {
  const hex = n.toString(16);
  const hexPadded = hex.padStart(size * 2, "0");
  return Buffer.from(hexPadded, "hex");
};
