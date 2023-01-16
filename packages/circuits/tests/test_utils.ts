import { hashPersonalMessage, ecsign } from "@ethereumjs/util";
import { CircuitPubInput } from "spartan-ecdsa";

export const getEffEcdsaCircuitInput = (privKey: Buffer, msg: Buffer) => {
  const msgHash = hashPersonalMessage(msg);
  const { v, r: _r, s } = ecsign(msgHash, privKey);
  const r = BigInt("0x" + _r.toString("hex"));

  const circuitPubInput = CircuitPubInput.computeFromSig(r, v, msg);
  const input = {
    s,
    ...circuitPubInput
  };

  return input;
};

export const bytesToBigInt = (bytes: Uint8Array): bigint =>
  BigInt("0x" + Buffer.from(bytes).toString("hex"));
