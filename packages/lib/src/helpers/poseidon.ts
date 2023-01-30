import { SpartanWasm } from "../wasm";
import { bigIntToLeBytes, bytesLeToBigInt } from "./utils";

export class Poseidon {
  wasm!: SpartanWasm;
  constructor() {}

  async initWasm(wasm: SpartanWasm) {
    this.wasm = wasm;
    await this.wasm.init();
  }

  assertInitWasm() {
    if (typeof this.wasm === "undefined") {
      throw new Error("wasm not initialized. Please call initWasm().");
    }
  }

  hash(inputs: bigint[]): bigint {
    this.assertInitWasm();
    const inputsBytes = new Uint8Array(32 * inputs.length);
    for (let i = 0; i < inputs.length; i++) {
      inputsBytes.set(bigIntToLeBytes(inputs[i], 32), i * 32);
    }

    const result = this.wasm.poseidon(inputsBytes);
    return bytesLeToBigInt(result);
  }

  hashPubKey(pubKey: Buffer): bigint {
    this.assertInitWasm();
    const pubKeyX = BigInt("0x" + pubKey.toString("hex").slice(0, 64));
    const pubKeyY = BigInt("0x" + pubKey.toString("hex").slice(64, 128));

    const pubKeyHash = this.hash([pubKeyX, pubKeyY]);
    return pubKeyHash;
  }
}
