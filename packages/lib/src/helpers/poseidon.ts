import { init, wasm } from "../wasm";
import { bigIntToLeBytes, bytesLeToBigInt } from "./utils";

export class Poseidon {
  hash(inputs: bigint[]): bigint {
    const inputsBytes = new Uint8Array(32 * inputs.length);
    for (let i = 0; i < inputs.length; i++) {
      inputsBytes.set(bigIntToLeBytes(inputs[i], 32), i * 32);
    }

    const result = wasm.poseidon(inputsBytes);
    return bytesLeToBigInt(result);
  }

  async initWasm() {
    await init();
  }

  hashPubKey(pubKey: Buffer): bigint {
    const pubKeyX = BigInt("0x" + pubKey.toString("hex").slice(0, 64));
    const pubKeyY = BigInt("0x" + pubKey.toString("hex").slice(64, 128));

    const pubKeyHash = this.hash([pubKeyX, pubKeyY]);
    return pubKeyHash;
  }
}
