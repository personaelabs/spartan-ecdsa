import { SpartanWasm } from "../wasm";
import { bigIntToLeBytes, bytesLeToBigInt } from "./utils";

export class Poseidon {
  wasm: SpartanWasm;
  constructor(wasm?: SpartanWasm) {
    if (typeof wasm === "undefined") {
      this.wasm = new SpartanWasm();
    } else {
      this.wasm = wasm;
    }
  }

  async init() {
    await this.wasm.init();
  }

  hash(inputs: bigint[]): bigint {
    const inputsBytes = new Uint8Array(32 * inputs.length);
    for (let i = 0; i < inputs.length; i++) {
      inputsBytes.set(bigIntToLeBytes(inputs[i], 32), i * 32);
    }

    const result = this.wasm.poseidon(inputsBytes);
    return bytesLeToBigInt(result);
  }
}
