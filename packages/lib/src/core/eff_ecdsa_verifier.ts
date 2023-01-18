// @ts-ignore
const snarkJs = require("snarkjs");
import { DEFAULT_EFF_ECDSA_CIRCUIT, DEFAULT_SPARTAN_WASM } from "../config";
import { fetchCircuit } from "../helpers/utils";
import { initWasm, verify } from "../wasm";
import {
  EffEcdsaPubInput,
  verifyEffEcdsaPubInput
} from "../helpers/efficient_ecdsa";
import { VerifyOptions } from "../types";

export class EffECDSAVerifier {
  circuit: string;
  spartanWasm: string;

  constructor(options?: VerifyOptions) {
    this.circuit = options?.circuit || DEFAULT_EFF_ECDSA_CIRCUIT;
    this.spartanWasm = options?.spartanWasm || DEFAULT_SPARTAN_WASM;
  }

  async verify(
    proof: Uint8Array,
    publicInputSer: Uint8Array
  ): Promise<boolean> {
    const circuitBin = await fetchCircuit(this.circuit);

    const publicInput = EffEcdsaPubInput.deserialize(publicInputSer);
    const isPubInputValid = verifyEffEcdsaPubInput(publicInput);

    await initWasm(this.spartanWasm);

    let nizkValid;
    try {
      nizkValid = await verify(
        circuitBin,
        proof,
        publicInput.circuitPubInput.serialize()
      );
    } catch (e) {
      return false;
    }

    return isPubInputValid && nizkValid;
  }
}
