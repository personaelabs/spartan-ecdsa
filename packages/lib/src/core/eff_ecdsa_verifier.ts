import { DEFAULT_EFF_ECDSA_CIRCUIT, DEFAULT_SPARTAN_WASM } from "../config";
import { fetchCircuit } from "../helpers/utils";
import { initWasm, verify } from "../wasm";
import {
  EffEcdsaPubInput,
  verifyEffEcdsaPubInput
} from "../helpers/efficient_ecdsa";
import { Profiler } from "../helpers/profiler";
import { VerifyOptions } from "../types";

export class EffECDSAVerifier extends Profiler {
  circuit: string;
  spartanWasm: string;

  constructor(options?: VerifyOptions) {
    super({ enabled: options?.enableProfiler });

    this.circuit = options?.circuit || DEFAULT_EFF_ECDSA_CIRCUIT;
    this.spartanWasm = options?.spartanWasm || DEFAULT_SPARTAN_WASM;
  }

  async verify(
    proof: Uint8Array,
    publicInputSer: Uint8Array
  ): Promise<boolean> {
    this.time("Fetch circuit");
    const circuitBin = await fetchCircuit(this.circuit);
    this.timeEnd("Fetch circuit");

    this.time("Verify public input");
    const publicInput = EffEcdsaPubInput.deserialize(publicInputSer);
    const isPubInputValid = verifyEffEcdsaPubInput(publicInput);
    this.timeEnd("Verify public input");

    await initWasm(this.spartanWasm);

    this.time("Verify NIZK");
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
    this.timeEnd("Verify NIZK");

    return isPubInputValid && nizkValid;
  }
}
