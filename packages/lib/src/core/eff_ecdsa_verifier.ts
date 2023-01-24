import { DEFAULT_EFF_ECDSA_CIRCUIT } from "../config";
import { loadCircuit } from "../helpers/utils";
import { SpartanWasm } from "../wasm";
import {
  EffEcdsaPubInput,
  verifyEffEcdsaPubInput
} from "../helpers/efficient_ecdsa";
import { Profiler } from "../helpers/profiler";
import { VerifyOptions, IVerifier } from "../types";

export class EffECDSAVerifier extends Profiler implements IVerifier {
  spartanWasm: SpartanWasm;
  circuit: string;

  constructor(options?: VerifyOptions) {
    super({ enabled: options?.enableProfiler });

    this.circuit = options?.circuit || DEFAULT_EFF_ECDSA_CIRCUIT;
    this.spartanWasm = new SpartanWasm({ spartanWasm: options?.spartanWasm });
  }

  async verify(
    proof: Uint8Array,
    publicInputSer: Uint8Array
  ): Promise<boolean> {
    this.time("Load circuit");
    const circuitBin = await loadCircuit(this.circuit);
    this.timeEnd("Load circuit");

    this.time("Verify public input");
    const publicInput = EffEcdsaPubInput.deserialize(publicInputSer);
    const isPubInputValid = verifyEffEcdsaPubInput(publicInput);
    this.timeEnd("Verify public input");

    this.time("Verify NIZK");
    await this.spartanWasm.init();
    let nizkValid;
    try {
      nizkValid = await this.spartanWasm.verify(
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
