import { Profiler } from "../helpers/profiler";
import { loadCircuit } from "../helpers/utils";
import { IVerifier, VerifyConfig } from "../types";
import { SpartanWasm } from "../wasm";

/**
 * ECDSA Membership Verifier
 */
export class MembershipVerifier extends Profiler implements IVerifier {
  spartanWasm!: SpartanWasm;
  circuit: string;

  constructor(options: VerifyConfig) {
    super({ enabled: options?.enableProfiler });

    this.circuit = options.circuit;
  }

  async initWasm(wasm: SpartanWasm) {
    this.spartanWasm = wasm;
    this.spartanWasm.init();
  }

  async verify(proof: Uint8Array, publicInput: Uint8Array): Promise<boolean> {
    this.time("Load circuit");
    const circuitBin = await loadCircuit(this.circuit);
    this.timeEnd("Load circuit");

    this.time("Verify proof");
    const result = await this.spartanWasm.verify(
      circuitBin,
      proof,
      publicInput
    );
    this.timeEnd("Verify proof");
    return result;
  }
}
