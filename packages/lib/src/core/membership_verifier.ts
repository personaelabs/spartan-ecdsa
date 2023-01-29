import { Profiler } from "../helpers/profiler";
import { loadCircuit } from "../helpers/utils";
import { IVerifier, VerifyOptions } from "../types";
import { SpartanWasm } from "../wasm";

export class MembershipVerifier extends Profiler implements IVerifier {
  spartanWasm!: SpartanWasm;
  circuit: string;

  constructor(options: VerifyOptions) {
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

    return this.spartanWasm.verify(circuitBin, proof, publicInput);
  }
}
