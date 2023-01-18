import { Profiler } from "../helpers/profiler";
import { IProver, NIZK, ProverOptions } from "../types";
import { SpartanWasm } from "../wasm";
import {
  DEFAULT_EFF_MEMBERSHIP_CIRCUIT,
  DEFAULT_MEMBERSHIP_WITNESS_GEN_WASM
} from "../config";

export class MembershipProver extends Profiler implements IProver {
  spartanWasm: SpartanWasm;
  circuit: string;
  witnessGenWasm: string;

  constructor(options?: ProverOptions) {
    super({ enabled: options?.enableProfiler });

    this.spartanWasm = new SpartanWasm({ spartanWasm: options?.spartanWasm });
    this.circuit = options?.circuit || DEFAULT_EFF_MEMBERSHIP_CIRCUIT;
    this.witnessGenWasm =
      options?.witnessGenWasm || DEFAULT_MEMBERSHIP_WITNESS_GEN_WASM;
  }

  // @ts-ignore
  async prove(): Promise<NIZK> {}
}
