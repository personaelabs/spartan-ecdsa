import {
  DEFAULT_EFF_ECDSA_CIRCUIT,
  DEFAULT_EFF_ECDSA_WITNESS_GEN_WASM
} from "../config";
import { fetchCircuit, snarkJsWitnessGen } from "../helpers/utils";
import { EffEcdsaPubInput, CircuitPubInput } from "../helpers/efficient_ecdsa";
import { SpartanWasm } from "../wasm";

import { ProverOptions, IProver, NIZK } from "../types";
import { fromRpcSig } from "@ethereumjs/util";
import { Profiler } from "../helpers/profiler";

export class EffECDSAProver extends Profiler implements IProver {
  spartanWasm: SpartanWasm;
  circuit: string;
  witnessGenWasm: string;

  constructor(options?: ProverOptions) {
    super({ enabled: options?.enableProfiler });

    this.spartanWasm = new SpartanWasm({ spartanWasm: options?.spartanWasm });
    this.circuit = options?.circuit || DEFAULT_EFF_ECDSA_CIRCUIT;
    this.witnessGenWasm =
      options?.witnessGenWasm || DEFAULT_EFF_ECDSA_WITNESS_GEN_WASM;
  }

  // sig: format of the `eth_sign` RPC method
  // https://ethereum.github.io/execution-apis/api-documentation
  async prove(sig: string, msgHash: Buffer): Promise<NIZK> {
    const { r: _r, s: _s, v } = fromRpcSig(sig);
    const r = BigInt("0x" + _r.toString("hex"));
    const s = BigInt("0x" + _s.toString("hex"));

    const circuitPubInput = CircuitPubInput.computeFromSig(r, v, msgHash);
    const effEcdsaPubInput = new EffEcdsaPubInput(
      r,
      v,
      msgHash,
      circuitPubInput
    );

    const witnessGenInput = {
      s,
      ...effEcdsaPubInput.circuitPubInput
    };

    this.time("Generate witness");
    const witness = await snarkJsWitnessGen(
      witnessGenInput,
      this.witnessGenWasm
    );
    this.timeEnd("Generate witness");

    this.time("Fetch circuit");
    const circuitBin = await fetchCircuit(this.circuit);
    this.timeEnd("Fetch circuit");

    await this.spartanWasm.init();
    this.time("Prove");
    let proof = await this.spartanWasm.prove(
      circuitBin,
      witness.data,
      effEcdsaPubInput.circuitPubInput.serialize()
    );
    this.timeEnd("Prove");

    return { proof, publicInput: effEcdsaPubInput.serialize() };
  }
}
