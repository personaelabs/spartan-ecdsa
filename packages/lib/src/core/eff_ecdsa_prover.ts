import {
  DEFAULT_EFF_ECDSA_CIRCUIT,
  DEFAULT_EFF_ECDSA_WITNESS_GEN_WASM,
  DEFAULT_SPARTAN_WASM
} from "../config";
import { fetchCircuit, generateWitness } from "../helpers/utils";
import { EffEcdsaPubInput, CircuitPubInput } from "../helpers/efficient_ecdsa";
import { initWasm, prove } from "../wasm";

import { ProveOptions, Proof } from "../types";
import { fromRpcSig } from "@ethereumjs/util";

export class EffECDSAProver {
  spartanWasm: string;
  enableProfiler: boolean;
  circuit: string;
  witnessGenWasm: string;

  constructor(options?: ProveOptions) {
    this.spartanWasm = options?.spartanWasm || DEFAULT_SPARTAN_WASM;
    this.circuit = options?.circuit || DEFAULT_EFF_ECDSA_CIRCUIT;
    this.witnessGenWasm =
      options?.witnessGenWasm || DEFAULT_EFF_ECDSA_WITNESS_GEN_WASM;
    this.enableProfiler = options?.enableProfiler || false;
  }

  // sig: format of the `eth_sign` RPC method
  // https://ethereum.github.io/execution-apis/api-documentation
  async prove(sig: string, msgHash: Buffer) {
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

    const { enableProfiler } = this;

    enableProfiler && console.time("Generate witness");
    const witness = await generateWitness(witnessGenInput, this.witnessGenWasm);
    enableProfiler && console.timeEnd("Generate witness");

    enableProfiler && console.time("Fetch circuit");
    const circuitBin = await fetchCircuit(this.circuit);
    enableProfiler && console.timeEnd("Fetch circuit");

    await initWasm(this.spartanWasm);

    console.time("Prove");
    let proof = await prove(
      circuitBin,
      witness.data,
      effEcdsaPubInput.circuitPubInput.serialize()
    );

    enableProfiler && console.timeEnd("Prove");
    return { proof, publicInput: effEcdsaPubInput.serialize() };
  }
}
