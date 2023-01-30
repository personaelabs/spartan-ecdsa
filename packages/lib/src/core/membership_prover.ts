import { Profiler } from "../helpers/profiler";
import { IProver, MerkleProof, NIZK, ProverConfig, LeafType } from "../types";
import { SpartanWasm } from "../wasm";
import {
  bigIntToBytes,
  loadCircuit,
  fromSig,
  snarkJsWitnessGen
} from "../helpers/utils";
import {
  EffEcdsaPubInput,
  EffEcdsaCircuitPubInput
} from "../helpers/efficient_ecdsa";

/**
 * ECDSA Membership Prover
 */
export class MembershipProver extends Profiler implements IProver {
  spartanWasm!: SpartanWasm;
  circuit: string;
  witnessGenWasm: string;
  leafType: LeafType;

  constructor(options: ProverConfig) {
    super({ enabled: options?.enableProfiler });

    this.leafType = options.leafType;
    this.circuit = options.circuit;
    this.witnessGenWasm = options.witnessGenWasm;
  }

  async initWasm(wasm: SpartanWasm) {
    this.spartanWasm = wasm;
    this.spartanWasm.init();
  }

  // @ts-ignore
  async prove(
    sig: string,
    msgHash: Buffer,
    merkleProof: MerkleProof
  ): Promise<NIZK> {
    if (typeof this.spartanWasm === "undefined") {
      throw new Error("wasm not initialized. Please call initWasm().");
    }

    const { r, s, v } = fromSig(sig);

    const circuitPubInput = EffEcdsaCircuitPubInput.computeFromSig(
      r,
      v,
      msgHash
    );
    const effEcdsaPubInput = new EffEcdsaPubInput(
      r,
      v,
      msgHash,
      circuitPubInput
    );

    const merkleRootSer: Uint8Array = bigIntToBytes(merkleProof.root, 32);
    const circuitPubInputSer = circuitPubInput.serialize();

    // Concatenate circuitPubInputSer and merkleRootSer to construct the full public input
    const pubInput = new Uint8Array(
      merkleRootSer.length + circuitPubInputSer.length
    );
    pubInput.set(merkleRootSer);
    pubInput.set(circuitPubInputSer, merkleRootSer.length);

    const witnessGenInput = {
      s,
      ...merkleProof,
      ...effEcdsaPubInput.circuitPubInput
    };

    this.time("Generate witness");
    const witness = await snarkJsWitnessGen(
      witnessGenInput,
      this.witnessGenWasm
    );
    this.timeEnd("Generate witness");

    this.time("Load circuit");
    const circuitBin = await loadCircuit(this.circuit);
    this.timeEnd("Load circuit");

    this.time("Prove");
    let proof = await this.spartanWasm.prove(
      circuitBin,
      witness.data,
      pubInput
    );
    this.timeEnd("Prove");

    return { proof, publicInput: effEcdsaPubInput.serialize() };
  }
}
