import { Profiler } from "../helpers/profiler";
import { IProver, MerkleProof, NIZK, ProveArgs, ProverConfig } from "../types";
import { loadCircuit, fromSig, snarkJsWitnessGen } from "../helpers/utils";
import {
  PublicInput,
  computeEffEcdsaPubInput,
  CircuitPubInput
} from "../helpers/publicInputs";
import { init, wasm } from "../wasm";
import {
  defaultPubkeyProverConfig,
  defaultAddressProverConfig
} from "../config";

/**
 * ECDSA Membership Prover
 */
export class MembershipProver extends Profiler implements IProver {
  circuit: string;
  witnessGenWasm: string;
  useRemoteCircuit: boolean;

  constructor({
    enableProfiler,
    circuit,
    witnessGenWasm,
    useRemoteCircuit
  }: ProverConfig) {
    super({ enabled: enableProfiler });

    if (
      circuit === defaultPubkeyProverConfig.circuit ||
      witnessGenWasm === defaultPubkeyProverConfig.witnessGenWasm ||
      circuit === defaultAddressProverConfig.circuit ||
      witnessGenWasm === defaultAddressProverConfig.witnessGenWasm
    ) {
      console.warn(`
      Spartan-ecdsa default config warning:
      We recommend using defaultPubkeyMembershipPConfig/defaultPubkeyMembershipVConfig only for testing purposes.
      Please host and specify the circuit and witnessGenWasm files on your own server for sovereign control.
      Download files: https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/lib/README.md#circuit-downloads
      `);
    }

    this.circuit = circuit;
    this.witnessGenWasm = witnessGenWasm;
    this.useRemoteCircuit = useRemoteCircuit ?? false;
  }

  async initWasm() {
    await init();
  }

  async prove({ sig, msgHash, merkleProof }: ProveArgs): Promise<NIZK> {
    const { r, s, v } = fromSig(sig);

    const effEcdsaPubInput = computeEffEcdsaPubInput(r, v, msgHash);
    const circuitPubInput = new CircuitPubInput(
      merkleProof.root,
      effEcdsaPubInput.Tx,
      effEcdsaPubInput.Ty,
      effEcdsaPubInput.Ux,
      effEcdsaPubInput.Uy
    );
    const publicInput = new PublicInput(r, v, msgHash, circuitPubInput);

    const witnessGenInput = {
      s,
      ...merkleProof,
      ...effEcdsaPubInput
    };

    this.time("Generate witness");
    const witness = await snarkJsWitnessGen(
      witnessGenInput,
      this.witnessGenWasm
    );
    this.timeEnd("Generate witness");

    this.time("Load circuit");
    const useRemoteCircuit =
      this.useRemoteCircuit || typeof window !== "undefined";
    const circuitBin = await loadCircuit(this.circuit, useRemoteCircuit);
    this.timeEnd("Load circuit");

    // Get the public input in bytes
    const circuitPublicInput: Uint8Array =
      publicInput.circuitPubInput.serialize();

    this.time("Prove");
    let proof = wasm.prove(circuitBin, witness.data, circuitPublicInput);
    this.timeEnd("Prove");

    return {
      proof,
      publicInput
    };
  }
}
