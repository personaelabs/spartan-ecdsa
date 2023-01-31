import {
  defaultAddressMembershipVConfig,
  defaultPubkeyMembershipVConfig
} from "../config";
import { Profiler } from "../helpers/profiler";
import { loadCircuit } from "../helpers/utils";
import { IVerifier, VerifyConfig } from "../types";
import wasm, { init } from "../wasm";

/**
 * ECDSA Membership Verifier
 */
export class MembershipVerifier extends Profiler implements IVerifier {
  circuit: string;

  constructor(options: VerifyConfig) {
    super({ enabled: options?.enableProfiler });

    if (
      options.circuit === defaultAddressMembershipVConfig.circuit ||
      options.circuit === defaultPubkeyMembershipVConfig.circuit
    ) {
      console.warn(`
      Spartan-ecdsa default config warning:
      We recommend using defaultPubkeyMembershipPConfig/defaultPubkeyMembershipVConfig only for testing purposes.
      Please host and specify the circuit and witnessGenWasm files on your own server for sovereign control.
      Download files: https://github.com/personaelabs/spartan-ecdsa/blob/dan/embed-spartan-wasm/packages/lib/README.md#circuit-downloads
      `);
    }

    this.circuit = options.circuit;
  }

  async initWasm() {
    await init();
  }

  async verify(proof: Uint8Array, publicInput: Uint8Array): Promise<boolean> {
    this.time("Load circuit");
    const circuitBin = await loadCircuit(this.circuit);
    this.timeEnd("Load circuit");

    this.time("Verify proof");
    const result = await wasm.verify(circuitBin, proof, publicInput);
    this.timeEnd("Verify proof");
    return result;
  }
}
