import {
  defaultAddressMembershipVConfig,
  defaultPubkeyMembershipVConfig
} from "../config";
import { Profiler } from "../helpers/profiler";
import { loadCircuit } from "../helpers/utils";
import { IVerifier, VerifyConfig } from "../types";
import { init, wasm } from "../wasm";
import { PublicInput, verifyEffEcdsaPubInput } from "../helpers/public_input";

/**
 * ECDSA Membership Verifier
 */
export class MembershipVerifier extends Profiler implements IVerifier {
  circuit: string;
  useRemoteCircuit: boolean;

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
      Download files: https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/lib/README.md#circuit-downloads
      `);
    }

    this.circuit = options.circuit;
    this.useRemoteCircuit =
      options.useRemoteCircuit || typeof window !== "undefined";
  }

  async initWasm() {
    await init();
  }

  async verify(
    proof: Uint8Array,
    publicInputSer: Uint8Array
  ): Promise<boolean> {
    this.time("Load circuit");
    const circuitBin = await loadCircuit(this.circuit, this.useRemoteCircuit);
    this.timeEnd("Load circuit");

    this.time("Verify public input");
    const publicInput = PublicInput.deserialize(publicInputSer);
    const isPubInputValid = verifyEffEcdsaPubInput(publicInput);
    this.timeEnd("Verify public input");

    this.time("Verify proof");
    let isProofValid;
    try {
      isProofValid = await wasm.verify(
        circuitBin,
        proof,
        publicInput.circuitPubInput.serialize()
      );
    } catch (_e) {
      isProofValid = false;
    }

    this.timeEnd("Verify proof");
    return isProofValid && isPubInputValid;
  }
}
