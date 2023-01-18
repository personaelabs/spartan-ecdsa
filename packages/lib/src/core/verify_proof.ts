// @ts-ignore
const snarkJs = require("snarkjs");
import { DEFAULT_CIRCUIT, DEFAULT_SPARTAN_WASM } from "../config";
import { fetchCircuit } from "../helpers/utils";
import { initWasm, verify } from "../wasm";
import {
  EffEcdsaPubInput,
  verifyEffEcdsaPubInput
} from "../helpers/efficient_ecdsa";
import { VerifyOptions } from "../types";

// Verify efficient ECDSA proof
export const verifyProof = async (
  proof: Uint8Array,
  publicInputSer: Uint8Array,
  options: VerifyOptions = {}
): Promise<boolean> => {
  const circuit = options.circuit || DEFAULT_CIRCUIT;
  const spartanWasm = options.spartanWasm || DEFAULT_SPARTAN_WASM;
  const circuitBin = await fetchCircuit(circuit);

  const publicInput = EffEcdsaPubInput.deserialize(publicInputSer);
  const isPubInputValid = verifyEffEcdsaPubInput(publicInput);

  await initWasm(spartanWasm);

  let nizkValid;
  try {
    nizkValid = await verify(
      circuitBin,
      proof,
      publicInput.circuitPubInput.serialize()
    );
  } catch (e) {
    return false;
  }

  return nizkValid && isPubInputValid;
};
