// @ts-ignore
const snarkJs = require("snarkjs");
import {
  DEFAULT_CIRCUIT,
  DEFAULT_WITNESS_GEN_WASM,
  DEFAULT_SPARTAN_WASM
} from "../config";
import { fetchCircuit } from "../helpers/utils";
import { EffEcdsaPubInput, CircuitPubInput } from "../helpers/efficient_ecdsa";
import { initWasm, prove } from "../wasm";

import { ProveOptions, Proof } from "../types";
import { fromRpcSig } from "@ethereumjs/util";

const generateWitness = async (input: any, wasmFile: string) => {
  const witness: {
    type: string;
    data?: any;
  } = {
    type: "mem"
  };

  await snarkJs.wtns.calculate(input, wasmFile, witness);
  return witness;
};

// sig: format of the `eth_sign` RPC method
// https://ethereum.github.io/execution-apis/api-documentation
export const proveSig = async (
  sig: string,
  msgHash: Buffer,
  options: ProveOptions = {},
  profile: boolean = false
): Promise<Proof> => {
  const { r: _r, s: _s, v } = fromRpcSig(sig);
  const r = BigInt("0x" + _r.toString("hex"));
  const s = BigInt("0x" + _s.toString("hex"));

  const circuitPubInput = CircuitPubInput.computeFromSig(r, v, msgHash);
  const effEcdsaPubInput = new EffEcdsaPubInput(r, v, msgHash, circuitPubInput);

  const witnessGenInput = {
    s,
    ...effEcdsaPubInput.circuitPubInput
  };

  const witnessGenWasm = options.witnessGenWasm || DEFAULT_WITNESS_GEN_WASM;
  const circuit = options.circuit || DEFAULT_CIRCUIT;
  const spartanWasm = options.spartanWasm || DEFAULT_SPARTAN_WASM;

  profile && console.time("Generate witness");
  const witness = await generateWitness(witnessGenInput, witnessGenWasm);
  profile && console.timeEnd("Generate witness");

  profile && console.time("Fetch circuit");
  const circuitBin = await fetchCircuit(circuit);
  profile && console.timeEnd("Fetch circuit");

  await initWasm(spartanWasm);

  console.time("Prove");
  let proof = await prove(
    circuitBin,
    witness.data,
    effEcdsaPubInput.circuitPubInput.serialize()
  );

  profile && console.timeEnd("Prove");
  return { proof, publicInput: effEcdsaPubInput.serialize() };
};
