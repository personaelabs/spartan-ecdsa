// @ts-ignore
const snarkJs = require("snarkjs");
import {
  DEFAULT_CIRCUIT,
  DEFAULT_WITNESS_GEN_WASM,
  DEFAULT_PROVER_WASM
} from "./config";
import { fetchCircuit, bigIntToBytes, genEffEcdsaInput } from "./utils";
import init, { initSync, init_panic_hook, prove, verify } from "./wasm/wasm.js";
import * as fs from "fs";
import * as path from "path";
import { ProveOptions } from "./types";

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
  msg: Buffer,
  options: ProveOptions = {}
): Promise<any> => {
  const input = genEffEcdsaInput(sig, msg);

  const witnessGenWasm = options.witnessGenWasm || DEFAULT_WITNESS_GEN_WASM;
  const circuit = options.circuit || DEFAULT_CIRCUIT;
  const proverWasm = options.proverWasm || DEFAULT_PROVER_WASM;

  const witness = await generateWitness(input, witnessGenWasm);
  const circuitBin = await fetchCircuit(circuit);

  let publicInput = new Uint8Array(32 * 4);

  publicInput.set(bigIntToBytes(BigInt(input.Tx), 32), 0);
  publicInput.set(bigIntToBytes(BigInt(input.Ty), 32), 32);
  publicInput.set(bigIntToBytes(BigInt(input.Ux), 32), 64);
  publicInput.set(bigIntToBytes(BigInt(input.Uy), 32), 96);

  let bytes;
  if (typeof window === "undefined") {
    // In Node.js, we can load the wasm binary from the file system
    bytes = fs.readFileSync(
      path.join(__dirname, "./wasm/build/prover_bg.wasm")
    );
    await initSync(bytes);
  } else {
    // In  browser, we need to fetch the wasm binary
    await init(proverWasm);
  }

  await init_panic_hook();
  let proof = await prove(circuitBin, witness.data, publicInput);
  return { proof, publicInput };
};

// Verify Spartan proof
export const verifyProof = async (
  proof: Uint8Array,
  publicInput: Uint8Array,
  options: any = {}
): Promise<boolean> => {
  const circuit = options.circuit || DEFAULT_CIRCUIT;
  const circuitBin = await fetchCircuit(circuit);

  const result = verify(circuitBin, proof, publicInput);
  return result;
};
