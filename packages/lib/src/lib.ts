// @ts-ignore
const snarkJs = require("snarkjs");
import {
  DEFAULT_CIRCUIT,
  DEFAULT_WITNESS_GEN_WASM,
  DEFAULT_PROVER_WASM
} from "./config";
import { fetchCircuit } from "./utils";
import {
  EffEcdsaPubInput,
  verifyEffEcdsaPubInput,
  CircuitPubInput
} from "./efficient_ecdsa";
import init, { initSync, init_panic_hook, prove, verify } from "./wasm/wasm.js";
import * as fs from "fs";
import * as path from "path";
import { ProveOptions, Proof } from "./types";
import { fromRpcSig } from "@ethereumjs/util";

export * from "./types";
export * from "./efficient_ecdsa";

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
  options: ProveOptions = {},
  profile: boolean = false
): Promise<Proof> => {
  const { r: _r, s: _s, v } = fromRpcSig(sig);
  const r = BigInt("0x" + _r.toString("hex"));
  const s = BigInt("0x" + _s.toString("hex"));

  const circuitPubInput = CircuitPubInput.computeFromSig(r, v, msg);
  const effEcdsaPubInput = new EffEcdsaPubInput(r, v, msg, circuitPubInput);

  const witnessGenInput = {
    s,
    ...effEcdsaPubInput.circuitPubInput
  };

  const witnessGenWasm = options.witnessGenWasm || DEFAULT_WITNESS_GEN_WASM;
  const circuit = options.circuit || DEFAULT_CIRCUIT;
  const proverWasm = options.proverWasm || DEFAULT_PROVER_WASM;

  profile && console.time("Generate witness");
  const witness = await generateWitness(witnessGenInput, witnessGenWasm);
  profile && console.timeEnd("Generate witness");

  profile && console.time("Fetch circuit");
  const circuitBin = await fetchCircuit(circuit);
  profile && console.timeEnd("Fetch circuit");

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
  console.time("Prove");
  let proof = await prove(
    circuitBin,
    witness.data,
    effEcdsaPubInput.circuitPubInput.serialize()
  );

  profile && console.timeEnd("Prove");
  return { proof, publicInput: effEcdsaPubInput.serialize() };
};

// Verify efficient ECDSA proof
export const verifyProof = async (
  proof: Uint8Array,
  publicInput: Uint8Array,
  options: any = {}
): Promise<boolean> => {
  const circuit = options.circuit || DEFAULT_CIRCUIT;
  const circuitBin = await fetchCircuit(circuit);

  const isPubInputValid = verifyEffEcdsaPubInput(
    EffEcdsaPubInput.deserialize(publicInput)
  );

  const result = await verify(circuitBin, proof, publicInput);

  return result && isPubInputValid;
};
