import { expose } from "comlink";
const snarkJs = require("snarkjs");
const { utils } = require("ffjavascript");

const generateWitness = async () => {
  const wasmFile = "/spartan_poseidon.wasm";

  const witness: {
    type: string;
    data?: any;
  } = {
    type: "mem"
  };

  const input = {
    inputs: new Array(16).fill("1")
  };

  await snarkJs.wtns.calculate(input, wasmFile, witness);
  return witness;
};

const fetchCircuit = async (): Promise<string> => {
  const response = await fetch("/poseidon_circuit.json");

  const circuit = await response.json();

  return circuit;
};

export const genProofSpartan = async () => {
  const {
    default: init,
    initThreadPool,
    prove_poseidon,
    init_panic_hook
  } = await import("./wasm/spartan_wasm.js");

  await init();
  await init_panic_hook();
  await initThreadPool(navigator.hardwareConcurrency);
  console.time("Spartan Full proving time");

  const witness = await generateWitness();

  console.time("Fetch circuit");
  const circuit = await fetchCircuit();
  console.timeEnd("Fetch circuit");

  const proof = await prove_poseidon(circuit, witness.data);

  console.timeEnd("Spartan Full proving time");
  console.log("proof", proof);
};

export const genProofGroth16 = async () => {
  const input = {
    inputs: new Array(16).fill("1")
  };

  console.log("Proving with Groth16...");
  console.time("Groth16 Full proving time");
  await snarkJs.groth16.fullProve(
    input,
    "/g16_poseidon.wasm",
    "/g16_poseidon.zkey"
  );
  console.timeEnd("Groth16 Full proving time");
};

const exports = {
  genProofSpartan,
  genProofGroth16
};

export type Prover = typeof exports;

expose(exports);
