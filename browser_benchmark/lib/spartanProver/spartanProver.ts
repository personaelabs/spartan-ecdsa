import { expose } from "comlink";
const { wtns } = require("snarkjs");
const { utils } = require("ffjavascript");

const generateWitness = async () => {
  const wasmFile = "/poseidon.wasm";

  const witness: {
    type: string;
    data?: any;
  } = {
    type: "mem"
  };

  const input = {
    inputs: new Array(16).fill("1")
  };

  await wtns.calculate(input, wasmFile, witness);
  return witness;
};

const fetchCircuit = async (): Promise<string> => {
  const response = await fetch("/poseidon_circuit.json");

  const circuit = await response.json();

  return circuit;
};

export const generateProof = async () => {
  const {
    default: init,
    initThreadPool,
    prove_poseidon,
    init_panic_hook
  } = await import("./wasm/spartan_wasm.js");

  await init();
  await init_panic_hook();
  await initThreadPool(navigator.hardwareConcurrency);
  console.time("Full proving time");

  const witness = await generateWitness();

  const circuit = await fetchCircuit();
  const proof = await prove_poseidon(circuit, witness.data);

  console.timeEnd("Full proving time");
  console.log("proof", proof);
};

const exports = {
  generateProof
};

export type SpartanProver = typeof exports;

expose(exports);
