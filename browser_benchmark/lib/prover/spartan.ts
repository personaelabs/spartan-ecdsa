const snarkJs = require("snarkjs");
import { genEffEcdsaInput } from "./eff_ecdsa";

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

const fetchCircuit = async (url: string): Promise<Uint8Array> => {
  const response = await fetch(url);

  const circuit = await response.arrayBuffer();

  return new Uint8Array(circuit);
};

export const genProofSpartan = async (
  input: any,
  witnessGenWasmUrl: string,
  circuitUrl: string
) => {
  console.log("Proving with Spartan...");
  const {
    default: init,
    prove,
    init_panic_hook
  } = await import("./wasm/spartan_wasm.js");

  await init();
  await init_panic_hook();
  console.time("Spartan Full proving time");

  const witness = await generateWitness(input, witnessGenWasmUrl);

  console.time("Fetch circuit");
  const circuit = await fetchCircuit(circuitUrl);
  console.timeEnd("Fetch circuit");
  console.log(circuit);

  const proof = await prove(circuit, witness.data);

  console.timeEnd("Spartan Full proving time");
  console.log("proof", proof);

  console.log("proof.byteLength", proof.byteLength);
};
