import { expose } from "comlink";
import { genProofSpartan } from "./spartan";
import { genProofGroth16 } from "./groth16";
import { genEffEcdsaInput } from "./eff_ecdsa";

const genProofSpartanEffEcdsa = async () => {
  const witnessGen =
    "https://storage.googleapis.com/proving_keys/eff_ecdsa/eff_ecdsa.wasm";
  const circuit =
    "https://storage.googleapis.com/proving_keys/eff_ecdsa/eff_ecdsa.circuit";

  const privKey = BigInt(
    "0xf5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f"
  );
  const msg = Buffer.from("hello world");

  const input = genEffEcdsaInput(privKey, msg);

  await genProofSpartan(input, witnessGen, circuit);
};

const poseidonInput = {
  inputs: new Array(16).fill("1")
};

const genProofSpartanPoseidon5 = async () => {
  const witnessGen =
    "https://storage.googleapis.com/proving_keys/poseidon5/spartan_poseidon5.wasm";
  const circuit =
    "https://storage.googleapis.com/proving_keys/poseidon5/spartan_poseidon5.circuit";

  await genProofSpartan(poseidonInput, witnessGen, circuit);
};

const genProofSpartanPoseidon32 = async () => {
  const witnessGen =
    "https://storage.googleapis.com/proving_keys/poseidon32/spartan_poseidon32.wasm";
  const circuit =
    "https://storage.googleapis.com/proving_keys/poseidon32/spartan_poseidon32.circuit";

  await genProofSpartan(poseidonInput, witnessGen, circuit);
};

const genProofSpartanPoseidon256 = async () => {
  const witnessGen =
    "https://storage.googleapis.com/proving_keys/poseidon256/spartan_poseidon256.wasm";
  const circuit =
    "https://storage.googleapis.com/proving_keys/poseidon256/spartan_poseidon256.circuit";

  await genProofSpartan(poseidonInput, witnessGen, circuit);
};

const genProofGroth16Poseidon5 = async () => {
  const witnessGen =
    "https://storage.googleapis.com/proving_keys/poseidon5/g16_poseidon5.wasm";
  const circuit =
    "https://storage.googleapis.com/proving_keys/poseidon5/g16_poseidon5.zkey";

  await genProofGroth16(witnessGen, circuit);
};

const genProofGroth16Poseidon32 = async () => {
  const witnessGen =
    "https://storage.googleapis.com/proving_keys/poseidon32/g16_poseidon32.wasm";
  const circuit =
    "https://storage.googleapis.com/proving_keys/poseidon32/g16_poseidon32.zkey";

  await genProofGroth16(witnessGen, circuit);
};

const genProofGroth16Poseidon256 = async () => {
  const witnessGen =
    "https://storage.googleapis.com/proving_keys/poseidon256/g16_poseidon256.wasm";
  const circuit =
    "https://storage.googleapis.com/proving_keys/poseidon256/g16_poseidon256.zkey";

  await genProofGroth16(witnessGen, circuit);
};

const exports = {
  genProofSpartanEffEcdsa,
  genProofSpartanPoseidon5,
  genProofSpartanPoseidon32,
  genProofSpartanPoseidon256,
  genProofGroth16Poseidon5,
  genProofGroth16Poseidon32,
  genProofGroth16Poseidon256
};

export type Prover = typeof exports;

expose(exports);
