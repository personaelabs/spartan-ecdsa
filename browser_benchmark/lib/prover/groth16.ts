const snarkJs = require("snarkjs");

export const genProofGroth16 = async (
  witnessGenWasmUrl: string,
  zKeyUrl: string
) => {
  const input = {
    inputs: new Array(16).fill("1")
  };

  console.log("Proving with Groth16...");
  console.time("Groth16 Full proving time");
  await snarkJs.groth16.fullProve(input, witnessGenWasmUrl, zKeyUrl);
  console.timeEnd("Groth16 Full proving time");
};
