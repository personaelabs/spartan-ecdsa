import { useState, useEffect } from "react";

import { wrap } from "comlink";

const withProverApi = (worker: Worker) =>
  wrap<import("../lib/prover/prover").Prover>(worker);

export default function Home() {
  const [worker, setWorker] = useState<any>();

  useEffect(() => {
    const worker = new Worker(
      new URL("../lib/prover/prover", import.meta.url),
      {
        name: "prover-worker",
        type: "module"
      }
    );

    setWorker(worker);
  }, []);

  return (
    <div>
      <button
        onClick={async () => {
          if (worker) {
            await withProverApi(worker).genProofSpartanEffEcdsa();
          }
        }}
      >
        Prove(Spartan eff ecdsa)
      </button>
      <button
        onClick={async () => {
          if (worker) {
            await withProverApi(worker).genProofSpartanPoseidon5();
          }
        }}
      >
        Prove(Spartan poseidon5)
      </button>
      <button
        onClick={async () => {
          if (worker) {
            await withProverApi(worker).genProofSpartanPoseidon32();
          }
        }}
      >
        Prove(Spartan poseidon32)
      </button>
      <button
        onClick={async () => {
          if (worker) {
            await withProverApi(worker).genProofSpartanPoseidon256();
          }
        }}
      >
        Prove(Spartan poseidon256)
      </button>
      <button
        onClick={async () => {
          if (worker) {
            await withProverApi(worker).genProofGroth16Poseidon5();
          }
        }}
      >
        Prove(Groth16 poseidon5)
      </button>
      <button
        onClick={async () => {
          if (worker) {
            await withProverApi(worker).genProofGroth16Poseidon32();
          }
        }}
      >
        Prove(Groth16 poseidon32)
      </button>
      <button
        onClick={async () => {
          if (worker) {
            await withProverApi(worker).genProofGroth16Poseidon256();
          }
        }}
      >
        Prove(Groth16 poseidon256)
      </button>
    </div>
  );
}
