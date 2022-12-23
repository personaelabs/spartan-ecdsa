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
            await withProverApi(worker).genProofSpartan();
          }
        }}
      >
        Prove(Spartan)
      </button>
      <button
        onClick={async () => {
          if (worker) {
            await withProverApi(worker).genProofGroth16();
          }
        }}
      >
        Prove(Groth16)
      </button>
    </div>
  );
}
