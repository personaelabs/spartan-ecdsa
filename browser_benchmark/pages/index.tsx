import { useState, useEffect } from "react";

import { wrap } from "comlink";

const withProverApi = (worker: Worker) =>
  wrap<import("../lib/spartanProver/spartanProver").SpartanProver>(worker);

export default function Home() {
  const [worker, setWorker] = useState<any>();

  useEffect(() => {
    const worker = new Worker(
      new URL("../lib/spartanProver/spartanProver", import.meta.url),
      {
        name: "halo-worker",
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
            await withProverApi(worker).generateProof();
          }
        }}
      >
        prove
      </button>
    </div>
  );
}
