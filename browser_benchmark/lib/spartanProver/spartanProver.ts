import { expose } from "comlink";

export const generateProof = async () => {
  const {
    default: init,
    initThreadPool,
    prove,
    init_panic_hook
  } = await import("./wasm/spartan_wasm.js");

  await init();
  await init_panic_hook();
  await initThreadPool(navigator.hardwareConcurrency);
  console.time("Full proving time");
  const proof = await prove();

  console.timeEnd("Full proving time");
  console.log("proof", proof);
};

const exports = {
  generateProof
};
export type SpartanProver = typeof exports;

expose(exports);
