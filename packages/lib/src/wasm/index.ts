import * as wasm from "./wasm";
import _init from "./wasm.js";
import fs from "fs";
import path from "path";

export const initWasm = async (proverWasm?: string) => {
  let bytes;
  if (typeof window === "undefined") {
    // In Node.js, we can load the wasm binary from the file system
    bytes = fs.readFileSync(
      path.join(__dirname, "./build/spartan_wasm_bg.wasm")
    );
    await wasm.initSync(bytes);
  } else {
    // In  browser, we need to fetch the wasm binary
    await _init(proverWasm);
  }

  await wasm.init_panic_hook();
};

export const prove = wasm.prove;
export const verify = wasm.verify;
