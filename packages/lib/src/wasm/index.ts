import * as wasm from "./wasm";
import _initWeb from "./wasm.js";

import { wasmBytes } from "./wasm_bytes";

export const init = async () => {
  await wasm.initSync(wasmBytes.buffer);
  wasm.init_panic_hook();
};

export default wasm;
