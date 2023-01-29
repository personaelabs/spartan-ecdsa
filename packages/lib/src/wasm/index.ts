import * as wasm from "./wasm";
import _initWeb from "./wasm.js";
import fs from "fs";
import path from "path";
import { WasmConfig } from "../types";

// TODO: Rename this to just Wasm since it includes not only Spartan but also Poseidon
export class SpartanWasm {
  private spartanWasmPathOrUrl: any;

  constructor(config: WasmConfig) {
    this.spartanWasmPathOrUrl = config.pathOrUrl;
  }

  async init() {
    if (typeof window === "undefined") {
      await this.initNode();
    } else {
      await this.initWeb();
    }
  }

  prove(circuit: Uint8Array, vars: Uint8Array, public_inputs: Uint8Array) {
    return wasm.prove(circuit, vars, public_inputs);
  }

  verify(circuit: Uint8Array, proof: Uint8Array, public_inputs: Uint8Array) {
    return wasm.verify(circuit, proof, public_inputs);
  }

  poseidon(inputs: Uint8Array) {
    return wasm.poseidon(inputs);
  }

  private async initNode() {
    const bytes = fs.readFileSync(this.spartanWasmPathOrUrl);

    await wasm.initSync(bytes);
    await wasm.init_panic_hook();
  }

  private async initWeb() {
    await _initWeb(this.spartanWasmPathOrUrl);
    await wasm.init_panic_hook();
  }
}
