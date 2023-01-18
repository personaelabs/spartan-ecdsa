import * as wasm from "./wasm";
import _initWeb from "./wasm.js";
import fs from "fs";
import path from "path";
import { SpartanWasmOptions } from "../types";
import { DEFAULT_SPARTAN_WASM } from "../config";

export class SpartanWasm {
  private spartanWasmPathOrUrl: any;

  constructor(options?: SpartanWasmOptions) {
    const defaultWasmPath =
      typeof window === "undefined"
        ? "./build/spartan_wasm_bg.wasm"
        : DEFAULT_SPARTAN_WASM;

    this.spartanWasmPathOrUrl = options?.spartanWasm || defaultWasmPath;
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

  verify(circuit: Uint8Array, vars: Uint8Array, public_inputs: Uint8Array) {
    return wasm.verify(circuit, vars, public_inputs);
  }

  private async initNode() {
    const bytes = fs.readFileSync(
      path.join(__dirname, this.spartanWasmPathOrUrl)
    );

    await wasm.initSync(bytes);
    await wasm.init_panic_hook();
  }

  private async initWeb() {
    await _initWeb(this.spartanWasmPathOrUrl);
    await wasm.init_panic_hook();
  }
}
