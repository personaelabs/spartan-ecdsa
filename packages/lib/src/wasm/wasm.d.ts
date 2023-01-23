/* tslint:disable */
/* eslint-disable */
/**
*/
export function init_panic_hook(): void;
/**
* @param {Uint8Array} circuit
* @param {Uint8Array} vars
* @param {Uint8Array} public_inputs
* @returns {Uint8Array}
*/
export function prove(circuit: Uint8Array, vars: Uint8Array, public_inputs: Uint8Array): Uint8Array;
/**
* @param {Uint8Array} circuit
* @param {Uint8Array} proof
* @param {Uint8Array} public_input
* @returns {boolean}
*/
export function verify(circuit: Uint8Array, proof: Uint8Array, public_input: Uint8Array): boolean;
/**
* @param {Uint8Array} input_bytes
* @returns {Uint8Array}
*/
export function poseidon(input_bytes: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly prove: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly poseidon: (a: number, b: number, c: number) => void;
  readonly init_panic_hook: () => void;
  readonly memory: WebAssembly.Memory;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __wbindgen_realloc: (a: number, b: number, c: number) => number;
  readonly __wbindgen_thread_destroy: () => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
* @param {WebAssembly.Memory} maybe_memory
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput, maybe_memory?: WebAssembly.Memory): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
* @param {WebAssembly.Memory} maybe_memory
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>, maybe_memory?: WebAssembly.Memory): Promise<InitOutput>;
