import * as path from "path";
const isWeb = typeof window !== "undefined";

export const DEFAULT_SPARTAN_WASM = isWeb
  ? "https://storage.googleapis.com/personae-proving_keys/spartan_wasm_bg.wasm"
  : path.join(__dirname, "wasm/build/spartan_wasm_bg.wasm");

export const DEFAULT_EFF_ECDSA_WITNESS_GEN_WASM = isWeb
  ? "https://storage.googleapis.com/personae-proving_keys/eff_ecdsa/eff_ecdsa.wasm"
  : path.join(__dirname, "circuits/eff_ecdsa.wasm");

export const DEFAULT_EFF_ECDSA_CIRCUIT = isWeb
  ? "https://storage.googleapis.com/personae-proving_keys/eff_ecdsa/eff_ecdsa.circuit"
  : path.join(__dirname, "circuits/eff_ecdsa.circuit");

export const DEFAULT_MEMBERSHIP_WITNESS_GEN_WASM = isWeb
  ? "https://storage.googleapis.com/personae-proving-keys/membership/membeship.wasm"
  : path.join(__dirname, "circuits/membership.wasm");

export const DEFAULT_MEMBERSHIP_CIRCUIT = isWeb
  ? "https://storage.googleapis.com/personae-proving_keys/membership/membership.circuit"
  : path.join(__dirname, "circuits/membership.circuit");
