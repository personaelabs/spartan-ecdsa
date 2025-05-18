import { ProverConfig, VerifyConfig } from "../types";

// Default configs for pubkey membership proving/verifying
export const defaultPubkeyProverConfig: ProverConfig = {
  witnessGenWasm:
    "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.wasm",
  circuit:
    "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.circuit"
};

export const defaultPubkeyVerifierConfig: VerifyConfig = {
  circuit: defaultPubkeyProverConfig.circuit
};

// Default configs for address membership proving/verifyign
export const defaultAddressProverConfig: ProverConfig = {
  witnessGenWasm:
    "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.wasm",
  circuit:
    "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.circuit"
};

export const defaultAddressVerifierConfig: VerifyConfig = {
  circuit: defaultAddressProverConfig.circuit
};
