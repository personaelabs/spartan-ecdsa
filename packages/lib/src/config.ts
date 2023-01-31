import { ProverConfig, VerifyConfig } from "./types";

// Default configs for pubkey membership proving/verifying
export const defaultPubkeyMembershipPConfig: ProverConfig = {
  witnessGenWasm:
    "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.wasm",
  circuit:
    "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.circuit"
};

export const defaultPubkeyMembershipVConfig: VerifyConfig = {
  circuit: defaultPubkeyMembershipPConfig.circuit
};

// Default configs for address membership proving/verifyign
export const defaultAddressMembershipPConfig: ProverConfig = {
  witnessGenWasm:
    "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.wasm",
  circuit:
    "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.circuit"
};

export const defaultAddressMembershipVConfig: VerifyConfig = {
  circuit: defaultAddressMembershipPConfig.circuit
};
