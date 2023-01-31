import * as path from "path";
const isWeb = typeof window !== "undefined";
import { LeafType, ProverConfig, VerifyConfig } from "./types";

// Default configs for pubkey membership proving/verifying
export const defaultPubkeyMembershipPConfig: ProverConfig = {
  witnessGenWasm: isWeb
    ? "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.wasm"
    : path.join(__dirname, "circuits/pubkey_membership.wasm"),

  circuit: isWeb
    ? "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.circuit"
    : path.join(__dirname, "circuits/pubkey_membership.circuit"),

  leafType: LeafType.PubKeyHash
};

export const defaultPubkeyMembershipVConfig: VerifyConfig = {
  circuit: defaultPubkeyMembershipPConfig.circuit
};

// Default configs for address membership proving/verifyign
export const defaultAddressMembershipPConfig: ProverConfig = {
  witnessGenWasm: isWeb
    ? "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.wasm"
    : path.join(__dirname, "circuits/addr_membership.wasm"),

  circuit: isWeb
    ? "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.circuit"
    : path.join(__dirname, "circuits/addr_membership.circuit"),

  leafType: LeafType.Address
};

export const defaultAddressMembershipVConfig: VerifyConfig = {
  circuit: defaultAddressMembershipPConfig.circuit
};
