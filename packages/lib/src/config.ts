import * as path from "path";
const isWeb = typeof window !== "undefined";
import { LeafType, ProverConfig } from "./types";

// Default configs for MembershipProver

// Default configs for pubkey membership proving
export const defaultPubkeyMembershipConfig: ProverConfig = {
  witnessGenWasm: isWeb
    ? "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.wasm"
    : path.join(__dirname, "circuits/pubkey_membership.wasm"),

  circuit: isWeb
    ? "https://storage.googleapis.com/personae-proving-keys/membership/pubkey_membership.circuit"
    : path.join(__dirname, "circuits/pubkey_membership.circuit"),

  leafType: LeafType.PubKeyHash
};

// Default configs for address membership proving
export const defaultAddressMembershipConfig: ProverConfig = {
  witnessGenWasm: isWeb
    ? "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.wasm"
    : path.join(__dirname, "circuits/addr_membership.wasm"),

  circuit: isWeb
    ? "https://storage.googleapis.com/personae-proving-keys/membership/addr_membership.circuit"
    : path.join(__dirname, "circuits/addr_membership.circuit"),

  leafType: LeafType.Address
};
