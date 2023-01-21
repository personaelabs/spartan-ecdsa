pragma circom 2.1.2;

include "../../eff_ecdsa_membership/eff_ecdsa_to_addr.circom";

component main { public[ Tx, Ty, Ux, Uy ]} = EfficientECDSAToAddr();