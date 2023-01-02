pragma circom 2.1.2;

include "../../eff_ecdsa_membership/eff_ecdsa.circom";

component main { public[ Tx, Ty, Ux, Uy ]} = EfficientECDSA();