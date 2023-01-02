pragma circom 2.1.2;

include "../../ecdsa_membership/ecdsa.circom";

component main { public[ Tx, Ty, Ux, Uy ]} = EfficientECDSA();