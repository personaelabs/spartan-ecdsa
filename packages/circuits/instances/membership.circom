pragma circom 2.1.2;

include "../eff_ecdsa_membership/membership.circom";

component main { public[ Tx, Ty, Ux, Uy ]} = Membership(14);