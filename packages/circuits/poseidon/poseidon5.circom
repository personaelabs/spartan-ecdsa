pragma circom 2.1.2;
include "./poseidons.circom";

// Constraint count equivalent to membership.circom. (right-filed ecdsa membership proof)
component main = Poseidons(5);