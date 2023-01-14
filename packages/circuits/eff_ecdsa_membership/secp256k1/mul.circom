pragma circom 2.1.2;

include "./add.circom";
include "./double.circom";

// Scalar multiplication using only complete additions.
// TODO: Only do a minimal amount of complete additions by applying the method described in https://zcash.github.io/halo2/design/gadgets/ecc/var-base-scalar-mul.html
template Secp256k1Mul() {
    var bits = 256;
    signal input scalar[bits];
    signal input xP; 
    signal input yP;

    signal output outX;
    signal output outY;

    component powers[bits];
    for (var i = 0; i < bits; i++) {
        if (i == 0) {
            powers[i] = Secp256k1Double();
            powers[i].xP <== xP;
            powers[i].yP <== yP;
        } else {
            powers[i] = Secp256k1Double();
            powers[i].xP <== powers[i-1].outX;
            powers[i].yP <== powers[i-1].outY;
        }
    }

    component accumulator[bits];
    for (var i = 0; i < bits; i++) {
        if (i == 0) {
            accumulator[i] = Secp256k1AddComplete();
            accumulator[i].xP <== xP * scalar[i];
            accumulator[i].yP <== yP * scalar[i];
            accumulator[i].xQ <== 0;
            accumulator[i].yQ <== 0;
        } else {
            accumulator[i] = Secp256k1AddComplete();
            accumulator[i].xP <== accumulator[i-1].outX;
            accumulator[i].yP <== accumulator[i-1].outY;
            accumulator[i].xQ <== powers[i-1].outX * scalar[i];
            accumulator[i].yQ <== powers[i-1].outY * scalar[i];
        }
    }


    outX <== accumulator[bits-1].outX;
    outY <== accumulator[bits-1].outY;
}