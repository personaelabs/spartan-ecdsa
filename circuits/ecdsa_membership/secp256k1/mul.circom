pragma circom 2.1.2;

include "./add.circom";
include "./double.circom";

template Secp256k1Mul() {
    var bits = 256;
    var a = 7;
    signal input scalar[bits];
    signal input pX; 
    signal input pY;

    signal output outX;
    signal output outY;

    component powers[bits];
    for (var i = 0; i < bits-1; i++) {
        if (i == 0) {
            powers[i] = Secp256k1Double();
            powers[i].pX <== pX;
            powers[i].pY <== pY;
        } else {
            powers[i] = Secp256k1Double();
            powers[i].pX <== powers[i-1].outX;
            powers[i].pY <== powers[i-1].outY;
        }
    }

    component accumulator[bits];
    for (var i = 0; i < bits-1; i++) {
        if (i == 0) {
            accumulator[i] = Secp256k1Add();
            accumulator[i].p1X <== pX * scalar[i];
            accumulator[i].p1Y <== pY * scalar[i];
            accumulator[i].p2X <== powers[i].outX * scalar[i + 1];
            accumulator[i].p2Y <== powers[i].outY * scalar[i + 1];
        } else {
            accumulator[i] = Secp256k1Add();
            accumulator[i].p1X <== accumulator[i-1].outX;
            accumulator[i].p1Y <== accumulator[i-1].outY;
            accumulator[i].p2X <== powers[i].outX * scalar[i];
            accumulator[i].p2Y <== powers[i].outY * scalar[i];
        }
    }

    outX <== accumulator[bits-2].outX;
    outY <== accumulator[bits-2].outY;
}