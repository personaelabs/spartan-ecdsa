pragma circom 2.1.2;

include "./add.circom";
include "./double.circom";

template Secp256k1Mul() {
    var bits = 256;
    signal input scalar[bits];
    signal input pX; 
    signal input pY;

    signal output outX;
    signal output outY;

    component powers[bits];
    for (var i = 0; i < bits; i++) {
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

    // Dummy point
    var dummyX = 115136800820456833737994126771386015026287095034625623644186278108926690779567;
    var dummyY = 3479535755779840016334846590594739014278212596066547564422106861430200972724;
    var dummyYNeg = 112312553481536355407236138418093168838991772069574016475035477146478633698939;

    component accumulator[bits];
    for (var i = 0; i < bits; i++) {
        if (i == 0) {
            accumulator[i] = Secp256k1AddIncomplete();
            accumulator[i].p1X <== dummyX;
            accumulator[i].p1Y <== dummyY;
            accumulator[i].p2X <== pX;
            accumulator[i].p2Y <== pY;
            accumulator[i].isP2Identity <== 1 - scalar[i];
        } else {
            accumulator[i] = Secp256k1AddIncomplete();
            accumulator[i].p1X <== accumulator[i-1].outX;
            accumulator[i].p1Y <== accumulator[i-1].outY;
            accumulator[i].p2X <== powers[i-1].outX;
            accumulator[i].p2Y <== powers[i-1].outY;
            accumulator[i].isP2Identity <== 1 - scalar[i];
        }
    }

    component adjust = Secp256k1AddIncomplete();
    adjust.p1X <== accumulator[bits-1].outX;
    adjust.p1Y <== accumulator[bits-1].outY;
    adjust.p2X <== dummyX;
    adjust.p2Y <== dummyYNeg;
    adjust.isP2Identity <== 0;

    outX <== adjust.outX;
    outY <== adjust.outY;
}