pragma circom 2.1.2;

include "./add.circom";
include "./double.circom";
include "../../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../../node_modules/circomlib/circuits/gates.circom";

// Scalar multiplication using only complete additions.
template Secp256k1Mul() {
    var bits = 256;
    signal input scalar;
    signal input xP; 
    signal input yP;
    signal output outX;
    signal output outY;

    component kBits = K(bits);
    kBits.s <== scalar;

    component acc0 = Secp256k1Double();
    acc0.xP <== xP;
    acc0.yP <== yP;

    component PIncomplete[bits-3]; 
    component accIncomplete[bits];

    for (var i = 0; i < bits-3; i++) {
        if (i == 0) {
            PIncomplete[i] = Secp256k1AddIncomplete(); // (Acc + P)
            PIncomplete[i].xP <== xP; // scalar[i] ? xP : -xP;
            PIncomplete[i].yP <== (2 * 0 - 1) * yP;// scalar[i] ? xP : -xP;
            PIncomplete[i].xQ <== acc0.outX;
            PIncomplete[i].yQ <== acc0.outY;
            

            accIncomplete[i] = Secp256k1AddIncomplete(); // (Acc + P) + Acc
            accIncomplete[i].xP <== acc0.outX;
            accIncomplete[i].yP <== acc0.outY;
            accIncomplete[i].xQ <== PIncomplete[i].outX;
            accIncomplete[i].yQ <== PIncomplete[i].outY;
        } else {
            PIncomplete[i] = Secp256k1AddIncomplete(); // (Acc + P)
            PIncomplete[i].xP <== xP; // k_i ? xP : -xP;
            PIncomplete[i].yP <== (2 * kBits.out[bits-i] - 1) * yP;// k_i ? xP : -xP;
            PIncomplete[i].xQ <== accIncomplete[i-1].outX;
            PIncomplete[i].yQ <== accIncomplete[i-1].outY;

            accIncomplete[i] = Secp256k1AddIncomplete(); // (Acc + P) + Acc
            accIncomplete[i].xP <== accIncomplete[i-1].outX;
            accIncomplete[i].yP <== accIncomplete[i-1].outY;
            accIncomplete[i].xQ <== PIncomplete[i].outX;
            accIncomplete[i].yQ <== PIncomplete[i].outY;
        }
    }

    component PComplete[bits-3]; 
    component accComplete[3];

    for (var i = 0; i < 3; i++) {
        PComplete[i] = Secp256k1AddComplete(); // (Acc + P)

        PComplete[i].xP <== xP; // k_i ? xP : -xP;
        PComplete[i].yP <== (2 * kBits.out[3 - i] - 1) * yP;// k_i ? xP : -xP;
        if (i == 0) {
            PComplete[i].xQ <== accIncomplete[252].outX;
            PComplete[i].yQ <== accIncomplete[252].outY;
        } else {
            PComplete[i].xQ <== accComplete[i-1].outX;
            PComplete[i].yQ <== accComplete[i-1].outY;
        }

        accComplete[i] = Secp256k1AddComplete(); // (Acc + P) + Acc
        if (i == 0) {
            accComplete[i].xP <== accIncomplete[252].outX;
            accComplete[i].yP <== accIncomplete[252].outY;
        } else {
            accComplete[i].xP <== accComplete[i-1].outX;
            accComplete[i].yP <== accComplete[i-1].outY;
        }

        accComplete[i].xQ <== PComplete[i].outX;
        accComplete[i].yQ <== PComplete[i].outY;
    }

    component out = Secp256k1AddComplete();
    out.xP <== accComplete[2].outX;
    out.yP <== accComplete[2].outY;
    out.xQ <== (1 - kBits.out[0]) * xP;
    out.yQ <== (1 - kBits.out[0]) * -yP;

    outX <== out.outX;
    outY <== out.outY;
}

template K(bits) {
    signal input s;
    signal output out[bits];

    signal khi;
    signal klo;
    signal shi;
    signal slo;
    signal carry;

    var q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141; // The order of the scalar field
    var qlo = q & (2 ** (bits / 2) - 1);
    var qhi = q >> (bits / 2);
    var tQ = 115792089237316195423570985008687907852405143892509244725752742275123193348738; // (q - 2^256) % q;
    var tQlo = tQ & (2 ** (bits / 2) - 1);
    var tQhi = tQ >> (bits / 2);

    slo <-- s & (2 ** (bits / 2) - 1);
    shi <-- s >> (bits / 2);

    // Get carry bit of (slo + tQlo)
    component inBits = Num2Bits((bits / 2) + 1);
    inBits.in <== slo + tQlo;
    carry <== inBits.out[bits / 2];
    
    /**
    quotient: if a >= b then 1; else 0
    quotient: ((s + tQ) >= q then 1 : 0)
    k = if quotient: (s + tQ) - q; else (s + tQ)
    */


    /**
    check that a >= b
    - alpha: if ahi > bhi ?  true： false
    - beta: if ahi = bhi
        - gamma if alo ≥ blo: true
        - theta alo < blo: false
    
    where
    a = (s + tQ)
    b = q
    */

    signal ahi;
    signal bhi;
    signal alo;
    signal blo;

    ahi <== shi + tQhi + carry;
    bhi <== qhi;
    alo <== slo + tQlo - (carry * 2 ** 128);
    blo <== qlo;

    component alpha = GreaterThan(129);
    alpha.in[0] <== ahi;
    alpha.in[1] <== bhi;

    component beta = IsEqual();
    beta.in[0] <== ahi;
    beta.in[1] <== bhi;

    component gamma = GreaterEqThan(129);
    gamma.in[0] <== alo;
    gamma.in[1] <== blo;

    component betaANDgamma = AND();
    betaANDgamma.a <== beta.out;
    betaANDgamma.b <== gamma.out;

    component isQuotientOne = OR();
    isQuotientOne.a <== betaANDgamma.out;
    isQuotientOne.b <== alpha.out;

    // if the quotient is 1, then q * 1 + k = s + tQ
    // if the quotient is 0, then k = s + tQ
    // s + tQ / div = quotient, k
    // s + tQ = quotient * div + k
    // k = (s + tQ) / q  * quotient

    // Check that if the mod was done correctly
    // (slo + shi * 2^128) * quotient + r = divisor
    // divisor * quotient + r = slo * quotient + shi * 2^128 

    // theta: if slo + tQlo < qlo ? 1 : 0
    component theta = GreaterThan(129);
    theta.in[0] <== qlo;
    theta.in[1] <== slo + tQlo;

    component borrow = AND();
    borrow.a <== theta.out;
    borrow.b <== isQuotientOne.out;

    // if slo + tQlo - borrowlo < 0 then borrow = 1 else borrow = 0
    klo <== (slo + tQlo + borrow.out * (2 ** 128)) - isQuotientOne.out * qlo;
    khi <== (shi + tQhi - borrow.out * 1)  - isQuotientOne.out * qhi;

    component kloBits = Num2Bits(256);
    kloBits.in <== klo;

    component khiBits = Num2Bits(256);
    khiBits.in <== khi;

    for (var i = 0; i < 128; i++) {
        out[i] <== kloBits.out[i];
        out[i + 128] <== khiBits.out[i];
    }
}