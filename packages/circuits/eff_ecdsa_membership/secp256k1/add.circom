pragma circom 2.1.2;

include "../../../../node_modules/circomlib/circuits/comparators.circom";

template Secp256k1AddIncomplete() {
    signal input p1X;
    signal input p1Y;
    signal input p2X;
    signal input p2Y;
    signal input isP2Identity;
    signal output outX;
    signal output outY;

    signal lambda;
    signal dx;
    signal dy;
    signal outXIntermid;
    signal outYIntermid;
    signal outXAdjusted;
    signal outYAdjusted;

    dx <== p1X - p2X;
    dy <== p1Y - p2Y;

    lambda <-- dy / dx;
    dx * lambda === dy;

    outXIntermid <== lambda * lambda - p1X - p2X;
    outYIntermid <== lambda * (p1X - outXIntermid) - p1Y;

    outXAdjusted <== outXIntermid - p1X;
    outYAdjusted <== outYIntermid - p1Y;

    outX <== (1 - isP2Identity) * outXAdjusted + p1X;
    outY <== (1 - isP2Identity) * outYAdjusted + p1Y;
}

template Secp256k1AddComplete() {
    signal input xP;
    signal input yP;
    signal input xQ;
    signal input yQ;

    signal output outX;
    signal output outY;

    signal lambdaXEqual; // λ when xP = xQ
    signal lambdaXUnequal; // λ when xP != xQ and yP != 0
    signal dx; // xQ - xP
    signal dy; // yQ - yP
    signal xPSquared; // xP^2
    signal lambda; // the actual λ to constrain xR and yR (either lambdaXEqual or lambdaXUnequal)

    signal xRXpZero; // xR when xP = 0
    signal xRXqZero; // xR when xQ = 0
    signal xRNonZero; // xR when xP != 0 and xQ != 0

    signal yRXpZero; // yR when xP = 0
    signal yRXqZero; // yR when xQ = 0
    signal yRNonZero; // yR when xP != 0 and xQ != 0

    xPSquared <== xP * xP;

    component isXEqual = IsEqual();
    isXEqual.in[0] <== xP;
    isXEqual.in[1] <== xQ;

    component isXpZero = IsZero();
    isXpZero.in <== xP;
 
    component isXqZero = IsZero();
    isXqZero.in <== xQ;

    component isEitherZero = IsZero();
    isEitherZero.in <== (1 - isXpZero.out) * (1 - isXqZero.out);

    // lambda constraints when xP != xQ
    dx <== xQ - xP;
    dy <== (yQ - yP) * (1 - isXEqual.out);
    lambdaXUnequal <-- ((yQ - yP) / dx) * (1 - isXEqual.out);
    // lambdaXUnequal and dy are zerorized when xP = xQ
    dx * lambdaXUnequal === dy;

    // lambda constraints when xP = xQ
    lambdaXEqual <-- ((3 * xPSquared) / (2 * yP));
    lambdaXEqual * 2 * yP === 3 * xPSquared;

    // lambdaXUnequal is zerorized above when xP = xQ
    lambda <== (lambdaXEqual * isXEqual.out) + lambdaXUnequal;

    // xR and yR when xP != 0 and xQ != 0
    xRNonZero <== lambda * lambda - xP - xQ;
    yRNonZero <== lambda * (xP - xRNonZero) - yP;

    signal xRNonZeroFinal <== xRNonZero * (1 - isEitherZero.out);
    signal yRNonZeroFinal <== yRNonZero * (1 - isEitherZero.out);

    // xR when xP = 0
    xRXpZero <== isXpZero.out * xQ;
    yRXpZero <== isXpZero.out * yQ;

    // xR when xQ = 0
    xRXqZero <== isXqZero.out * xP;
    yRXqZero <== isXqZero.out * yP;

    // zeroize = 1 when xP = xQ and yP = -yQ
    component zeroize = IsEqual();
    zeroize.in[0] <== isXEqual.out;
    zeroize.in[1] <== 1 - (yP + yQ);

    // Final assignment
    // Only one of xRXpZero, xRXqZero, or xRNonZeroFinal will be non-zero, so we can safely add them. 
    outX <== (xRXpZero + xRXqZero + xRNonZeroFinal) * (1 - zeroize.out);
    outY <== (yRXpZero + yRXqZero + yRNonZeroFinal) * (1 - zeroize.out);
}