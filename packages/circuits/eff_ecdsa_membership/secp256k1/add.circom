pragma circom 2.1.2;

include "../../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../../node_modules/circomlib/circuits/gates.circom";

template Secp256k1AddIncomplete() {
    signal input xP;
    signal input yP;
    signal input xQ;
    signal input yQ;
    signal output outX;
    signal output outY;

    signal lambda;
    signal dx;
    signal dy;

    dx <== xP - xQ;
    dy <== yP - yQ;

    lambda <-- dy / dx;
    dx * lambda === dy;

    outX <== lambda * lambda - xP - xQ;
    outY <== lambda * (xP - outX) - yP;
}

// Assuming that (0, 0) is not a valid point.
template Secp256k1AddComplete() {
    signal input xP;
    signal input yP;
    signal input xQ;
    signal input yQ;

    signal output outX;
    signal output outY;

    signal xPSquared <== xP * xP;

    component isXEqual = IsEqual();
    isXEqual.in[0] <== xP;
    isXEqual.in[1] <== xQ;

    component isXpZero = IsZero();
    isXpZero.in <== xP;
 
    component isXqZero = IsZero();
    isXqZero.in <== xQ;

    component isXEitherZero = IsZero();
    isXEitherZero.in <== (1 - isXpZero.out) * (1 - isXqZero.out);

    
    // dx = xQ - xP
    // dy = xP != xQ ? yQ - yP : 0
    // lambdaA = xP != xQ ? (yQ - yP) / (xQ - xP) : 0
    signal dx <== xQ - xP;
    signal dy <== (yQ - yP) * (1 - isXEqual.out);
    signal lambdaA <-- ((yQ - yP) / dx) * (1 - isXEqual.out);
    dx * lambdaA === dy;

    // lambdaB = (3 * xP^2) / (2 * yP)
    signal lambdaB <-- ((3 * xPSquared) / (2 * yP));
    lambdaB * 2 * yP === 3 * xPSquared;

    // lambda = xP != xQ ? lambdaA : lambdaB
    signal lambda <== (lambdaB * isXEqual.out) + lambdaA;

    // outAx = lambda^2 - xP - xQ
    // outAy = lambda * (xP - outAx) - yP
    signal outAx <== lambda * lambda - xP - xQ;
    signal outAy <== lambda * (xP - outAx) - yP;

    // (outBx, outBy) = xP != 0 and xQ != 0 ? (outAx, outAy) : (0, 0)
    signal outBx <== outAx * (1 - isXEitherZero.out);
    signal outBy <== outAy * (1 - isXEitherZero.out);

    //(outCx, outCy) = xP = 0 ? (xQ, yQ) : (0, 0)
    signal outCx <== isXpZero.out * xQ;
    signal outCy <== isXpZero.out * yQ;

    // (outDx, outDy) = xQ = 0 ? (xP, yP) : (0, 0)
    signal outDx <== isXqZero.out * xP;
    signal outDy <== isXqZero.out * yP;

    // zeroizeA = (xP = xQ and yP = -yQ) ? 1 : 0
    component zeroizeA = IsEqual();
    zeroizeA.in[0] <== isXEqual.out;
    zeroizeA.in[1] <== 1 - (yP + yQ);

    // zeroizeB = (xP = 0 and xQ = 0) ? 1 : 0
    component zeroizeB = AND();
    zeroizeB.a <== isXpZero.out;
    zeroizeB.b <== isXqZero.out;

    // zeroize = (xP = xQ and yP = -yQ) or (xP = 0 and xQ = 0) ? 1 : 0
    component zeroize = OR();
    zeroize.a <== zeroizeA.out;
    zeroize.b <== zeroizeB.out;

    // The below three conditionals are mutually exclusive when zeroize = 0, 
    // so we can safely sum the outputs.
    // outBx != 0 iff xP != 0 and xQ != 0
    // outCx != 0 iff xP = 0
    // outDx != 0 iff xQ = 0
    outX <== (outBx + outCx + outDx) * (1 - zeroize.out);
    outY <== (outBy + outCy + outDy) * (1 - zeroize.out);
}