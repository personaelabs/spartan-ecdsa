pragma circom 2.1.2;

template Secp256k1Add() {
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