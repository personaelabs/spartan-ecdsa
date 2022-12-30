pragma circom 2.1.2;

template Secp256k1Add() {
    signal input p1X;
    signal input p1Y;
    signal input p2X;
    signal input p2Y;
    signal output outX;
    signal output outY;

    signal lambda;
    signal dx;
    signal dy;

    dx <== p1X - p2X;
    dy <== p1Y - p2Y;

    lambda <-- dy / dx;
    dx * lambda === dy;

    outX <== lambda * lambda - p1X - p2X;
    outY <== lambda * (p1X - outX) - p1Y;
}