pragma circom 2.1.2;

template Secp256k1Double() {
    signal input pX; 
    signal input pY;

    signal output outX;
    signal output outY;

    signal lambda;
    signal pXSquared;

    pXSquared <== pX * pX;

    lambda <-- (3 * pXSquared) / (2 * pY);
    lambda * 2 * pY === 3 * pXSquared;

    outX <== lambda * lambda - (2 * pX);
    outY <== lambda * (pX - outX) - pY;
}
