pragma circom 2.1.2;

template Secp256k1Double() {
    signal input xP; 
    signal input yP;

    signal output outX;
    signal output outY;

    signal lambda;
    signal xPSquared;

    xPSquared <== xP * xP;

    lambda <-- (3 * xPSquared) / (2 * yP);
    lambda * 2 * yP === 3 * xPSquared;

    outX <== lambda * lambda - (2 * xP);
    outY <== lambda * (xP - outX) - yP;
}
