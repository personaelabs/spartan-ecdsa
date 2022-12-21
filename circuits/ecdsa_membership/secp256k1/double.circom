pragma circom 2.1.2;

template Secp256k1Double() {
    var a = 7;
    signal input pX; 
    signal input pY;

    signal output outX;
    signal output outY;

    var lambda = (3 * pX * pX + a) / (2 * pY);
    outX <-- lambda * lambda - 2 * pX;
    outY <-- lambda * (pX - outX) - pY;
}
