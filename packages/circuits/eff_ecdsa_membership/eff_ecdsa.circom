pragma circom 2.1.2;

include "./secp256k1/mul.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// ECDSA public key recovery without public key validation.
template EfficientECDSA() {
    var bits = 256;
    signal input s;
    signal input Tx; // T = r^-1 * R
    signal input Ty; 
    signal input Ux; // U = -(m * r^-1 * G)
    signal input Uy;

    signal output pubKeyX;
    signal output pubKeyY;

    var gX = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    var gY = 32670510020758816978083085130507043184471273380659243275938904335757337482424;
    var a = 7;

    component sBits = Num2Bits(bits);
    sBits.in <== s;

    // t * R = s * r^-1 * R
    component sMultT = Secp256k1Mul();
    for (var i = 0; i < bits; i++) {
        sMultT.scalar[i] <== sBits.out[i];
    }
    sMultT.pX <== Tx;
    sMultT.pY <== Ty;

    // sMultT + U 
    component pubKey = Secp256k1Add();
    pubKey.p1X <== sMultT.outX;
    pubKey.p1Y <== sMultT.outY;
    pubKey.p2X <== Ux;
    pubKey.p2Y <== Uy;
    pubKey.isP2Identity <== 0;

    pubKeyX <== pubKey.outX;
    pubKeyY <== pubKey.outY;
}