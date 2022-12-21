pragma circom 2.1.2;

include "./secp256k1/mul.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// ECDSA public key recovery without public key validation.
template ECDSA() {
    var bits = 256;
    signal input s;
    signal input msg;
    signal input rInv;
    signal input rX;
    signal input rXSquared;
    signal input rY;
    signal input rYSquared;

    signal output pubKeyX;
    signal output pubKeyY;

    var gX = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    var gY = 32670510020758816978083085130507043184471273380659243275938904335757337482424;
    var a = 7;

    // Check that (rX, rY) is on the curve

    // enforce r^-1 * rX = 1;
    rInv * rX === 1;

    // enforce rYSquared = rY^2;
    rYSquared === rY * rY;

    // enforce rXSquared = rX^2;
    rXSquared === rX * rX; 

    var rXCubic = rXSquared * rX;
    
    // enforce rYSquared = rX^3 + a * rX;
    rYSquared === rXCubic + a * rX;

    // s * r^-1 
    var t = s * rInv;
    component tBits = Num2Bits(bits);
    tBits.in <== t;

    // msg * r^-1
    var u = msg * rInv;
    component uBits = Num2Bits(bits);
    uBits.in <== u;

    // t * R = s * r^-1 * R
    component tR = Secp256k1Mul();
    for (var i = 0; i < bits; i++) {
        tR.scalar[i] <== tBits.out[i];
    }
    tR.pX <== rX;
    tR.pY <== rY;

    // u * G = msg * r^-1 * G
    component uG = Secp256k1Mul();
    for (var i = 0; i < bits; i++) {
        uG.scalar[i] <== uBits.out[i];
    }
    uG.pX <== gX;
    uG.pY <== gY;

    // uG + tR = msg * r^-1 * G + s * r^-1 * G  = pubKey
    component pubKey = Secp256k1Add();
    pubKey.p1X <== uG.pX;
    pubKey.p1Y <== uG.pY;
    pubKey.p2X <== tR.pX;
    pubKey.p2Y <== tR.pY;

    pubKeyX <== pubKey.outX;
    pubKeyY <== pubKey.outY;
}