pragma circom 2.0.6;
include "./node_modules/circomlib/circuits/escalarmulfix.circom";

template ScalarMult() {
    signal input S[256];

    // BabyJubJub base point
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component mulFix = EscalarMulFix(256, BASE8);

    for (var i=0; i<256; i++) {
        mulFix.e[i] <== S[i];
    }
}

component main = ScalarMult();