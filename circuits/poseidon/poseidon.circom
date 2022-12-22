pragma circom 2.1.2;
include "../node_modules/circomlib/circuits/poseidon.circom";

template PoseidonHash(nInputs) {
    signal input inputs[nInputs];
    signal output hash;

    component poseidon = Poseidon(nInputs);

    for (var i = 0; i < nInputs; i++) {
        poseidon.inputs[i] <== inputs[i];
    }

    hash <== poseidon.out;

}

component main = PoseidonHash(16);

