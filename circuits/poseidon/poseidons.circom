pragma circom 2.1.2;
include "../node_modules/circomlib/circuits/poseidon.circom";

template Poseidons(nPoseidons) {
    var nInputs = 16;
    signal input inputs[nInputs];
    signal output hash;

    component poseidons[nPoseidons];
    for (var i = 0; i < nPoseidons; i++) {
        poseidons[i] = Poseidon(nInputs);
        
        for (var j = 0; j < nInputs; j++) {
            poseidons[i].inputs[j] <== inputs[j];
        }
    }
    
    hash <== poseidons[nPoseidons - 1].out;
}

