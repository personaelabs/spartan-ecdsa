pragma circom 2.1.2;
include "../node_modules/circomlib/circuits/poseidon.circom";

template Poseidons(nInputs) {
    signal input inputs[nInputs];
    signal output hash;

    var num_poseidons = 8;
    component poseidons[num_poseidons];
    for (var i = 0; i < num_poseidons; i++) {
        poseidons[i] = Poseidon(nInputs);
        
        for (var j = 0; j < nInputs; j++) {
            poseidons[i].inputs[j] <== inputs[j];
        }
    }
    
    hash <== poseidons[num_poseidons - 1].out;
}

component main = Poseidons(16);

