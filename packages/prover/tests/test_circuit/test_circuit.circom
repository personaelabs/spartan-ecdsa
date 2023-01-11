pragma circom 2.1.2;

template TestCircuit() {
    signal input a;
    signal input b[2];
    signal output c;

    signal b_prod;
    b_prod <== b[0] * b[1];

    c <== a * b_prod;
}

component main { public [ a ] } = TestCircuit();