mkdir -p ./circuits/build/eff_ecdsa
circom ./circuits/instances/eff_ecdsa.circom --r1cs --wasm --prime secq256k1 -o ./circuits/build/eff_ecdsa/