mkdir -p ./packages/circuits/build/eff_ecdsa
circom ./packages/circuits/instances/eff_ecdsa.circom --r1cs --wasm --prime secq256k1 -o ./packages/circuits/build/eff_ecdsa/