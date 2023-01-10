mkdir -p ./circuits/build/eff_ecdsa_membership
circom ./circuits/eff_ecdsa_membership/membership.circom --r1cs --wasm --prime secq256k1 -o ./circuits/build/ecdsa_membership/