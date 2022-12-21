mkdir -p ./circuits/build/ecdsa_membership
circom ./circuits/ecdsa_membership/membership.circom --r1cs --wasm --prime curve25519 -o ./circuits/build/ecdsa_membership/