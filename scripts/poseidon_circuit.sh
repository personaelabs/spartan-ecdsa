mkdir -p ./circuits/build/poseidon
circom ./circuits/poseidon/poseidon.circom --r1cs --wasm --prime curve25519 -o ./circuits/build/poseidon