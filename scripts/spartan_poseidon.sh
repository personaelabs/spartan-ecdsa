BUILD_DIR=./packages/circuits/build/spartan/poseidon
CIRCUIT_NAME="poseidon"$1

mkdir -p $BUILD_DIR
circom ./packages/circuits/poseidon/$CIRCUIT_NAME.circom --r1cs --wasm --prime secq256k1 -o $BUILD_DIR

cargo run --release --bin gen_spartan_inst -- $BUILD_DIR/$CIRCUIT_NAME.r1cs $BUILD_DIR/$CIRCUIT_NAME.circuit 0