BUILD_DIR=./circuits/build/spartan/poseidon
EXPORT_DIR=./browser_benchmark/public

mkdir -p $BUILD_DIR
circom ./circuits/poseidon/poseidon.circom --r1cs --wasm --prime curve25519 -o $BUILD_DIR

cp $BUILD_DIR/poseidon_js/poseidon.wasm $EXPORT_DIR/spartan_poseidon.wasm

cargo run --release --bin gen_spartan_inst