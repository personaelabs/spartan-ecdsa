BUILD_DIR=./packages/circuits/build/membership
mkdir -p $BUILD_DIR &&
circom ./packages/circuits/instances/membership.circom --r1cs --wasm --prime secq256k1 -o $BUILD_DIR &&
cargo run --bin gen_spartan_inst $BUILD_DIR/membership.r1cs $BUILD_DIR/membership.circuit 4