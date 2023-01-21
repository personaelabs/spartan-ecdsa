BUILD_DIR=./packages/circuits/build/eff_ecdsa_to_addr
mkdir -p $BUILD_DIR &&
circom ./packages/circuits/instances/eff_ecdsa_to_addr.circom --r1cs --wasm --prime secq256k1 -o $BUILD_DIR &&
cargo run --release --bin gen_spartan_inst $BUILD_DIR/eff_ecdsa_to_addr.r1cs $BUILD_DIR/eff_ecdsa_to_addr.circuit 4
