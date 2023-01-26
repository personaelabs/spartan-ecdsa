BUILD_DIR=./packages/circuits/build/membership
mkdir -p $BUILD_DIR &&
circom ./packages/circuits/instances/membership.circom --r1cs --wasm --prime secq256k1 -o $BUILD_DIR &&

# Copy the circuit into the lib dir
LIB_CIRCUITS_DIR=./packages/lib/src/circuits
mkdir -p $LIB_CIRCUITS_DIR &&
cp $BUILD_DIR/*_js/*.wasm $LIB_CIRCUITS_DIR &&
cp $BUILD_DIR/*.circuit $LIB_CIRCUITS_DIR &&

cargo run --release --bin gen_spartan_inst $BUILD_DIR/membership.r1cs $BUILD_DIR/membership.circuit 4