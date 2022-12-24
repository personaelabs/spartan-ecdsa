BUILD_DIR=./circuits/build/g16/poseidon
CIRCUIT_NAME="poseidon"$1
PTAU_FILE=./circuits/pot18_final.ptau

mkdir -p $BUILD_DIR
circom ./circuits/poseidon/$CIRCUIT_NAME.circom --r1cs --wasm -o $BUILD_DIR

yarn snarkjs groth16 setup $BUILD_DIR/$CIRCUIT_NAME.r1cs $PTAU_FILE $BUILD_DIR/$CIRCUIT_NAME"_0.zkey"
yarn snarkjs zkey contribute $BUILD_DIR/$CIRCUIT_NAME"_0.zkey" $BUILD_DIR/g16_$CIRCUIT_NAME.zkey --name="1st Contributor Name" -v -e="Entropy"
