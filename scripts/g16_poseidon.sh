BUILD_DIR=./circuits/build/g16/poseidon
EXPORT_DIR=./browser_benchmark/public
PTAU_FILE=./circuits/pot12_final.ptau

mkdir -p $BUILD_DIR
circom ./circuits/poseidon/poseidon.circom --r1cs --wasm -o $BUILD_DIR

cp $BUILD_DIR/poseidon_js/poseidon.wasm $EXPORT_DIR/g16_poseidon.wasm


yarn snarkjs groth16 setup $BUILD_DIR/poseidon.r1cs $PTAU_FILE $BUILD_DIR/poseidon_0.zkey
yarn snarkjs zkey contribute $BUILD_DIR/poseidon_0.zkey $EXPORT_DIR/g16_poseidon.zkey --name="1st Contributor Name" -v -e="Entropy"
