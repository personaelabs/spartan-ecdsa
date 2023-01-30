# Copy circuit artifacts into the lib build dir
mkdir -p ./build/circuits/ &&
cp ./src/circuits/* ./build/circuits/ &&

# Copy wasm into the lib build dir
cp ./src/wasm/build/*.wasm ./build/wasm/build/

