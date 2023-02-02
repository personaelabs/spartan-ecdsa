rm -rf ./packages/spartan_wasm/build &&
cd ./packages/spartan_wasm &&
wasm-pack build --target web --out-dir ../spartan_wasm/build
