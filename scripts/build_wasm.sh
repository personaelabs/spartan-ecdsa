rm -r ./packages/lib/src/wasm/build &&
cd ./packages/spartan_wasm &&
wasm-pack build --target web --out-dir ../lib/src/wasm/build
