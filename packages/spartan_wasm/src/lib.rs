pub mod wasm;

#[cfg(not(target_family = "wasm"))]
pub mod circom_reader;
