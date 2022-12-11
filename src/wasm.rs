use console_error_panic_hook;
use libspartan::{Instance, NIZKGens, NIZK};
use merlin::Transcript;
use serde_json;
use wasm_bindgen::prelude::*;
use web_sys;

// A macro to provide `println!(..)`-style syntax for `console.log` logging.
macro_rules! log {
  ( $( $t:tt )* ) => {
      web_sys::console::log_1(&format!( $( $t )* ).into());
  }
}

#[cfg(target_family = "wasm")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn prove() -> String {
    // specify the size of an R1CS instance
    let num_vars = 2usize.pow(14);
    let num_cons = 2usize.pow(14);
    let num_inputs = 10;

    // produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    // ask the library to produce a synthentic R1CS instance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"nizk_example");
    let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
        .verify(&inst, &inputs, &mut verifier_transcript, &gens)
        .is_ok());
    println!("proof verification successful!");

    serde_json::to_string(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify(proof: String) {
    let proof: NIZK = serde_json::from_str(&proof).unwrap();

    // specify the size of an R1CS instance
    let num_vars = 1024;
    let num_cons = 1024;
    let num_inputs = 10;

    // produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    // ask the library to produce a synthentic R1CS instance
    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

    let mut verifier_transcript = Transcript::new(b"nizk_example");
    assert!(proof
        .verify(&inst, &inputs, &mut verifier_transcript, &gens)
        .is_ok());

    println!("proof verification successful!");
}
