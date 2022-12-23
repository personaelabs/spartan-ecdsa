use bincode;
use serde_json::json;
use spartan_wasm::circuits::utils::load_as_spartan_inst;
use std::env::current_dir;
use std::fs::File;
use std::io::Write;

fn main() {
    let root = current_dir().unwrap();
    let circuit_file = root.join("circuits/build/spartan/poseidon/poseidon.r1cs");
    let spartan_inst = load_as_spartan_inst(circuit_file, 0);
    let sparta_inst_bytes = bincode::serialize(&spartan_inst).unwrap();

    let output_file = "browser_benchmark/public/poseidon_circuit.bin";
    File::create(root.join(output_file))
        .unwrap()
        .write_all(sparta_inst_bytes.as_slice())
        .unwrap();

    println!("Written Spartan circuit to {}", output_file);
}
