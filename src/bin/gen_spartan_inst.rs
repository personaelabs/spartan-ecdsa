use serde_json::json;
use spartan_wasm::circuits::utils::load_as_spartan_inst;
use std::env::current_dir;
use std::fs::File;
use std::io::Write;

fn main() {
    let root = current_dir().unwrap();
    let circuit_file = root.join("circuits/build/poseidon/poseidon.r1cs");
    let spartan_inst = load_as_spartan_inst(circuit_file, 0);
    let spartan_inst_json = json!(spartan_inst);

    let output_file = "browser_benchmark/public/poseidon_circuit.json";
    File::create(root.join(output_file))
        .unwrap()
        .write_all(spartan_inst_json.to_string().as_bytes())
        .unwrap();

    println!("Written Spartan circuit to {}", output_file);
}
