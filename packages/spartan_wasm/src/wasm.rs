use byteorder::{LittleEndian, ReadBytesExt};
use console_error_panic_hook;
use ff::PrimeField;
use libspartan::{Assignment, Instance, NIZKGens, NIZK};
use merlin::Transcript;
use poseidon::poseidon_k256::{hash, FieldElement};
use secq256k1::affine::Group;
use std::io::{Error, Read};
use wasm_bindgen::prelude::*;

pub type G1 = secq256k1::AffinePoint;
pub type F1 = <G1 as Group>::Scalar;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn prove(circuit: &[u8], vars: &[u8], public_inputs: &[u8]) -> Result<Vec<u8>, JsValue> {
    let witness = load_witness_from_bin_reader::<F1, _>(vars).unwrap();
    let witness_bytes = witness
        .iter()
        .map(|w| w.to_repr().into())
        .collect::<Vec<[u8; 32]>>();

    let assignment = Assignment::new(&witness_bytes).unwrap();
    let circuit: Instance = bincode::deserialize(&circuit).unwrap();

    let num_cons = circuit.inst.get_num_cons();
    let num_vars = circuit.inst.get_num_vars();
    let num_inputs = circuit.inst.get_num_inputs();

    // produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    let mut input = Vec::new();
    for i in 0..num_inputs {
        input.push(public_inputs[(i * 32)..((i + 1) * 32)].try_into().unwrap());
    }
    let input = Assignment::new(&input).unwrap();

    let mut prover_transcript = Transcript::new(b"nizk_example");

    // produce a proof of satisfiability
    let proof = NIZK::prove(
        &circuit,
        assignment.clone(),
        &input,
        &gens,
        &mut prover_transcript,
    );

    Ok(bincode::serialize(&proof).unwrap())
}

#[wasm_bindgen]
pub fn verify(circuit: &[u8], proof: &[u8], public_input: &[u8]) -> Result<bool, JsValue> {
    let circuit: Instance = bincode::deserialize(&circuit).unwrap();
    let proof: NIZK = bincode::deserialize(&proof).unwrap();

    let num_cons = circuit.inst.get_num_cons();
    let num_vars = circuit.inst.get_num_vars();
    let num_inputs = circuit.inst.get_num_inputs();

    // produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    let mut inputs = Vec::new();
    for i in 0..num_inputs {
        inputs.push(public_input[(i * 32)..((i + 1) * 32)].try_into().unwrap());
    }

    let inputs = Assignment::new(&inputs).unwrap();

    let mut verifier_transcript = Transcript::new(b"nizk_example");

    let verified = proof
        .verify(&circuit, &inputs, &mut verifier_transcript, &gens)
        .is_ok();

    Ok(verified)
}

#[wasm_bindgen]
pub fn poseidon(input_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut input = Vec::new();
    for i in 0..(input_bytes.len() / 32) {
        let f: [u8; 32] = input_bytes[(i * 32)..(i + 1) * 32].try_into().unwrap();
        let val = FieldElement::from_bytes(&f).unwrap();
        input.push(FieldElement::from(val));
    }

    let result = hash(input);

    Ok(result.to_bytes().to_vec())
}

// Copied from Nova Scotia
pub fn read_field<R: Read, Fr: PrimeField>(mut reader: R) -> Result<Fr, Error> {
    let mut repr = Fr::zero().to_repr();
    for digit in repr.as_mut().iter_mut() {
        // TODO: may need to reverse order?
        *digit = reader.read_u8()?;
    }
    let fr = Fr::from_repr(repr).unwrap();
    Ok(fr)
}

pub fn load_witness_from_bin_reader<Fr: PrimeField, R: Read>(
    mut reader: R,
) -> Result<Vec<Fr>, Error> {
    let mut wtns_header = [0u8; 4];
    reader.read_exact(&mut wtns_header)?;
    if wtns_header != [119, 116, 110, 115] {
        // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
        panic!("invalid file header");
    }
    let version = reader.read_u32::<LittleEndian>()?;
    // println!("wtns version {}", version);
    if version > 2 {
        panic!("unsupported file version");
    }
    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        panic!("invalid num sections");
    }
    // read the first section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        panic!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != 4 + 32 + 4 {
        panic!("invalid section len")
    }
    let field_size = reader.read_u32::<LittleEndian>()?;
    if field_size != 32 {
        panic!("invalid field byte size");
    }
    let mut prime = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime)?;
    // if prime != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
    //     bail!("invalid curve prime {:?}", prime);
    // }
    let witness_len = reader.read_u32::<LittleEndian>()?;
    // println!("witness len {}", witness_len);
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        panic!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != (witness_len * field_size) as u64 {
        panic!("invalid witness section size {}", sec_size);
    }
    let mut result = Vec::with_capacity(witness_len as usize);
    for _ in 0..witness_len {
        result.push(read_field::<&mut R, Fr>(&mut reader)?);
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{env::current_dir, fs};

    #[test]
    fn check_nizk() {
        let root = current_dir().unwrap();
        let circuit = fs::read(root.join("test_circuit/test_circuit.circuit")).unwrap();
        let vars = fs::read(root.join("test_circuit/witness.wtns")).unwrap();

        let public_inputs = [F1::from(1u64), F1::from(1u64), F1::from(1u64)]
            .iter()
            .map(|w| w.to_repr())
            .flatten()
            .collect::<Vec<u8>>();

        let proof = prove(
            circuit.as_slice(),
            vars.as_slice(),
            public_inputs.as_slice(),
        )
        .unwrap();

        let result = verify(
            circuit.as_slice(),
            proof.as_slice(),
            public_inputs.as_slice(),
        );

        assert!(result.unwrap());
    }

    #[test]
    fn test_poseidon() {
        // Using the same inputs as poseidon.test.ts
        let a = FieldElement::from_str_vartime(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663",
        )
        .unwrap()
        .to_bytes();
        let b = FieldElement::from_str_vartime(
            "115792089237316195423570985008687907853269984665640564039457584007908834671662",
        )
        .unwrap()
        .to_bytes();

        let mut inputs = [0u8; 64];
        inputs[..32].copy_from_slice(&a);
        inputs[32..].copy_from_slice(&b);
        let result = poseidon(&inputs).unwrap();

        assert_eq!(
            result.as_slice(),
            &[
                181, 226, 121, 200, 61, 3, 57, 70, 184, 30, 115, 145, 192, 7, 138, 73, 36, 8, 40,
                132, 190, 141, 35, 89, 108, 149, 235, 51, 129, 165, 64, 103
            ]
        )
    }
}
