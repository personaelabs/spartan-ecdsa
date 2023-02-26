use crate::sumcheck::ToCircuitVal;
use commitments::MultiCommitGens;
pub use libspartan::scalar::Scalar;
use libspartan::{
    math::Math,
    transcript::{AppendToTranscript, ProofTranscript, Transcript},
    Instance, NIZKGens, NIZK,
};
pub mod commitments;
pub mod dotprod;
pub mod sumcheck;
use std::cmp::max;

pub mod utils;

pub type Fp = secpq_curves::Fq;
pub type Fq = secpq_curves::Fp;
use libspartan::commitments::Commitments;

pub const DEGREE_BOUND: usize = 3;
pub const N_ROUNDS: usize = 1;

pub fn verify_nizk(
    inst: &Instance,
    num_cons: usize,
    num_vars: usize,
    input: &[libspartan::scalar::Scalar],
    proof: &NIZK,
    gens: &NIZKGens,
) {
    let mut transcript = Transcript::new(b"test_verify");

    transcript.append_protocol_name(b"Spartan NIZK proof");
    transcript.append_message(b"R1CSInstanceDigest", &inst.digest);

    transcript.append_protocol_name(b"R1CS proof");
    input.append_to_transcript(b"input", &mut transcript);

    proof
        .r1cs_sat_proof
        .comm_vars
        .append_to_transcript(b"poly_commitment", &mut transcript);

    let num_rounds_x = if num_cons == 0 {
        0
    } else {
        max(num_cons.log_2(), 1)
    };
    let _num_rounds_y = if num_vars == 0 {
        0
    } else {
        (2 * num_vars).log_2()
    };

    let _tau = transcript.challenge_vector(b"challenge_tau", num_rounds_x);

    let gens_1 = gens.gens_r1cs_sat.gens_sc.gens_1.clone();
    let gens_4 = gens.gens_r1cs_sat.gens_sc.gens_4.clone();

    // ############################
    // # Verify Phase 1 SumCheck
    // ############################

    let sc_proof_phase1 = proof.r1cs_sat_proof.sc_proof_phase1.to_circuit_val();

    let phase1_expected_sum = Scalar::zero()
        .commit(&Scalar::zero(), &gens_1)
        .compress()
        .to_circuit_val();

    assert!(sumcheck::verify(
        &phase1_expected_sum,
        &sc_proof_phase1,
        &gens_1.into(),
        &gens_4.into(),
        &mut transcript,
    ));

    // ############################
    // # Verify Phase 2 SumCheck
    // ############################

    // TBD
}

#[cfg(test)]
mod tests {
    use super::*;
    use libspartan::{InputsAssignment, Instance, NIZKGens, VarsAssignment};

    #[allow(non_snake_case)]
    #[test]
    fn test_verify_nizk() {
        // parameters of the R1CS instance
        let num_cons = 1;
        let num_vars = 0;
        let num_inputs = 3;

        // We will encode the above constraints into three matrices, where
        // the coefficients in the matrix are in the little-endian byte order
        let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new(); // <row, column, value>
        let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
        let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

        // Create a^2 + b + 13
        A.push((0, num_vars + 2, Fq::one().to_bytes())); // 1*a
        B.push((0, num_vars + 2, Fq::one().to_bytes())); // 1*a
        C.push((0, num_vars + 1, Fq::one().to_bytes())); // 1*z
        C.push((0, num_vars, (-Fq::from(13u64)).to_bytes())); // -13*1
        C.push((0, num_vars + 3, (-Fq::one()).to_bytes())); // -1*b

        // Var Assignments (Z_0 = 16 is the only output)
        let vars = vec![Fq::zero().to_bytes(); num_vars];

        // create an InputsAssignment (a = 1, b = 2)
        let mut inputs = vec![Fq::zero().to_bytes(); num_inputs];
        inputs[0] = Fq::from(16u64).to_bytes();
        inputs[1] = Fq::from(1u64).to_bytes();
        inputs[2] = Fq::from(2u64).to_bytes();

        let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
        let assignment_vars = VarsAssignment::new(&vars).unwrap();

        // Check if instance is satisfiable
        let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
        let res = inst.is_sat(&assignment_vars, &assignment_inputs);
        assert!(res.unwrap(), "should be satisfied");

        let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

        let mut prover_transcript = Transcript::new(b"test_verify");

        let proof = NIZK::prove(
            &inst,
            assignment_vars,
            &assignment_inputs,
            &gens,
            &mut prover_transcript,
        );

        // In the phase 1 sum check com_eval uses gens_1 and dot product uses gens_4
        // com_eval uses gens_1, and dot product uses gen_3
        verify_nizk(
            &inst,
            num_cons,
            num_vars,
            &assignment_inputs.assignment,
            &proof,
            &gens,
        );
    }
}
