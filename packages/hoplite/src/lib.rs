#![allow(non_snake_case)]
use crate::circuit_vals::{CVSumCheckProof, ToCircuitVal};
use commitments::{Commitments, MultiCommitGens};
pub use libspartan::scalar::Scalar;
use libspartan::{
    group::DecompressEncodedPoint,
    transcript::{AppendToTranscript, ProofTranscript, Transcript},
    Instance, NIZKGens, NIZK,
};
use secpq_curves::{group::Curve, Secq256k1};
pub mod circuit_vals;
pub mod commitments;
pub mod dotprod;
pub mod poly_evaluation_proof;
pub mod proof_bullet_reduce;
pub mod proof_log_of_dotprod;
pub mod proof_of_eq;
pub mod proof_of_opening;
pub mod proof_of_prod;
pub mod sumcheck;

pub mod utils;
use utils::eval_ml_poly;

pub type Fp = secpq_curves::Fq;
pub type Fq = secpq_curves::Fp;

pub fn eq_eval(t: &[Fq], x: &[Fq]) -> Fq {
    let mut result = Fq::one();
    for i in 0..t.len() {
        result *= t[i] * x[i] + (Fq::one() - t[i]) * (Fq::one() - x[i]);
    }
    result
}

/**
 * Verify a SpartanNIZK proof
 */
pub fn verify_nizk(
    inst: &Instance,
    input: &[libspartan::scalar::Scalar],
    proof: &NIZK,
    gens: &NIZKGens,
) {
    // Append the domain parameters to the transcript
    let mut transcript = Transcript::new(b"test_verify");

    transcript.append_protocol_name(b"Spartan NIZK proof");
    transcript.append_message(b"R1CSInstanceDigest", &inst.digest);

    transcript.append_protocol_name(b"R1CS proof");
    input.append_to_transcript(b"input", &mut transcript);

    proof
        .r1cs_sat_proof
        .comm_vars
        .append_to_transcript(b"poly_commitment", &mut transcript);

    let tau: Vec<Fq> = transcript
        .challenge_vector(
            b"challenge_tau",
            proof.r1cs_sat_proof.sc_proof_phase1.proofs.len(),
        )
        .iter()
        .map(|tau_i| tau_i.to_circuit_val())
        .collect();

    // Convert the generators to circuit value representations
    let gens_1: MultiCommitGens = gens.gens_r1cs_sat.gens_sc.gens_1.clone().into();
    let gens_3: MultiCommitGens = gens.gens_r1cs_sat.gens_sc.gens_3.clone().into();
    let gens_4: MultiCommitGens = gens.gens_r1cs_sat.gens_sc.gens_4.clone().into();
    let gens_pc_gens = &gens.gens_r1cs_sat.gens_pc.gens;
    let gens_pc_1: MultiCommitGens = gens_pc_gens.gens_1.clone().into();
    let gens_pc_n: MultiCommitGens = gens_pc_gens.gens_n.clone().into();

    let sc_proof_phase1: CVSumCheckProof = proof.r1cs_sat_proof.sc_proof_phase1.to_circuit_val();

    // The expected sum of the phase 1 sum-check is zero
    let phase1_expected_sum = Fq::zero().commit(&Fq::zero(), &gens_1);

    // comm_claim_post_phase1: Commitment to the claimed evaluation of the final round polynomial over rx
    let (comm_claim_post_phase1, rx) = sumcheck::verify(
        3,
        &phase1_expected_sum,
        &sc_proof_phase1,
        &gens_1,
        &gens_4,
        &mut transcript,
    );

    // Verify Az * Bz = Cz
    let (comm_Az_claim, comm_Bz_claim, comm_Cz_claim, comm_prod_Az_Bz_claims) =
        &proof.r1cs_sat_proof.claims_phase2;

    // First, we verify that the prover knows the opening to comm_Cz_claim

    let (pok_Cz_claim, proof_prod) = &proof.r1cs_sat_proof.pok_claims_phase2;

    proof_of_opening::verify(
        &comm_Cz_claim.to_circuit_val(),
        &pok_Cz_claim.to_circuit_val(),
        &gens_1,
        &mut transcript,
    );

    // Second, we verify Az * Bz = "Commitment to the claimed prod"

    proof_of_prod::verify(
        &proof_prod.to_circuit_val(),
        comm_Az_claim.to_circuit_val(),
        comm_Bz_claim.to_circuit_val(),
        comm_prod_Az_Bz_claims.to_circuit_val(),
        &gens_1,
        &mut transcript,
    );

    comm_Az_claim.append_to_transcript(b"comm_Az_claim", &mut transcript);
    comm_Bz_claim.append_to_transcript(b"comm_Bz_claim", &mut transcript);
    comm_Cz_claim.append_to_transcript(b"comm_Cz_claim", &mut transcript);
    comm_prod_Az_Bz_claims.append_to_transcript(b"comm_prod_Az_Bz_claims", &mut transcript);

    // Verify the final query to the polynomial

    // Now, we verify that
    // (Az * Bz - Cz) * eq(tau, rx) = Commitment to the claimed evaluation of the final round polynomial over rx
    // In the first sum-check, we verify that

    // (A(x, y) * Z(y) + B(x, y) * Z(y) - C(x, y) * Z(y)) * eq(tau, rx) = 0
    // So the final round polynomial's evaluation over rx should equal to the
    // evaluation of the above poly over rx

    let eq_tau_rx = eq_eval(&tau, &rx);
    let expected_claim_post_phase1 = (comm_prod_Az_Bz_claims.decompress().unwrap()
        + -comm_Cz_claim.decompress().unwrap())
    .compress()
    .to_circuit_val()
    .to_affine()
        * eq_tau_rx;

    // Check the equality between the evaluation of the final round poly of the sum-check
    // and the evaluation of the F(x) poly over rx
    let proof_eq_sc_phase1 = &proof.r1cs_sat_proof.proof_eq_sc_phase1;
    proof_of_eq::verify(
        &expected_claim_post_phase1,
        &comm_claim_post_phase1,
        &proof_eq_sc_phase1.to_circuit_val(),
        &gens_1,
        &mut transcript,
    );

    // Verify that the commitments to Az, Bz and Cz are correct

    let r_A = transcript.challenge_scalar(b"challenege_Az");
    let r_B = transcript.challenge_scalar(b"challenege_Bz");
    let r_C = transcript.challenge_scalar(b"challenege_Cz");

    // M(r_y) = r_A * comm_Az_claim + r_B * comm_Bz_claim + r_C * comm_Cz_claim;
    let comm_claim_phase2 = r_A * comm_Az_claim.decompress().unwrap()
        + r_B * comm_Bz_claim.decompress().unwrap()
        + r_C * comm_Cz_claim.decompress().unwrap();

    // Verify the sum-check over M(x)

    let sc_proof_phase2: CVSumCheckProof = proof.r1cs_sat_proof.sc_proof_phase2.to_circuit_val();
    // comm_claim_post_phase2: Claimed evaluation of the final round polynomial over ry
    let (comm_claim_post_phase2, ry) = sumcheck::verify(
        2,
        &comm_claim_phase2.compress().to_circuit_val(),
        &sc_proof_phase2,
        &gens_1,
        &gens_3,
        &mut transcript,
    );

    // Verify that the final round polynomial's evaluation over ry is equal to the
    // evaluation of M(x) over ry.

    // In order to do so, we need to get the evaluation of Z(X) over ry.
    // We use proof_log of dot prod to verify that.

    // comm_vars: Commitment to the evaluations of Z(X) over the boolean hypercube
    let comm_vars = proof
        .r1cs_sat_proof
        .comm_vars
        .C
        .iter()
        .map(|c_i| c_i.to_circuit_val())
        .collect::<Vec<Secq256k1>>();

    let poly_eval_proof = &proof.r1cs_sat_proof.proof_eval_vars_at_ry;
    let comm_vars_at_ry = proof.r1cs_sat_proof.comm_vars_at_ry.to_circuit_val();

    poly_evaluation_proof::verify(
        &gens_pc_1,
        &gens_pc_n,
        &ry[1..],
        &comm_vars_at_ry,
        &comm_vars,
        &poly_eval_proof.to_circuit_val(),
        &mut transcript,
    );

    // Interpolate the input as a multilinear polynomial and evaluate at ry[1..]
    let mut input_with_one: Vec<Fq> = vec![Fq::one()];

    input_with_one.extend_from_slice(
        &input
            .iter()
            .map(|x| x.to_circuit_val())
            .collect::<Vec<Fq>>(),
    );

    let poly_input_eval = eval_ml_poly(&input_with_one, &ry[1..]);
    let comm_poly_input_eval = poly_input_eval.commit(&Fq::zero(), &gens_pc_1);

    // compute commitment to eval_Z_at_ry = (Scalar::one() - ry[0]) * self.eval_vars_at_ry + ry[0] * poly_input_eval
    let comm_eval_Z_at_ry = comm_vars_at_ry * (Fq::one() - ry[0]) + comm_poly_input_eval * ry[0];

    let (claimed_rx, claimed_ry) = &proof.r;
    let inst_evals = inst.inst.evaluate(&claimed_rx, &claimed_ry);

    let (eval_A_r, eval_B_r, eval_C_r) = inst_evals;

    // Z(r_y) * (r_A * A(r_y) + r_B * B(r_y) + r_C * C(r_y))
    let expected_claim_post_phase2 = comm_eval_Z_at_ry
        * (r_A.to_circuit_val() * eval_A_r.to_circuit_val()
            + r_B.to_circuit_val() * eval_B_r.to_circuit_val()
            + r_C.to_circuit_val() * eval_C_r.to_circuit_val());

    // Verify that the commitment to the evaluation of the final round polynomial
    // is correct
    proof_of_eq::verify(
        &expected_claim_post_phase2,
        &comm_claim_post_phase2,
        &proof.r1cs_sat_proof.proof_eq_sc_phase2.to_circuit_val(),
        &gens_1,
        &mut transcript,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use libspartan::{InputsAssignment, Instance, NIZKGens, VarsAssignment};

    #[test]
    fn test_verify_nizk() {
        // Tiny circuit

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

        let mut verifier_transcript = Transcript::new(b"test_verify");

        // Just running the verification of the original implementation as a reference
        let _result = proof.verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens);

        // In the phase 1 sum check com_eval uses gens_1 and dot product uses gens_4
        // com_eval uses gens_1, and dot product uses gen_3
        verify_nizk(&inst, &assignment_inputs.assignment, &proof, &gens);
    }
}
