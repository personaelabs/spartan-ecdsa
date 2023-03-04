use crate::{
    circuit_vals::{CVBulletReductionProof, CVDotProductProofLog, FromCircuitVal},
    commitments::MultiCommitGens,
    proof_bullet_reduce,
    utils::to_fq,
    Fq,
};
use libspartan::{
    group::CompressedGroup,
    nizk::DotProductProofLog,
    transcript::{AppendToTranscript, ProofTranscript, Transcript},
};
use secpq_curves::Secq256k1;

// https://eprint.iacr.org/2017/1132.pdf
// P.19 proof_log-of-dot-prod
pub fn verify<const DIMENSION: usize>(
    gens_1: &MultiCommitGens,
    gens_n: &MultiCommitGens,
    a: &[Fq],
    Cx: &Secq256k1, // commitment to the evaluation (Cy)
    Cy: &Secq256k1, // commitment to the evaluation (Cy)
    proof: &CVDotProductProofLog<DIMENSION>,
    transcript: &mut Transcript,
) {
    transcript.append_protocol_name(b"dot product proof (log)");
    CompressedGroup::from_circuit_val(Cx).append_to_transcript(b"Cx", transcript);
    CompressedGroup::from_circuit_val(Cy).append_to_transcript(b"Cy", transcript);

    transcript.append_message(b"a", b"begin_append_vector");
    for a_i in a {
        transcript.append_message(b"a", &a_i.to_bytes());
    }
    transcript.append_message(b"a", b"end_append_vector");

    // Upsilon
    let Gamma = Cx + Cy;

    let a_L = &a[0..DIMENSION].try_into().unwrap();
    let a_R = &a[DIMENSION..].try_into().unwrap();

    let G_L = &gens_n.G[0..DIMENSION].try_into().unwrap();
    let G_R = &gens_n.G[DIMENSION..].try_into().unwrap();

    let upsilon_L = &proof.bullet_reduction_proof.L_vec.map(|L_i| L_i.unwrap());
    let upsilon_R = &proof.bullet_reduction_proof.R_vec.map(|L_i| L_i.unwrap());

    let (Gamma_hat, a_hat, g_hat) =
        proof_bullet_reduce::verify(&Gamma, a_L, a_R, upsilon_L, upsilon_R, G_L, G_R, transcript);

    CompressedGroup::from_circuit_val(&proof.delta.unwrap())
        .append_to_transcript(b"delta", transcript);
    CompressedGroup::from_circuit_val(&proof.beta.unwrap())
        .append_to_transcript(b"beta", transcript);

    let c = to_fq(&transcript.challenge_scalar(b"c"));

    let lhs = (Gamma_hat * c + proof.beta.unwrap()) * a_hat + proof.delta.unwrap();
    let rhs = (g_hat + gens_1.G[0] * a_hat) * proof.z1.unwrap() + gens_1.h * proof.z2.unwrap();

    assert!(rhs == lhs, "Proof (log) of dot prod verification failed");
}
