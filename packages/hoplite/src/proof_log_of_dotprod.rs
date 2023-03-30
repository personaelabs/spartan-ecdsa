use crate::{
    circuit_vals::{CVBulletReductionProof, CVDotProductProofLog, FromCircuitVal, ToCircuitVal},
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
pub fn verify(
    gens_1: &MultiCommitGens,
    gens_n: &MultiCommitGens,
    a: &[Fq],
    Cx: &Secq256k1, // commitment to the evaluation (Cy)
    Cy: &Secq256k1, // commitment to the evaluation (Cy)
    proof: &CVDotProductProofLog,
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

    // sample a random base and scale the generator used for
    // the output of the inner product
    let r = to_fq(&transcript.challenge_scalar(b"r"));
    let gens_1_scaled = gens_1.scale(&r);

    // Upsilon
    let Gamma = Cx + Cy * r;

    let nn = a.len() / 2;
    let a_L = &a[0..nn];
    let a_R = &a[nn..];

    let G_L = &gens_n.G[0..nn];
    let G_R = &gens_n.G[nn..];

    let L_vec = proof
        .bullet_reduction_proof
        .L_vec
        .iter()
        .map(|L_i| L_i.unwrap())
        .collect::<Vec<Secq256k1>>();

    let upsilon_L = L_vec.as_slice();

    let R_vec = &proof
        .bullet_reduction_proof
        .R_vec
        .iter()
        .map(|L_i| L_i.unwrap())
        .collect::<Vec<Secq256k1>>();

    let upsilon_R = R_vec.as_slice();

    let (Gamma_hat, a_hat, g_hat) =
        proof_bullet_reduce::verify(&Gamma, a_L, a_R, upsilon_L, upsilon_R, G_L, G_R, transcript);

    CompressedGroup::from_circuit_val(&proof.delta.unwrap())
        .append_to_transcript(b"delta", transcript);
    CompressedGroup::from_circuit_val(&proof.beta.unwrap())
        .append_to_transcript(b"beta", transcript);

    let c = to_fq(&transcript.challenge_scalar(b"c"));

    let lhs = (Gamma_hat * c + proof.beta.unwrap()) * a_hat + proof.delta.unwrap();
    let rhs = (g_hat + gens_1_scaled.G[0] * a_hat) * proof.z1.unwrap()
        + gens_1_scaled.h * proof.z2.unwrap();

    assert!(rhs == lhs, "Proof (log) of dot prod verification failed");
}
