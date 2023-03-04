use crate::{
    circuit_vals::{CVKnowledgeProof, FromCircuitVal},
    commitments::{Commitments, MultiCommitGens},
    utils::to_fq,
    Fq,
};
use libspartan::{
    group::CompressedGroup,
    transcript::{AppendToTranscript, ProofTranscript, Transcript},
};
use secpq_curves::Secq256k1;

// https://eprint.iacr.org/2017/1132.pdf
// P.17 Knowledge of opening
pub fn verify(
    C: &Secq256k1,
    proof: &CVKnowledgeProof,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
) {
    transcript.append_protocol_name(b"knowledge proof");

    let alpha = proof.alpha.unwrap();
    CompressedGroup::from_circuit_val(C).append_to_transcript(b"C", transcript);
    CompressedGroup::from_circuit_val(&alpha).append_to_transcript(b"alpha", transcript);

    let c = to_fq(&transcript.challenge_scalar(b"c"));

    let lhs = proof.z1.unwrap().commit(&proof.z2.unwrap(), gens_n);
    let rhs = C * c + alpha;
    assert!(lhs == rhs, "proof of opening verification failed");
}
