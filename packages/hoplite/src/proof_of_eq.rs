use crate::{
    circuit_vals::{CVEqualityProof, FromCircuitVal},
    commitments::MultiCommitGens,
    utils::to_fq,
    Fq,
};
use libspartan::{
    group::CompressedGroup,
    transcript::{AppendToTranscript, ProofTranscript, Transcript},
};
use secpq_curves::Secq256k1;

// https://eprint.iacr.org/2017/1132.pdf
// P.17 proof-of-equality
pub fn verify(
    C1: &Secq256k1,
    C2: &Secq256k1,
    proof: &CVEqualityProof,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
) {
    transcript.append_protocol_name(b"equality proof");
    CompressedGroup::from_circuit_val(C1).append_to_transcript(b"C1", transcript);
    CompressedGroup::from_circuit_val(C2).append_to_transcript(b"C2", transcript);
    CompressedGroup::from_circuit_val(&proof.alpha.unwrap())
        .append_to_transcript(b"alpha", transcript);

    let lhs = gens_n.h * proof.z.unwrap();

    let c = to_fq(&transcript.challenge_scalar(b"c"));
    let rhs = (C1 - C2) * c + proof.alpha.unwrap();

    assert!(rhs == lhs, "Proof of equality verification failed");
}
