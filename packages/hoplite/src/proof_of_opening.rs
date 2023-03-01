use crate::{
    commitments::{Commitments, MultiCommitGens},
    sumcheck::FromCircuitVal,
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
    alpha: &Secq256k1,
    z1: &Fq,
    z2: &Fq,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
) {
    transcript.append_protocol_name(b"knowledge proof");

    CompressedGroup::from_circuit_val(C).append_to_transcript(b"C", transcript);
    CompressedGroup::from_circuit_val(alpha).append_to_transcript(b"alpha", transcript);

    let c = to_fq(&transcript.challenge_scalar(b"c"));

    let lhs = z1.commit(z2, gens_n);
    let rhs = C * c + alpha;
    assert!(lhs == rhs, "proof of opening verification failed");
}
