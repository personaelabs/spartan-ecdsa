use crate::{
    circuit_vals::CVProductProof,
    commitments::{Commitments, MultiCommitGens},
    utils::to_fq,
    Fq,
};
use libspartan::{
    group::CompressedGroup,
    transcript::{AppendToTranscript, ProofTranscript, Transcript},
};
use secpq_curves::Secq256k1;

use crate::circuit_vals::FromCircuitVal;

// https://eprint.iacr.org/2017/1132.pdf
// P.17 Figure 5
pub fn verify(
    proof: &CVProductProof,
    X: Secq256k1,
    Y: Secq256k1,
    Z: Secq256k1,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
) {
    let alpha = proof.alpha.unwrap();
    let beta = proof.beta.unwrap();
    let delta = proof.delta.unwrap();
    let z: [Fq; 5] = proof
        .z
        .iter()
        .map(|z_i| z_i.unwrap())
        .collect::<Vec<Fq>>()
        .try_into()
        .unwrap();

    transcript.append_protocol_name(b"product proof");

    CompressedGroup::from_circuit_val(&X).append_to_transcript(b"X", transcript);
    CompressedGroup::from_circuit_val(&Y).append_to_transcript(b"Y", transcript);
    CompressedGroup::from_circuit_val(&Z).append_to_transcript(b"Z", transcript);

    CompressedGroup::from_circuit_val(&alpha).append_to_transcript(b"alpha", transcript);
    CompressedGroup::from_circuit_val(&beta).append_to_transcript(b"beta", transcript);
    CompressedGroup::from_circuit_val(&delta).append_to_transcript(b"delta", transcript);

    let c = to_fq(&transcript.challenge_scalar(b"c"));

    let z1 = z[0];
    let z2 = z[1];
    let z3 = z[2];
    let z4 = z[3];
    let z5 = z[4];

    // (7)
    let lhs = alpha + X * c;
    let rhs = z1.commit(&z2, gens_n);
    assert!(lhs == rhs, "prod proof verification failed (7)");

    // (8)
    let lhs = beta + Y * c;
    let rhs = z3.commit(&z4, gens_n);
    assert!(lhs == rhs, "prod proof verification failed (8)");

    // (9)
    let lhs = delta + Z * c;
    let gens_x = MultiCommitGens {
        G: vec![X],
        h: gens_n.h,
    };
    let rhs = z3.commit(&z5, &gens_x);
    assert!(lhs == rhs, "prod proof verification failed (9)");
}
