use crate::{
    circuit_vals::{FromCircuitVal, ToCircuitVal},
    Fq,
};
use libspartan::{
    group::CompressedGroup,
    scalar::Scalar,
    transcript::{ProofTranscript, Transcript},
};
use secpq_curves::{group::Group, Secq256k1};

pub fn verify<const N: usize>(
    upsilon: &Secq256k1, // The upsilon calculated in this func should equal this
    a_L: &[Fq; N],
    a_R: &[Fq; N],
    upsilon_L: &[Secq256k1; N],
    upsilon_R: &[Secq256k1; N],
    G_L: &[Secq256k1; N],
    G_R: &[Secq256k1; N],
    transcript: &mut Transcript,
) -> (Secq256k1, Fq, Secq256k1) {
    // #####
    // 1: Compute the verification scalars
    // #####

    // Compute challenges
    let mut challenges = Vec::with_capacity(N);
    for (L, R) in upsilon_L.iter().zip(upsilon_R.iter()) {
        transcript.append_point(b"L", &CompressedGroup::from_circuit_val(L));
        transcript.append_point(b"R", &CompressedGroup::from_circuit_val(R));
        //        CompressedGroup::from_circuit_val(R).append_to_transcript(b"R", transcript);
        challenges.push(transcript.challenge_scalar(b"u"));
    }

    let mut challenges_inv = challenges.clone();

    // 2. Compute the invert of the challenges
    Scalar::batch_invert(&mut challenges_inv);

    // 3. Compute the square of the challenges
    let challenges_sq = challenges
        .iter()
        .map(|c| c.square())
        .collect::<Vec<Scalar>>();
    let challenges_inv_sq = challenges_inv
        .iter()
        .map(|c| c.square())
        .collect::<Vec<Scalar>>();

    let mut upsilon_hat = Secq256k1::identity();
    upsilon_hat += upsilon;

    for i in 0..N {
        upsilon_hat += upsilon_L[i] * challenges_sq[i].to_circuit_val()
            + upsilon_R[i] * challenges_inv_sq[i].to_circuit_val();
    }

    let mut a_hat = Fq::zero();
    for i in 0..N {
        a_hat +=
            a_L[i] * challenges_inv[i].to_circuit_val() + a_R[i] * challenges[i].to_circuit_val();
    }

    let mut g_hat = Secq256k1::identity();
    for i in 0..N {
        g_hat +=
            G_L[i] * challenges_inv[i].to_circuit_val() + G_R[i] * challenges[i].to_circuit_val();
    }

    (upsilon_hat, a_hat, g_hat)
}
