use crate::{
    circuit_vals::{FromCircuitVal, ToCircuitVal},
    Fq,
};
use libspartan::{
    group::CompressedGroup,
    scalar::Scalar,
    transcript::{ProofTranscript, Transcript},
};
use secpq_curves::{
    group::{Curve, Group},
    Secq256k1,
};

pub fn verify(
    upsilon: &Secq256k1, // The upsilon calculated in this func should equal this
    a: &[Fq],
    G: &[Secq256k1],
    upsilon_L: &[Secq256k1],
    upsilon_R: &[Secq256k1],
    transcript: &mut Transcript,
) -> (Secq256k1, Fq, Secq256k1) {
    // #####
    // 1: Compute the verification scalars
    // #####

    // Compute challenges
    let mut challenges = vec![];
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

    let n = upsilon_L.len();
    for i in 0..n {
        upsilon_hat += upsilon_L[i] * challenges_sq[i].to_circuit_val()
            + upsilon_R[i] * challenges_inv_sq[i].to_circuit_val();
    }

    let mut a = &mut a.to_owned()[..];
    let mut G = &mut G.to_owned()[..];

    let mut n = G.len();
    while n != 1 {
        n /= 2;
        let (a_L, a_R) = a.split_at_mut(n);
        let (G_L, G_R) = G.split_at_mut(n);

        for i in 0..n {
            let u = challenges[challenges.len() - n / 2 - 1];
            let u_inv = challenges_inv[challenges.len() - n / 2 - 1];
            a_L[i] = a_L[i] * u_inv.to_circuit_val() + a_R[i] * u.to_circuit_val();

            G_L[i] = G_L[i] * u_inv.to_circuit_val() + G_R[i] * u.to_circuit_val();
        }

        a = a_L;
        G = G_L;
    }

    let a_hat = a[0];
    let g_hat = G[0];

    (upsilon_hat, a_hat, g_hat)
}
