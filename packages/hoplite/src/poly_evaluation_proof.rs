use crate::circuit_vals::CVPolyEvalProof;
use crate::{commitments::MultiCommitGens, proof_log_of_dotprod, Fq};
use libspartan::math::Math;
use libspartan::transcript::{ProofTranscript, Transcript};
use secpq_curves::{group::Group, Secq256k1};

fn evals(r: &[Fq]) -> Vec<Fq> {
    let ell = r.len();
    let mut evals: Vec<Fq> = vec![Fq::one(); ell.pow2()];
    let mut size = 1;
    for j in 0..ell {
        // in each iteration, we double the size of chis
        size *= 2;
        for i in (0..size).rev().step_by(2) {
            // copy each element from the prior iteration twice
            let scalar = evals[i / 2];
            evals[i] = scalar * r[j];
            evals[i - 1] = scalar - evals[i];
        }
    }

    evals
}

pub fn verify<const N: usize, const DIMENSION: usize>(
    gens_1: &MultiCommitGens,
    gens_n: &MultiCommitGens,
    r: &[Fq; N],                // point at which the polynomial is evaluated
    C_Zr: &Secq256k1,           // commitment to \widetilde{Z}(r)
    comm_poly: &[Secq256k1; N], // commitment to the evaluations of the polynomial over the boolean hypercube
    proof: &CVPolyEvalProof<DIMENSION>,
    transcript: &mut Transcript,
) {
    transcript.append_protocol_name(b"polynomial evaluation proof");
    // Evaluate the eq poly over the boolean hypercube bounded to r
    let r_left = &r[0..N / 2];
    let r_right = &r[N / 2..];

    let L = evals(r_left);
    let R = evals(r_right);

    // L * r_left;
    let mut C_LZ = Secq256k1::identity();

    for i in 0..comm_poly.len() {
        C_LZ += comm_poly[i] * L[i];
    }

    proof_log_of_dotprod::verify(gens_1, gens_n, &R, &C_LZ, C_Zr, &proof.proof, transcript);
}
