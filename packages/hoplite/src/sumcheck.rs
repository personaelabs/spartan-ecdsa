use crate::{dotprod, dotprod::ZKDotProdProof, utils::to_fq, Fp, Fq, MultiCommitGens};
use libspartan::{
    group::CompressedGroup,
    nizk::{BulletReductionProof, DotProductProof},
    scalar::Scalar,
    sumcheck::ZKSumcheckInstanceProof,
    transcript::{AppendToTranscript, ProofTranscript, Transcript},
};
use secpq_curves::group::{prime::PrimeCurveAffine, Curve};
use secpq_curves::{CurveAffine, Secq256k1, Secq256k1Affine};

#[derive(Debug, Clone, Copy)]
pub struct ZKSumCheckProof<const N_ROUNDS: usize, const DIMENSION: usize> {
    pub comm_polys: [Secq256k1; N_ROUNDS],
    pub comm_evals: [Secq256k1; N_ROUNDS],
    pub proofs: [ZKDotProdProof<DIMENSION>; N_ROUNDS],
}

pub struct ZKBulletReductionProof<const DIMENSION: usize> {
    pub L_vec: [Secq256k1; DIMENSION],
    pub R_vec: [Secq256k1; DIMENSION],
}

// We define our own trait rather than using the `From` trait because
// we need to "convert to" some types that are defined outside of this crate.
pub trait ToCircuitVal<V> {
    fn to_circuit_val(&self) -> V;
}

pub trait FromCircuitVal<V> {
    fn from_circuit_val(v: &V) -> Self;
}

impl FromCircuitVal<Secq256k1> for CompressedGroup {
    fn from_circuit_val(point: &Secq256k1) -> CompressedGroup {
        if point.is_identity().into() {
            return CompressedGroup::identity();
        }

        let coords = point.to_affine().coordinates().unwrap();
        let mut x = coords.x().to_bytes();
        let mut y = coords.y().to_bytes();

        x.reverse();
        y.reverse();

        let result = CompressedGroup::from_affine_coordinates(&x.into(), &y.into(), true);

        result
    }
}

impl ToCircuitVal<Fq> for Scalar {
    fn to_circuit_val(&self) -> Fq {
        let bytes = self.to_bytes();
        Fq::from_bytes(&bytes).unwrap()
    }
}
use secq256k1::elliptic_curve::{
    subtle::{Choice, ConditionallySelectable},
    Field,
};
use secq256k1::{
    affine::Group,
    elliptic_curve::{subtle::ConstantTimeEq, PrimeField},
};

impl ToCircuitVal<Secq256k1> for CompressedGroup {
    fn to_circuit_val(&self) -> Secq256k1 {
        if self.is_identity() {
            return Secq256k1::identity();
        }

        let mut x_bytes: [u8; 32] = (*self.x().unwrap()).try_into().unwrap();
        // x_bytes is in big-endian!
        x_bytes.reverse();

        let x = Fp::from_bytes(&x_bytes).unwrap();

        let coords = self.coordinates();
        let y_odd: Choice = match coords.tag() {
            secq256k1::elliptic_curve::sec1::Tag::CompressedOddY => Choice::from(1),
            secq256k1::elliptic_curve::sec1::Tag::CompressedEvenY => Choice::from(0),
            _ => Choice::from(0),
        };

        let x3 = x.square() * x;
        let b = Fp::from_raw([7, 0, 0, 0]);
        let y = (x3 + b).sqrt();

        let res = y
            .map(|y| {
                let y = Fp::conditional_select(&-y, &y, y.is_odd().ct_eq(&y_odd));
                let p = Secq256k1Affine::from_xy(x, y).unwrap();
                p.to_curve()
            })
            .unwrap();

        res
    }
}

impl<const DIMENSION: usize> ToCircuitVal<ZKDotProdProof<DIMENSION>> for DotProductProof {
    fn to_circuit_val(&self) -> ZKDotProdProof<DIMENSION> {
        ZKDotProdProof {
            delta: self.delta.to_circuit_val(),
            beta: self.beta.to_circuit_val(),
            z_beta: self.z_beta.to_circuit_val(),
            z_delta: self.z_delta.to_circuit_val(),
            z: self
                .z
                .iter()
                .map(|z_i| z_i.to_circuit_val())
                .collect::<Vec<Fq>>()
                .try_into()
                .unwrap(),
        }
    }
}

impl<const N_ROUNDS: usize, const DIMENSION: usize>
    ToCircuitVal<ZKSumCheckProof<N_ROUNDS, DIMENSION>> for ZKSumcheckInstanceProof
{
    fn to_circuit_val(&self) -> ZKSumCheckProof<N_ROUNDS, DIMENSION> {
        assert!(self.proofs.len() == N_ROUNDS);

        let mut dotprod_proofs = Vec::with_capacity(N_ROUNDS);
        let mut comm_polys = Vec::with_capacity(N_ROUNDS);
        let mut comm_evals = Vec::with_capacity(N_ROUNDS);
        for i in 0..N_ROUNDS {
            dotprod_proofs.push(self.proofs[i].to_circuit_val());
            comm_polys.push(self.comm_polys[i].to_circuit_val());
            comm_evals.push(self.comm_evals[i].to_circuit_val());
        }

        ZKSumCheckProof {
            comm_polys: comm_polys.try_into().unwrap(),
            comm_evals: comm_evals.try_into().unwrap(),
            proofs: dotprod_proofs.try_into().unwrap(),
        }
    }
}

impl<const DIMENSION: usize> ToCircuitVal<ZKBulletReductionProof<DIMENSION>>
    for BulletReductionProof
{
    fn to_circuit_val(&self) -> ZKBulletReductionProof<DIMENSION> {
        let mut L_vec = Vec::with_capacity(DIMENSION);
        let mut R_vec = Vec::with_capacity(DIMENSION);
        for i in 0..DIMENSION {
            L_vec.push(self.L_vec[i].to_circuit_val());
            R_vec.push(self.R_vec[i].to_circuit_val());
        }

        ZKBulletReductionProof {
            L_vec: L_vec.try_into().unwrap(),
            R_vec: R_vec.try_into().unwrap(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoundProof<const DIMENSION: usize> {
    pub dotprod_proof: ZKDotProdProof<DIMENSION>,
    pub com_eval: Secq256k1,
}

// This function should be able to verify proofs generated by the above `prove` function
// and also the proofs generated by the original Spartan implementation
#[allow(dead_code)]
pub fn verify<const N_ROUNDS: usize, const DIMENSION: usize>(
    target_com: &Secq256k1,
    proof: &ZKSumCheckProof<N_ROUNDS, DIMENSION>,
    gens_1: &MultiCommitGens,
    gens_n: &MultiCommitGens,
    transcript: &mut Transcript,
) -> (Secq256k1, Vec<Fq>) {
    let mut r = vec![];
    for (i, round_dotprod_proof) in proof.proofs.iter().enumerate() {
        let com_poly = &proof.comm_polys[i];
        let com_poly_encoded = CompressedGroup::from_circuit_val(com_poly);
        com_poly_encoded.append_to_transcript(b"comm_poly", transcript);

        let com_eval = &proof.comm_evals[i];

        let r_i = to_fq(&transcript.challenge_scalar(b"challenge_nextround"));
        r.push(r_i);

        // The sum over (0, 1) is expected to be equal to the challenge evaluation of the prev round
        let com_round_sum = if i == 0 {
            target_com
        } else {
            &proof.comm_evals[i - 1]
        };

        let com_round_sum_encoded = CompressedGroup::from_circuit_val(com_round_sum);
        com_round_sum_encoded.append_to_transcript(b"comm_claim_per_round", transcript);

        CompressedGroup::from_circuit_val(&com_eval.clone())
            .append_to_transcript(b"comm_eval", transcript);

        let w_scalar = transcript.challenge_vector(b"combine_two_claims_to_one", 2);

        let w = w_scalar.iter().map(|x| to_fq(x)).collect::<Vec<Fq>>();

        let a = {
            // the vector to use to decommit for sum-check test
            let a_sc = {
                let mut a = vec![Fq::one(); DIMENSION];
                a[0] += Fq::one();
                a
            };

            // the vector to use to decommit for evaluation
            let a_eval = {
                let mut a = vec![Fq::one(); DIMENSION];
                for j in 1..a.len() {
                    a[j] = a[j - 1] * r_i;
                }
                a
            };

            // take weighted sum of the two vectors using w
            assert_eq!(a_sc.len(), a_eval.len());
            (0..a_sc.len())
                .map(|i| w[0] * a_sc[i] + w[1] * a_eval[i])
                .collect::<Vec<Fq>>()
        };

        let tau = com_round_sum * w[0] + com_eval * w[1];

        // Check that the dot product proofs are valid
        dotprod::verify(
            &tau,
            &a,
            &round_dotprod_proof,
            com_poly,
            &gens_1,
            &gens_n,
            transcript,
        );
    }

    (proof.comm_evals[proof.comm_evals.len() - 1], r)
}
