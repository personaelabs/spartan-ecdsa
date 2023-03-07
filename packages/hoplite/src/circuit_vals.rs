use crate::{Fp, Fq};
use libspartan::{
    dense_mlpoly::{PolyCommitment, PolyEvalProof},
    group::CompressedGroup,
    nizk::{BulletReductionProof, DotProductProof, EqualityProof, KnowledgeProof, ProductProof},
    scalar::Scalar,
    sumcheck::ZKSumcheckInstanceProof,
};
use secpq_curves::group::{prime::PrimeCurveAffine, Curve};
use secpq_curves::{CurveAffine, Secq256k1, Secq256k1Affine};
use std::option::Option;

#[derive(Debug, Clone, Copy)]
pub struct CVSumCheckProof<const N_ROUNDS: usize, const DIMENSION: usize> {
    pub comm_polys: [Option<Secq256k1>; N_ROUNDS],
    pub comm_evals: [Option<Secq256k1>; N_ROUNDS],
    pub proofs: [CVDotProdProof<DIMENSION>; N_ROUNDS],
}

impl<const N_ROUNDS: usize, const DIMENSION: usize> Default
    for CVSumCheckProof<N_ROUNDS, DIMENSION>
{
    fn default() -> Self {
        Self {
            comm_polys: [None; N_ROUNDS],
            comm_evals: [None; N_ROUNDS],
            proofs: [CVDotProdProof::default(); N_ROUNDS],
        }
    }
}

pub struct CVBulletReductionProof<const DIMENSION: usize> {
    pub L_vec: [Option<Secq256k1>; DIMENSION],
    pub R_vec: [Option<Secq256k1>; DIMENSION],
}

impl<const DIMENSION: usize> Default for CVBulletReductionProof<DIMENSION> {
    fn default() -> Self {
        Self {
            L_vec: [None; DIMENSION],
            R_vec: [None; DIMENSION],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CVDotProdProof<const DIMENSION: usize> {
    pub delta: Option<Secq256k1>,
    pub beta: Option<Secq256k1>,
    pub z: [Option<Fq>; DIMENSION],
    pub z_delta: Option<Fq>,
    pub z_beta: Option<Fq>,
}

impl<const DIMENSION: usize> Default for CVDotProdProof<DIMENSION> {
    fn default() -> Self {
        Self {
            delta: None,
            beta: None,
            z: [None; DIMENSION],
            z_delta: None,
            z_beta: None,
        }
    }
}

pub struct CVEqualityProof {
    pub alpha: Option<Secq256k1>,
    pub z: Option<Fq>,
}

impl Default for CVEqualityProof {
    fn default() -> Self {
        Self {
            alpha: None,
            z: None,
        }
    }
}

pub struct CVKnowledgeProof {
    pub alpha: Option<Secq256k1>,
    pub z1: Option<Fq>,
    pub z2: Option<Fq>,
}

impl Default for CVKnowledgeProof {
    fn default() -> Self {
        Self {
            alpha: None,
            z1: None,
            z2: None,
        }
    }
}

pub struct CVProductProof {
    pub alpha: Option<Secq256k1>,
    pub beta: Option<Secq256k1>,
    pub delta: Option<Secq256k1>,
    pub z: [Option<Fq>; 5],
}

impl Default for CVProductProof {
    fn default() -> Self {
        Self {
            alpha: None,
            beta: None,
            delta: None,
            z: [None; 5],
        }
    }
}

pub struct CVDotProductProofLog<const N: usize> {
    pub bullet_reduction_proof: CVBulletReductionProof<N>,
    pub delta: Option<Secq256k1>,
    pub beta: Option<Secq256k1>,
    pub z1: Option<Fq>,
    pub z2: Option<Fq>,
}

impl<const N: usize> Default for CVDotProductProofLog<N> {
    fn default() -> Self {
        Self {
            bullet_reduction_proof: CVBulletReductionProof::default(),
            delta: None,
            beta: None,
            z1: None,
            z2: None,
        }
    }
}

pub struct CVPolyEvalProof<const N: usize> {
    pub proof: CVDotProductProofLog<N>,
}

impl<const N: usize> Default for CVPolyEvalProof<N> {
    fn default() -> Self {
        Self {
            proof: CVDotProductProofLog::default(),
        }
    }
}

pub struct CVPolyCommitment<const N: usize> {
    pub C: [Option<Secq256k1>; N],
}

impl<const N: usize> Default for CVPolyCommitment<N> {
    fn default() -> Self {
        Self { C: [None; N] }
    }
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

impl ToCircuitVal<CVEqualityProof> for EqualityProof {
    fn to_circuit_val(&self) -> CVEqualityProof {
        let alpha = Some(self.alpha.to_circuit_val());
        let z = Some(self.z.to_circuit_val());

        CVEqualityProof { alpha, z }
    }
}

impl ToCircuitVal<CVKnowledgeProof> for KnowledgeProof {
    fn to_circuit_val(&self) -> CVKnowledgeProof {
        let alpha = Some(self.alpha.to_circuit_val());
        let z1 = Some(self.z1.to_circuit_val());
        let z2 = Some(self.z2.to_circuit_val());

        CVKnowledgeProof { alpha, z1, z2 }
    }
}

impl ToCircuitVal<CVProductProof> for ProductProof {
    fn to_circuit_val(&self) -> CVProductProof {
        let alpha = Some(self.alpha.to_circuit_val());
        let beta = Some(self.beta.to_circuit_val());
        let delta = Some(self.delta.to_circuit_val());
        let z: [Option<Fq>; 5] = self
            .z
            .iter()
            .map(|z_i| Some(z_i.to_circuit_val()))
            .collect::<Vec<Option<Fq>>>()
            .try_into()
            .unwrap();

        CVProductProof {
            alpha,
            beta,
            delta,
            z,
        }
    }
}

impl<const N: usize> ToCircuitVal<CVPolyEvalProof<N>> for PolyEvalProof {
    fn to_circuit_val(&self) -> CVPolyEvalProof<N> {
        let dotprod_proof_log = &self.proof;
        let beta = Some(dotprod_proof_log.beta.to_circuit_val());
        let delta = Some(dotprod_proof_log.delta.to_circuit_val());
        let z1 = Some(dotprod_proof_log.z1.to_circuit_val());
        let z2 = Some(dotprod_proof_log.z2.to_circuit_val());

        let cv_bullet_reduction_proof = CVBulletReductionProof {
            L_vec: dotprod_proof_log
                .bullet_reduction_proof
                .L_vec
                .iter()
                .map(|val| Some(val.compress().to_circuit_val()))
                .collect::<Vec<Option<Secq256k1>>>()
                .try_into()
                .unwrap(),
            R_vec: dotprod_proof_log
                .bullet_reduction_proof
                .R_vec
                .iter()
                .map(|val| Some(val.compress().to_circuit_val()))
                .collect::<Vec<Option<Secq256k1>>>()
                .try_into()
                .unwrap(),
        };

        let cv_dotprod_proof_log = CVDotProductProofLog {
            delta,
            beta,
            z1,
            z2,
            bullet_reduction_proof: cv_bullet_reduction_proof,
        };

        CVPolyEvalProof {
            proof: cv_dotprod_proof_log,
        }
    }
}

impl<const N: usize> ToCircuitVal<CVPolyCommitment<N>> for PolyCommitment {
    fn to_circuit_val(&self) -> CVPolyCommitment<N> {
        let C = self
            .C
            .iter()
            .map(|c| Some(c.to_circuit_val()))
            .collect::<Vec<Option<Secq256k1>>>()
            .try_into()
            .unwrap();

        CVPolyCommitment { C }
    }
}

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

impl<const DIMENSION: usize> ToCircuitVal<CVDotProdProof<DIMENSION>> for DotProductProof {
    fn to_circuit_val(&self) -> CVDotProdProof<DIMENSION> {
        CVDotProdProof {
            delta: Some(self.delta.to_circuit_val()),
            beta: Some(self.beta.to_circuit_val()),
            z_beta: Some(self.z_beta.to_circuit_val()),
            z_delta: Some(self.z_delta.to_circuit_val()),
            z: self
                .z
                .iter()
                .map(|z_i| Some(z_i.to_circuit_val()))
                .collect::<Vec<Option<Fq>>>()
                .try_into()
                .unwrap(),
        }
    }
}

impl<const N_ROUNDS: usize, const DIMENSION: usize>
    ToCircuitVal<CVSumCheckProof<N_ROUNDS, DIMENSION>> for ZKSumcheckInstanceProof
{
    fn to_circuit_val(&self) -> CVSumCheckProof<N_ROUNDS, DIMENSION> {
        assert!(self.proofs.len() == N_ROUNDS);

        let mut dotprod_proofs = Vec::with_capacity(N_ROUNDS);
        let mut comm_polys = Vec::with_capacity(N_ROUNDS);
        let mut comm_evals = Vec::with_capacity(N_ROUNDS);
        for i in 0..N_ROUNDS {
            dotprod_proofs.push(self.proofs[i].to_circuit_val());
            comm_polys.push(Some(self.comm_polys[i].to_circuit_val()));
            comm_evals.push(Some(self.comm_evals[i].to_circuit_val()));
        }

        CVSumCheckProof {
            comm_polys: comm_polys.try_into().unwrap(),
            comm_evals: comm_evals.try_into().unwrap(),
            proofs: dotprod_proofs.try_into().unwrap(),
        }
    }
}

impl<const DIMENSION: usize> ToCircuitVal<CVBulletReductionProof<DIMENSION>>
    for BulletReductionProof
{
    fn to_circuit_val(&self) -> CVBulletReductionProof<DIMENSION> {
        let mut L_vec = Vec::with_capacity(DIMENSION);
        let mut R_vec = Vec::with_capacity(DIMENSION);
        for i in 0..DIMENSION {
            L_vec.push(Some(self.L_vec[i].to_circuit_val()));
            R_vec.push(Some(self.R_vec[i].to_circuit_val()));
        }

        CVBulletReductionProof {
            L_vec: L_vec.try_into().unwrap(),
            R_vec: R_vec.try_into().unwrap(),
        }
    }
}
