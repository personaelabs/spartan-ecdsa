use crate::{Fp, Fq};
use libspartan::{
    dense_mlpoly::{PolyCommitment, PolyEvalProof},
    group::CompressedGroup,
    nizk::{BulletReductionProof, DotProductProof, EqualityProof, KnowledgeProof, ProductProof},
    scalar::Scalar,
    sumcheck::ZKSumcheckInstanceProof,
};
use secpq_curves::{
    group::{prime::PrimeCurveAffine, Curve},
    CurveAffine, Secq256k1, Secq256k1Affine,
};
use secq256k1::{
    affine::Group,
    elliptic_curve::{
        subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
        Field, PrimeField,
    },
};

use std::option::Option;

// ############################
// `CV` stands for `Circuit Value`.
// ############################

#[derive(Debug)]
pub struct CVSumCheckProof {
    pub comm_polys: Vec<Option<Secq256k1>>,
    pub comm_evals: Vec<Option<Secq256k1>>,
    pub proofs: Vec<CVDotProdProof>,
}

impl CVSumCheckProof {
    pub fn without_witness(num_rounds: usize, poly_degree: usize) -> Self {
        Self {
            comm_polys: vec![None; num_rounds],
            comm_evals: vec![None; num_rounds],
            // We pass poly_degree + 1 because we're counting the degree 0 term as well.
            proofs: vec![CVDotProdProof::without_witness(poly_degree + 1); num_rounds],
        }
    }
}

pub struct CVBulletReductionProof {
    pub L_vec: Vec<Option<Secq256k1>>,
    pub R_vec: Vec<Option<Secq256k1>>,
}

impl CVBulletReductionProof {
    fn without_witness(vec_len: usize) -> Self {
        assert!(vec_len % 2 == 0, "vec_len must be even");

        Self {
            L_vec: vec![None; vec_len / 2],
            R_vec: vec![None; vec_len / 2],
        }
    }
}

#[derive(Debug, Clone)]
pub struct CVDotProdProof {
    pub delta: Option<Secq256k1>,
    pub beta: Option<Secq256k1>,
    pub z: Vec<Option<Fq>>,
    pub z_delta: Option<Fq>,
    pub z_beta: Option<Fq>,
}

impl CVDotProdProof {
    fn without_witness(vec_len: usize) -> Self {
        Self {
            delta: None,
            beta: None,
            z: vec![None; vec_len],
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

pub struct CVDotProductProofLog {
    pub bullet_reduction_proof: CVBulletReductionProof,
    pub delta: Option<Secq256k1>,
    pub beta: Option<Secq256k1>,
    pub z1: Option<Fq>,
    pub z2: Option<Fq>,
}

impl CVDotProductProofLog {
    fn without_witness(vec_len: usize) -> Self {
        Self {
            bullet_reduction_proof: CVBulletReductionProof::without_witness(vec_len),
            delta: None,
            beta: None,
            z1: None,
            z2: None,
        }
    }
}

pub struct CVPolyEvalProof {
    pub proof: CVDotProductProofLog,
}

impl CVPolyEvalProof {
    pub fn without_witness(vec_len: usize) -> Self {
        Self {
            proof: CVDotProductProofLog::without_witness(vec_len),
        }
    }
}

pub struct CVPolyCommitment {
    pub C: Vec<Option<Secq256k1>>,
}

impl CVPolyCommitment {
    pub fn without_witness(vec_len: usize) -> Self {
        let C = vec![None; vec_len];
        Self { C }
    }
}

// Convert the types defined in the `secq256k1` crate
// to the types defined in the `secpq_curves` crate.
// This conversion is necessary because,
// `libspartan` uses `secq256k1` for curve/field operations
// whereas halo2 uses `secpq_curves`

// In general, we need to do the following two conversions
// `CompressedGroup` -> `Secq256k1`
// `Scalar` -> `Fq`
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

impl ToCircuitVal<CVPolyEvalProof> for PolyEvalProof {
    fn to_circuit_val(&self) -> CVPolyEvalProof {
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

impl ToCircuitVal<CVPolyCommitment> for PolyCommitment {
    fn to_circuit_val(&self) -> CVPolyCommitment {
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

impl ToCircuitVal<CVDotProdProof> for DotProductProof {
    fn to_circuit_val(&self) -> CVDotProdProof {
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

impl ToCircuitVal<CVSumCheckProof> for ZKSumcheckInstanceProof {
    fn to_circuit_val(&self) -> CVSumCheckProof {
        let mut proofs = vec![];
        let mut comm_polys = vec![];
        let mut comm_evals = vec![];
        for i in 0..self.proofs.len() {
            proofs.push(self.proofs[i].to_circuit_val());
            comm_polys.push(Some(self.comm_polys[i].to_circuit_val()));
            comm_evals.push(Some(self.comm_evals[i].to_circuit_val()));
        }

        CVSumCheckProof {
            comm_polys,
            comm_evals,
            proofs,
        }
    }
}

impl ToCircuitVal<CVBulletReductionProof> for BulletReductionProof {
    fn to_circuit_val(&self) -> CVBulletReductionProof {
        let mut L_vec = vec![];
        let mut R_vec = vec![];
        for i in 0..self.L_vec.len() {
            L_vec.push(Some(self.L_vec[i].to_circuit_val()));
            R_vec.push(Some(self.R_vec[i].to_circuit_val()));
        }

        CVBulletReductionProof { L_vec, R_vec }
    }
}
