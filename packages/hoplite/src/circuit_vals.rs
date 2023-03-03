use crate::{dotprod::ZKDotProdProof, Fp, Fq};
use libspartan::{
    group::CompressedGroup,
    nizk::{BulletReductionProof, DotProductProof},
    scalar::Scalar,
    sumcheck::ZKSumcheckInstanceProof,
};
use secpq_curves::group::{prime::PrimeCurveAffine, Curve};
use secpq_curves::{CurveAffine, Secq256k1, Secq256k1Affine};

#[derive(Debug, Clone, Copy)]
pub struct CVSumCheckProof<const N_ROUNDS: usize, const DIMENSION: usize> {
    pub comm_polys: [Secq256k1; N_ROUNDS],
    pub comm_evals: [Secq256k1; N_ROUNDS],
    pub proofs: [ZKDotProdProof<DIMENSION>; N_ROUNDS],
}

pub struct CVBulletReductionProof<const DIMENSION: usize> {
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
    ToCircuitVal<CVSumCheckProof<N_ROUNDS, DIMENSION>> for ZKSumcheckInstanceProof
{
    fn to_circuit_val(&self) -> CVSumCheckProof<N_ROUNDS, DIMENSION> {
        assert!(self.proofs.len() == N_ROUNDS);

        let mut dotprod_proofs = Vec::with_capacity(N_ROUNDS);
        let mut comm_polys = Vec::with_capacity(N_ROUNDS);
        let mut comm_evals = Vec::with_capacity(N_ROUNDS);
        for i in 0..N_ROUNDS {
            dotprod_proofs.push(self.proofs[i].to_circuit_val());
            comm_polys.push(self.comm_polys[i].to_circuit_val());
            comm_evals.push(self.comm_evals[i].to_circuit_val());
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
            L_vec.push(self.L_vec[i].to_circuit_val());
            R_vec.push(self.R_vec[i].to_circuit_val());
        }

        CVBulletReductionProof {
            L_vec: L_vec.try_into().unwrap(),
            R_vec: R_vec.try_into().unwrap(),
        }
    }
}
