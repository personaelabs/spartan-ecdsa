use libspartan::math::Math;

use crate::{Fp, Fq};

pub fn hypercube(n: u32) -> Vec<Vec<u8>> {
    let mut v = vec![];
    for i in 0..(2u64.pow(n)) {
        let mut row = vec![];
        for j in 0..n {
            row.push(((i >> j) & 1) as u8);
        }
        v.push(row);
    }

    v
}

pub fn to_fp(x: &libspartan::scalar::Scalar) -> Fp {
    Fp::from_bytes(&x.to_bytes().into()).unwrap()
}

pub fn to_fq(x: &libspartan::scalar::Scalar) -> Fq {
    Fq::from_bytes(&x.to_bytes().into()).unwrap()
}

fn compute_chi(e: &[Fq], x: &[Fq]) -> Fq {
    let mut chi = Fq::one();
    for i in 0..e.len() {
        chi *= e[i] * x[i] + (Fq::one() - e[i]) * (Fq::one() - x[i]);
    }

    chi
}

pub fn eval_ml_poly(z: &[Fq], r: &[Fq]) -> Fq {
    let mut eval = Fq::zero();
    // compute chi
    for i in 0..z.len() {
        let i_bits: Vec<Fq> = i
            .get_bits(r.len())
            .iter()
            .map(|b| if *b { Fq::one() } else { Fq::zero() })
            .collect();

        eval += compute_chi(&i_bits, r) * z[i];
    }

    eval
}
