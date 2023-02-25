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
