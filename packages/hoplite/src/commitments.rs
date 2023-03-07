use crate::Fq;
use secpq_curves::Secq256k1;
use secq256k1::{affine::Group, AffinePoint};
use sha3::{
    digest::{ExtendableOutput, Input},
    Shake256,
};
use std::{io::Read, ops::Mul};

use crate::circuit_vals::ToCircuitVal;

pub struct MultiCommitGens {
    pub G: Vec<Secq256k1>,
    pub h: Secq256k1,
}

impl Default for MultiCommitGens {
    fn default() -> Self {
        MultiCommitGens {
            G: vec![],
            h: Secq256k1::default(),
        }
    }
}

impl From<libspartan::commitments::MultiCommitGens> for MultiCommitGens {
    fn from(gens: libspartan::commitments::MultiCommitGens) -> Self {
        MultiCommitGens {
            G: gens
                .G
                .iter()
                .map(|g| g.compress().to_circuit_val())
                .collect(),
            h: gens.h.compress().to_circuit_val(),
        }
    }
}

impl MultiCommitGens {
    pub fn new(n: usize, label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.input(label);
        shake.input(AffinePoint::generator().compress().as_bytes());

        let mut reader = shake.xof_result();
        let mut gens: Vec<Secq256k1> = Vec::new();
        let mut uniform_bytes = [0u8; 128];
        for _ in 0..n + 1 {
            reader.read_exact(&mut uniform_bytes).unwrap();
            let gen = AffinePoint::from_uniform_bytes(&uniform_bytes).compress();
            gens.push(gen.to_circuit_val());
        }

        MultiCommitGens {
            G: gens[..n].to_vec(),
            h: gens[n],
        }
    }
}

pub trait Commitments {
    fn commit(&self, blind: &Fq, gens: &MultiCommitGens) -> Secq256k1;
}

impl Commitments for Fq {
    fn commit(&self, blind: &Fq, gens: &MultiCommitGens) -> Secq256k1 {
        gens.G[0] * self + gens.h * blind
    }
}

impl Commitments for Vec<Fq> {
    fn commit(&self, blind: &Fq, gens: &MultiCommitGens) -> Secq256k1 {
        let mut result = Secq256k1::identity();
        for (i, val) in self.iter().enumerate() {
            result += gens.G[i] * val;
        }
        result += gens.h * blind;
        result
    }
}

impl Commitments for [Fq] {
    fn commit(&self, blind: &Fq, gens: &MultiCommitGens) -> Secq256k1 {
        let mut result = Secq256k1::identity();
        for (i, val) in self.iter().enumerate() {
            result += gens.G[i] * val;
        }
        result += gens.h * blind;
        result
    }
}
