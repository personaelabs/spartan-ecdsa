use super::group::{GroupElement, VartimeMultiscalarMul};
use super::scalar::Scalar;
use digest::{ExtendableOutput, Input};
use secq256k1::AffinePoint;
use sha3::Shake256;
use std::io::Read;

#[derive(Debug)]
pub struct MultiCommitGens {
  pub n: usize,
  pub G: Vec<GroupElement>,
  pub h: GroupElement,
}

impl MultiCommitGens {
  pub fn new(n: usize, label: &[u8]) -> Self {
    let mut shake = Shake256::default();
    shake.input(label);
    shake.input(AffinePoint::generator().compress().as_bytes());

    let mut reader = shake.xof_result();
    let mut gens: Vec<GroupElement> = Vec::new();
    let mut uniform_bytes = [0u8; 128];
    for _ in 0..n + 1 {
      reader.read_exact(&mut uniform_bytes).unwrap();
      gens.push(AffinePoint::from_uniform_bytes(&uniform_bytes));
    }

    MultiCommitGens {
      n,
      G: gens[..n].to_vec(),
      h: gens[n],
    }
  }

  pub fn clone(&self) -> MultiCommitGens {
    MultiCommitGens {
      n: self.n,
      h: self.h,
      G: self.G.clone(),
    }
  }

  pub fn split_at(&self, mid: usize) -> (MultiCommitGens, MultiCommitGens) {
    let (G1, G2) = self.G.split_at(mid);

    (
      MultiCommitGens {
        n: G1.len(),
        G: G1.to_vec(),
        h: self.h,
      },
      MultiCommitGens {
        n: G2.len(),
        G: G2.to_vec(),
        h: self.h,
      },
    )
  }
}

pub trait Commitments {
  fn commit(&self, blind: &Scalar, gens_n: &MultiCommitGens) -> GroupElement;
}

impl Commitments for Scalar {
  fn commit(&self, blind: &Scalar, gens_n: &MultiCommitGens) -> GroupElement {
    assert_eq!(gens_n.n, 1);
    GroupElement::vartime_multiscalar_mul(
      [*self, *blind].to_vec(),
      [gens_n.G[0], gens_n.h].to_vec(),
    )
  }
}

impl Commitments for Vec<Scalar> {
  fn commit(&self, blind: &Scalar, gens_n: &MultiCommitGens) -> GroupElement {
    assert_eq!(gens_n.n, self.len());
    GroupElement::vartime_multiscalar_mul((*self).clone(), gens_n.G.clone()) + blind * gens_n.h
  }
}

impl Commitments for [Scalar] {
  fn commit(&self, blind: &Scalar, gens_n: &MultiCommitGens) -> GroupElement {
    assert_eq!(gens_n.n, self.len());
    GroupElement::vartime_multiscalar_mul(self.to_vec(), gens_n.G.clone()) + blind * gens_n.h
  }
}
