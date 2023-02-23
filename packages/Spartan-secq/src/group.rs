use secq256k1::{AffinePoint, ProjectivePoint};

use super::errors::ProofVerifyError;
use super::scalar::{Scalar, ScalarBytes, ScalarBytesFromScalar};
use core::ops::{Mul, MulAssign};
use multiexp::multiexp;

pub type GroupElement = secq256k1::AffinePoint;
pub type CompressedGroup = secq256k1::EncodedPoint;
pub trait CompressedGroupExt {
  type Group;
  fn unpack(&self) -> Result<Self::Group, ProofVerifyError>;
}

impl CompressedGroupExt for CompressedGroup {
  type Group = secq256k1::AffinePoint;
  fn unpack(&self) -> Result<Self::Group, ProofVerifyError> {
    let result = AffinePoint::decompress(*self);
    if result.is_some().into() {
      return Ok(result.unwrap());
    } else {
      Err(ProofVerifyError::DecompressionError(
        (*self.to_bytes()).try_into().unwrap(),
      ))
    }
  }
}

pub trait DecompressEncodedPoint {
  fn decompress(&self) -> Option<GroupElement>;
}

impl DecompressEncodedPoint for CompressedGroup {
  fn decompress(&self) -> Option<GroupElement> {
    Some(self.unpack().unwrap())
  }
}

impl<'b> MulAssign<&'b Scalar> for GroupElement {
  fn mul_assign(&mut self, scalar: &'b Scalar) {
    let result = (self as &GroupElement) * Scalar::decompress_scalar(scalar);
    *self = result;
  }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a GroupElement {
  type Output = GroupElement;
  fn mul(self, scalar: &'b Scalar) -> GroupElement {
    *self * Scalar::decompress_scalar(scalar)
  }
}

impl<'a, 'b> Mul<&'b GroupElement> for &'a Scalar {
  type Output = GroupElement;

  fn mul(self, point: &'b GroupElement) -> GroupElement {
    (*point * Scalar::decompress_scalar(self)).into()
  }
}

macro_rules! define_mul_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
    impl<'b> Mul<&'b $rhs> for $lhs {
      type Output = $out;
      fn mul(self, rhs: &'b $rhs) -> $out {
        &self * rhs
      }
    }

    impl<'a> Mul<$rhs> for &'a $lhs {
      type Output = $out;
      fn mul(self, rhs: $rhs) -> $out {
        self * &rhs
      }
    }

    impl Mul<$rhs> for $lhs {
      type Output = $out;
      fn mul(self, rhs: $rhs) -> $out {
        &self * &rhs
      }
    }
  };
}

macro_rules! define_mul_assign_variants {
  (LHS = $lhs:ty, RHS = $rhs:ty) => {
    impl MulAssign<$rhs> for $lhs {
      fn mul_assign(&mut self, rhs: $rhs) {
        *self *= &rhs;
      }
    }
  };
}

define_mul_assign_variants!(LHS = GroupElement, RHS = Scalar);
define_mul_variants!(LHS = GroupElement, RHS = Scalar, Output = GroupElement);
define_mul_variants!(LHS = Scalar, RHS = GroupElement, Output = GroupElement);

pub trait VartimeMultiscalarMul {
  type Scalar;
  fn vartime_multiscalar_mul(scalars: Vec<Scalar>, points: Vec<GroupElement>) -> Self;
}

impl VartimeMultiscalarMul for GroupElement {
  type Scalar = super::scalar::Scalar;
  // TODO Borrow the arguments so we don't have to clone them, as it was in the original implementation
  fn vartime_multiscalar_mul(scalars: Vec<Scalar>, points: Vec<GroupElement>) -> Self {
    let points: Vec<ProjectivePoint> = points.iter().map(|p| ProjectivePoint::from(p.0)).collect();

    let pairs: Vec<(ScalarBytes, ProjectivePoint)> = scalars
      .into_iter()
      .enumerate()
      .map(|(i, s)| (Scalar::decompress_scalar(&s), points[i]))
      .collect();

    let result = multiexp::<ProjectivePoint>(pairs.as_slice());

    AffinePoint(result.to_affine())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn msm() {
    let scalars = vec![Scalar::from(1), Scalar::from(2), Scalar::from(3)];
    let points = vec![
      GroupElement::generator(),
      GroupElement::generator(),
      GroupElement::generator(),
    ];
    let result = GroupElement::vartime_multiscalar_mul(scalars, points);

    assert_eq!(result, GroupElement::generator() * Scalar::from(6));
  }
}
