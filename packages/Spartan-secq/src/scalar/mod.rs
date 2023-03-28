use secq256k1::elliptic_curve::ops::Reduce;
use secq256k1::U256;

mod scalar;

pub type Scalar = scalar::Scalar;
pub type ScalarBytes = secq256k1::Scalar;

pub trait ScalarFromPrimitives {
  fn to_scalar(self) -> Scalar;
}

impl ScalarFromPrimitives for usize {
  #[inline]
  fn to_scalar(self) -> Scalar {
    (0..self).map(|_i| Scalar::one()).sum()
  }
}

impl ScalarFromPrimitives for bool {
  #[inline]
  fn to_scalar(self) -> Scalar {
    if self {
      Scalar::one()
    } else {
      Scalar::zero()
    }
  }
}

pub trait ScalarBytesFromScalar {
  fn decompress_scalar(s: &Scalar) -> ScalarBytes;
  fn decompress_vector(s: &[Scalar]) -> Vec<ScalarBytes>;
}

impl ScalarBytesFromScalar for Scalar {
  fn decompress_scalar(s: &Scalar) -> ScalarBytes {
    ScalarBytes::from_uint_reduced(U256::from_le_slice(&s.to_bytes()))
  }

  fn decompress_vector(s: &[Scalar]) -> Vec<ScalarBytes> {
    (0..s.len())
      .map(|i| Scalar::decompress_scalar(&s[i]))
      .collect::<Vec<ScalarBytes>>()
  }
}
