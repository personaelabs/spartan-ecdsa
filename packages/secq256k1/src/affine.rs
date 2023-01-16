use std::iter::Sum;
use std::ops::{Add, Mul, MulAssign, Neg, Sub};
use std::ops::{AddAssign, SubAssign};

use super::{ProjectivePoint, Secq256K1};
use crate::{EncodedPoint, Scalar};
use k256::elliptic_curve::subtle::Choice;
use primeorder::elliptic_curve::group::Group;
use primeorder::elliptic_curve::sec1::FromEncodedPoint;
use primeorder::elliptic_curve::sec1::ToEncodedPoint;
use primeorder::elliptic_curve::subtle::CtOption;

pub type AffinePointCore = primeorder::AffinePoint<Secq256K1>;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AffinePoint(pub AffinePointCore);

impl Mul<Scalar> for AffinePoint {
    type Output = AffinePoint;

    fn mul(self, rhs: Scalar) -> Self::Output {
        AffinePoint((self.0 * rhs).into())
    }
}

impl Mul<Scalar> for &AffinePoint {
    type Output = AffinePoint;

    fn mul(self, rhs: Scalar) -> Self::Output {
        AffinePoint((self.0 * rhs).into())
    }
}

impl Mul<&Scalar> for AffinePoint {
    type Output = AffinePoint;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        AffinePoint((self.0 * *rhs).into())
    }
}

impl MulAssign<&Scalar> for AffinePoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = *self * rhs;
    }
}

impl MulAssign<Scalar> for AffinePoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = *self * rhs;
    }
}

impl Add<AffinePoint> for AffinePoint {
    type Output = AffinePoint;

    fn add(self, rhs: AffinePoint) -> Self::Output {
        AffinePoint((ProjectivePoint::from(self.0) + ProjectivePoint::from(rhs.0)).into())
    }
}

impl AddAssign<AffinePoint> for AffinePoint {
    fn add_assign(&mut self, rhs: AffinePoint) {
        *self = *self + rhs;
    }
}

impl Sub<AffinePoint> for AffinePoint {
    type Output = AffinePoint;

    fn sub(self, rhs: AffinePoint) -> Self::Output {
        AffinePoint((ProjectivePoint::from(self.0) - rhs.0).into())
    }
}

impl SubAssign<AffinePoint> for AffinePoint {
    fn sub_assign(&mut self, rhs: AffinePoint) {
        *self = *self - rhs;
    }
}

impl AffinePoint {
    pub fn identity() -> Self {
        AffinePoint(AffinePointCore::IDENTITY)
    }

    pub fn generator() -> Self {
        AffinePoint(AffinePointCore::GENERATOR)
    }

    pub fn compress(&self) -> EncodedPoint {
        self.0.to_encoded_point(true)
    }

    pub fn decompress(bytes: EncodedPoint) -> CtOption<Self> {
        AffinePointCore::from_encoded_point(&bytes).map(AffinePoint)
    }
}

impl From<ProjectivePoint> for AffinePoint {
    fn from(p: ProjectivePoint) -> Self {
        AffinePoint(p.into())
    }
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    fn neg(self) -> Self::Output {
        AffinePoint(self.0.neg())
    }
}

impl Add<&AffinePoint> for AffinePoint {
    type Output = AffinePoint;

    fn add(self, rhs: &AffinePoint) -> Self::Output {
        self + *rhs
    }
}

impl AddAssign<&AffinePoint> for AffinePoint {
    fn add_assign(&mut self, rhs: &AffinePoint) {
        *self = *self + *rhs;
    }
}

impl Sub<&AffinePoint> for AffinePoint {
    type Output = AffinePoint;

    fn sub(self, rhs: &AffinePoint) -> Self::Output {
        self - *rhs
    }
}

impl SubAssign<&AffinePoint> for AffinePoint {
    fn sub_assign(&mut self, rhs: &AffinePoint) {
        *self = *self - *rhs;
    }
}

impl Sum for AffinePoint {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(AffinePoint::identity(), |acc, x| acc + x)
    }
}

impl<'a> Sum<&'a AffinePoint> for AffinePoint {
    fn sum<I: Iterator<Item = &'a AffinePoint>>(iter: I) -> Self {
        iter.fold(AffinePoint::identity(), |acc, x| acc + x)
    }
}

impl Group for AffinePoint {
    type Scalar = Scalar;

    fn random(rng: impl rand_core::RngCore) -> Self {
        AffinePoint(AffinePointCore::from(ProjectivePoint::random(rng)))
    }

    fn generator() -> Self {
        AffinePoint::generator()
    }

    fn identity() -> Self {
        AffinePoint::identity()
    }

    fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    fn double(&self) -> Self {
        self.add(self)
    }
}
