use crate::field::field_secp::FieldElement;

use super::{FieldBytes, Secq256K1};

use primeorder::elliptic_curve::{
    bigint::{Limb, U256},
    generic_array::arr,
    ops::Reduce,
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    Curve, Error, Field, IsHigh, PrimeField, Result,
};

use std::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

type ScalarCore = primeorder::elliptic_curve::ScalarCore<Secq256K1>;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Scalar(pub ScalarCore);

impl Field for Scalar {
    fn zero() -> Self {
        Self(ScalarCore::ZERO)
    }

    fn one() -> Self {
        Self(ScalarCore::ONE)
    }

    fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = FieldBytes::default();

        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(scalar) = Self::from_repr(bytes).into() {
                return scalar;
            }
        }
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    #[must_use]
    fn square(&self) -> Self {
        unimplemented!();
    }

    #[must_use]
    fn double(&self) -> Self {
        self.add(self)
    }

    fn invert(&self) -> CtOption<Self> {
        unimplemented!();
    }

    fn sqrt(&self) -> CtOption<Self> {
        unimplemented!();
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const S: u32 = 4;

    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        ScalarCore::from_be_bytes(bytes).map(Self)
    }

    fn to_repr(&self) -> FieldBytes {
        self.0.to_be_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    fn multiplicative_generator() -> Self {
        7u64.into()
    }

    fn root_of_unity() -> Self {
        Self::from_repr(arr![u8;
            0xff, 0xc9, 0x7f, 0x06, 0x2a, 0x77, 0x09, 0x92, 0xba, 0x80, 0x7a, 0xce, 0x84, 0x2a,
            0x3d, 0xfc, 0x15, 0x46, 0xca, 0xd0, 0x04, 0x37, 0x8d, 0xaf, 0x05, 0x92, 0xd7, 0xfb,
            0xb4, 0x1e, 0x66, 0x02,
        ])
        .unwrap()
    }
}
impl DefaultIsZeroes for Scalar {}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        self.add(&other)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Self(self.0.add(&other.0))
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, other: Scalar) {
        *self = *self + other;
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, other: &Scalar) {
        *self = *self + other;
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        self.sub(&other)
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Self(self.0.sub(&other.0))
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, other: Scalar) {
        *self = *self - other;
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, other: &Scalar) {
        *self = *self - other;
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        let self_as_f = FieldElement::from_bytes(&self.to_bytes()).unwrap();
        let other_as_f = FieldElement::from_bytes(&other.to_bytes()).unwrap();
        let result = self_as_f.mul(other_as_f);
        Scalar::from_repr(*FieldBytes::from_slice(&result.to_be_bytes())).unwrap()
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        self.mul(*other)
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = self.mul(rhs)
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = self.mul(*rhs)
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Self(self.0.neg())
    }
}

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Self>>(_iter: I) -> Self {
        unimplemented!();
    }
}

impl<'a> Sum<&'a Scalar> for Scalar {
    fn sum<I: Iterator<Item = &'a Scalar>>(_iter: I) -> Self {
        unimplemented!();
    }
}

impl Product for Scalar {
    fn product<I: Iterator<Item = Self>>(_iter: I) -> Self {
        unimplemented!();
    }
}

impl<'a> Product<&'a Scalar> for Scalar {
    fn product<I: Iterator<Item = &'a Scalar>>(_iter: I) -> Self {
        unimplemented!();
    }
}

impl Reduce<U256> for Scalar {
    fn from_uint_reduced(w: U256) -> Self {
        let (r, underflow) = w.sbb(&Secq256K1::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BIT_SIZE - 1)) as u8);
        let reduced = U256::conditional_select(&w, &r, !underflow);
        Self(ScalarCore::new(reduced).unwrap())
    }
}

impl TryFrom<U256> for Scalar {
    type Error = Error;

    fn try_from(w: U256) -> Result<Self> {
        Option::from(ScalarCore::new(w)).map(Self).ok_or(Error)
    }
}

impl From<Scalar> for U256 {
    fn from(scalar: Scalar) -> U256 {
        *scalar.0.as_uint()
    }
}

impl From<u64> for Scalar {
    fn from(n: u64) -> Scalar {
        Self(n.into())
    }
}

impl From<ScalarCore> for Scalar {
    fn from(scalar: ScalarCore) -> Scalar {
        Self(scalar)
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        Self::from(&scalar)
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        scalar.to_repr()
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        self.0.is_high()
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(ScalarCore::conditional_select(&a.0, &b.0, choice))
    }
}

impl Scalar {
    pub const ZERO: Scalar = Scalar(ScalarCore::ZERO);
    pub const ONE: Scalar = Scalar(ScalarCore::ONE);

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_le_bytes().into()
    }
}

impl From<u32> for Scalar {
    fn from(n: u32) -> Scalar {
        Self((n as u64).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add() {
        let a = Scalar::from(1u32);
        let b = Scalar::from(2u32);
        let c = a + b;
        assert_eq!(c, Scalar::from(3u32));
    }

    #[test]
    fn test_all() {
        let a = Scalar::from(2u64.pow(63) - 2);
        let b = Scalar::from(2u64.pow(63) - 3);
        let add = a + b;
        let sub = a - b;
        let mul = a * b;
        let neg = -a;

        println!("add {:?}", add.0.to_string());
        println!("sub {:?}", sub.0.to_string());
        println!("mul {:?}", mul.0.to_string());
        println!("neg {:?}", neg.0.to_string());
    }
}
