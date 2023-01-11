//! This module provides an implementation of the secq256k1's scalar field $\mathbb{F}_q$
//! where `q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`
//! This is an adaptation of code from the k256 crate
//! We modify various constants (MODULUS, R, R2, etc.) to appropriate values for secq256k1 and update tests
#![allow(clippy::all)]
use crate::FieldBytes;
use core::borrow::Borrow;
use core::convert::TryFrom;
use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use k256::Scalar;
use primeorder::elliptic_curve::generic_array::arr;
use primeorder::elliptic_curve::subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, CtOption,
};
use primeorder::{Field, PrimeField};
use rand_core::{CryptoRng, RngCore};
use serde::de::Visitor;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// use crate::util::{adc, mac, sbb};
/// Compute a + b + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a - (b + borrow), returning the result and the new borrow.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

macro_rules! impl_add_binop_specify_output {
    ($lhs:ident, $rhs:ident, $output:ident) => {
        impl<'b> Add<&'b $rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn add(self, rhs: &'b $rhs) -> $output {
                &self + rhs
            }
        }

        impl<'a> Add<$rhs> for &'a $lhs {
            type Output = $output;

            #[inline]
            fn add(self, rhs: $rhs) -> $output {
                self + &rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn add(self, rhs: $rhs) -> $output {
                &self + &rhs
            }
        }
    };
}

macro_rules! impl_sub_binop_specify_output {
    ($lhs:ident, $rhs:ident, $output:ident) => {
        impl<'b> Sub<&'b $rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn sub(self, rhs: &'b $rhs) -> $output {
                &self - rhs
            }
        }

        impl<'a> Sub<$rhs> for &'a $lhs {
            type Output = $output;

            #[inline]
            fn sub(self, rhs: $rhs) -> $output {
                self - &rhs
            }
        }

        impl Sub<$rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn sub(self, rhs: $rhs) -> $output {
                &self - &rhs
            }
        }
    };
}

macro_rules! impl_binops_additive_specify_output {
    ($lhs:ident, $rhs:ident, $output:ident) => {
        impl_add_binop_specify_output!($lhs, $rhs, $output);
        impl_sub_binop_specify_output!($lhs, $rhs, $output);
    };
}

macro_rules! impl_binops_multiplicative_mixed {
    ($lhs:ident, $rhs:ident, $output:ident) => {
        impl<'b> Mul<&'b $rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn mul(self, rhs: &'b $rhs) -> $output {
                &self * rhs
            }
        }

        impl<'a> Mul<$rhs> for &'a $lhs {
            type Output = $output;

            #[inline]
            fn mul(self, rhs: $rhs) -> $output {
                self * &rhs
            }
        }

        impl Mul<$rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn mul(self, rhs: $rhs) -> $output {
                &self * &rhs
            }
        }
    };
}

macro_rules! impl_binops_additive {
    ($lhs:ident, $rhs:ident) => {
        impl_binops_additive_specify_output!($lhs, $rhs, $lhs);

        impl SubAssign<$rhs> for $lhs {
            #[inline]
            fn sub_assign(&mut self, rhs: $rhs) {
                *self = &*self - &rhs;
            }
        }

        impl AddAssign<$rhs> for $lhs {
            #[inline]
            fn add_assign(&mut self, rhs: $rhs) {
                *self = &*self + &rhs;
            }
        }

        impl<'b> SubAssign<&'b $rhs> for $lhs {
            #[inline]
            fn sub_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self - rhs;
            }
        }

        impl<'b> AddAssign<&'b $rhs> for $lhs {
            #[inline]
            fn add_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self + rhs;
            }
        }
    };
}

macro_rules! impl_binops_multiplicative {
    ($lhs:ident, $rhs:ident) => {
        impl_binops_multiplicative_mixed!($lhs, $rhs, $lhs);

        impl MulAssign<$rhs> for $lhs {
            #[inline]
            fn mul_assign(&mut self, rhs: $rhs) {
                *self = &*self * &rhs;
            }
        }

        impl<'b> MulAssign<&'b $rhs> for $lhs {
            #[inline]
            fn mul_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self * rhs;
            }
        }
    };
}

/// Represents an element of the scalar field $\mathbb{F}_q$ of the secq256k1 elliptic
/// curve construction.
// The internal representation of this type is four 64-bit unsigned
// integers in little-endian order. `FieldElement` values are always in
// Montgomery form; i.e., FieldElement(a) = aR mod q, with R = 2^256.
#[derive(Clone, Copy, Eq)]
pub struct FieldElement(pub(crate) [u64; 5]);

use serde::ser::SerializeSeq;
use serde::{Deserializer, Serializer};

impl Serialize for FieldElement {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let values: Vec<u8> = self.0.iter().map(|v| v.to_le_bytes()).flatten().collect();
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for val in values.iter() {
            seq.serialize_element(val)?;
        }

        seq.end()
    }
}

struct U64ArrayVisitor;

impl<'de> Visitor<'de> for U64ArrayVisitor {
    type Value = FieldElement;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 4 u64 values")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut result = [0u64; 4];

        for i in 0..4 {
            let mut val: u64 = 0;
            for j in 0..8 {
                val += (seq.next_element::<u8>().unwrap().unwrap() as u64) * 256u64.pow(j)
            }
            result[i] = val;
        }

        Ok(FieldElement::from_raw(result))
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(U64ArrayVisitor)
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter().rev() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl From<u64> for FieldElement {
    fn from(val: u64) -> FieldElement {
        FieldElement([val, 0, 0, 0, 0]) * R2
    }
}

impl Field for FieldElement {
    fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = FieldBytes::default();

        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(fe) = Self::from_bytes(&bytes.into()).into() {
                return fe;
            }
        }
    }

    fn zero() -> Self {
        FieldElement::zero()
    }

    fn one() -> Self {
        FieldElement::one()
    }

    fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn double(&self) -> Self {
        self.double()
    }

    fn sqrt(&self) -> CtOption<Self> {
        let as_scalar: Scalar = Scalar::from_repr(self.to_repr()).unwrap();
        as_scalar
            .sqrt()
            .map(|s| FieldElement::from_sec1(s.to_bytes()).unwrap())
    }

    fn is_zero_vartime(&self) -> bool {
        self.is_zero().into()
    }

    fn cube(&self) -> Self {
        self.square() * self
    }

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const S: u32 = 1;

    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_sec1(bytes)
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_sec1()
    }

    fn is_odd(&self) -> Choice {
        // TODO: Possible optimization?
        let val = FieldElement::montgomery_reduce(
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], 0, 0, 0, 0,
        );
        (val.0[0] as u8 & 1).into()
    }

    fn multiplicative_generator() -> Self {
        7.into()
    }

    fn root_of_unity() -> Self {
        Self::from_repr(arr![u8;
            0x0c, 0x1d, 0xc0, 0x60, 0xe7, 0xa9, 0x19, 0x86, 0xdf, 0x98, 0x79, 0xa3, 0xfb, 0xc4,
            0x83, 0xa8, 0x98, 0xbd, 0xea, 0xb6, 0x80, 0x75, 0x60, 0x45, 0x99, 0x2f, 0x4b, 0x54,
            0x02, 0xb0, 0x52, 0xf2
        ])
        .unwrap()
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl PartialEq for FieldElement {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        FieldElement([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
        ])
    }
}

/// Constant representing the modulus
/// 0xffffffffffffffff fffffffffffffffe baaedce6af48a03b bfd25e8cd0364141
const MODULUS: FieldElement = FieldElement([
    0xbfd25e8cd0364141,
    0xbaaedce6af48a03b,
    0xfffffffffffffffe,
    0xffffffffffffffff,
    0,
]);

impl<'a> Neg for &'a FieldElement {
    type Output = FieldElement;

    #[inline]
    fn neg(self) -> FieldElement {
        self.neg()
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn neg(self) -> FieldElement {
        -&self
    }
}

impl<'a, 'b> Sub<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    #[inline]
    fn sub(self, rhs: &'b FieldElement) -> FieldElement {
        self.sub(rhs)
    }
}

impl<'a, 'b> Add<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    #[inline]
    fn add(self, rhs: &'b FieldElement) -> FieldElement {
        self.add(rhs)
    }
}

impl<'a, 'b> Mul<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    #[inline]
    fn mul(self, rhs: &'b FieldElement) -> FieldElement {
        self.mul(rhs)
    }
}

impl_binops_additive!(FieldElement, FieldElement);
impl_binops_multiplicative!(FieldElement, FieldElement);

/// INV = -(q^{-1} mod 2^64) mod 2^64
const INV: u64 = 0x4b0dff665588b13f;

/// R = 2^256 mod q
/// 0x1 4551231950b75fc4 402da1732fc9bebf
const R: FieldElement = FieldElement([
    0x402da1732fc9bebf,
    0x4551231950b75fc4,
    0x0000000000000001,
    0x0000000000000000,
    0x0,
]);

/// R^2 = 2^512 mod q
/// 0x9d671cd581c69bc5 e697f5e45bcd07c6 741496c20e7cf878 896cf21467d7d140
const R2: FieldElement = FieldElement([
    0x896cf21467d7d140,
    0x741496c20e7cf878,
    0xe697f5e45bcd07c6,
    0x9d671cd581c69bc5,
    0,
]);

/// R^3 = 2^768 mod q
/// 0x555d800c18ef116d b1b31347f1d0b2da 0017648444d4322c 7bc0cfe0e9ff41ed
const R3: FieldElement = FieldElement([
    0x7bc0cfe0e9ff41ed,
    0x0017648444d4322c,
    0xb1b31347f1d0b2da,
    0x555d800c18ef116d,
    0x0,
]);

impl Default for FieldElement {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl<T> Product<T> for FieldElement
where
    T: Borrow<FieldElement>,
{
    fn product<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(FieldElement::one(), |acc, item| acc * item.borrow())
    }
}

impl<T> Sum<T> for FieldElement
where
    T: Borrow<FieldElement>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(FieldElement::zero(), |acc, item| acc + item.borrow())
    }
}

impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0 = [0u64; 5];
    }
}

impl FieldElement {
    pub const ZERO: Self = Self([0, 0, 0, 0, 0]);
    pub const ONE: Self = R;

    fn pow2k(&self, k: usize) -> Self {
        let mut x = *self;
        for _j in 0..k {
            x = x.square();
        }
        x
    }

    /// Returns zero, the additive identity.
    #[inline]
    pub const fn zero() -> FieldElement {
        FieldElement([0, 0, 0, 0, 0])
    }

    /// Returns one, the multiplicative identity.
    #[inline]
    pub const fn one() -> FieldElement {
        R
    }

    pub fn random<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Self {
        let mut limbs = [0u64; 8];
        for i in 0..8 {
            limbs[i] = rng.next_u64();
        }
        FieldElement::from_u512(limbs)
    }

    /// Doubles this field element.
    #[inline]
    pub const fn double(&self) -> FieldElement {
        // TODO: This can be achieved more efficiently with a bitshift.
        self.add(self)
    }

    /// Attempts to convert a little-endian byte representation of
    /// a scalar into a `FieldElement`, failing if the input is not canonical.
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<FieldElement> {
        let mut tmp = FieldElement([0, 0, 0, 0, 0]);

        tmp.0[0] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[..8]).unwrap());
        tmp.0[1] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        tmp.0[2] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        tmp.0[3] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

        // Try to subtract the modulus
        let (_, borrow) = sbb(tmp.0[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(tmp.0[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(tmp.0[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(tmp.0[3], MODULUS.0[3], borrow);

        // If the element is smaller than MODULUS then the
        // subtraction will underflow, producing a borrow value
        // of 0xffff...ffff. Otherwise, it'll be zero.
        let is_some = (borrow as u8) & 1;

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        tmp *= &R2;

        CtOption::new(tmp, Choice::from(is_some))
    }

    /// Converts an element of `FieldElement` into a byte representation in
    /// little-endian byte order.
    pub fn to_bytes(&self) -> [u8; 32] {
        // Turn into canonical form by computing
        // (a.R) / R = a
        let tmp = FieldElement::montgomery_reduce(
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], 0, 0, 0, 0,
        );

        let mut res = [0; 32];
        res[..8].copy_from_slice(&tmp.0[0].to_le_bytes());
        res[8..16].copy_from_slice(&tmp.0[1].to_le_bytes());
        res[16..24].copy_from_slice(&tmp.0[2].to_le_bytes());
        res[24..32].copy_from_slice(&tmp.0[3].to_le_bytes());

        res
    }

    /// Converts a 512-bit little endian integer into
    /// a `FieldElement` by reducing by the modulus.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> FieldElement {
        FieldElement::from_u512([
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap()),
        ])
    }

    fn from_u512(limbs: [u64; 8]) -> FieldElement {
        // We reduce an arbitrary 512-bit number by decomposing it into two 256-bit digits
        // with the higher bits multiplied by 2^256. Thus, we perform two reductions
        //
        // 1. the lower bits are multiplied by R^2, as normal
        // 2. the upper bits are multiplied by R^2 * 2^256 = R^3
        //
        // and computing their sum in the field. It remains to see that arbitrary 256-bit
        // numbers can be placed into Montgomery form safely using the reduction. The
        // reduction works so long as the product is less than R=2^256 multipled by
        // the modulus. This holds because for any `c` smaller than the modulus, we have
        // that (2^256 - 1)*c is an acceptable product for the reduction. Therefore, the
        // reduction always works so long as `c` is in the field; in this case it is either the
        // constant `R2` or `R3`.
        let d0 = FieldElement([limbs[0], limbs[1], limbs[2], limbs[3], 0]);
        let d1 = FieldElement([limbs[4], limbs[5], limbs[6], limbs[7], 0]);
        // Convert to Montgomery form
        d0 * R2 + d1 * R3
    }

    /// Converts from an integer represented in little endian
    /// into its (congruent) `FieldElement` representation.
    pub const fn from_raw(val: [u64; 4]) -> Self {
        (&FieldElement([val[0], val[1], val[2], val[3], 0])).mul(&R2)
    }

    /// Squares this element.
    #[inline]
    pub const fn square(&self) -> FieldElement {
        let (r1, carry) = mac(0, self.0[0], self.0[1], 0);
        let (r2, carry) = mac(0, self.0[0], self.0[2], carry);
        let (r3, r4) = mac(0, self.0[0], self.0[3], carry);

        let (r3, carry) = mac(r3, self.0[1], self.0[2], 0);
        let (r4, r5) = mac(r4, self.0[1], self.0[3], carry);

        let (r5, r6) = mac(r5, self.0[2], self.0[3], 0);

        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        let (r0, carry) = mac(0, self.0[0], self.0[0], 0);
        let (r1, carry) = adc(0, r1, carry);
        let (r2, carry) = mac(r2, self.0[1], self.0[1], carry);
        let (r3, carry) = adc(0, r3, carry);
        let (r4, carry) = mac(r4, self.0[2], self.0[2], carry);
        let (r5, carry) = adc(0, r5, carry);
        let (r6, carry) = mac(r6, self.0[3], self.0[3], carry);
        let (r7, _) = adc(0, r7, carry);

        FieldElement::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7, 0)
    }

    /// Exponentiates `self` by `by`, where `by` is a
    /// little-endian order integer exponent.
    pub fn pow(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();
                let mut tmp = res;
                tmp *= self;
                res.conditional_assign(&tmp, (((*e >> i) & 0x1) as u8).into());
            }
        }
        res
    }

    pub fn invert(&self) -> CtOption<Self> {
        // Using an addition chain from
        // https://briansmith.org/ecc-inversion-addition-chains-01#secp256k1_scalar_inversion
        let x_1 = *self;
        let x_10 = self.pow2k(1);
        let x_11 = x_10.mul(&x_1);
        let x_101 = x_10.mul(&x_11);
        let x_111 = x_10.mul(&x_101);
        let x_1001 = x_10.mul(&x_111);
        let x_1011 = x_10.mul(&x_1001);
        let x_1101 = x_10.mul(&x_1011);

        let x6 = x_1101.pow2k(2).mul(&x_1011);
        let x8 = x6.pow2k(2).mul(&x_11);
        let x14 = x8.pow2k(6).mul(&x6);
        let x28 = x14.pow2k(14).mul(&x14);
        let x56 = x28.pow2k(28).mul(&x28);

        #[rustfmt::skip]
            let res = x56
            .pow2k(56).mul(&x56)
            .pow2k(14).mul(&x14)
            .pow2k(3).mul(&x_101)
            .pow2k(4).mul(&x_111)
            .pow2k(4).mul(&x_101)
            .pow2k(5).mul(&x_1011)
            .pow2k(4).mul(&x_1011)
            .pow2k(4).mul(&x_111)
            .pow2k(5).mul(&x_111)
            .pow2k(6).mul(&x_1101)
            .pow2k(4).mul(&x_101)
            .pow2k(3).mul(&x_111)
            .pow2k(5).mul(&x_1001)
            .pow2k(6).mul(&x_101)
            .pow2k(10).mul(&x_111)
            .pow2k(4).mul(&x_111)
            .pow2k(9).mul(&x8)
            .pow2k(5).mul(&x_1001)
            .pow2k(6).mul(&x_1011)
            .pow2k(4).mul(&x_1101)
            .pow2k(5).mul(&x_11)
            .pow2k(6).mul(&x_1101)
            .pow2k(10).mul(&x_1101)
            .pow2k(4).mul(&x_1001)
            .pow2k(6).mul(&x_1)
            .pow2k(8).mul(&x6);

        CtOption::new(res, !self.is_zero())
    }

    pub fn batch_invert(inputs: &mut [FieldElement]) -> FieldElement {
        // This code is essentially identical to the FieldElement
        // implementation, and is documented there.  Unfortunately,
        // it's not easy to write it generically, since here we want
        // to use `UnpackedScalar`s internally, and `FieldElement`s
        // externally, but there's no corresponding distinction for
        // field elements.

        use zeroize::Zeroizing;

        let n = inputs.len();
        let one = FieldElement::one();

        // Place scratch storage in a Zeroizing wrapper to wipe it when
        // we pass out of scope.
        let scratch_vec = vec![one; n];
        let mut scratch = Zeroizing::new(scratch_vec);

        // Keep an accumulator of all of the previous products
        let mut acc = FieldElement::one();

        // Pass through the input vector, recording the previous
        // products in the scratch space
        for (input, scratch) in inputs.iter().zip(scratch.iter_mut()) {
            *scratch = acc;

            acc = acc * input;
        }

        // acc is nonzero iff all inputs are nonzero
        debug_assert!(acc != FieldElement::zero());

        // Compute the inverse of all products
        acc = acc.invert().unwrap();

        // We need to return the product of all inverses later
        let ret = acc;

        // Pass through the vector backwards to compute the inverses
        // in place
        for (input, scratch) in inputs.iter_mut().rev().zip(scratch.iter().rev()) {
            let tmp = &acc * input.clone();
            *input = &acc * scratch;
            acc = tmp;
        }

        ret
    }

    #[inline(always)]
    const fn montgomery_reduce(
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64,
        r8: u64,
    ) -> Self {
        // The Montgomery reduction here is based on Algorithm 14.32 in
        // Handbook of Applied Cryptography
        // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

        let k = r0.wrapping_mul(INV);
        let (_, carry) = mac(r0, k, MODULUS.0[0], 0);
        let (r1, carry) = mac(r1, k, MODULUS.0[1], carry);
        let (r2, carry) = mac(r2, k, MODULUS.0[2], carry);
        let (r3, carry) = mac(r3, k, MODULUS.0[3], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[4], carry);
        let (r5, carry2) = adc(r5, 0, carry);

        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac(r1, k, MODULUS.0[0], 0);
        let (r2, carry) = mac(r2, k, MODULUS.0[1], carry);
        let (r3, carry) = mac(r3, k, MODULUS.0[2], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[3], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[4], carry);
        let (r6, carry2) = adc(r6, carry2, carry);

        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac(r2, k, MODULUS.0[0], 0);
        let (r3, carry) = mac(r3, k, MODULUS.0[1], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[2], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[3], carry);
        let (r6, carry) = mac(r6, k, MODULUS.0[4], carry);
        let (r7, carry2) = adc(r7, carry2, carry);

        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac(r3, k, MODULUS.0[0], 0);
        let (r4, carry) = mac(r4, k, MODULUS.0[1], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[2], carry);
        let (r6, carry) = mac(r6, k, MODULUS.0[3], carry);
        let (r7, carry) = mac(r7, k, MODULUS.0[4], carry);
        let (r8, _) = adc(r8, carry2, carry);

        // Result may be within MODULUS of the correct value
        (&FieldElement([r4, r5, r6, r7, r8])).sub(&MODULUS)
    }

    /// Multiplies `rhs` by `self`, returning the result.
    #[inline]
    pub const fn mul(&self, rhs: &Self) -> Self {
        // Schoolbook multiplication

        let (r0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (r1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (r2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (r3, carry) = mac(0, self.0[0], rhs.0[3], carry);
        let (r4, r5) = mac(0, self.0[0], rhs.0[4], carry);

        let (r1, carry) = mac(r1, self.0[1], rhs.0[0], 0);
        let (r2, carry) = mac(r2, self.0[1], rhs.0[1], carry);
        let (r3, carry) = mac(r3, self.0[1], rhs.0[2], carry);
        let (r4, carry) = mac(r4, self.0[1], rhs.0[3], carry);
        let (r5, r6) = mac(r5, self.0[1], rhs.0[4], carry);

        let (r2, carry) = mac(r2, self.0[2], rhs.0[0], 0);
        let (r3, carry) = mac(r3, self.0[2], rhs.0[1], carry);
        let (r4, carry) = mac(r4, self.0[2], rhs.0[2], carry);
        let (r5, carry) = mac(r5, self.0[2], rhs.0[3], carry);
        let (r6, r7) = mac(r6, self.0[2], rhs.0[4], carry);

        let (r3, carry) = mac(r3, self.0[3], rhs.0[0], 0);
        let (r4, carry) = mac(r4, self.0[3], rhs.0[1], carry);
        let (r5, carry) = mac(r5, self.0[3], rhs.0[2], carry);
        let (r6, carry) = mac(r6, self.0[3], rhs.0[3], carry);
        let (r7, r8) = mac(r7, self.0[3], rhs.0[4], carry);

        let (r4, carry) = mac(r4, self.0[4], rhs.0[0], 0);
        let (r5, carry) = mac(r5, self.0[4], rhs.0[1], carry);
        let (r6, carry) = mac(r6, self.0[4], rhs.0[2], carry);
        let (r7, carry) = mac(r7, self.0[4], rhs.0[3], carry);
        let (r8, _) = mac(r8, self.0[4], rhs.0[4], carry);

        FieldElement::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7, r8)
    }

    /// Subtracts `rhs` from `self`, returning the result.
    #[inline]
    pub const fn sub(&self, rhs: &Self) -> Self {
        let (d0, borrow) = sbb(self.0[0], rhs.0[0], 0);
        let (d1, borrow) = sbb(self.0[1], rhs.0[1], borrow);
        let (d2, borrow) = sbb(self.0[2], rhs.0[2], borrow);
        let (d3, borrow) = sbb(self.0[3], rhs.0[3], borrow);
        let (d4, borrow) = sbb(self.0[4], rhs.0[4], borrow);

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the modulus.
        let (d0, carry) = adc(d0, MODULUS.0[0] & borrow, 0);
        let (d1, carry) = adc(d1, MODULUS.0[1] & borrow, carry);
        let (d2, carry) = adc(d2, MODULUS.0[2] & borrow, carry);
        let (d3, carry) = adc(d3, MODULUS.0[3] & borrow, carry);
        let (d4, _) = adc(d4, MODULUS.0[4] & borrow, carry);

        FieldElement([d0, d1, d2, d3, d4])
    }

    /// Adds `rhs` to `self`, returning the result.
    #[inline]
    pub const fn add(&self, rhs: &Self) -> Self {
        let (d0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (d1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (d2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (d3, carry) = adc(self.0[3], rhs.0[3], carry);
        let (d4, _) = adc(self.0[4], rhs.0[4], carry);

        // Attempt to subtract the modulus, to ensure the value
        // is smaller than the modulus.
        (&FieldElement([d0, d1, d2, d3, d4])).sub(&MODULUS)
    }

    /// Negates `self`.
    #[inline]
    pub const fn neg(&self) -> Self {
        // Subtract `self` from `MODULUS` to negate. Ignore the final
        // borrow because it cannot underflow; self is guaranteed to
        // be in the field.
        let (d0, borrow) = sbb(MODULUS.0[0], self.0[0], 0);
        let (d1, borrow) = sbb(MODULUS.0[1], self.0[1], borrow);
        let (d2, borrow) = sbb(MODULUS.0[2], self.0[2], borrow);
        let (d3, borrow) = sbb(MODULUS.0[3], self.0[3], borrow);
        let (d4, _) = sbb(MODULUS.0[4], self.0[4], borrow);

        // `tmp` could be `MODULUS` if `self` was zero. Create a mask that is
        // zero if `self` was zero, and `u64::max_value()` if self was nonzero.
        let mask = (((self.0[0] | self.0[1] | self.0[2] | self.0[3] | self.0[4]) == 0) as u64)
            .wrapping_sub(1);

        FieldElement([d0 & mask, d1 & mask, d2 & mask, d3 & mask, d4 & mask])
    }
}

impl<'a> From<&'a FieldElement> for [u8; 32] {
    fn from(value: &'a FieldElement) -> [u8; 32] {
        value.to_bytes()
    }
}

impl FieldElement {
    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_sec1(bytes: FieldBytes) -> CtOption<Self> {
        let mut be = bytes.to_vec();
        be.reverse();

        Self::from_bytes(&be.as_slice().try_into().unwrap())
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_sec1(self) -> FieldBytes {
        let mut le_bytes = self.to_bytes().to_vec();
        le_bytes.reverse();

        *FieldBytes::from_slice(le_bytes.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use primeorder::elliptic_curve::ops::Invert;

    use crate::Secq256K1;

    use super::*;

    #[test]
    fn test_inv() {
        // Compute -(q^{-1} mod 2^64) mod 2^64 by exponentiating
        // by totient(2**64) - 1

        let mut inv = 1u64;
        for _ in 0..63 {
            inv = inv.wrapping_mul(inv);
            inv = inv.wrapping_mul(MODULUS.0[0]);
        }
        inv = inv.wrapping_neg();

        assert_eq!(inv, INV);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_debug() {
        assert_eq!(
            format!("{:?}", FieldElement::zero()),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format!("{:?}", FieldElement::one()),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            format!("{:?}", R2),
            "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe"
        );
    }

    #[test]
    fn test_equality() {
        assert_eq!(FieldElement::zero(), FieldElement::zero());
        assert_eq!(FieldElement::one(), FieldElement::one());
        assert_eq!(R2, R2);

        assert!(FieldElement::zero() != FieldElement::one());
        assert!(FieldElement::one() != R2);
    }

    #[test]
    fn test_to_bytes() {
        assert_eq!(
            FieldElement::zero().to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );

        assert_eq!(
            FieldElement::one().to_bytes(),
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_from_bytes() {
        assert_eq!(
            FieldElement::from_bytes(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ])
            .unwrap(),
            FieldElement::zero()
        );

        assert_eq!(
            FieldElement::from_bytes(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ])
            .unwrap(),
            FieldElement::one()
        );
    }

    #[test]
    fn test_from_u512_zero() {
        assert_eq!(
            FieldElement::zero(),
            FieldElement::from_u512([
                MODULUS.0[0],
                MODULUS.0[1],
                MODULUS.0[2],
                MODULUS.0[3],
                0,
                0,
                0,
                0
            ])
        );
    }

    #[test]
    fn test_from_u512_r() {
        assert_eq!(R, FieldElement::from_u512([1, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_from_u512_r2() {
        assert_eq!(R2, FieldElement::from_u512([0, 0, 0, 0, 1, 0, 0, 0]));
    }

    #[test]
    fn test_from_u512_max() {
        let max_u64 = 0xffffffffffffffff;
        assert_eq!(
            R3 - R,
            FieldElement::from_u512([
                max_u64, max_u64, max_u64, max_u64, max_u64, max_u64, max_u64, max_u64
            ])
        );
    }

    #[test]
    fn test_from_bytes_wide_r2() {
        assert_eq!(
            R2,
            FieldElement::from_bytes_wide(&[
                191, 190, 201, 47, 115, 161, 45, 64, 196, 95, 183, 80, 25, 35, 81, 69, 1, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ])
        );
    }

    #[test]
    fn test_from_bytes_wide_negative_one() {
        assert_eq!(
            -&FieldElement::one(),
            FieldElement::from_bytes_wide(&[
                64, 65, 54, 208, 140, 94, 210, 191, 59, 160, 72, 175, 230, 220, 174, 186, 254, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ])
        );
    }

    #[test]
    fn test_zero() {
        assert_eq!(FieldElement::zero(), -&FieldElement::zero());
        assert_eq!(
            FieldElement::zero(),
            FieldElement::zero() + FieldElement::zero()
        );
        assert_eq!(
            FieldElement::zero(),
            FieldElement::zero() - FieldElement::zero()
        );
        assert_eq!(
            FieldElement::zero(),
            FieldElement::zero() * FieldElement::zero()
        );
    }

    const LARGEST: FieldElement = FieldElement([
        0xfffffffefffffc2e,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0,
    ]);

    #[test]
    fn test_addition() {
        let mut tmp = LARGEST;
        tmp += &LARGEST;

        let target = FieldElement([
            0xfffffffefffffc2d,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0,
        ]);

        assert_eq!(tmp, target);

        let mut tmp = LARGEST;
        tmp += &FieldElement([1, 0, 0, 0, 0]);

        assert_eq!(tmp, FieldElement::zero());
    }

    #[test]
    fn test_negation() {
        let tmp = -&LARGEST;

        assert_eq!(tmp, FieldElement([1, 0, 0, 0, 0]));

        let tmp = -&FieldElement::zero();
        assert_eq!(tmp, FieldElement::zero());
        let tmp = -&FieldElement([1, 0, 0, 0, 0]);
        assert_eq!(tmp, LARGEST);
    }

    #[test]
    fn test_subtraction() {
        let mut tmp = LARGEST;
        tmp -= &LARGEST;

        assert_eq!(tmp, FieldElement::zero());

        let mut tmp = FieldElement::zero();
        tmp -= &LARGEST;

        let mut tmp2 = MODULUS;
        tmp2 -= &LARGEST;

        assert_eq!(tmp, tmp2);
    }

    #[test]
    fn test_multiplication() {
        let mut cur = LARGEST;

        for _ in 0..100 {
            let mut tmp = cur;
            tmp *= &cur;

            let mut tmp2 = FieldElement::zero();
            for b in cur
                .to_bytes()
                .iter()
                .rev()
                .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
            {
                let tmp3 = tmp2;
                tmp2.add_assign(&tmp3);

                if b {
                    tmp2.add_assign(&cur);
                }
            }

            assert_eq!(tmp, tmp2);

            cur.add_assign(&LARGEST);
        }
    }

    #[test]
    fn test_squaring() {
        let mut cur = LARGEST;

        for _ in 0..100 {
            let mut tmp = cur;
            tmp = tmp.square();

            let mut tmp2 = FieldElement::zero();
            for b in cur
                .to_bytes()
                .iter()
                .rev()
                .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
            {
                let tmp3 = tmp2;
                tmp2.add_assign(&tmp3);

                if b {
                    tmp2.add_assign(&cur);
                }
            }

            assert_eq!(tmp, tmp2);

            cur.add_assign(&LARGEST);
        }
    }

    #[test]
    fn test_sqrt() {
        /*
        let a = FieldElement::from_be_hex(
            "4f513cd2261276cff62ee29f160e37ab696186232f43ae681fe57fad91ef2135",
        );
        println!("a {:?}", a);
        let result = a.sqrt().unwrap();
        println!("result {:?}", result);
         */
    }

    #[test]
    fn test_inversion() {
        assert_eq!(FieldElement::zero().invert().is_none().unwrap_u8(), 1);
        assert_eq!(FieldElement::one().invert().unwrap(), FieldElement::one());
        assert_eq!(
            (-&FieldElement::one()).invert().unwrap(),
            -&FieldElement::one()
        );

        let a = FieldElement::from(123);
        let result = a.invert().unwrap();
        println!("result {:?}", result);

        let mut tmp = R2;

        for _ in 0..100 {
            let mut tmp2 = tmp.invert().unwrap();
            println!("tmp2 {:?}", tmp2);
            tmp2.mul_assign(&tmp);

            assert_eq!(tmp2, FieldElement::one());

            tmp.add_assign(&R2);
        }
    }

    #[test]
    fn test_invert_is_pow() {
        let q_minus_2 = [
            0xbfd25e8cd036413f,
            0xbaaedce6af48a03b,
            0xfffffffffffffffe,
            0xffffffffffffffff,
        ];

        let mut r1 = R;
        let mut r2 = R;
        let mut r3 = R;

        for _ in 0..100 {
            r1 = r1.invert().unwrap();
            r2 = r2.pow_vartime(&q_minus_2);
            r3 = r3.pow(&q_minus_2);

            assert_eq!(r1, r2);
            assert_eq!(r2, r3);
            // Add R so we check something different next time around
            r1.add_assign(&R);
            r2 = r1;
            r3 = r1;
        }
    }

    #[test]
    fn test_from_raw() {
        assert_eq!(
            FieldElement::from_raw([0x402da1732fc9bebe, 0x4551231950b75fc4, 0x1, 0x0]),
            FieldElement::from_raw([0xffffffffffffffff; 4])
        );

        assert_eq!(
            FieldElement::from_raw(MODULUS.0[..4].try_into().unwrap()),
            FieldElement::zero()
        );

        assert_eq!(FieldElement::from_raw([1, 0, 0, 0]), R);
    }

    #[test]
    fn test_double() {
        let a = FieldElement::from_raw([
            0x1fff3231233ffffd,
            0x4884b7fa00034802,
            0x998c4fefecbc4ff3,
            0x1824b159acc50562,
        ]);

        assert_eq!(a.double(), a + a);
    }
}
