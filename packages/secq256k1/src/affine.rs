use std::iter::Sum;
use std::ops::{Add, Mul, MulAssign, Neg, Sub};
use std::ops::{AddAssign, SubAssign};

use super::{ProjectivePoint, Secq256K1};
use crate::field::BaseField;
use crate::hashtocurve::hash_to_curve;
use crate::{EncodedPoint, Scalar};
use k256::elliptic_curve::subtle::Choice;
pub use primeorder::elliptic_curve::group::Group;
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

use crate::FieldElement;

impl AffinePoint {
    pub const fn identity() -> Self {
        AffinePoint(AffinePointCore::IDENTITY)
    }

    pub const fn generator() -> Self {
        AffinePoint(AffinePointCore::GENERATOR)
    }

    // The isogeny constants are outputs of hashtocurve_params.sage

    pub const fn iso_a() -> FieldElement {
        // 3642995984045157452672683439396299070953881827175886364060394186787010798372
        FieldElement([
            13132896970247110882,
            16600479225705962415,
            2267171952686981219,
            10308142380130580469,
            0,
        ])
    }

    pub const fn iso_b() -> FieldElement {
        // 1771
        FieldElement([18134843254882603861, 9821735204204806823, 2250, 0, 0])
    }

    pub const fn iso_z() -> FieldElement {
        // -14
        FieldElement([
            4419027667721769679,
            17311539568058655616,
            18446744073709551596,
            18446744073709551615,
            0,
        ])
    }

    pub const fn iso_constants() -> [FieldElement; 13] {
        [
            FieldElement::from_raw([
                7679007869575068054,
                9522933797269734319,
                16397105843297379213,
                10248191152060862008,
            ]),
            FieldElement::from_raw([
                9826996953646961554,
                15182850926035153421,
                14578491762904662818,
                12647934416601614380,
            ]),
            FieldElement::from_raw([
                12837744973953074055,
                3022921441994356503,
                9226076221592167090,
                5322610924144458968,
            ]),
            FieldElement::from_raw([
                7679007869575068113,
                9522933797269734319,
                16397105843297379213,
                10248191152060862008,
            ]),
            FieldElement::from_raw([
                5509687591411919004,
                593833991126057235,
                2079217350175104065,
                3150945307157219731,
            ]),
            FieldElement::from_raw([
                10055942181862970998,
                5902098865151897053,
                9296385024764340435,
                14583286435933530837,
            ]),
            FieldElement::from_raw([
                1018159320366879645,
                7658288605871115257,
                17763531330238827481,
                9564978408590137874,
            ]),
            FieldElement::from_raw([
                14136870513678256585,
                7591425463017576710,
                7289245881452331409,
                6323967208300807190,
            ]),
            FieldElement::from_raw([
                14802773332216597422,
                16078857340678580677,
                3084372689655359971,
                1069495981486797935,
            ]),
            FieldElement::from_raw([
                2553960894281893207,
                13252224180066972444,
                13664254869414482677,
                11614616639002310276,
            ]),
            FieldElement::from_raw([
                17487903423972654314,
                10114123023543861660,
                12342198062117431905,
                4726417960735829596,
            ]),
            FieldElement::from_raw([
                2523398215118668000,
                9249176628478019873,
                9442411000583469692,
                6856371160381489280,
            ]),
            FieldElement::from_raw([
                13822214165235121741,
                13451932020343611451,
                18446744073709551614,
                18446744073709551615,
            ]),
        ]
    }

    pub fn compress(&self) -> EncodedPoint {
        self.0.to_encoded_point(true)
    }

    pub fn decompress(bytes: EncodedPoint) -> CtOption<Self> {
        AffinePointCore::from_encoded_point(&bytes).map(AffinePoint)
    }

    pub fn from_uniform_bytes(bytes: &[u8; 128]) -> Self {
        let u1 = FieldElement::from_bytes_wide(bytes[0..64].try_into().unwrap());
        let u2 = FieldElement::from_bytes_wide(bytes[64..128].try_into().unwrap());

        let (p1_coords, p2_coords) = hash_to_curve(
            u1,
            u2,
            Self::iso_a(),
            Self::iso_b(),
            Self::iso_z(),
            Self::iso_constants(),
        );
        let p1 = AffinePoint::decompress(EncodedPoint::from_affine_coordinates(
            &p1_coords.0.to_be_bytes().into(),
            &p1_coords.1.to_be_bytes().into(),
            false,
        ))
        .unwrap();

        let p2 = AffinePoint::decompress(EncodedPoint::from_affine_coordinates(
            &p2_coords.0.to_be_bytes().into(),
            &p2_coords.1.to_be_bytes().into(),
            false,
        ))
        .unwrap();

        p1 + p2
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_uniform_bytes() {
        // Case 1
        let pseudo_bytes = [1u8; 128];
        let p1 = AffinePoint::from_uniform_bytes(&pseudo_bytes);

        let expected_point_1 = AffinePoint::decompress(
            EncodedPoint::from_bytes(&[
                3, 24, 36, 60, 213, 183, 10, 225, 197, 211, 160, 231, 226, 115, 43, 236, 156, 4,
                195, 217, 173, 140, 136, 199, 137, 204, 135, 28, 56, 55, 158, 90, 42,
            ])
            .unwrap(),
        )
        .unwrap();

        assert_eq!(p1, expected_point_1);

        // Case 2
        let pseudo_bytes = [255u8; 128];
        let p2 = AffinePoint::from_uniform_bytes(&pseudo_bytes);
        let expected_point_2 = AffinePoint::decompress(
            EncodedPoint::from_bytes(&[
                2, 224, 201, 211, 109, 246, 2, 231, 80, 53, 75, 7, 198, 101, 138, 177, 41, 203, 12,
                215, 7, 190, 221, 177, 146, 53, 58, 202, 32, 229, 192, 136, 229,
            ])
            .unwrap(),
        )
        .unwrap();

        assert_eq!(p2, expected_point_2);
    }
}
