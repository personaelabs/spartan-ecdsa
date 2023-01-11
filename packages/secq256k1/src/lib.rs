pub mod affine;
pub mod field;
pub mod scalar;

pub use affine::AffinePoint;
use affine::AffinePointCore;
pub use primeorder::elliptic_curve;
pub use primeorder::elliptic_curve::bigint::U256;

use field::field_secq::FieldElement;
use primeorder::elliptic_curve::{AffineArithmetic, Curve, ProjectiveArithmetic, ScalarArithmetic};
use primeorder::{PrimeCurve, PrimeCurveParams};
pub use scalar::Scalar;

pub type EncodedPoint = primeorder::elliptic_curve::sec1::EncodedPoint<Secq256K1>;
pub type FieldBytes = primeorder::elliptic_curve::FieldBytes<Secq256K1>;
pub type ProjectivePoint = primeorder::ProjectivePoint<Secq256K1>;

pub const ORDER: U256 =
    // U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Secq256K1;

impl Curve for Secq256K1 {
    type UInt = U256;

    const ORDER: U256 =
        //    U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
}

impl PrimeCurveParams for Secq256K1 {
    type FieldElement = FieldElement;

    const ZERO: FieldElement = FieldElement::ZERO;
    const ONE: FieldElement = FieldElement::ONE;

    const EQUATION_A: FieldElement = FieldElement::ZERO;

    const EQUATION_B: FieldElement =
        FieldElement([13924965285611452217, 16516940299852029533, 8, 0, 0]); // 7 * R2

    const GENERATOR: (FieldElement, FieldElement) = (
        // 76c39f5585cb160eb6b06c87a2ce32e23134e45a097781a6a24288e37702eda6 * R2
        FieldElement([
            10469571329630693389,
            10742150477581383480,
            16610251588214968909,
            7161385764161811800,
            0,
        ]),
        // 3ffc646c7b2918b5dc2d265a8e82a7f7d18983d26e8dc055a4120ddad952677f * R2
        FieldElement([
            12565599782544440070,
            11151484775266214907,
            5786122696412099978,
            14641184162808952937,
            0,
        ]),
    );
}

impl PrimeCurve for Secq256K1 {}

impl AffineArithmetic for Secq256K1 {
    type AffinePoint = AffinePointCore;
}

impl ProjectiveArithmetic for Secq256K1 {
    type ProjectivePoint = ProjectivePoint;
}

impl ScalarArithmetic for Secq256K1 {
    type Scalar = Scalar;
}
