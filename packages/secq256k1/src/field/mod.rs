use primeorder::{
    elliptic_curve::subtle::{Choice, CtOption},
    PrimeField,
};

pub trait BaseField: PrimeField {
    fn to_bytes(&self) -> [u8; 32];
    /// Converts an element of `FieldElement` into a byte representation in
    /// big-endian byte order.
    fn to_be_bytes(&self) -> [u8; 32];
    fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self>;
}

pub trait SqrtRatio: BaseField {
    fn sqrt_ratio(u: &Self, v: &Self, z: &Self) -> (Choice, Self);
}

pub mod field_secp;
pub mod field_secq;
