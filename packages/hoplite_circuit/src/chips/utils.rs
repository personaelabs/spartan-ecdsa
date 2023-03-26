use super::secq256k1::Secq256k1Chip;
use halo2_base::{utils::PrimeField, Context};

pub trait Assign<'v, F: PrimeField, A> {
    fn assign(&self, ctx: &mut Context<'v, F>, secq_chip: &Secq256k1Chip<F>) -> A;
}

pub trait AssignArray<'v, F: PrimeField, A, const N: usize> {
    fn assign(&self, ctx: &mut Context<'v, F>, secq_chip: &Secq256k1Chip<F>) -> [A; N];
}
