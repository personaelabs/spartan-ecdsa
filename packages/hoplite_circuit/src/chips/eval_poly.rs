use crate::FpChip;
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::{bigint::CRTInteger, fields::FieldChip};
use num_bigint::BigUint;
use num_traits::Zero;

pub struct EvalMLPolyChip<F: PrimeField, const N_VARS: usize> {
    pub fp_chip: FpChip<F>,
}

impl<'v, F: PrimeField, const N_VARS: usize> EvalMLPolyChip<F, N_VARS> {
    pub fn construct(fp_chip: FpChip<F>) -> Self {
        Self { fp_chip }
    }

    pub fn eval(
        &self,
        ctx: &mut Context<'v, F>,
        coeffs: &[CRTInteger<'v, F>; N_VARS],
        vals: &[CRTInteger<'v, F>; N_VARS],
    ) -> CRTInteger<'v, F> {
        let mut acc = self.fp_chip.load_constant(ctx, BigUint::zero());
        for (coeff, val) in coeffs.iter().zip(vals.iter()) {
            let term = self.fp_chip.mul(ctx, coeff, val);
            acc = self.fp_chip.add_no_carry(ctx, &term, &acc);

            self.fp_chip.carry_mod(ctx, &acc);
        }
        acc
    }
}
