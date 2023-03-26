use super::utils::{Assign, AssignArray};
use crate::{FpChip, Fq, FqChip};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::{EcPoint, EccChip},
    fields::FieldChip,
};
use halo2_proofs::circuit::Value;
use secpq_curves::Secq256k1;

#[derive(Clone)]
pub struct Secq256k1Chip<F: PrimeField> {
    pub ecc_chip: EccChip<F, FpChip<F>>,
    pub fq_chip: FqChip<F>,
}

impl<F: PrimeField> Secq256k1Chip<F> {
    pub fn construct(ecc_chip: EccChip<F, FpChip<F>>, fq_chip: FqChip<F>) -> Self {
        Self { ecc_chip, fq_chip }
    }
}

impl<'v, F: PrimeField> Assign<'v, F, EcPoint<F, CRTInteger<'v, F>>> for Option<Secq256k1> {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> EcPoint<F, CRTInteger<'v, F>> {
        secq_chip.ecc_chip.load_private(
            ctx,
            (
                self.map_or(Value::unknown(), |p| Value::known(p.x)),
                self.map_or(Value::unknown(), |p| Value::known(p.y)),
            ),
        )
    }
}

impl<'v, F: PrimeField> Assign<'v, F, CRTInteger<'v, F>> for Option<Fq> {
    fn assign(&self, ctx: &mut Context<'v, F>, secq_chip: &Secq256k1Chip<F>) -> CRTInteger<'v, F> {
        secq_chip.fq_chip.load_private(
            ctx,
            self.map_or(Value::unknown(), |z| {
                FqChip::<F>::fe_to_witness(&Value::known(z))
            }),
        )
    }
}

impl<'v, F: PrimeField, const N: usize> AssignArray<'v, F, CRTInteger<'v, F>, N>
    for [Option<Fq>; N]
{
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> [CRTInteger<'v, F>; N] {
        self.iter()
            .map(|v| v.assign(ctx, secq_chip))
            .collect::<Vec<CRTInteger<'v, F>>>()
            .try_into()
            .unwrap()
    }
}

impl<'v, F: PrimeField, const N: usize> AssignArray<'v, F, EcPoint<F, CRTInteger<'v, F>>, N>
    for [Option<Secq256k1>; N]
{
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> [EcPoint<F, CRTInteger<'v, F>>; N] {
        self.iter()
            .map(|v| v.assign(ctx, secq_chip))
            .collect::<Vec<EcPoint<F, CRTInteger<'v, F>>>>()
            .try_into()
            .unwrap()
    }
}
