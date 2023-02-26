use crate::FpChip;
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_ecc::ecc::{fixed_base, EcPoint, EccChip};
use hoplite::commitments::MultiCommitGens;
use secpq_curves::group::Curve;

#[derive(Clone)]
pub struct PedersenCommitChip<F: PrimeField> {
    pub ecc_chip: EccChip<F, FpChip<F>>,
    pub fp_chip: FpChip<F>,
    window_bits: usize,
}

impl<F: PrimeField> PedersenCommitChip<F> {
    pub fn construct(ecc_chip: EccChip<F, FpChip<F>>, fp_chip: FpChip<F>) -> Self {
        Self {
            ecc_chip,
            fp_chip,
            window_bits: 4,
        }
    }

    pub fn commit<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        x: &CRTInteger<'v, F>,
        blinder: &CRTInteger<'v, F>,
        gens: &MultiCommitGens,
    ) -> EcPoint<F, CRTInteger<'v, F>> {
        let max_bits = self.fp_chip.limb_bits;
        let gx = fixed_base::scalar_multiply(
            &self.fp_chip,
            ctx,
            &gens.G[0].to_affine(),
            &x.truncation.limbs,
            max_bits,
            self.window_bits,
        );

        let hb = fixed_base::scalar_multiply(
            &self.fp_chip,
            ctx,
            &gens.h.to_affine(),
            &blinder.truncation.limbs,
            max_bits,
            self.window_bits,
        );

        let com = self.ecc_chip.add_unequal(ctx, &gx, &hb, true);
        com
    }

    pub fn multi_commit<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        x: &[CRTInteger<'v, F>],
        blinder: &CRTInteger<'v, F>,
        gens: &MultiCommitGens,
    ) -> EcPoint<F, CRTInteger<'v, F>> {
        let max_bits = self.fp_chip.limb_bits;

        let mut g_sum = fixed_base::scalar_multiply(
            &self.fp_chip,
            ctx,
            &gens.G[0].to_affine(),
            &x[0].truncation.limbs,
            max_bits,
            self.window_bits,
        );

        for (i, x_i) in x[1..].iter().enumerate() {
            let g = fixed_base::scalar_multiply(
                &self.fp_chip,
                ctx,
                &gens.G[i + 1].to_affine(),
                &x_i.truncation.limbs,
                max_bits,
                self.window_bits,
            );

            g_sum = self.ecc_chip.add_unequal(ctx, &g_sum, &g, true);
        }

        let hb = fixed_base::scalar_multiply(
            &self.fp_chip,
            ctx,
            &gens.h.to_affine(),
            &blinder.truncation.limbs,
            max_bits,
            self.window_bits,
        );

        let com = self.ecc_chip.add_unequal(ctx, &g_sum, &hb, true);
        com
    }
}
