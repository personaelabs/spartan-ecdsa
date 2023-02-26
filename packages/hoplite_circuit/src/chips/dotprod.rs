use crate::{
    chips::pedersen_commit::PedersenCommitChip,
    {FpChip, Fq, FqChip, ZKDotProdProof},
};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_ecc::ecc::{EcPoint, EccChip};
use halo2_ecc::fields::FieldChip;
use halo2_proofs::circuit::Value;
use hoplite::{commitments::MultiCommitGens, DEGREE_BOUND};

pub struct AssignedZKDotProdProof<'v, F: PrimeField> {
    pub delta: EcPoint<F, CRTInteger<'v, F>>,
    pub beta: EcPoint<F, CRTInteger<'v, F>>,
    pub z: [CRTInteger<'v, F>; DEGREE_BOUND + 1],
    pub z_delta: CRTInteger<'v, F>,
    pub z_beta: CRTInteger<'v, F>,
}

pub struct ZKDotProdChip<F: PrimeField> {
    pub ecc_chip: EccChip<F, FpChip<F>>,
    pub fq_chip: FqChip<F>,
    pub pedersen_chip: PedersenCommitChip<F>,
    window_bits: usize,
}

impl<F: PrimeField> ZKDotProdChip<F> {
    pub fn construct(
        ecc_chip: EccChip<F, FpChip<F>>,
        fq_chip: FqChip<F>,
        pedersen_chip: PedersenCommitChip<F>,
    ) -> Self {
        Self {
            ecc_chip,
            fq_chip,
            pedersen_chip,
            window_bits: 4,
        }
    }

    fn dot_prod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &[CRTInteger<'v, F>],
        b: &[CRTInteger<'v, F>],
    ) -> CRTInteger<'v, F> {
        let mut sum = self
            .fq_chip
            .load_private(ctx, FqChip::<F>::fe_to_witness(&Value::known(Fq::zero())));

        // Implement this
        for i in 0..a.len() {
            let prod_no_carry = self.fq_chip.mul_no_carry(ctx, &a[i], &b[i]);
            let sum_no_carry = self.fq_chip.add_no_carry(ctx, &sum, &prod_no_carry);
            sum = self.fq_chip.carry_mod(ctx, &sum_no_carry);
        }

        sum
    }

    pub fn verify<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        tau: &EcPoint<F, CRTInteger<'v, F>>,
        a: [CRTInteger<'v, F>; DEGREE_BOUND + 1],
        com_poly: &EcPoint<F, CRTInteger<'v, F>>,
        proof: AssignedZKDotProdProof<'v, F>,
        gens_1: &MultiCommitGens,
        gens_n: &MultiCommitGens,
    ) {
        let max_bits = self.fq_chip.limb_bits;

        // TODO: Actually compute the challenge!
        let c = self
            .fq_chip
            .load_private(ctx, FqChip::<F>::fe_to_witness(&Value::known(Fq::one())));

        // (13)
        let epsilon_c = self.ecc_chip.scalar_mult(
            ctx,
            &com_poly,
            &c.truncation.limbs,
            max_bits,
            self.window_bits,
        );

        // (epsilon * c) + delta
        let lhs = self
            .ecc_chip
            .add_unequal(ctx, &epsilon_c, &proof.delta, true);

        // com(z, z_delta)
        let rhs = self
            .pedersen_chip
            .multi_commit(ctx, &proof.z, &proof.z_delta, &gens_n);

        self.ecc_chip.assert_equal(ctx, &lhs, &rhs);

        // (14)
        let tau_c = self
            .ecc_chip
            .scalar_mult(ctx, &tau, &c.truncation.limbs, max_bits, 4);

        // (tau * c) + beta
        let lhs = self.ecc_chip.add_unequal(ctx, &tau_c, &proof.beta, true);

        let a_dot_z = self.dot_prod(ctx, &a, &proof.z);

        // com((a ・ z), z_beta)
        let rhs = self
            .pedersen_chip
            .commit(ctx, &a_dot_z, &proof.z_beta, &gens_1);

        self.ecc_chip.assert_equal(ctx, &lhs, &rhs);
    }
}
