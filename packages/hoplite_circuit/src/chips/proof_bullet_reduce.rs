use super::utils::{Assign, AssignArray};
use crate::{chips::secq256k1::Secq256k1Chip, transcript::HopliteTranscript, Fq};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::fields::FieldChip;
use halo2_ecc::{bigint::CRTInteger, ecc::fixed_base};
use hoplite::{
    circuit_vals::{CVProductProof, FromCircuitVal, ToCircuitVal},
    commitments::MultiCommitGens,
};
use libspartan::{
    group::CompressedGroup,
    transcript::{ProofTranscript, Transcript},
};
use num_bigint::BigUint;
use num_traits::identities::Zero;
use secpq_curves::group::{Curve, Group};
use secpq_curves::Secq256k1;

use super::pedersen_commit::PedersenCommitChip;

#[derive(Clone)]
pub struct AssignedBulletReductionProof<'v, F: PrimeField, const N: usize> {
    pub L_vec: [EcPoint<F, CRTInteger<'v, F>>; N],
    pub R_vec: [EcPoint<F, CRTInteger<'v, F>>; N],
}

#[derive(Clone)]
pub struct BulletReduceChip<F: PrimeField, const N: usize> {
    pub secq_chip: Secq256k1Chip<F>,
    pub pedersen_chip: PedersenCommitChip<F>,
    pub window_bits: usize,
}

impl<'v, F: PrimeField, const N: usize> BulletReduceChip<F, N> {
    pub fn construct(
        secq_chip: Secq256k1Chip<F>,
        pedersen_chip: PedersenCommitChip<F>,
        window_bits: usize,
    ) -> Self {
        Self {
            secq_chip,
            pedersen_chip,
            window_bits,
        }
    }

    fn batch_invert(&self, ctx: &mut Context<'v, F>, a: [CRTInteger<'v, F>; N]) {}

    pub fn verify(
        &self,
        ctx: &mut Context<'v, F>,
        upsilon: &EcPoint<F, CRTInteger<'v, F>>, // The upsilon calculated in this func should equal this
        a_L: &[CRTInteger<'v, F>; N],
        a_R: &[CRTInteger<'v, F>; N],
        upsilon_L: &[EcPoint<F, CRTInteger<'v, F>>; N],
        upsilon_R: &[EcPoint<F, CRTInteger<'v, F>>; N],
        G_L: &[Secq256k1; N],
        G_R: &[Secq256k1; N],
        transcript: &mut Transcript,
    ) -> (
        EcPoint<F, CRTInteger<'v, F>>,
        CRTInteger<'v, F>,
        EcPoint<F, CRTInteger<'v, F>>,
    ) {
        let limb_bits = self.secq_chip.ecc_chip.field_chip.limb_bits;
        // #####
        // 1: Compute the verification scalars
        // #####

        // Compute challenges
        let mut challenges = Vec::with_capacity(N);
        for (L, R) in upsilon_L.iter().zip(upsilon_R.iter()) {
            transcript.append_circuit_point(b"L", L.clone());
            transcript.append_circuit_point(b"R", R.clone());
            let c_i = transcript.challenge_scalar(b"u");
            let c_i = Some(c_i.to_circuit_val()).assign(ctx, &self.secq_chip);
            challenges.push(c_i);
        }

        let challenges_inv = challenges.clone();

        // 2. Compute the invert of the challenges
        // TODO: Compute the invert!
        // Scalar::batch_invert(&mut challenges_inv);

        // 3. Compute the square of the challenges
        let mut challenges_sq = vec![];
        for c in challenges.clone() {
            let c_i_squared = self.secq_chip.fq_chip.mul(ctx, &c, &c);
            challenges_sq.push(c_i_squared.clone());
        }

        let mut challenges_inv_sq = vec![];
        for c in challenges_inv.clone() {
            let c_i_squared = self.secq_chip.fq_chip.mul(ctx, &c, &c);
            challenges_inv_sq.push(c_i_squared.clone());
        }

        let mut upsilon_hat = self
            .secq_chip
            .ecc_chip
            .assign_constant_point(ctx, Secq256k1::identity().to_affine());

        for i in 0..N {
            let p_i_l = self.secq_chip.ecc_chip.scalar_mult(
                ctx,
                &upsilon_L[i],
                &challenges_sq[i].truncation.limbs,
                limb_bits,
                4,
            );
            let p_i_r = self.secq_chip.ecc_chip.scalar_mult(
                ctx,
                &upsilon_R[i],
                &challenges_inv_sq[i].truncation.limbs,
                limb_bits,
                4,
            );

            let p_i = self
                .secq_chip
                .ecc_chip
                .add_unequal(ctx, &p_i_l, &p_i_r, true);

            upsilon_hat = self
                .secq_chip
                .ecc_chip
                .add_unequal(ctx, &p_i, &upsilon_hat, true);
        }

        let mut a_hat = self.secq_chip.fq_chip.load_constant(ctx, BigUint::zero());
        for i in 0..N {
            let a_i_l = self.secq_chip.fq_chip.mul(ctx, &a_L[i], &challenges_inv[i]);
            let a_i_r = self.secq_chip.fq_chip.mul(ctx, &a_R[i], &challenges[i]);
            let a_i_no_carry = self.secq_chip.fq_chip.add_no_carry(ctx, &a_i_l, &a_i_r);
            let a_i = self.secq_chip.fq_chip.carry_mod(ctx, &a_i_no_carry);

            let a_hat_no_carry = self.secq_chip.fq_chip.add_no_carry(ctx, &a_i, &a_hat);
            a_hat = self.secq_chip.fq_chip.carry_mod(ctx, &a_hat_no_carry);
        }

        let mut g_hat = self
            .secq_chip
            .ecc_chip
            .assign_constant_point(ctx, Secq256k1::identity().to_affine());

        for i in 0..N {
            let g_i_l = fixed_base::scalar_multiply(
                &self.secq_chip.ecc_chip.field_chip,
                ctx,
                &G_L[i].to_affine(),
                &challenges_inv[i].truncation.limbs,
                limb_bits,
                self.window_bits,
            );

            let g_i_r = fixed_base::scalar_multiply(
                &self.secq_chip.ecc_chip.field_chip,
                ctx,
                &G_R[i].to_affine(),
                &challenges[i].truncation.limbs,
                limb_bits,
                self.window_bits,
            );

            let g_i = self
                .secq_chip
                .ecc_chip
                .add_unequal(ctx, &g_i_l, &g_i_r, true);

            g_hat = self.secq_chip.ecc_chip.add_unequal(ctx, &g_i, &g_hat, true);
        }

        (upsilon_hat, a_hat, g_hat)
    }
}
