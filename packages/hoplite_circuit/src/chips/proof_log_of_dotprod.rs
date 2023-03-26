use crate::{chips::proof_bullet_reduce::BulletReduceChip, transcript::HopliteTranscript};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::{bigint::CRTInteger, ecc::fixed_base};
use hoplite::{circuit_vals::ToCircuitVal, commitments::MultiCommitGens};
use libspartan::transcript::{ProofTranscript, Transcript};

use super::{
    proof_bullet_reduce::AssignedBulletReductionProof, secq256k1::Secq256k1Chip, utils::Assign,
};
use secpq_curves::group::Curve;

pub struct AssignedDotProductProofLog<'v, F: PrimeField, const N: usize> {
    pub bullet_reduction_proof: AssignedBulletReductionProof<'v, F, N>,
    pub delta: EcPoint<F, CRTInteger<'v, F>>,
    pub beta: EcPoint<F, CRTInteger<'v, F>>,
    pub z1: CRTInteger<'v, F>,
    pub z2: CRTInteger<'v, F>,
}

#[derive(Clone)]
pub struct ProofLogOfDotProdChip<F: PrimeField, const N: usize, const N_HALF: usize> {
    pub secq_chip: Secq256k1Chip<F>,
    pub bullet_reduce_chip: BulletReduceChip<F, N_HALF>,
    pub window_bits: usize,
}

impl<'v, F: PrimeField, const N: usize, const N_HALF: usize> ProofLogOfDotProdChip<F, N, N_HALF> {
    pub fn construct(
        secq_chip: Secq256k1Chip<F>,
        bullet_reduce_chip: BulletReduceChip<F, N_HALF>,
        window_bits: usize,
    ) -> Self {
        Self {
            secq_chip,
            bullet_reduce_chip,
            window_bits,
        }
    }

    pub fn verify(
        &self,
        ctx: &mut Context<'v, F>,
        a: &[CRTInteger<'v, F>; N],
        Cx: &EcPoint<F, CRTInteger<'v, F>>,
        Cy: &EcPoint<F, CRTInteger<'v, F>>,
        proof: &AssignedDotProductProofLog<'v, F, N_HALF>,
        gens_1: &MultiCommitGens,
        gens_n: &MultiCommitGens,
        transcript: &mut Transcript,
    ) {
        let limb_bits = self.secq_chip.ecc_chip.field_chip.limb_bits;
        transcript.append_protocol_name(b"dot product proof (log)");
        transcript.append_circuit_point(b"Cx", Cx.clone());
        transcript.append_circuit_point(b"Cy", Cy.clone());

        transcript.append_message(b"a", b"begin_append_vector");
        for a_i in a {
            transcript.append_circuit_fq(b"a", a_i.clone());
        }
        transcript.append_message(b"a", b"end_append_vector");

        // Upsilon

        let Gamma = self.secq_chip.ecc_chip.add_unequal(ctx, &Cx, &Cy, true);

        let a_L = a[0..N_HALF].try_into().unwrap();
        let a_R = a[N_HALF..].try_into().unwrap();

        let G_L = &gens_n.G[0..N_HALF].try_into().unwrap();
        let G_R = &gens_n.G[N_HALF..].try_into().unwrap();

        let bullet_reduction_proof = &proof.bullet_reduction_proof;
        let upsilon_L = &bullet_reduction_proof.clone().L_vec.try_into().unwrap();
        let upsilon_R = &bullet_reduction_proof.clone().R_vec.try_into().unwrap();

        let (Gamma_hat, a_hat, g_hat) = self.bullet_reduce_chip.verify(
            ctx, &Gamma, a_L, a_R, upsilon_L, upsilon_R, G_L, G_R, transcript,
        );

        transcript.append_circuit_point(b"delta", proof.delta.clone());
        transcript.append_circuit_point(b"beta", proof.beta.clone());

        let c = transcript.challenge_scalar(b"c");
        let c = Some(c.to_circuit_val()).assign(ctx, &self.secq_chip);

        let Gamma_hat_c = self.secq_chip.ecc_chip.scalar_mult(
            ctx,
            &Gamma_hat,
            &c.truncation.limbs,
            limb_bits,
            self.window_bits,
        );

        let Gamma_hat_c_beta =
            self.secq_chip
                .ecc_chip
                .add_unequal(ctx, &Gamma_hat_c, &proof.beta, true);
        let lhs_1 = self.secq_chip.ecc_chip.scalar_mult(
            ctx,
            &Gamma_hat_c_beta,
            &a_hat.truncation.limbs,
            limb_bits,
            self.window_bits,
        );

        let lhs = self
            .secq_chip
            .ecc_chip
            .add_unequal(ctx, &lhs_1, &proof.delta, true);

        let G_a_hat = fixed_base::scalar_multiply(
            self.secq_chip.ecc_chip.field_chip(),
            ctx,
            &gens_1.G[0].to_affine(),
            &a_hat.truncation.limbs,
            limb_bits,
            self.window_bits,
        );

        let rhs_1 = self
            .secq_chip
            .ecc_chip
            .add_unequal(ctx, &G_a_hat, &g_hat, true);

        let rhs_2 = self.secq_chip.ecc_chip.scalar_mult(
            ctx,
            &rhs_1,
            &proof.z1.truncation.limbs,
            limb_bits,
            self.window_bits,
        );

        let rhs_3 = fixed_base::scalar_multiply(
            self.secq_chip.ecc_chip.field_chip(),
            ctx,
            &gens_1.h.to_affine(),
            &proof.z2.truncation.limbs,
            limb_bits,
            self.window_bits,
        );

        let rhs = self
            .secq_chip
            .ecc_chip
            .add_unequal(ctx, &rhs_2, &rhs_3, true);

        self.secq_chip.ecc_chip.assert_equal(ctx, &lhs, &rhs);
    }
}
