use super::utils::{Assign, AssignArray};
use crate::{chips::secq256k1::Secq256k1Chip, transcript::HopliteTranscript};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::{bigint::CRTInteger, ecc::fixed_base};
use hoplite::{
    circuit_vals::{CVProductProof, ToCircuitVal},
    commitments::MultiCommitGens,
};
use libspartan::transcript::{ProofTranscript, Transcript};
use secpq_curves::group::Curve;

use super::pedersen_commit::PedersenCommitChip;

pub struct AssignedProofOfProd<'v, F: PrimeField> {
    pub alpha: EcPoint<F, CRTInteger<'v, F>>,
    pub beta: EcPoint<F, CRTInteger<'v, F>>,
    pub delta: EcPoint<F, CRTInteger<'v, F>>,
    pub z: [CRTInteger<'v, F>; 5],
}

impl<'v, F: PrimeField> Assign<'v, F, AssignedProofOfProd<'v, F>> for CVProductProof {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> AssignedProofOfProd<'v, F> {
        let alpha = self.alpha.assign(ctx, secq_chip);
        let beta = self.beta.assign(ctx, secq_chip);
        let delta = self.delta.assign(ctx, secq_chip);
        let z = self.z.assign(ctx, secq_chip);

        AssignedProofOfProd {
            alpha,
            beta,
            delta,
            z,
        }
    }
}

pub struct ProofOfProdChip<F: PrimeField> {
    pub secq_chip: Secq256k1Chip<F>,
    pub pedersen_chip: PedersenCommitChip<F>,
    pub window_bits: usize,
}

impl<'v, F: PrimeField> ProofOfProdChip<F> {
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

    pub fn verify(
        &self,
        ctx: &mut Context<'v, F>,

        X: &EcPoint<F, CRTInteger<'v, F>>,
        Y: &EcPoint<F, CRTInteger<'v, F>>,
        Z: &EcPoint<F, CRTInteger<'v, F>>,
        proof: AssignedProofOfProd<'v, F>,
        gens_n: &MultiCommitGens,
        transcript: &mut Transcript,
    ) {
        let limb_bits = self.secq_chip.ecc_chip.field_chip.limb_bits;
        let window_bits = self.window_bits;
        transcript.append_protocol_name(b"product proof");

        transcript.append_circuit_point(b"X", X.clone());
        transcript.append_circuit_point(b"Y", Y.clone());
        transcript.append_circuit_point(b"Z", Z.clone());

        transcript.append_circuit_point(b"alpha", (&proof.alpha).clone());
        transcript.append_circuit_point(b"beta", (&proof.beta).clone());
        transcript.append_circuit_point(b"delta", (&proof.delta).clone());

        let c = transcript.challenge_scalar(b"c");
        let c = Some(c.to_circuit_val()).assign(ctx, &self.secq_chip);

        let z1 = &proof.z[0];
        let z2 = &proof.z[1];
        let z3 = &proof.z[2];
        let z4 = &proof.z[3];
        let z5 = &proof.z[4];

        // (7)
        let X_c = self.secq_chip.ecc_chip.scalar_mult(
            ctx,
            X,
            &c.truncation.limbs,
            limb_bits,
            window_bits,
        );
        let lhs_7 = self
            .secq_chip
            .ecc_chip
            .add_unequal(ctx, &X_c, &proof.alpha, true);
        let rhs_7 = self.pedersen_chip.commit(ctx, &z1, &z2, gens_n);
        self.secq_chip.ecc_chip.assert_equal(ctx, &lhs_7, &rhs_7);

        // (8)
        let Y_c = self.secq_chip.ecc_chip.scalar_mult(
            ctx,
            Y,
            &c.truncation.limbs,
            limb_bits,
            window_bits,
        );
        let lhs_8 = self
            .secq_chip
            .ecc_chip
            .add_unequal(ctx, &Y_c, &proof.beta, true);

        let rhs_8 = self.pedersen_chip.commit(ctx, &z3, &z4, gens_n);

        self.secq_chip.ecc_chip.assert_equal(ctx, &lhs_8, &rhs_8);

        // (9)
        let Z_c = self.secq_chip.ecc_chip.scalar_mult(
            ctx,
            Z,
            &c.truncation.limbs,
            limb_bits,
            window_bits,
        );
        let lhs_9 = self
            .secq_chip
            .ecc_chip
            .add_unequal(ctx, &Z_c, &proof.delta, true);

        let rhs_9_gx = self.secq_chip.ecc_chip.scalar_mult(
            ctx,
            X,
            &z3.truncation.limbs,
            limb_bits,
            window_bits,
        );

        let rhs_9_hb = fixed_base::scalar_multiply(
            &self.secq_chip.ecc_chip.field_chip,
            ctx,
            &gens_n.h.to_affine(),
            &z5.truncation.limbs,
            limb_bits,
            window_bits,
        );

        let rhs_9 = self
            .secq_chip
            .ecc_chip
            .add_unequal(ctx, &rhs_9_gx, &rhs_9_hb, true);

        self.secq_chip.ecc_chip.assert_equal(ctx, &lhs_9, &rhs_9);
    }
}
