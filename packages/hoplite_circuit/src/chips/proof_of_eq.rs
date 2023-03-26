use super::utils::Assign;
use crate::{chips::secq256k1::Secq256k1Chip, transcript::HopliteTranscript};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::{bigint::CRTInteger, ecc::fixed_base};
use hoplite::{
    circuit_vals::{CVEqualityProof, ToCircuitVal},
    commitments::MultiCommitGens,
};
use libspartan::transcript::{ProofTranscript, Transcript};
use secpq_curves::group::Curve;

pub struct AssignedProofOfEq<'v, F: PrimeField> {
    pub alpha: EcPoint<F, CRTInteger<'v, F>>,
    pub z: CRTInteger<'v, F>,
}

impl<'v, F: PrimeField> Assign<'v, F, AssignedProofOfEq<'v, F>> for CVEqualityProof {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> AssignedProofOfEq<'v, F> {
        let alpha = self.alpha.assign(ctx, secq_chip);
        let z = self.z.assign(ctx, secq_chip);

        AssignedProofOfEq { alpha, z }
    }
}

pub struct ProofOfEqChip<F: PrimeField> {
    pub secq_chip: Secq256k1Chip<F>,
    pub window_bits: usize,
}

impl<'v, F: PrimeField> ProofOfEqChip<F> {
    pub fn construct(secq_chip: Secq256k1Chip<F>, window_bits: usize) -> Self {
        Self {
            secq_chip,
            window_bits,
        }
    }

    pub fn verify(
        &self,
        ctx: &mut Context<'v, F>,
        C1: &EcPoint<F, CRTInteger<'v, F>>,
        C2: &EcPoint<F, CRTInteger<'v, F>>,
        proof: AssignedProofOfEq<'v, F>,
        gens_n: &MultiCommitGens,
        transcript: &mut Transcript,
    ) {
        let limb_bits = self.secq_chip.ecc_chip.field_chip.limb_bits;
        let window_bits = self.window_bits;
        transcript.append_protocol_name(b"equality proof");

        transcript.append_circuit_point(b"C1", C1.clone());
        transcript.append_circuit_point(b"C2", C2.clone());

        transcript.append_circuit_point(b"alpha", (&proof.alpha).clone());

        let lhs = fixed_base::scalar_multiply(
            &self.secq_chip.ecc_chip.field_chip,
            ctx,
            &gens_n.h.to_affine(),
            &proof.z.truncation.limbs,
            limb_bits,
            window_bits,
        );

        let c = transcript.challenge_scalar(b"c");
        let c = Some(c.to_circuit_val()).assign(ctx, &self.secq_chip);

        let C1_minus_C2 = self.secq_chip.ecc_chip.sub_unequal(ctx, &C1, &C2, true);
        let C1_minus_C2_c = self.secq_chip.ecc_chip.scalar_mult(
            ctx,
            &C1_minus_C2,
            &c.truncation.limbs,
            limb_bits,
            window_bits,
        );

        let rhs = self
            .secq_chip
            .ecc_chip
            .add_unequal(ctx, &C1_minus_C2_c, &proof.alpha, true);

        self.secq_chip.ecc_chip.assert_equal(ctx, &lhs, &rhs);
    }
}
