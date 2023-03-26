use super::utils::Assign;
use crate::{
    chips::secq256k1::Secq256k1Chip,
    transcript::HopliteTranscript,
    {FpChip, FqChip},
};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_ecc::ecc::{EcPoint, EccChip};
use halo2_ecc::fields::FieldChip;
use halo2_proofs::circuit::Value;
use hoplite::{
    circuit_vals::{CVKnowledgeProof, ToCircuitVal},
    commitments::MultiCommitGens,
};
use libspartan::transcript::{ProofTranscript, Transcript};

use super::pedersen_commit::PedersenCommitChip;

pub struct AssignedProofOfOpening<'v, F: PrimeField> {
    pub alpha: EcPoint<F, CRTInteger<'v, F>>,
    pub z1: CRTInteger<'v, F>,
    pub z2: CRTInteger<'v, F>,
}

impl<'v, F: PrimeField> Assign<'v, F, AssignedProofOfOpening<'v, F>> for CVKnowledgeProof {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> AssignedProofOfOpening<'v, F> {
        let alpha = self.alpha.assign(ctx, secq_chip);
        let z1 = self.z1.assign(ctx, secq_chip);
        let z2 = self.z2.assign(ctx, secq_chip);

        AssignedProofOfOpening { alpha, z1, z2 }
    }
}

pub struct ZKKnowledgeProofChip<F: PrimeField> {
    pub ecc_chip: EccChip<F, FpChip<F>>,
    pub fp_chip: FpChip<F>,
    pub fq_chip: FqChip<F>,
    pub pedersen_chip: PedersenCommitChip<F>,
    pub window_bits: usize,
}

impl<'v, F: PrimeField> ZKKnowledgeProofChip<F> {
    pub fn construct(
        ecc_chip: EccChip<F, FpChip<F>>,
        fp_chip: FpChip<F>,
        fq_chip: FqChip<F>,
        pedersen_chip: PedersenCommitChip<F>,
        window_bits: usize,
    ) -> Self {
        Self {
            ecc_chip,
            fp_chip,
            fq_chip,
            pedersen_chip,
            window_bits,
        }
    }

    pub fn verify(
        &self,
        ctx: &mut Context<'v, F>,
        C: &EcPoint<F, CRTInteger<'v, F>>,
        proof: AssignedProofOfOpening<'v, F>,
        gens_n: &MultiCommitGens,
        transcript: &mut Transcript,
    ) {
        let limb_bits = self.fp_chip.limb_bits;

        transcript.append_protocol_name(b"knowledge proof");

        let alpha = &proof.alpha;
        transcript.append_circuit_point(b"C", C.clone());
        transcript.append_circuit_point(b"alpha", alpha.clone());

        let c = &transcript.challenge_scalar(b"c");
        let c = self.fq_chip.load_private(
            ctx,
            FqChip::<F>::fe_to_witness(&Value::known(c.to_circuit_val())),
        );

        let lhs = self.pedersen_chip.commit(ctx, &proof.z1, &proof.z2, gens_n);

        let C_mult_c =
            self.ecc_chip
                .scalar_mult(ctx, C, &c.truncation.limbs, limb_bits, self.window_bits);

        let rhs = self.ecc_chip.add_unequal(ctx, &C_mult_c, &alpha, true);

        self.ecc_chip.assert_equal(ctx, &lhs, &rhs);
    }
}
