use super::{
    proof_log_of_dotprod::{AssignedDotProductProofLog, ProofLogOfDotProdChip},
    utils::{Assign, AssignArray},
};
use crate::chips::{proof_bullet_reduce::AssignedBulletReductionProof, secq256k1::Secq256k1Chip};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_ecc::ecc::EcPoint;
use hoplite::{circuit_vals::CVPolyEvalProof, commitments::MultiCommitGens};
use libspartan::transcript::{ProofTranscript, Transcript};
use secpq_curves::{
    group::{Curve, Group},
    Secq256k1,
};

pub trait AssignN<'v, F: PrimeField, const N: usize> {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> AssignedPolyEvalProof<'v, F, N>;
}

pub struct AssignedPolyEvalProof<'v, F: PrimeField, const N: usize> {
    pub proof: AssignedDotProductProofLog<'v, F, N>,
}

impl<'v, F: PrimeField, const N: usize> AssignN<'v, F, N> for CVPolyEvalProof<N> {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> AssignedPolyEvalProof<'v, F, N> {
        let z1 = self.proof.z1.assign(ctx, secq_chip);
        let z2 = self.proof.z2.assign(ctx, secq_chip);
        let beta = self.proof.beta.assign(ctx, secq_chip);
        let delta = self.proof.delta.assign(ctx, secq_chip);

        let L_vec = self
            .proof
            .bullet_reduction_proof
            .L_vec
            .assign(ctx, secq_chip);

        let R_vec = self
            .proof
            .bullet_reduction_proof
            .R_vec
            .assign(ctx, secq_chip);

        let bullet_reduction_proof = AssignedBulletReductionProof { L_vec, R_vec };

        let proof = AssignedDotProductProofLog {
            bullet_reduction_proof,
            delta,
            beta,
            z1,
            z2,
        };

        AssignedPolyEvalProof { proof }
    }
}

pub struct PolyEvalProofChip<F: PrimeField, const N: usize, const N_HALF: usize> {
    pub secq_chip: Secq256k1Chip<F>,
    pub proof_log_dotprod_chip: ProofLogOfDotProdChip<F, N, N_HALF>,
    pub window_bits: usize,
}

impl<'v, F: PrimeField, const N: usize, const N_HALF: usize> PolyEvalProofChip<F, N, N_HALF> {
    pub fn construct(
        secq_chip: Secq256k1Chip<F>,
        proof_log_dotprod_chip: ProofLogOfDotProdChip<F, N, N_HALF>,
        window_bits: usize,
    ) -> Self {
        Self {
            secq_chip,
            proof_log_dotprod_chip,
            window_bits,
        }
    }

    pub fn verify(
        &self,
        ctx: &mut Context<'v, F>,
        r: &[CRTInteger<'v, F>; N],
        C_Zr: &EcPoint<F, CRTInteger<'v, F>>,
        comm_polys: &[EcPoint<F, CRTInteger<'v, F>>; N],
        proof: AssignedPolyEvalProof<'v, F, N_HALF>,
        gens_1: &MultiCommitGens,
        gens_n: &MultiCommitGens,
        transcript: &mut Transcript,
    ) {
        let limbs_bits = self.secq_chip.ecc_chip.field_chip.limb_bits;
        transcript.append_protocol_name(b"polynomial evaluation proof");

        // Evaluate the eq poly over the boolean hypercube bounded to r
        let r_left = &r[0..N / 2];
        let r_right = &r[N / 2..];

        // TODO: IMplement the evals() constraint
        // L = evals(r_left);
        // R = evals(r_right);
        let L = r_left;
        let R = r_right;

        // L * r_left;
        let mut C_LZ = self
            .secq_chip
            .ecc_chip
            .assign_constant_point(ctx, Secq256k1::identity().to_affine());

        for i in 0..comm_polys.len() {
            let comm_poly_L = self.secq_chip.ecc_chip.scalar_mult(
                ctx,
                &comm_polys[i],
                &L[i].truncation.limbs,
                limbs_bits,
                self.window_bits,
            );

            C_LZ = self
                .secq_chip
                .ecc_chip
                .add_unequal(ctx, &comm_poly_L, &C_LZ, true);
        }

        self.proof_log_dotprod_chip.verify(
            ctx,
            R.try_into().unwrap(),
            &C_LZ,
            &C_Zr,
            &proof.proof,
            &gens_1,
            &gens_n,
            transcript,
        );
    }
}
