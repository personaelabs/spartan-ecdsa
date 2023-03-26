use crate::{
    chips::{
        dotprod::{AssignedZKDotProdProof, ZKDotProdChip},
        pedersen_commit::PedersenCommitChip,
        secq256k1::Secq256k1Chip,
    },
    transcript::HopliteTranscript,
    {FpChip, Fq, FqChip},
};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_ecc::ecc::{fixed_base, EcPoint, EccChip};
use halo2_ecc::fields::FieldChip;
use halo2_proofs::circuit::Value;
use hoplite::{
    circuit_vals::{CVSumCheckProof, ToCircuitVal},
    commitments::MultiCommitGens,
};
use libspartan::transcript::{ProofTranscript, Transcript};
use secpq_curves::group::Group;
use secpq_curves::{group::Curve, Secq256k1};

use super::utils::{Assign, AssignArray};

#[derive(Clone)]
pub struct AssignedZKSumCheck<'v, const N_ROUNDS: usize, const DIMENSION: usize, F: PrimeField> {
    pub comm_polys: [EcPoint<F, CRTInteger<'v, F>>; N_ROUNDS],
    pub comm_evals: [EcPoint<F, CRTInteger<'v, F>>; N_ROUNDS],
    pub proofs: [AssignedZKDotProdProof<'v, DIMENSION, F>; N_ROUNDS],
}

pub trait AssignZKSumCheckProof<'v, const N_ROUNDS: usize, const DIMENSION: usize, F: PrimeField> {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> AssignedZKSumCheck<'v, N_ROUNDS, DIMENSION, F>;
}

impl<'v, const N_ROUNDS: usize, const DIMENSION: usize, F: PrimeField>
    AssignZKSumCheckProof<'v, N_ROUNDS, DIMENSION, F> for CVSumCheckProof<N_ROUNDS, DIMENSION>
{
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> AssignedZKSumCheck<'v, N_ROUNDS, DIMENSION, F> {
        let comm_evals = self.comm_evals.assign(ctx, secq_chip);

        let comm_polys = self.comm_polys.assign(ctx, secq_chip);

        let proofs = self
            .proofs
            .iter()
            .map(|proof| proof.assign(ctx, secq_chip))
            .collect::<Vec<AssignedZKDotProdProof<'v, DIMENSION, F>>>()
            .try_into()
            .unwrap();

        AssignedZKSumCheck {
            comm_evals,
            comm_polys,
            proofs,
        }
    }
}

pub struct ZKSumCheckChip<const N_ROUNDS: usize, const DIMENSION: usize, F: PrimeField> {
    pub ecc_chip: EccChip<F, FpChip<F>>,
    pub fp_chip: FpChip<F>,
    pub fq_chip: FqChip<F>,
    pub pedersen_chip: PedersenCommitChip<F>,
    pub zkdotprod_chip: ZKDotProdChip<DIMENSION, F>,
    pub window_bits: usize,
}

impl<const N_ROUNDS: usize, const DIMENSION: usize, F: PrimeField>
    ZKSumCheckChip<N_ROUNDS, DIMENSION, F>
{
    pub fn construct(
        ecc_chip: EccChip<F, FpChip<F>>,
        fp_chip: FpChip<F>,
        fq_chip: FqChip<F>,
        pedersen_chip: PedersenCommitChip<F>,
        zkdotprod_chip: ZKDotProdChip<DIMENSION, F>,
    ) -> Self {
        Self {
            ecc_chip,
            fp_chip,
            fq_chip,
            pedersen_chip,
            zkdotprod_chip,
            window_bits: 4,
        }
    }

    pub fn verify<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        proof: &AssignedZKSumCheck<'v, N_ROUNDS, DIMENSION, F>,
        gens_n: &MultiCommitGens,
        gens_1: &MultiCommitGens,
        target_sum: EcPoint<F, CRTInteger<'v, F>>,
        target_sum_identity: bool,
        transcript: &mut Transcript,
    ) -> (EcPoint<F, CRTInteger<'v, F>>, [CRTInteger<'v, F>; N_ROUNDS]) {
        let limb_bits = self.fp_chip.limb_bits;
        let num_limbs = self.fp_chip.num_limbs;
        let mut r = vec![];

        for i in 0..N_ROUNDS {
            // Load claimed_sum
            let com_eval = &proof.comm_evals[i];
            let com_poly = &proof.comm_polys[i];

            transcript.append_circuit_point(b"comm_poly", com_poly.clone());

            let r_i = &transcript.challenge_scalar(b"challenge_nextround");
            let r_i = self.fp_chip.load_private(
                ctx,
                FqChip::<F>::fe_to_witness(&Value::known(r_i.to_circuit_val())),
            );
            r.push(r_i.clone());

            let com_round_sum = if i == 0 {
                &target_sum
            } else {
                &proof.comm_evals[i - 1]
            };

            transcript.append_circuit_point(b"comm_claim_per_round", com_round_sum.clone());
            transcript.append_circuit_point(b"comm_eval", com_eval.clone());

            // Convert the CRT integer back into native
            // Might be easier to use CRT integer in the original implementation as well.
            // Need to append bunch of hashes to transcript
            // The point should be SEC-1 encoded as well

            let w_scalar = transcript.challenge_vector(b"combine_two_claims_to_one", 2);

            let w_0: CRTInteger<F> = self.fq_chip.load_private(
                ctx,
                FqChip::<F>::fe_to_witness(&Value::known(w_scalar[0].to_circuit_val())),
            );

            let w_1: CRTInteger<F> = self.fq_chip.load_private(
                ctx,
                FqChip::<F>::fe_to_witness(&Value::known(w_scalar[1].to_circuit_val())),
            );

            let tau_0 = if target_sum_identity {
                fixed_base::scalar_multiply(
                    &self.fp_chip,
                    ctx,
                    &Secq256k1::identity().to_affine(),
                    &w_0.truncation.limbs,
                    limb_bits,
                    self.window_bits,
                )
            } else {
                self.ecc_chip.scalar_mult(
                    ctx,
                    &com_round_sum,
                    &w_0.truncation.limbs,
                    limb_bits,
                    self.window_bits,
                )
            };

            let tau_1 = self.ecc_chip.scalar_mult(
                ctx,
                &com_eval,
                &w_1.truncation.limbs,
                limb_bits,
                self.window_bits,
            );

            let tau = if target_sum_identity {
                tau_1
            } else {
                self.ecc_chip.add_unequal(ctx, &tau_0, &tau_1, true)
            };

            let mut a_sc = vec![];
            let mut a_eval_base = vec![]; // All ones
            let mut a_eval = vec![];

            for i in 0..DIMENSION {
                // TODO These should be instance column values?
                if i == 0 {
                    a_sc.push(
                        self.fq_chip.load_private(
                            ctx,
                            FqChip::<F>::fe_to_witness(&Value::known(Fq::from(2))),
                        ),
                    );
                } else {
                    a_sc.push(
                        self.fq_chip.load_private(
                            ctx,
                            FqChip::<F>::fe_to_witness(&Value::known(Fq::from(1))),
                        ),
                    );
                }
            }

            for _ in 0..DIMENSION {
                // TODO These should be instance column values?
                a_eval_base.push(
                    self.fq_chip
                        .load_private(ctx, FqChip::<F>::fe_to_witness(&Value::known(Fq::from(1)))),
                );
            }

            a_eval.push(
                self.fq_chip
                    .load_private(ctx, FqChip::<F>::fe_to_witness(&Value::known(Fq::from(1)))),
            );

            for i in 1..DIMENSION {
                // TODO These should be instance column values?
                if i == 1 {
                    let a_eval_i_no_carry = self.fq_chip.mul_no_carry(ctx, &a_eval_base[i], &r_i);
                    let a_eval_i = self.fq_chip.carry_mod(ctx, &a_eval_i_no_carry);
                    a_eval.push(a_eval_i);
                } else {
                    let a_eval_i_no_carry = self.fq_chip.mul_no_carry(ctx, &a_eval[i - 1], &r_i);
                    let a_eval_i = self.fq_chip.carry_mod(ctx, &a_eval_i_no_carry);
                    a_eval.push(a_eval_i);
                }
            }

            let mut a = vec![];

            for i in 0..DIMENSION {
                let a_i_lhs = self.fq_chip.mul_no_carry(ctx, &a_sc[i], &w_0);
                let a_i_rhs = self.fq_chip.mul_no_carry(ctx, &a_eval[i], &w_1);
                let a_i_no_carry = self.fq_chip.add_no_carry(ctx, &a_i_lhs, &a_i_rhs);
                let a_i = self.fq_chip.carry_mod(ctx, &a_i_no_carry);

                a.push(a_i);
            }

            let zk_dot_prod_chip = ZKDotProdChip::construct(
                self.ecc_chip.clone(),
                self.fq_chip.clone(),
                self.pedersen_chip.clone(),
            );

            let round_proof: &AssignedZKDotProdProof<DIMENSION, F> = &proof.proofs[i];

            zk_dot_prod_chip.verify(
                ctx,
                &tau,
                a.try_into().unwrap(),
                com_poly,
                round_proof,
                gens_1,
                gens_n,
                transcript,
            );
        }

        self.fp_chip.finalize(ctx);
        (
            proof.comm_evals[proof.comm_evals.len() - 1].clone(),
            r.try_into().unwrap(),
        )
    }
}
