use crate::{
    chips::pedersen_commit::PedersenCommitChip,
    transcript::HopliteTranscript,
    {FpChip, Fq, FqChip},
};
use halo2_base::{utils::PrimeField, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_ecc::ecc::{EcPoint, EccChip};
use halo2_ecc::fields::FieldChip;
use halo2_proofs::circuit::Value;
use hoplite::{
    circuit_vals::{CVDotProdProof, ToCircuitVal},
    commitments::MultiCommitGens,
};
use libspartan::transcript::{ProofTranscript, Transcript};

use super::{
    secq256k1::Secq256k1Chip,
    utils::{Assign, AssignArray},
};

#[derive(Clone, Debug)]
pub struct AssignedZKDotProdProof<'v, const DIMENSION: usize, F: PrimeField> {
    pub delta: EcPoint<F, CRTInteger<'v, F>>,
    pub beta: EcPoint<F, CRTInteger<'v, F>>,
    pub z: [CRTInteger<'v, F>; DIMENSION],
    pub z_delta: CRTInteger<'v, F>,
    pub z_beta: CRTInteger<'v, F>,
}

impl<'v, const DIMENSION: usize, F: PrimeField>
    Assign<'v, F, AssignedZKDotProdProof<'v, DIMENSION, F>> for CVDotProdProof<DIMENSION>
{
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        secq_chip: &Secq256k1Chip<F>,
    ) -> AssignedZKDotProdProof<'v, DIMENSION, F> {
        let beta = self.beta.assign(ctx, secq_chip);
        let delta = self.delta.assign(ctx, secq_chip);

        let z: [CRTInteger<'v, F>; DIMENSION] = self
            .z
            .iter()
            .map(|z_i| z_i.assign(ctx, secq_chip))
            .collect::<Vec<CRTInteger<'v, F>>>()
            .try_into()
            .unwrap();

        let z_beta = self.z_beta.assign(ctx, secq_chip);
        let z_delta = self.z_delta.assign(ctx, secq_chip);

        AssignedZKDotProdProof {
            beta,
            delta,
            z,
            z_beta,
            z_delta,
        }
    }
}

#[derive(Clone)]
pub struct ZKDotProdChip<const DIMENSION: usize, F: PrimeField> {
    pub ecc_chip: EccChip<F, FpChip<F>>,
    pub fq_chip: FqChip<F>,
    pub pedersen_chip: PedersenCommitChip<F>,
    window_bits: usize,
}

impl<const DIMENSION: usize, F: PrimeField> ZKDotProdChip<DIMENSION, F> {
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
        a: [CRTInteger<'v, F>; DIMENSION],
        com_poly: &EcPoint<F, CRTInteger<'v, F>>,
        proof: &AssignedZKDotProdProof<'v, DIMENSION, F>,
        gens_1: &MultiCommitGens,
        gens_n: &MultiCommitGens,
        transcript: &mut Transcript,
    ) {
        transcript.append_protocol_name(b"dot product proof");

        transcript.append_circuit_point(b"Cx", com_poly.clone());
        transcript.append_circuit_point(b"Cy", tau.clone());

        transcript.append_message(b"a", b"begin_append_vector");
        // TODO: Implement this in a trait
        for a_i_val in &a {
            let mut a_i = [0u8; 32];
            a_i_val.clone().value.and_then(|val| {
                let mut a_i_bytes = val.to_bytes_be().1;
                a_i_bytes.resize(32, 0);
                a_i_bytes.reverse();
                a_i = a_i_bytes.try_into().unwrap();
                Value::known(val)
            });
            transcript.append_message(b"a", &a_i);
        }
        transcript.append_message(b"a", b"end_append_vector");

        transcript.append_circuit_point(b"delta", (&proof.delta).clone());
        transcript.append_circuit_point(b"beta", (&proof.beta).clone());

        let max_bits = self.fq_chip.limb_bits;

        let c = transcript.challenge_scalar(b"c");
        let c = self.fq_chip.load_private(
            ctx,
            FqChip::<F>::fe_to_witness(&Value::known(c.to_circuit_val())),
        );

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
