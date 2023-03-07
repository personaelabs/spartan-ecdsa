mod chips;
mod transcript;

use chips::{
    dotprod::ZKDotProdChip,
    pedersen_commit::PedersenCommitChip,
    sumcheck::{AssignZKSumCheckProof, ZKSumCheckChip},
};
use halo2_base::{
    utils::{modulus, PrimeField},
    Context,
};
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::{fixed_base::FixedEcPoint, EccChip},
    fields::fp::{FpConfig, FpStrategy},
};
use halo2_ecc::{ecc::EcPoint, fields::FieldChip};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk,
    plonk::{Circuit, Column, ConstraintSystem, Instance},
};
use hoplite::circuit_vals::{FromCircuitVal, ToCircuitVal};
use hoplite::{
    circuit_vals::{
        CVEqualityProof, CVKnowledgeProof, CVPolyCommitment, CVPolyEvalProof, CVProductProof,
        CVSumCheckProof,
    },
    commitments::{Commitments, MultiCommitGens},
};
use libspartan::{
    group::CompressedGroup,
    transcript::{ProofTranscript, Transcript},
};

use secpq_curves::{group::Curve, CurveAffine, Secq256k1};

pub type Fp = secpq_curves::Fq;
pub type Fq = secpq_curves::Fp;

pub type FqChip<F> = FpConfig<F, secpq_curves::Fp>;
pub type FpChip<F> = FpConfig<F, secpq_curves::Fq>;

trait AssignPoint<'v, F: PrimeField> {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        field_chip: &EccChip<F, FpChip<F>>,
    ) -> EcPoint<F, CRTInteger<'v, F>>;
}

impl<'v, F: PrimeField> AssignPoint<'v, F> for Value<Secq256k1> {
    fn assign(
        &self,
        ctx: &mut Context<'v, F>,
        ecc_chip: &EccChip<F, FpChip<F>>,
    ) -> EcPoint<F, CRTInteger<'v, F>> {
        let x = self.and_then(|point| Value::known(*point.to_affine().coordinates().unwrap().x()));
        let y = self.and_then(|point| Value::known(*point.to_affine().coordinates().unwrap().y()));
        ecc_chip.load_private(ctx, (x, y))
    }
}

#[derive(Clone, Debug)]
pub struct HopliteCircuitConfig<F: PrimeField> {
    field_config: FpChip<F>,
    /// Public inputs
    instance: Column<Instance>,
    window_bits: usize,
}

// SpartanNIZK verification circuit
pub struct HopliteCircuit<
    const NUM_INPUTS: usize,
    const NUM_CONSTRAINTS: usize,
    const NUM_VARS: usize,
    const NUM_VARS_H: usize,
> {
    pub inst: Vec<u8>,
    pub input: Vec<Fq>,
    pub comm_vars: CVPolyCommitment<NUM_VARS>,
    pub sc_proof_phase1: CVSumCheckProof<NUM_CONSTRAINTS, 4>,
    pub claims_phase2: (
        Option<Secq256k1>,
        Option<Secq256k1>,
        Option<Secq256k1>,
        Option<Secq256k1>,
    ),
    pub pok_claims_phase2: (CVKnowledgeProof, CVProductProof),
    pub proof_eq_sc_phase1: CVEqualityProof,
    pub sc_proof_phase2: CVSumCheckProof<3, 3>,
    pub comm_vars_at_ry: Option<Secq256k1>,
    pub proof_eval_vars_at_ry: CVPolyEvalProof<NUM_VARS_H>,
    pub proof_eq_sc_phase2: CVEqualityProof,
    pub gens_sc_1: MultiCommitGens,
    pub gens_sc_3: MultiCommitGens,
    pub gens_sc_4: MultiCommitGens,
    pub gens_pc_1: MultiCommitGens,
    pub gens_pc_n: MultiCommitGens,
}

pub struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

impl<
        const NUM_INPUTS: usize,
        const NUM_CONSTRAINTS: usize,
        const NUM_VARS: usize,
        const NUM_VARS_H: usize,
        F: PrimeField,
    > Circuit<F> for HopliteCircuit<NUM_INPUTS, NUM_CONSTRAINTS, NUM_VARS, NUM_VARS_H>
{
    type Config = HopliteCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params = CircuitParams {
            strategy: FpStrategy::Simple,
            degree: 18,
            num_advice: 20,
            num_lookup_advice: 6,
            num_fixed: 1,
            lookup_bits: 17,
            limb_bits: 88,
            num_limbs: 3,
        };

        let field_config = FpChip::<F>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            modulus::<Fp>(),
            0,
            params.degree as usize,
        );

        let instance = meta.instance_column();

        meta.enable_equality(instance);

        HopliteCircuitConfig {
            instance,
            field_config,
            window_bits: 4,
        }
    }

    fn without_witnesses(&self) -> Self {
        HopliteCircuit::<NUM_INPUTS, NUM_CONSTRAINTS, NUM_VARS, NUM_VARS_H> {
            comm_vars: CVPolyCommitment::<NUM_VARS>::default(),
            inst: vec![],
            input: vec![Fq::zero(); NUM_INPUTS],
            sc_proof_phase1: CVSumCheckProof::<NUM_CONSTRAINTS, 4>::default(),
            claims_phase2: (None, None, None, None),
            pok_claims_phase2: (CVKnowledgeProof::default(), CVProductProof::default()),
            proof_eq_sc_phase1: CVEqualityProof::default(),
            sc_proof_phase2: CVSumCheckProof::<3, 3>::default(),
            comm_vars_at_ry: None,
            proof_eval_vars_at_ry: CVPolyEvalProof::<NUM_VARS_H>::default(),
            proof_eq_sc_phase2: CVEqualityProof::default(),
            gens_sc_1: MultiCommitGens::default(),
            gens_sc_3: MultiCommitGens::default(),
            gens_sc_4: MultiCommitGens::default(),
            gens_pc_1: MultiCommitGens::default(),
            gens_pc_n: MultiCommitGens::default(),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        // Scalar mult
        let n_rounds = 1;

        let fp_chip = config.field_config;
        fp_chip.range.load_lookup_table(&mut layouter)?;

        // Actually perform the calculation

        let limb_bits = fp_chip.limb_bits;
        let num_limbs = fp_chip.num_limbs;
        let _num_fixed = fp_chip.range.gate.constants.len();
        let _lookup_bits = fp_chip.range.lookup_bits;
        let _num_advice = fp_chip.range.gate.num_advice;

        // We can construct the fp_chip from the config of the fp_chip
        // (fp_chip can use the same columns as the fp_chip)
        let fq_chip =
            FqChip::<F>::construct(fp_chip.range.clone(), limb_bits, num_limbs, modulus::<Fq>());

        let ecc_chip = EccChip::construct(fp_chip.clone());
        let pedersen_chip = PedersenCommitChip::construct(ecc_chip.clone(), fp_chip.clone());
        let phase_1_zkdotprod_chip: ZKDotProdChip<4, F> =
            ZKDotProdChip::construct(ecc_chip.clone(), fq_chip.clone(), pedersen_chip.clone());

        let phase_1_zksumcheck_chip = ZKSumCheckChip::construct(
            ecc_chip.clone(),
            fp_chip.clone(),
            fq_chip.clone(),
            pedersen_chip.clone(),
            phase_1_zkdotprod_chip.clone(),
        );

        //  let mut results = Vec::new();

        layouter.assign_region(
            || "",
            |region| {
                let mut ctx = fp_chip.new_context(region);

                let mut transcript = Transcript::new(b"test_verify");

                transcript.append_protocol_name(b"Spartan NIZK proof");
                transcript.append_message(b"R1CSInstanceDigest", &self.inst);

                transcript.append_protocol_name(b"R1CS proof");

                // Append input to the transcript
                transcript.append_message(b"input", b"begin_append_vector");
                for item in &self.input {
                    transcript.append_message(b"input", &item.to_bytes());
                }
                transcript.append_message(b"input", b"end_append_vector");

                // Append poly commitment to the transcript
                transcript.append_message(b"poly_commitment", b"poly_commitment_begin");
                for comm_var in self.comm_vars.C {
                    transcript.append_point(
                        b"poly_commitment_share",
                        &CompressedGroup::from_circuit_val(&comm_var.unwrap()),
                    );
                }
                transcript.append_message(b"poly_commitment", b"poly_commitment_end");

                let phase1_expected_sum = Fq::zero().commit(&Fq::zero(), &self.gens_sc_1);

                let phase1_expected_sum =
                    FixedEcPoint::from_curve(phase1_expected_sum.to_affine(), num_limbs, limb_bits);

                let phase1_expected_sum = FixedEcPoint::assign(
                    phase1_expected_sum,
                    &fp_chip,
                    &mut ctx,
                    fp_chip.native_modulus(),
                );

                let _tau: Vec<Fq> = transcript
                    .challenge_vector(b"challenge_tau", n_rounds)
                    .iter()
                    .map(|tau_i| tau_i.to_circuit_val())
                    .collect();

                let phase1_sc_proof = self.sc_proof_phase1.assign(&mut ctx, &fq_chip, &ecc_chip);
                phase_1_zksumcheck_chip.verify(
                    &mut ctx,
                    phase1_sc_proof,
                    &self.gens_sc_4,
                    &self.gens_sc_1,
                    phase1_expected_sum,
                    true,
                    &mut transcript,
                );

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use hoplite::{circuit_vals::ToCircuitVal, verify_nizk};
    use libspartan::{
        transcript::Transcript, InputsAssignment, Instance, NIZKGens, VarsAssignment, NIZK,
    };

    #[allow(non_snake_case)]
    #[test]
    fn test_hoplite_circuit() {
        // parameters of the R1CS instance
        let num_cons = 1;
        let num_vars = 0;
        let num_inputs = 3;

        // We will encode the above constraints into three matrices, where
        // the coefficients in the matrix are in the little-endian byte order
        let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new(); // <row, column, value>
        let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
        let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

        // Create a^2 + b + 13
        A.push((0, num_vars + 2, Fq::one().to_bytes())); // 1*a
        B.push((0, num_vars + 2, Fq::one().to_bytes())); // 1*a
        C.push((0, num_vars + 1, Fq::one().to_bytes())); // 1*z
        C.push((0, num_vars, (-Fq::from(13u64)).to_bytes())); // -13*1
        C.push((0, num_vars + 3, (-Fq::one()).to_bytes())); // -1*b

        // Var Assignments (Z_0 = 16 is the only output)
        let vars = vec![Fq::zero().to_bytes(); num_vars];

        // create an InputsAssignment (a = 1, b = 2)
        let mut inputs = vec![Fq::zero().to_bytes(); num_inputs];
        inputs[0] = Fq::from(16u64).to_bytes();
        inputs[1] = Fq::from(1u64).to_bytes();
        inputs[2] = Fq::from(2u64).to_bytes();

        let assignment_inputs = InputsAssignment::new(&inputs).unwrap();
        let assignment_vars = VarsAssignment::new(&vars).unwrap();

        // Check if instance is satisfiable
        let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
        let res = inst.is_sat(&assignment_vars, &assignment_inputs);
        assert!(res.unwrap(), "should be satisfied");

        let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

        let mut prover_transcript = Transcript::new(b"test_verify");

        let proof = NIZK::prove(
            &inst,
            assignment_vars,
            &assignment_inputs,
            &gens,
            &mut prover_transcript,
        );

        verify_nizk(
            &inst,
            num_cons,
            num_vars,
            &assignment_inputs.assignment,
            &proof,
            &gens,
        );

        // Verify the phase 1 zk-sumcheck  proof
        let sc_proof_phase1: CVSumCheckProof<1, 4> =
            proof.r1cs_sat_proof.sc_proof_phase1.to_circuit_val();

        let r1cs_sat_proof = &proof.r1cs_sat_proof;
        let claims_phase2 = &r1cs_sat_proof.claims_phase2;

        let input = assignment_inputs
            .assignment
            .iter()
            .map(|x| x.to_circuit_val())
            .collect();

        let circuit = HopliteCircuit::<4, 1, 2, 1> {
            inst: inst.digest,
            input,
            comm_vars: r1cs_sat_proof.comm_vars.to_circuit_val(),
            sc_proof_phase1: sc_proof_phase1,
            sc_proof_phase2: r1cs_sat_proof.sc_proof_phase2.to_circuit_val(),
            claims_phase2: (
                Some(claims_phase2.0.to_circuit_val()),
                Some(claims_phase2.1.to_circuit_val()),
                Some(claims_phase2.2.to_circuit_val()),
                Some(claims_phase2.3.to_circuit_val()),
            ),
            pok_claims_phase2: (
                r1cs_sat_proof.pok_claims_phase2.0.to_circuit_val(),
                r1cs_sat_proof.pok_claims_phase2.1.to_circuit_val(),
            ),
            proof_eq_sc_phase1: r1cs_sat_proof.proof_eq_sc_phase1.to_circuit_val(),
            proof_eq_sc_phase2: r1cs_sat_proof.proof_eq_sc_phase2.to_circuit_val(),
            comm_vars_at_ry: Some(r1cs_sat_proof.comm_vars_at_ry.to_circuit_val()),
            proof_eval_vars_at_ry: r1cs_sat_proof.proof_eval_vars_at_ry.to_circuit_val(),
            gens_pc_1: gens.gens_r1cs_sat.gens_pc.gens.gens_1.into(),
            gens_pc_n: gens.gens_r1cs_sat.gens_pc.gens.gens_n.into(),
            gens_sc_1: gens.gens_r1cs_sat.gens_sc.gens_1.into(),
            gens_sc_3: gens.gens_r1cs_sat.gens_sc.gens_3.into(),
            gens_sc_4: gens.gens_r1cs_sat.gens_sc.gens_4.into(),
        };

        // Convert ZkSumCheckProof into a HopliteCircuit

        /*
        let claimed_sum_0_limbs: Vec<Fr> = decompose_biguint(
            &BigUint::from_bytes_le(&phase1_expected_sum.x.to_bytes()),
            3,
            88,
        );

        let claimed_sum_1_limbs: Vec<Fr> = decompose_biguint(
            &BigUint::from_bytes_le(&phase1_expected_sum.y.to_bytes()),
            3,
            88,
        );
         */

        let k = 18;
        //  let public_inputs = vec![claimed_sum_0_limbs, claimed_sum_1_limbs].concat();

        let prover = MockProver::<Fr>::run(k, &circuit, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    /*
    fn empty_round_proof() -> RoundProof {
        let unknown_point = AffinePoint {
            x: Value::unknown(),
            y: Value::unknown(),
        };
        let dotprod_proof = CVDotProdProof {
            delta: unknown_point.clone(),
            beta: unknown_point.clone(),
            epsilon: unknown_point.clone(),
            z_beta: Value::unknown(),
            z: vec![Value::unknown(); 3],
            z_delta: Value::unknown(),
        };

        RoundProof {
            dotprod_proof,
            com_eval: unknown_point,
        }
    }

    #[test]
    fn plot_circuit() {
    use plotters::prelude::*;

        let unknown_point = AffinePoint {
            x: Value::unknown(),
            y: Value::unknown(),
        };

        let circuit = HopliteCircuit {
            claimed_sum: unknown_point.clone(),
            round_proofs: vec![empty_round_proof(); 2],
        };

        let root = BitMapBackend::new("layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Example Circuit Layout", ("sans-serif", 60))
            .unwrap();


        halo2_proofs::dev::CircuitLayout::default()
            // You can optionally render only a section of the circuit.
            .view_width(0..2)
            .view_height(0..16)
            // You can hide labels, which can be useful with smaller areas.
            .show_labels(false)
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render::<Fr, _, _>(20, &circuit, &root)
            .unwrap();
    }
     */
}
