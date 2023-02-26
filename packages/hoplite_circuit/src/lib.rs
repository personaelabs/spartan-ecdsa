mod chips;

use chips::{
    dotprod::{AssignedZKDotProdProof, ZKDotProdChip},
    pedersen_commit::PedersenCommitChip,
};
use halo2_base::{
    utils::{modulus, PrimeField},
    Context,
};
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::{fixed_base, EccChip},
    fields::fp::{FpConfig, FpStrategy},
};
use halo2_ecc::{ecc::EcPoint, fields::FieldChip};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk,
    plonk::{Circuit, Column, ConstraintSystem, Instance},
};
use hoplite::{commitments::MultiCommitGens, dotprod::ZKDotProdProof, sumcheck::ZKSumCheckProof};

use secpq_curves::group::cofactor::CofactorCurveAffine;
use secpq_curves::{
    group::{Curve, Group},
    CurveAffine, Secq256k1, Secq256k1Affine,
};

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
pub struct ZKSumCheckCircuitConfig<F: PrimeField> {
    field_config: FpChip<F>,
    /// Public inputs
    instance: Column<Instance>,
    window_bits: usize,
}

pub struct ZKSumCheckCircuit {
    proof: Value<ZKSumCheckProof>,
    gens_n: MultiCommitGens,
    gens_1: MultiCommitGens,
    target_sum: Value<Secq256k1>,
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

impl<F: PrimeField> Circuit<F> for ZKSumCheckCircuit {
    type Config = ZKSumCheckCircuitConfig<F>;
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

        ZKSumCheckCircuitConfig {
            instance,
            field_config,
            window_bits: 4,
        }
    }

    fn without_witnesses(&self) -> Self {
        // TODO: This is temporary!
        let gens_1 = MultiCommitGens {
            G: vec![Secq256k1::generator(); 1],
            h: Secq256k1::generator(),
        };
        let gens_4 = MultiCommitGens {
            G: vec![Secq256k1::generator(); 4],
            h: Secq256k1::generator(),
        };

        ZKSumCheckCircuit {
            proof: Value::unknown(),
            gens_1,
            gens_n: gens_4,
            target_sum: Value::unknown(),
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

        //        let mut results = Vec::new();

        layouter.assign_region(
            || "",
            |region| {
                let mut ctx = fp_chip.new_context(region);

                // We can construct the fp_chip from the config of the fp_chip
                // (fp_chip can use the same columns as the fp_chip)
                let fq_chip = FqChip::<F>::construct(
                    fp_chip.range.clone(),
                    limb_bits,
                    num_limbs,
                    modulus::<Fq>(),
                );

                let ecc_chip = EccChip::construct(fp_chip.clone());
                let pedersen_chip =
                    PedersenCommitChip::construct(ecc_chip.clone(), fp_chip.clone());

                for i in 0..n_rounds {
                    // Load claimed_sum
                    let com_eval = self
                        .proof
                        .and_then(|proof| Value::known(proof.comm_evals[i]))
                        .assign(&mut ctx, &ecc_chip);

                    let com_round_sum = if i == 0 {
                        self.target_sum
                            .and_then(|target_sum| Value::known(target_sum))
                            .assign(&mut ctx, &ecc_chip)
                    } else {
                        let com_eval = self
                            .proof
                            .and_then(|proof| Value::known(proof.comm_evals[i - 1]))
                            .assign(&mut ctx, &ecc_chip);

                        com_eval
                    };

                    let w_0: CRTInteger<F> = fq_chip.load_private(
                        &mut ctx,
                        FqChip::<F>::fe_to_witness(&Value::known(Fq::one())),
                    );

                    let w_1: CRTInteger<F> = fq_chip.load_private(
                        &mut ctx,
                        FqChip::<F>::fe_to_witness(&Value::known(Fq::one())),
                    );

                    let tau_0 = fixed_base::scalar_multiply(
                        &fp_chip,
                        &mut ctx,
                        &Secq256k1Affine::generator(),
                        &w_0.truncation.limbs,
                        limb_bits,
                        config.window_bits,
                    );
                    /*
                    let tau_0 = ecc_chip.scalar_mult(
                        &mut ctx,
                        &com_round_sum,
                        &w_0.truncation.limbs,
                        limb_bits,
                        config.window_bits,
                    );
                         */

                    let tau_1 = ecc_chip.scalar_mult(
                        &mut ctx,
                        &com_eval,
                        &w_1.truncation.limbs,
                        limb_bits,
                        config.window_bits,
                    );

                    let tau = ecc_chip.add_unequal(&mut ctx, &tau_0, &tau_1, true);

                    let degree_bound = 3;

                    // TODO: Compute "a"
                    let a = [
                        fq_chip.load_private(
                            &mut ctx,
                            FqChip::<F>::fe_to_witness(&Value::known(Fq::from(3))),
                        ),
                        fq_chip.load_private(
                            &mut ctx,
                            FqChip::<F>::fe_to_witness(&Value::known(Fq::from(2))),
                        ),
                        fq_chip.load_private(
                            &mut ctx,
                            FqChip::<F>::fe_to_witness(&Value::known(Fq::from(2))),
                        ),
                        fq_chip.load_private(
                            &mut ctx,
                            FqChip::<F>::fe_to_witness(&Value::known(Fq::from(2))),
                        ),
                    ];
                    /*
                    let a = vec![
                        fq_chip.load_private(
                            &mut ctx,
                            FqChip::<F>::fe_to_witness(&Value::known(Fq::one()))
                        );
                        degree_bound + 1
                    ];
                    let a = {
                        // the vector to use to decommit for sum-check test
                        let a_sc = {
                            let mut a = vec![Fp::one(); degree_bound + 1];
                            a[0] += Fp::one();
                            a
                        };

                        // the vector to use to decommit for evaluation
                        let a_eval = {
                            let mut a = vec![Fp::one(); degree_bound + 1];
                            for j in 1..a.len() {
                                a[j] = a[j - 1] * r_i;
                            }
                            a
                        };

                        // take weighted sum of the two vectors using w
                        assert_eq!(a_sc.len(), a_eval.len());
                        (0..a_sc.len())
                            .map(|i| w_0 * a_sc[i] + w_1 * a_eval[i])
                            .collect::<Vec<Fp>>()
                    };
                     */

                    let zk_dot_prod_chip = ZKDotProdChip::construct(
                        ecc_chip.clone(),
                        fq_chip.clone(),
                        pedersen_chip.clone(),
                    );

                    let com_poly_assigned = ecc_chip.load_private(
                        &mut ctx,
                        (
                            self.proof
                                .and_then(|proof| Value::known(proof.comm_polys[i].x)),
                            self.proof
                                .and_then(|proof| Value::known(proof.comm_polys[i].y)),
                        ),
                    );

                    let z_delta = self
                        .proof
                        .and_then(|proof| Value::known(proof.proofs[i].z_delta));

                    let z_beta = self
                        .proof
                        .and_then(|proof| Value::known(proof.proofs[i].z_beta));

                    let delta_assinged = self
                        .proof
                        .and_then(|proof| Value::known(proof.proofs[i].delta))
                        .assign(&mut ctx, &ecc_chip);

                    let beta_assigned = self
                        .proof
                        .and_then(|proof| Value::known(proof.proofs[i].beta))
                        .assign(&mut ctx, &ecc_chip);

                    let mut z_assigned = vec![];

                    for j in 0..(degree_bound + 1) {
                        let z_j = self
                            .proof
                            .and_then(|proof| Value::known(proof.proofs[i].z[j]));

                        z_assigned
                            .push(fq_chip.load_private(&mut ctx, FqChip::<F>::fe_to_witness(&z_j)));
                    }

                    assert!(z_assigned.len() == (degree_bound + 1));

                    let assigned_dot_prod_prood = AssignedZKDotProdProof {
                        delta: delta_assinged,
                        beta: beta_assigned,
                        z_delta: fq_chip
                            .load_private(&mut ctx, FqChip::<F>::fe_to_witness(&z_delta)),
                        z_beta: fq_chip.load_private(&mut ctx, FqChip::<F>::fe_to_witness(&z_beta)),
                        z: z_assigned.try_into().unwrap(),
                    };

                    zk_dot_prod_chip.verify(
                        &mut ctx,
                        &tau,
                        a.try_into().unwrap(),
                        &com_poly_assigned,
                        assigned_dot_prod_prood,
                        &self.gens_1,
                        &self.gens_n,
                    );
                }

                fp_chip.finalize(&mut ctx);

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use halo2_base::utils::decompose_biguint;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use hoplite::{commitments::Commitments, sumcheck::ToCircuitVal, verify_nizk, Scalar};
    use libspartan::{
        transcript::Transcript, InputsAssignment, Instance, NIZKGens, VarsAssignment, NIZK,
    };
    use num_bigint::BigUint;
    use secpq_curves::Fp;

    #[allow(non_snake_case)]
    #[test]
    fn test_zk_sumcheck_circuit() {
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
        let sc_proof_phase1 = proof.r1cs_sat_proof.sc_proof_phase1.to_circuit_val();

        let phase1_expected_sum = Secq256k1::identity();

        let circuit = ZKSumCheckCircuit {
            proof: Value::known(sc_proof_phase1),
            target_sum: Value::known(phase1_expected_sum),
            gens_1: gens.gens_r1cs_sat.gens_sc.gens_1.into(),
            gens_n: gens.gens_r1cs_sat.gens_sc.gens_4.into(),
        };

        // Convert ZkSumCheckProof into a ZKSumCheckCircuit

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
        let dotprod_proof = ZKDotProdProof {
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

        let circuit = ZKSumCheckCircuit {
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
