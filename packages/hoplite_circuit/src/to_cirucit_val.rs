use crate::{AffinePoint, Fp, Fq, RoundProof, ZKDotProdProof};
use halo2_proofs::circuit::Value;
use libspartan::{nizk::DotProductProof, sumcheck::ZKSumcheckInstanceProof};

// We define our own trait rather than using the `From` trait because
// we need to "convert to" some types that are defined outside of this crate.
trait ToCircuitVal<V> {
    fn to_circuit_val(&self) -> V;
}

impl ToCircuitVal<AffinePoint> for libspartan::group::CompressedGroup {
    fn to_circuit_val(&self) -> AffinePoint {
        let x_bytes: [u8; 32] = (*self.x().unwrap()).try_into().unwrap();
        let y_bytes: [u8; 32] = (*self.y().unwrap()).try_into().unwrap();

        let x = Value::known(Fp::from_bytes(&x_bytes).unwrap());
        let y = Value::known(Fp::from_bytes(&y_bytes).unwrap());

        AffinePoint { x, y }
    }
}

impl ToCircuitVal<AffinePoint> for libspartan::group::GroupElement {
    fn to_circuit_val(&self) -> AffinePoint {
        self.compress().to_circuit_val()
    }
}

impl ToCircuitVal<Value<Fq>> for libspartan::scalar::Scalar {
    fn to_circuit_val(&self) -> Value<Fq> {
        let bytes: [u8; 32] = self.to_bytes();
        Value::known(Fq::from_bytes(&bytes).unwrap())
    }
}

impl ToCircuitVal<ZKDotProdProof> for DotProductProof {
    fn to_circuit_val(&self) -> ZKDotProdProof {
        let delta = self.delta.to_circuit_val();
        let beta = self.beta.to_circuit_val();
        let z_beta = self.z_beta.to_circuit_val();
        let z_delta = self.z_delta.to_circuit_val();
        let z = self.z.into_iter().map(|z_i| z_i.to_circuit_val()).collect();

        ZKDotProdProof {
            delta,
            beta,
            z_beta,
            z_delta,
            z,
        }
    }
}
