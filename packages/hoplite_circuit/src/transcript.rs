use halo2_base::utils::PrimeField;
use halo2_ecc::bigint::CRTInteger;
use halo2_ecc::ecc::EcPoint;
use halo2_proofs::circuit::Value;
use libspartan::{
    group::CompressedGroup,
    transcript::{ProofTranscript, Transcript},
};

pub trait HopliteTranscript<'v, F: PrimeField> {
    fn append_circuit_point(&mut self, label: &'static [u8], point: EcPoint<F, CRTInteger<'v, F>>);
}

impl<'v, F: PrimeField> HopliteTranscript<'v, F> for Transcript {
    fn append_circuit_point(
        &mut self,
        label: &'static [u8],
        circuit_point: EcPoint<F, CRTInteger<'v, F>>,
    ) {
        let mut x = [0u8; 32];
        let _x = circuit_point.x.value.and_then(|val| {
            let mut x_bytes = val.to_bytes_be().1;
            x_bytes.resize(32, 0);
            x = x_bytes.try_into().unwrap();
            Value::known(val)
        });

        let mut y = [0u8; 32];
        let _y = circuit_point.y.value.and_then(|val| {
            let mut y_bytes = val.to_bytes_be().1;
            y_bytes.resize(32, 0);
            y = y_bytes.try_into().unwrap();
            Value::known(val)
        });

        let point = if (x == [0u8; 32]) && (y == [0u8; 32]) {
            CompressedGroup::identity()
        } else {
            CompressedGroup::from_affine_coordinates(&x.into(), &y.into(), true)
        };

        self.append_point(label, &point);
    }
}
