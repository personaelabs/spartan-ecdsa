use crate::field::{BaseField, SqrtRatio};
use k256::elliptic_curve::subtle::{Choice, ConstantTimeEq};

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-3
pub fn hash_to_curve<F: BaseField + SqrtRatio>(
    u1: F,
    u2: F,
    curve_a: F,
    curve_b: F,
    z: F,
    k: [F; 13],
) -> ((F, F), (F, F)) {
    let q1 = map_to_curve_simple_swu(u1, curve_a, curve_b, z);
    let q2 = map_to_curve_simple_swu(u2, curve_a, curve_b, z);

    // iso_map and add then together
    let p1 = iso_map(q1.0, q1.1, k);
    let p2 = iso_map(q2.0, q2.1, k);

    (p1, p2)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#appendix-E.1
fn iso_map<F: BaseField + SqrtRatio>(x: F, y: F, k: [F; 13]) -> (F, F) {
    let x_squared = x.pow_vartime(&[2, 0, 0, 0]);
    let x_cubed = x_squared * x;

    let x_num = k[0] * x_cubed + k[1] * x_squared + k[2] * x + k[3];
    let x_den = x_squared + k[4] * x + k[5];

    let x_f0 = x_num * x_den.invert().unwrap();

    let y_num = k[6] * x_cubed + k[7] * x_squared + k[8] * x + k[9];
    let y_den = x_cubed + k[10] * x_squared + k[11] * x + k[12];

    let y_f0 = y * (y_num * y_den.invert().unwrap());

    (x_f0, y_f0)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#appendix-F.2
fn map_to_curve_simple_swu<F: BaseField + SqrtRatio>(u: F, curve_a: F, curve_b: F, z: F) -> (F, F) {
    let mut tv1 = u * u;
    tv1 = z * tv1;
    let mut tv2 = tv1 * tv1;
    tv2 = tv2 + tv1;
    let mut tv3 = tv2 + F::one();
    tv3 = curve_b * tv3;

    let mut tv4 = F::conditional_select(&z, &-tv2, Choice::from(!tv2.is_zero()));
    tv4 = curve_a * tv4;

    tv2 = tv3 * tv3;
    let mut tv6 = tv4 * tv4;
    let mut tv5 = curve_a * tv6;
    tv2 = tv2 + tv5;

    tv2 = tv2 * tv3;
    tv6 = tv6 * tv4;
    tv5 = curve_b * tv6;

    tv2 = tv2 + tv5;
    let mut x = tv1 * tv3;

    let (is_gx1_square, y1) = F::sqrt_ratio(&tv2, &tv6);

    let mut y = tv1 * u;
    y = y * y1;
    x = F::conditional_select(&x, &tv3, is_gx1_square);
    y = F::conditional_select(&y, &y1, is_gx1_square);

    y = F::conditional_select(&(-y), &y, u.is_odd().ct_eq(&y.is_odd()));

    x = x * tv4.invert().unwrap();
    (x, y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::field_secp::FieldElement;
    use hex_literal::hex;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{AffinePoint, EncodedPoint, ProjectivePoint};
    type F = FieldElement;

    // The constants are outputs of hashtocurve_params.sage

    // 28734576633528757162648956269730739219262246272443394170905244663053633733939
    const ISO_A: F = FieldElement([
        15812504324673914017,
        4924912935180573090,
        11593825521208392688,
        5790129131709978969,
        0,
    ]);

    // 1771
    const ISO_B: F = FieldElement([7606388811483, 0, 0, 0, 0]);

    // -11
    const ISO_Z: F = FieldElement([
        18446744022169932340,
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
        0,
    ]);

    const ISO_CONSTANTS: [F; 13] = [
        F::from_raw([
            10248191149674768524,
            4099276460824344803,
            16397105843297379214,
            10248191152060862008,
        ]),
        F::from_raw([
            5677861232072053346,
            16451756383528566833,
            16331199996347402988,
            6002227985152881894,
        ]),
        F::from_raw([
            16140637477814429057,
            15390439281582816146,
            13399077293683197125,
            564028334007329237,
        ]),
        F::from_raw([
            10248191149674768583,
            4099276460824344803,
            16397105843297379214,
            10248191152060862008,
        ]),
        F::from_raw([
            14207262949819313428,
            491854862080688571,
            17853591451159765588,
            17126563718956833821,
        ]),
        F::from_raw([
            11522098205669897371,
            9713490981125900413,
            11286949528964841693,
            15228765018197889418,
        ]),
        F::from_raw([
            9564978407794773380,
            13664254869414482678,
            11614616639002310276,
            3416063717353620669,
        ]),
        F::from_raw([
            12062302652890802481,
            8225878191764283416,
            8165599998173701494,
            3001113992576440947,
        ]),
        F::from_raw([
            16139934577133973923,
            7240293169244854895,
            12236461929419286229,
            14365933273833241615,
        ]),
        F::from_raw([
            11614616637729727036,
            3416063717353620669,
            7515340178177965473,
            5465701947765793071,
        ]),
        F::from_raw([
            12087522392169162607,
            737782293121032857,
            17557015139884872574,
            7243101504725699116,
        ]),
        F::from_raw([
            16119550551890077043,
            10693728869668149624,
            15414104513184973464,
            8792806907174565023,
        ]),
        F::from_raw([
            18446744069414582587,
            18446744073709551615,
            18446744073709551615,
            18446744073709551615,
        ]),
    ];

    struct TestSuite {
        u1: [u8; 32],
        u2: [u8; 32],
        px: [u8; 32],
        py: [u8; 32],
    }

    impl TestSuite {
        fn new(u1: [u8; 32], u2: [u8; 32], px: [u8; 32], py: [u8; 32]) -> Self {
            Self { u1, u2, px, py }
        }
    }

    fn assert_hash_to_curve(u1: FieldElement, u2: FieldElement, expected: AffinePoint) {
        let (p1_coords, p2_coords) = hash_to_curve(u1, u2, ISO_A, ISO_B, ISO_Z, ISO_CONSTANTS);

        let p1x = p1_coords.0.to_be_bytes();
        let p1y = p1_coords.1.to_be_bytes();
        let p2x = p2_coords.0.to_be_bytes();
        let p2y = p2_coords.1.to_be_bytes();

        let p1_encoded = EncodedPoint::from_affine_coordinates(&p1x.into(), &p1y.into(), false);
        let p2_encoded = EncodedPoint::from_affine_coordinates(&p2x.into(), &p2y.into(), false);

        let p1 = ProjectivePoint::from_encoded_point(&p1_encoded).unwrap();
        let p2 = ProjectivePoint::from_encoded_point(&p2_encoded).unwrap();

        let result = p1 + p2;

        assert_eq!(result.to_affine(), expected);
    }

    #[test]
    fn test_secp_hash_to_curve() {
        // Use test suites from:
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#appendix-J.8.1
        let suites: [TestSuite; 5] = [
            TestSuite::new(
                hex!("6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3"),
                hex!("1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16"),
                hex!("c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346"),
                hex!("64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067"),
            ),
            TestSuite::new(
                hex!("128aab5d3679a1f7601e3bdf94ced1f43e491f544767e18a4873f397b08a2b61"),
                hex!("5897b65da3b595a813d0fdcc75c895dc531be76a03518b044daaa0f2e4689e00"),
                hex!("3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"),
                hex!("7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"),
            ),
            TestSuite::new(
                hex!("ea67a7c02f2cd5d8b87715c169d055a22520f74daeb080e6180958380e2f98b9"),
                hex!("7434d0d1a500d38380d1f9615c021857ac8d546925f5f2355319d823a478da18"),
                hex!("bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a"),
                hex!("4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828"),
            ),
            TestSuite::new(
                hex!("eda89a5024fac0a8207a87e8cc4e85aa3bce10745d501a30deb87341b05bcdf5"),
                hex!("dfe78cd116818fc2c16f3837fedbe2639fab012c407eac9dfe9245bf650ac51d"),
                hex!("e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9"),
                hex!("f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873"),
            ),
            TestSuite::new(
                hex!("8d862e7e7e23d7843fe16d811d46d7e6480127a6b78838c277bca17df6900e9f"),
                hex!("68071d2530f040f081ba818d3c7188a94c900586761e9115efa47ae9bd847938"),
                hex!("e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998"),
                hex!("8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6"),
            ),
        ];

        for suite in suites {
            let expected_point =
                EncodedPoint::from_affine_coordinates(&suite.px.into(), &suite.py.into(), false);
            let expected_point = AffinePoint::from_encoded_point(&expected_point).unwrap();

            let mut u1 = suite.u1.clone();
            u1.reverse();
            let mut u2 = suite.u2.clone();
            u2.reverse();

            let u1 = FieldElement::from_bytes(&u1).unwrap();
            let u2 = FieldElement::from_bytes(&u2).unwrap();

            assert_hash_to_curve(u1, u2, expected_point);
        }
    }
}
