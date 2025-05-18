import { hashPersonalMessage } from "@ethereumjs/util";

import {
  CircuitPubInput,
  PublicInput,
  verifyEffEcdsaPubInput
} from "../helpers/publicInputs";

describe("public_input", () => {
  /**
     Hard coded values were computed in sage using the following code 
      p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
      K = GF(p)
      a = K(0x0000000000000000000000000000000000000000000000000000000000000000)
      b = K(0x0000000000000000000000000000000000000000000000000000000000000007)
      E = EllipticCurve(K, (a, b))
      G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
      E.set_order(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 * 0x1)

      q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
      msgHash = 0x8e05c70f46dbc3dda34547fc23ac835d728001bac55db9bd122d77d10d294431
      rX = 0x5d5d43bec648296f5ef4b72c269bfde291fc0ed13bfc7e59c56b6c74aa9c932e
      rY = 0x1b8ac22e769c661f029c58d04ee7871a8fc2327fd43b38fb3eeafe5e3e8343b5
      R = E(rX, rY)
      rInv = inverse_mod(rX, q)
      T = R * rInv
      U = ((-rInv * msgHash) % q) * G
  */

  it("should verify valid public input", () => {
    const merkleRoot = BigInt("0xbeef");
    const msg = Buffer.from("harry potter");
    const msgHash = hashPersonalMessage(msg);

    const rX = BigInt(
      "0x5d5d43bec648296f5ef4b72c269bfde291fc0ed13bfc7e59c56b6c74aa9c932e"
    );
    const Tx = BigInt(
      "0x2af2c62145d39e7dd285b55d5c51963baa31b58e0c1b8b7e1de9351840917581"
    );
    const Ty = BigInt(
      "0xa662125801a14f2301cfb92965d5ba7a63765e6477a14ecd8e2d4f0b1353b83b"
    );
    const Ux = BigInt(
      "0x7641bcce6a558dfa5018fe45da507ff49cc09aca5c02cceddfd845edebea6682"
    );
    const Uy = BigInt(
      "0xeaeeff65d77a9334606577c4696178497a94e775573553267eb856bee4c54a6f"
    );
    const v = BigInt(28);

    const circuitPubInput = new CircuitPubInput(merkleRoot, Tx, Ty, Ux, Uy);
    const effEcdsaPubInput = new PublicInput(rX, v, msgHash, circuitPubInput);
    const isValid = verifyEffEcdsaPubInput(effEcdsaPubInput);

    expect(isValid).toBe(true);
  });

  // TODO Add more tests!
});
