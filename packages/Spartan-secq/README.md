## Fork of [Spartan](https://github.com/microsoft/Spartan)
_This fork is still under development._

Modify Spartan to operate over the **base field** of secp256k1.

### Changes from the original Spartan
- Use the secq256k1 crate instead of curve25519-dalek
- Modify values in scalar.rs (originally ristretto255.rs) 

Please refer to [spartan-ecdsa](https://github.com/personaelabs/spartan-ecdsa) for development status.
