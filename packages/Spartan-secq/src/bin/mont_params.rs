use hex_literal::hex;
use num_bigint_dig::{BigInt, BigUint, ModInverse, ToBigInt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::ops::Neg;

fn get_words(n: &BigUint) -> [u64; 4] {
  let mut words = [0u64; 4];
  for i in 0..4 {
    let word = n.clone() >> (64 * i) & BigUint::from(0xffffffffffffffffu64);
    words[i] = word.to_u64().unwrap();
  }
  words
}

fn render_hex(label: String, words: &[u64; 4]) {
  println!("// {}", label);
  for word in words {
    println!("0x{:016x},", word);
  }
}

fn main() {
  let modulus = BigUint::from_bytes_be(&hex!(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
  ));

  let r = BigUint::from_u8(2)
    .unwrap()
    .modpow(&BigUint::from_u64(256).unwrap(), &modulus);

  let r2 = BigUint::from_u8(2)
    .unwrap()
    .modpow(&BigUint::from_u64(512).unwrap(), &modulus);

  let r3 = BigUint::from_u8(2)
    .unwrap()
    .modpow(&BigUint::from_u64(768).unwrap(), &modulus);

  let two_pow_64 = BigUint::from_u128(18446744073709551616u128).unwrap();
  let one = BigInt::from_u8(1).unwrap();

  let inv = modulus
    .clone()
    .mod_inverse(&two_pow_64)
    .unwrap()
    .neg()
    .modpow(&one, &two_pow_64.to_bigint().unwrap());

  render_hex("Modulus".to_string(), &get_words(&modulus));
  render_hex("R".to_string(), &get_words(&r));
  render_hex("R2".to_string(), &get_words(&r2));
  render_hex("R3".to_string(), &get_words(&r3));
  render_hex("INV".to_string(), &get_words(&inv.to_biguint().unwrap()));
}
