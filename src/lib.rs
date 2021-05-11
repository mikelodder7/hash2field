//!

#![no_std]

mod expand_msg;
mod expand_msg_xmd;
mod expand_msg_xof;

use core::convert::TryFrom;
pub use expand_msg::*;
pub use expand_msg_xmd::*;
pub use expand_msg_xof::*;

/// The trait for helping to convert to a scalar
pub trait FromOkm<const L: usize>: Sized {
    /// Convert a byte sequence into a scalar
    fn from_okm(data: &[u8; L]) -> Self;
}

/// Convert an arbitrary byte sequence according to
/// <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3>
pub fn hash_to_field<E, T, const L: usize, const COUNT: usize, const OUT: usize>(
    data: &[u8],
    domain: &[u8],
) -> [T; COUNT]
where
    E: ExpandMsg<OUT>,
    T: FromOkm<L> + Default + Copy,
{
    let random_bytes = E::expand_message(data.as_ref(), domain.as_ref());
    let mut out = [T::default(); COUNT];
    for i in 0..COUNT {
        let u = <[u8; L]>::try_from(&random_bytes[(L * i)..L * (i + 1)]).unwrap();
        out[i] = T::from_okm(&u);
    }
    out
}

// Tests has to be here in order to implement FromOkm for other crates
#[test]
fn secp256k1_test() {
    use digest::generic_array::{typenum::U32, GenericArray};
    use k256::FieldElement;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use sha2::Sha256;

    const L: usize = 48;
    const COUNT: usize = 2;
    const OUT: usize = L * COUNT;
    const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

    impl FromOkm<L> for FieldElement {
        fn from_okm(data: &[u8; L]) -> Self {
            let p = BigUint::from_bytes_be(
                &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
                    .unwrap(),
            );
            let mut x = BigUint::from_bytes_be(&data[..]);
            x = x.mod_floor(&p);
            let mut t = x.to_bytes_be();
            while t.len() < 32 {
                t.insert(0, 0u8);
            }
            let t = GenericArray::<u8, U32>::clone_from_slice(&t);
            FieldElement::from_bytes(&t).unwrap()
        }
    }

    let tests: [(&[u8], &str, &str); 5] = [
        (b"", "6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3", "1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16"),
        (b"abc", "128aab5d3679a1f7601e3bdf94ced1f43e491f544767e18a4873f397b08a2b61", "5897b65da3b595a813d0fdcc75c895dc531be76a03518b044daaa0f2e4689e00"),
        (b"abcdef0123456789", "ea67a7c02f2cd5d8b87715c169d055a22520f74daeb080e6180958380e2f98b9", "7434d0d1a500d38380d1f9615c021857ac8d546925f5f2355319d823a478da18"),
        (b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "eda89a5024fac0a8207a87e8cc4e85aa3bce10745d501a30deb87341b05bcdf5", "dfe78cd116818fc2c16f3837fedbe2639fab012c407eac9dfe9245bf650ac51d"),
        (b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "8d862e7e7e23d7843fe16d811d46d7e6480127a6b78838c277bca17df6900e9f", "68071d2530f040f081ba818d3c7188a94c900586761e9115efa47ae9bd847938"),
    ];

    for (msg, e0, e1) in &tests {
        let output = hash_to_field::<ExpandMsgXmd<Sha256>, FieldElement, L, COUNT, OUT>(*msg, DST);
        let exp0 = GenericArray::clone_from_slice(&hex::decode(e0).unwrap());
        let exp1 = GenericArray::clone_from_slice(&hex::decode(e1).unwrap());
        assert_eq!(output[0], FieldElement::from_bytes(&exp0).unwrap());
        assert_eq!(output[1], FieldElement::from_bytes(&exp1).unwrap());
    }
}
