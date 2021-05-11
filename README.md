# hash2field

This crate is designed to be used **no-std** environments.

Implements safe hash to a finite field as described in section 5 from the [IETF Draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5).

This crate is designed to be called by implementers of hash to curve without needing to write the hash to field section, 
since this is curve agnostic.

It provides two structs, two traits, and the function `hash_to_field`.

`FromRO` should be implemented by the caller of `hash_to_field` and is used to convert the output digests to field elements.

`ExpandMsg` is implemented by `ExpandMsgXof` and `ExpandMsgXmd` so it should not need to be implemented directly.

`ExpandMsgXmd` is the implementation of [Section 5.4.1](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1)
and allows the caller the flexibility of picking a fixed output digest.

`ExpandMsgXof` is the implementation of [Section 5.4.2](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.2)
and allows the caller the flexibility of picking any XOF.

`hash_to_field` uses const generics as implemented in rust 1.51. 

Here's an example of using it for the `k256` crate
```rust
use hash2field::*;
use digest::generic_array::{GenericArray, typenum::U32};
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
        let p = BigUint::from_bytes_be(&hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").unwrap());
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

let output = hash_to_field::<ExpandMsgXmd<Sha256>, FieldElement, L, COUNT, OUT>(b"this is a test", DST);
}
```

Using `ExpandMsgXof` is very similar

```rust
use hash2field::*;
use digest::generic_array::{GenericArray, typenum::U32};
use k256::FieldElement;
use num_bigint::BigUint;
use num_integer::Integer;
use sha3::Shake256;

const L: usize = 48;
const COUNT: usize = 2;
const OUT: usize = L * COUNT;
const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XOF:SHAKE-256_SSWU_RO_";

impl FromOkm<L> for FieldElement {
    fn from_okm(data: &[u8; L]) -> Self {
        let p = BigUint::from_bytes_be(&hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").unwrap());
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

let output = hash_to_field::<ExpandMsgXof<Shake256>, FieldElement, L, COUNT, OUT>(b"this is a test", DST);
```