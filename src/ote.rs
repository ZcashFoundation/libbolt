/*
    One-time encryption - keyspace of the OTE is also the range of the pseudo-random function
*/

use std::fmt;
use bn::{Group, Fr, G1};
use rand;

pub struct OTMessage {
    m1: G1,
    m2: G1
}

pub struct OTCiphertext {
    c1: G1,
    c2: G1
}

pub fn keygen() -> G1 {
    let rng = &mut rand::thread_rng();
    let k = G1::random(rng);
    return k;
}

// encryption scheme can be implemented by encoding the plaintext as an element in a cyclic group G
// and multiplying by a random group element.
pub fn otenc(k: G1, m: &OTMessage) -> OTCiphertext {
    let c1 = k + m.m1;
    let c2 = k + m.m2;
    assert!(c1 != c2);
    return OTCiphertext { c1: c1, c2: c2 };
}

pub fn otdec(k: G1, c: &OTCiphertext) -> OTMessage {
    let X = c.c1 - k;
    let Y = c.c2 - k;
    return OTMessage { m1: X, m2: Y};
}
