/*
    One-time encryption - keyspace of the OTE is also the range of the pseudo-random function
*/

use std::fmt;
use bn::{Group, Fr, G1};
use rand;

pub struct OTMessage {
    pub m1: G1,
    pub m2: G1
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
    let x = c.c1 - k;
    let y = c.c2 - k;
    return OTMessage { m1: x, m2: y};
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};
    use bn::{G1, Group};

    #[test]
    fn one_time_enc_dec_works() {
        let rng = &mut rand::thread_rng();

        // Test the OTE scheme
        let k = keygen();
        let x = G1::random(rng);
        let y = G1::random(rng);
        let m = OTMessage { m1: x, m2: y };
        let c = otenc(k, &m);
        let orig_m = otdec(k, &c);

        assert!(m.m1 == orig_m.m1 && m.m2 == orig_m.m2);
    }
}