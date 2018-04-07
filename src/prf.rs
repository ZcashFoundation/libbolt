/*
    Pseudo-random Function (PRF) using Dodis-Yampolskiy PRF to support proofs of knowledge.
    Properties:
    - strong pr-image resistance
*/
use rand;
use bn::{Group, Fr, G1};

pub struct PRFKey {
    s: Fr,
    g: G1
}

// initialize the PRF with a seed and an optional generator
pub fn initPRF(s: Fr, G: Option<G1>) -> PRFKey {
    let rng = &mut rand::thread_rng();
    let g = G.unwrap_or(G1::random(rng));
    return PRFKey { s: s, g: g };
}

// compute the PRF given the key and an input
pub fn compute(key: &PRFKey, x: Fr) -> G1 {
    let r = key.s + x;
    return key.g * r.inverse().unwrap();
}