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
pub fn init_prf(s: Fr, gen: Option<G1>) -> PRFKey {
    let rng = &mut rand::thread_rng();
    let g = gen.unwrap_or(G1::random(rng));
    return PRFKey { s: s, g: g };
}

// compute the PRF given the key and an input
pub fn compute(key: &PRFKey, x: Fr) -> G1 {
    let r = key.s + x;
    return key.g * r.inverse().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};
    use bn::{Fr, G1, Group};

    #[test]
    fn prf_works() {
        let rng = &mut rand::thread_rng();
        let s = Fr::random(rng);
        let key = init_prf(s, None);

        let x = Fr::random(rng);
        let y = compute(&key, x);
        let z = compute(&key, x + Fr::from_str("1").unwrap());

        // confirm that PRF(k, x) != PRF(k, x+1)
        assert!(y != z);
    }
}