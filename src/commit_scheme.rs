// commit_schemes.rs

use std::fmt;
use rand::{thread_rng, Rng};
use bn::{Group, Fr, G1, G2};
use clsigs;
use debug_elem_in_hex;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use sodiumoxide::crypto::hash::sha512;

#[derive(Copy, Clone)]
pub struct PublicKey {
    g: G2,
    h: G2
}

#[derive(Copy, Clone)]
pub struct Commitment {
    pub c: G2,
    pub r: Fr
}

#[derive(Clone)]
pub struct CSParams {
    pub pub_bases: Vec<G2>
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let g_vec: Vec<u8> = encode(&self.g, Infinite).unwrap();
        let h_vec: Vec<u8> = encode(&self.h, Infinite).unwrap();
        let mut g_s = String::new();
        for x in g_vec.iter() {
            g_s = format!("{}{:x}", g_s, x);
        }

        let mut h_s = String::new();
        for y in h_vec.iter() {
            h_s = format!("{}{:x}", h_s, y);
        }

        write!(f, "PK : (g=0x{}, h=0x{})", g_s, h_s)
    }
}


impl fmt::Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let c_vec: Vec<u8> = encode(&self.c, Infinite).unwrap();
        let mut c_s = String::new();
        for x in c_vec.iter() {
            c_s = format!("{}{:x}", c_s, x);
        }

        let d_vec: Vec<u8> = encode(&self.r, Infinite).unwrap();
        let mut d_s = String::new();
        for x in d_vec.iter() {
            d_s = format!("{}{:x}", d_s, x);
        }
        write!(f, "Commitment : (c=0x{}, d=0x{})", c_s, d_s)
    }
}

/*
Implements the setup algorithm for the Pedersen92 commitment scheme
*/
pub fn ped92_setup() -> PublicKey {
    println!("Run Setup...");
    let rng = &mut thread_rng();
    let g = G2::random(rng);
    let h = G2::random(rng);
    let pk = PublicKey { g: g, h: h };
    println!("{}", pk);
    return pk;
}

/*
commit(pk, msg) -> cm where
- pk is the public key generated from setup()
- msg is the message structure for the commitment scheme
- cm is the output commitment message for the given message
*/
pub fn ped92_commit(pk: &PublicKey, m: Fr, R: Option<Fr>) -> Commitment {
    let rng = &mut thread_rng();

    let r = R.unwrap_or(Fr::random(rng));
    //let r = Fr::random(rng);

    //let m = msg.hash();
    let p = "commit -> m";
    debug_elem_in_hex(p, &m);
    // c = g^m * h^r
    let c = (pk.g * m) + (pk.h * r);
    // return (c, r) <- d=r
    let commitment = Commitment { c: c, r: r };

    // debugging
    println!("{}", commitment);
    return commitment;
}

/*
decommit(pk, cm, msg) -> bool where
- pk is the public key generated from setup()
- cm is the commitment
- m is the message to validate
- outputs T/F for whether the cm is a valid commitment to the msg
*/
pub fn ped92_decommit(pk: &PublicKey, cm: &Commitment, m: Fr) -> bool {
    let p = "decommit -> m";
    debug_elem_in_hex(p, &m);

    let dm = (pk.g * m) + (pk.h * cm.r);
    return dm == cm.c;
}


/*
Implements the setup algorithm for the Pedersen92 commitment scheme over
a vector of messages.
*/

pub fn setup(len: usize, pub_bases: Vec<G2>, h: G2) -> CSParams {
    let rng = &mut thread_rng();
    //let base_h = h.unwrap_or(G2::random(rng));
    let mut p: Vec<G2> = Vec::new();
    p.push(h);

    let _p = pub_bases;
    for i in 0 .. _p.len() {
        p.push(_p[i]);
    }
    return CSParams { pub_bases: p };
}

pub fn setup_gen_params(len: usize) -> CSParams {
    let rng = &mut thread_rng();

    let mut p: Vec<G2> = Vec::new();
    for i in 0 .. len {
        p.push(G2::random(rng));
    }
    return CSParams { pub_bases: p };
}

pub fn commit(csp: &CSParams, x: &Vec<Fr>, r: Fr) -> Commitment {
    let rng = &mut thread_rng();

    //let r = R.unwrap_or(Fr::random(rng));
    // c = g1^m1 * ... * gn^mn * h^r
    //println!("(commit) index: 0");
    let mut c = (csp.pub_bases[0] * r);
    for i in 1 .. x.len() {
        //println!("(commit) index: {}", i);
        c = c + (csp.pub_bases[i] * x[i]);
    }
    // return (c, r) <- r
    let commitment = Commitment { c: c, r: r };

    // debugging
    //println!("{}", commitment);
    return commitment;
}

pub fn decommit(csp: &CSParams, cm: &Commitment, x: &Vec<Fr>) -> bool {
    let l = x.len();
    // pub_base[0] => h, x[0] => r
    // check that cm.r == x[0]
    // assert!(cm.r == x[0]);
    let mut dc = csp.pub_bases[0] * cm.r;
    for i in 1 .. l {
        dc = dc + (csp.pub_bases[i] * x[i]);
    }
    return dc == cm.c && cm.r == x[0];
}

#[cfg(test)]
mod tests {
    use super::*;
    use bn::{Fr, Group};

    #[test]
    fn commit_one_message_works() {
        let rng = &mut thread_rng();
        let pk = ped92_setup();

        let m1 = Fr::random(rng);
        let m2 = m1 + Fr::from_str("1").unwrap();
        let r = Fr::random(rng);
        let c = ped92_commit(&pk, m1, Some(r));

        assert!(ped92_decommit(&pk, &c, m1) == true);
        assert!(ped92_decommit(&pk, &c, m2) == false);
    }

    #[test]
    fn commit_n_message_works() {
        let rng = &mut thread_rng();
        let len = 3;
        let csp = setup_gen_params(len);

        let mut m: Vec<Fr> = Vec::new();
        for i in 0 .. len {
            m.push(Fr::random(rng));
        }
        let r = m[0];
        let c = commit(&csp, &m, r);

        assert!(decommit(&csp, &c, &m) == true);
    }
}
