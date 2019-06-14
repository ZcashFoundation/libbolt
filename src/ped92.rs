// commit_schemes.rs
extern crate serde;

use serialization_wrappers;
use std::fmt;
use rand::{thread_rng, Rng};
use bn::{Group, Fr, G1, G2};
use pairing::{Engine, CurveProjective, CurveAffine};
use ff::Rand;
use clsigs;
use debug_elem_in_hex;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use sodiumoxide::crypto::hash::sha512;

use serde::{Serialize, Deserialize};

#[derive(Clone)]
pub struct PublicKey<E: Engine> {
    g: E::G2,
    h: E::G2
}

#[derive(Clone)]
pub struct Commitment<E: Engine> {
    pub c: E::G2,
    pub r: E::Fr
}

#[derive(Clone)]
pub struct CSParams<E: Engine> {
    pub pub_bases: Vec<E::G2>
}

//impl<E: Engine> fmt::Display for PublicKey<E> {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        let g_vec: Vec<u8> = encode(&self.g, Infinite).unwrap();
//        let h_vec: Vec<u8> = encode(&self.h, Infinite).unwrap();
//        let mut g_s = String::new();
//        for x in g_vec.iter() {
//            g_s = format!("{}{:x}", g_s, x);
//        }
//
//        let mut h_s = String::new();
//        for y in h_vec.iter() {
//            h_s = format!("{}{:x}", h_s, y);
//        }
//
//        write!(f, "PK : (g=0x{}, h=0x{})", g_s, h_s)
//    }
//}

//impl<E: Engine> fmt::Display for Commitment<E> {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        let c_vec: Vec<u8> = encode(&self.c, Infinite).unwrap();
//        let mut c_s = String::new();
//        for x in c_vec.iter() {
//            c_s = format!("{}{:x}", c_s, x);
//        }
//
//        let d_vec: Vec<u8> = encode(&self.r, Infinite).unwrap();
//        let mut d_s = String::new();
//        for x in d_vec.iter() {
//            d_s = format!("{}{:x}", d_s, x);
//        }
//        write!(f, "Commitment : (c=0x{}, r=0x{})", c_s, d_s)
//    }
//}

/*
Implements the setup algorithm for the Pedersen92 commitment scheme
*/
pub fn ped92_setup<E: Engine>() -> PublicKey<E> {
    println!("Run Setup...");
    let rng = &mut thread_rng();
    let g = E::G2::rand(rng);
    let h = E::G2::rand(rng);
    let pk = PublicKey { g, h };
    return pk;
}

/*
commit(pk, msg) -> cm where
- pk is the public key generated from setup()
- msg is the message structure for the commitment scheme
- cm is the output commitment message for the given message
*/
pub fn ped92_commit<E: Engine>(pk: &PublicKey<E>, m: E::Fr, R: Option<E::Fr>) -> Commitment<E> {
    let rng = &mut thread_rng();

    let r = R.unwrap_or(E::Fr::rand(rng));
    //let r = Fr::random(rng);

    //let m = msg.hash();
    let p = "commit -> m";
    // c = g^m * h^r
    let mut c = pk.g.clone();
    c.mul_assign(m);
    let mut h = pk.h.clone();
    h.mul_assign(r);
    c.add_assign(&h);
    // return (c, r) <- d=r
    let commitment = Commitment { c, r };

    // debugging
    return commitment;
}

/*
decommit(pk, cm, msg) -> bool where
- pk is the public key generated from setup()
- cm is the commitment
- m is the message to validate
- outputs T/F for whether the cm is a valid commitment to the msg
*/
pub fn ped92_decommit<E: Engine>(pk: &PublicKey<E>, cm: &Commitment<E>, m: E::Fr) -> bool {
    let p = "decommit -> m";

    let mut dm = pk.g.clone();
    dm.mul_assign(m);
    let mut h = pk.h.clone();
    h.mul_assign(cm.r.clone());
    dm.add_assign(&h);
    return dm == cm.c;
}


/*
Implements the setup algorithm for the Pedersen92 commitment scheme over
a vector of messages.
*/

pub fn setup<E: Engine>(len: usize, pub_bases: Vec<E::G2>, h: E::G2) -> CSParams<E> {
    let rng = &mut thread_rng();
    //let base_h = h.unwrap_or(G2::random(rng));
    let mut p: Vec<E::G2> = Vec::new();
    p.push(h);

    let _p = pub_bases;
    for i in 0 .. _p.len() {
        p.push(_p[i]);
    }
    return CSParams { pub_bases: p };
}

pub fn setup_gen_params<E: Engine>(len: usize) -> CSParams<E> {
    let rng = &mut thread_rng();

    let mut p: Vec<E::G2> = Vec::new();
    for i in 0 .. len {
        p.push(E::G2::rand(rng));
    }
    return CSParams { pub_bases: p };
}

pub fn commit<E: Engine>(csp: &CSParams<E>, x: &Vec<E::Fr>, r: E::Fr) -> Commitment<E> {
    let rng = &mut thread_rng();

    //let r = R.unwrap_or(Fr::random(rng));
    // c = g1^m1 * ... * gn^mn * h^r
    //println!("(commit) index: 0");
    let mut c = csp.pub_bases[0].clone();
    c.mul_assign(r);
    for i in 1 .. x.len() {
        //println!("(commit) index: {}", i);
        let mut basis= csp.pub_bases[i];
        basis.mul_assign(x[i]);
        c.add_assign(&basis);
    }
    // return (c, r) <- r
    let commitment = Commitment { c, r };

    // debugging
    //println!("{}", commitment);
    return commitment;
}

pub fn decommit<E: Engine>(csp: &CSParams<E>, cm: &Commitment<E>, x: &Vec<E::Fr>) -> bool {
    let l = x.len();
    // pub_base[0] => h, x[0] => r
    // check that cm.r == x[0]
    // assert!(cm.r == x[0]);
    let mut dc = csp.pub_bases[0].clone();
    dc.mul_assign(cm.r.clone());
    for i in 1 .. l {
        let mut basis= csp.pub_bases[i];
        basis.mul_assign(x[i]);
        dc.add_assign(&basis);
    }
    return dc == cm.c && cm.r == x[0];
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr};
    use ff::Field;

    #[test]
    fn commit_one_message_works() {
        let rng = &mut thread_rng();
        let pk = ped92_setup::<Bls12>();

        let m1 = Fr::rand(rng);
        let mut m2 = m1.clone();
        m2.add_assign(&Fr::one());
        let r = Fr::rand(rng);
        let c = ped92_commit(&pk, m1, Some(r));

        assert!(ped92_decommit(&pk, &c, m1) == true);
        assert!(ped92_decommit(&pk, &c, m2) == false);
    }

    #[test]
    fn commit_n_message_works() {
        let rng = &mut thread_rng();
        let len = 3;
        let csp = setup_gen_params::<Bls12>(len);

        let mut m: Vec<Fr> = Vec::new();
        for i in 0 .. len {
            m.push(Fr::rand(rng));
        }
        let r = m[0].clone();
        let c = commit(&csp, &m, r);

        assert!(decommit(&csp, &c, &m) == true);
    }
}
