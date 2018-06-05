// commit_schemes.rs

use std::fmt;
use rand;
use bn::{Group, Fr, G1};
use clsigs;
use debug_elem_in_hex;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use sodiumoxide::crypto::hash::sha512;

// define some structures here
#[derive(Copy, Clone)]
pub struct PublicParams {
    pub g1: G1,
    pub g2: G1,
    pub g3: G1,
    pub h: G1
}


// define some structures here
#[derive(Copy, Clone)]
pub struct PublicKey {
    g: G1,
    h: G1
}

#[derive(Copy, Clone)]
pub struct Commitment {
    c: G1,
    d: Fr
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

        let d_vec: Vec<u8> = encode(&self.d, Infinite).unwrap();
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
    let rng = &mut rand::thread_rng();
    let g = G1::random(rng);
    let h = G1::random(rng);
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
    let rng = &mut rand::thread_rng();

    let r = R.unwrap_or(Fr::random(rng));
    //let r = Fr::random(rng);

    //let m = msg.hash();
    let p = "commit -> m";
    debug_elem_in_hex(p, &m);
    // c = g^m * h^r
    let c = (pk.g * m) + (pk.h * r);
    // return (c, r) <- d=r
    let commitment = Commitment { c: c, d: r };

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
    //let m = msg.hash();
    let p = "decommit -> m";
    debug_elem_in_hex(p, &m);

    let dm = (pk.g * m) + (pk.h * cm.d);
    return dm == cm.c;
}


/*
Implements the setup algorithm for the Pedersen92 commitment scheme
*/
pub fn setup() -> PublicParams {
    println!("Run Setup...");
    let rng = &mut rand::thread_rng();
    let g1 = G1::random(rng);
    let g2 = G1::random(rng);
    let g3 = G1::random(rng);
    let g4 = G1::random(rng);
    let h = G1::random(rng);
    let pp = PublicParams { g1: g1, g2: g2, g3: g3, h: h };
    //println!("{}", pp);
    return pp;
}

pub fn commit(pp: &PublicParams, channelId: Fr, wpk: Fr, balance: Fr, R: Option<Fr>) -> Commitment {
    let rng = &mut rand::thread_rng();

    let r = R.unwrap_or(Fr::random(rng));

    let p = "commit -> cid";
    debug_elem_in_hex(p, &channelId);
    // c = g^m * h^r
    let c = (pp.g1 * channelId) + (pp.g2 * wpk) + (pp.g3 * balance) + (pp.h * r);
    // return (c, r) <- d=r
    let commitment = Commitment { c: c, d: r };

    // debugging
    println!("{}", commitment);
    return commitment;
}

pub fn decommit(pp: &PublicParams, cm: &Commitment, channelId: Fr, wpk: Fr, balance: Fr) -> bool {
    let p = "decommit -> cid";
    debug_elem_in_hex(p, &channelId);
    let dm = (pp.g1 * channelId) + (pp.g2 * wpk) + (pp.g3 * balance) + (pp.h * cm.d);
    return dm == cm.c;
}
