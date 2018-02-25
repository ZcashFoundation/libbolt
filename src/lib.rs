extern crate bn;
extern crate rand;
extern crate bincode;
extern crate sodiumoxide;
use std::fmt;
use bn::{Group, Fr, G1, G2, pairing};
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use sodiumoxide::crypto::hash::sha256;

// define some structures here
pub struct PublicKey {
    g: G1,
    h: G1
}

pub struct Commitment {
    c: G1,
    d: Fr
}

// Begin CL Signature scheme data structures
pub struct PublicKeySigs {
    X: G1,
    Y: G1
}

pub struct SecretKeySigs {
    x: Fr,
    y: Fr
}

// End CL Signature scheme data structures



// To hash this message structure, encode each element in the tuple
// as a byte stream, then apply a hash on it. Then, convert the output value into
// a Fr element.
pub struct Message {
    sk_sigs: SecretKeySigs, // the secret key for the signature scheme
    k1: Fr, // seed 1 for PRF
    k2: Fr, // seed 2 for PRF
    balance: i32 // the balance for the user
}

// TODO: add a function that operates over the Message structure
// TODO: to perform the encodng an hash
impl Message {
    fn hash(&self) -> Fr {
        let rng = &mut rand::thread_rng();
        let a = Fr::random(rng);
        return a;
    }
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

pub fn misc_tests() {
    let rng = &mut rand::thread_rng();
    let a = Fr::random(rng);
    // println!("crs = {}", stringify!(a));
    // let limit = bincode::SizeLimit::Bounded(256);
    let encoded: Vec<u8> = encode(&a, Infinite).unwrap();
    println!("a length = {}", encoded.len());
    println!("a = {:?}", encoded);
    print!("a (hex) = 0x");
    for x in encoded.iter() {
        print!("{:x}", x);
    }
    print!("\n");

}

/*
    Implements the setup algorithm for the Pedersen92 commitment scheme
*/
pub fn setup() -> PublicKey {
    println!("Run Setup...");
    let rng = &mut rand::thread_rng();
    let g = G1::random(rng);
    let h = G1::random(rng);
    let pk = PublicKey { g: g, h: h };
    println!("{}", pk);
    return pk;
}

// TODO: need to be able to handle a message structure
pub fn commit(pk : PublicKey, msg : Message) -> Commitment {
    let rng = &mut rand::thread_rng();

    let r = Fr::random(rng);
    // TODO: replace with hash of message into m (of type Fr)
    let m = msg.hash();
    let c = (pk.g * m) + (pk.h * r);
    // return (c, r) <- d=r
    let commitment = Commitment { c: c, d: r };

    // debugging
    println!("{}", commitment);
    return commitment;
}

/*
pub fn decommit(pk: PublicKey, cm: Commitment, msg: Message) -> bool {
    // TODO: replace with hash of message into m (of type Fr)
    let m = Fr::random(rng);
    let dm = (pk.g * m) + (pk.h * cm.d);
    return dm == cm.c;
}
*/



//pub fn keygen() {
//    println!("Run Keygen...");
//}
//
//pub fn init() {
//    println!("Run Init...");
//
//}
//
//pub fn refund() {
//    println!("Run Refund...");
//
//}
//
//pub fn refute() {
//    println!("Run Refute...");
//
//}
//
//pub fn resolve() {
//    println!("Run Resolve...");
//
//}
