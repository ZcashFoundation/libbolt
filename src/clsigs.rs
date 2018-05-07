// clsigs.rs

use std::fmt;
use std::str;
//use std::default;
use rand;
use bn::{Group, Fr, G1, G2, pairing};
//use debug_elem_in_hex;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use sodiumoxide::crypto::hash::sha512;

pub struct PublicParams {
    g: G1
}

#[derive(Copy, Clone)]
pub struct PublicKey {
    X: G1,
    Y: G1
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let x_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();
        let y_vec: Vec<u8> = encode(&self.Y, Infinite).unwrap();
        let mut x_s = String::new();
        for x in x_vec.iter() {
            x_s = format!("{}{:x}", x_s, x);
        }

        let mut y_s = String::new();
        for y in y_vec.iter() {
            y_s = format!("{}{:x}", y_s, y);
        }

        write!(f, "PK : (X=0x{}, Y=0x{})", x_s, y_s)
    }
}

#[derive(Copy, Clone)]
pub struct SecretKey {
    x: Fr,
    y: Fr
}

impl SecretKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut output_buf = Vec::new();
        let x_vec: Vec<u8> = encode(&self.x, Infinite).unwrap();
        let y_vec: Vec<u8> = encode(&self.y, Infinite).unwrap();
        output_buf.extend(x_vec);
        output_buf.extend(y_vec);
        return output_buf;
    }
}

pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey
}

pub struct Signature {
    a: G2,
    b: G2,
    c: G2
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let a_vec: Vec<u8> = encode(&self.a, Infinite).unwrap();
        let b_vec: Vec<u8> = encode(&self.b, Infinite).unwrap();
        let c_vec: Vec<u8> = encode(&self.c, Infinite).unwrap();
        let mut a_s = String::new();
        for x in a_vec.iter() {
            a_s = format!("{}{:x}", a_s, x);
        }

        let mut b_s = String::new();
        for y in b_vec.iter() {
            b_s = format!("{}{:x}", b_s, y);
        }

        let mut c_s = String::new();
        for y in c_vec.iter() {
            c_s = format!("{}{:x}", c_s, y);
        }

        write!(f, "Signature : (\na = 0x{},\nb = 0x{},\nc = 0x{}\n)", a_s, b_s, c_s)
    }
}

pub fn setup() -> PublicParams {
    let rng = &mut rand::thread_rng();
    let g = G1::random(rng);
    let mpk = PublicParams { g: g };
    return mpk;
}

pub fn keygen(mpk : &PublicParams) -> KeyPair {
    let rng = &mut rand::thread_rng();
    let x = Fr::random(rng);
    let y = Fr::random(rng);
    let sk = SecretKey { x: x, y: y };
    let pk = PublicKey { X: mpk.g * x,
                         Y: mpk.g * y
                        };
    return KeyPair { sk: sk, pk: pk }
}

pub fn sign(sk: &SecretKey, m: Fr) -> Signature {
    let rng = &mut rand::thread_rng();
    let a = G2::random(rng);

    let b = a * sk.y;
    let c = a * (sk.x + (m * sk.x * sk.y));
    let sig = Signature { a: a, b: b, c: c };
    return sig;
}

pub fn verify(mpk: &PublicParams, pk: &PublicKey, m: Fr, sig: &Signature) -> bool {
    let lhs1 = pairing(pk.Y, sig.a);
    let rhs1 = pairing(mpk.g, sig.b);
    let lhs2 = pairing(pk.X, sig.a) * (pairing(pk.X, sig.b).pow(m));
    let rhs2 = pairing(mpk.g, sig.c);
    return (lhs1 == rhs1) && (lhs2 == rhs2);
}

pub fn gen_blind(sig: &Signature) -> Signature {
    let rng = &mut rand::thread_rng();
    let r = Fr::random(rng);
    let r1 = Fr::random(rng);
    let a = sig.a * r;
    let b = sig.b * r;
    let c = (sig.c * r) * r1;
    let bsig = Signature { a: a, b: b, c:c };
    return bsig;
}