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

// scheme A - for single messages

pub fn setup_A() -> PublicParams {
    let rng = &mut rand::thread_rng();
    let g = G1::random(rng);
    let mpk = PublicParams { g: g };
    return mpk;
}

pub fn keygen_A(mpk : &PublicParams) -> KeyPair {
    let rng = &mut rand::thread_rng();
    let x = Fr::random(rng);
    let y = Fr::random(rng);
    let sk = SecretKey { x: x, y: y };
    let pk = PublicKey { X: mpk.g * x,
                         Y: mpk.g * y
                        };
    return KeyPair { sk: sk, pk: pk }
}

pub fn sign_A(sk: &SecretKey, m: Fr) -> Signature {
    let rng = &mut rand::thread_rng();
    let a = G2::random(rng);

    let b = a * sk.y;
    let c = a * (sk.x + (m * sk.x * sk.y));
    let sig = Signature { a: a, b: b, c: c };
    return sig;
}

pub fn verify_A(mpk: &PublicParams, pk: &PublicKey, m: Fr, sig: &Signature) -> bool {
    let lhs1 = pairing(pk.Y, sig.a);
    let rhs1 = pairing(mpk.g, sig.b);
    let lhs2 = pairing(pk.X, sig.a) * (pairing(pk.X, sig.b).pow(m));
    let rhs2 = pairing(mpk.g, sig.c);
    return (lhs1 == rhs1) && (lhs2 == rhs2);
}

//pub fn gen_blind(sig: &Signature) -> Signature {
//    let rng = &mut rand::thread_rng();
//    let r = Fr::random(rng);
//    let r1 = Fr::random(rng);
//    let a = sig.a * r;
//    let b = sig.b * r;
//    let c = (sig.c * r) * r1;
//    let bsig = Signature { a: a, b: b, c:c };
//    return bsig;
//}

// scheme D - for a vector of messages
#[derive(Copy, Clone)]
pub struct PublicKeyD {
    X: G1,
    Y: G1,
    Z: Vec<G1>,
    W: Vec<G1>
}

#[derive(Copy, Clone)]
pub struct SecretKeyD {
    x: Fr,
    y: Fr,
    z: Vec<Fr>
}

#[derive(Copy, Clone)]
pub struct SignatureD {
    a: G2,
    A: Vec<G2>,
    b: G2,
    B: Vec<G2>,
    c: G2
}


pub fn setupD() -> PublicParams {
    let rng = &mut rand::thread_rng();
    let g = G1::random(rng);
    let mpk = PublicParams { g: g };
    return mpk;
}

pub fn keygenD(mpk : &PublicParams, l: i32) -> KeyPair {
    let rng = &mut rand::thread_rng();
    let x = Fr::random(rng);
    let y = Fr::random(rng);
    let X = mpk.g * x;
    let Y = mpk.g * y;
    let mut z: Vec<Fr> = Vec::new();
    let mut Z: Vec<G1> = Vec::new();
    let mut W: Vec<G1> = Vec::new();
    // generate the vector ck of sym keys
    for i in 1 .. l {
        let _z = Fr::random(rng);
        let _Z = mpk.g * _z;
        let _W = Y * _z;
        z.push(_z);
        Z.push(_Z);
        W.push(_W);
    }

    let sk = SecretKeyD { x: x, y: y, z: z };
    let pk = PublicKeyD { X: X, Y: Y, Z: Z, W: W };
    return KeyPairD { sk: sk, pk: pk }
}

pub fn signD(sk: &SecretKeyD, m: Vec<Fr>) -> Signature {
    assert_eq!(m.len(), sk.z.len());
    let l = m.len();

    let rng = &mut rand::thread_rng();
    let a = G2::random(rng);
    let mut A: Vec<G2> = Vec::new();
    let b = a * sk.y;
    let mut B: Vec<G2> = Vec::new();
    let mut c = (a * (sk.x + (m[0] * sk.x * sk.y)));

    for i in 1 .. l {
        let _A = a * z[i];
        let _B = _A * sk.y;
        A.push(_A);
        B.push(_B);
        c = c + (_A * (m[i] * sk.x * sk.y));
    }

    let sig = SignatureD { a: a, A: A, b: b, B: B, c: c };
    return sig;
}

pub fn verifyD(mpk: &PublicParams, pk: &PublicKeyD, m: Vec<Fr>, sig: &SignatureD) -> bool {
    assert_eq!(m.len(), sig.A.len());
    assert_eq!(m.len(), sig.B.len());

    let l = m.len();
    let lhs1 = pairing(pk.Z, sig.a);
    let rhs1 = pairing(mpk.g, sig.b);

    let lhs2a = pairing(pk.Y, a);
    let rhs2a = pairing(mpk.g, sig.b);

    let mut result2b = true;
    for i in 1 .. l {
        let lhs2b = pairing(pk.Y, sig.A[i]);
        let rhs2b = pairing(mpk.g, sig.B[i]);
        if lhs2b != rhs2b {
            result2b = false;
        }
    }

    let mut lhs3 = pairing(pk.X, sig.a) * pairing(pk.X, sig.b * m[0]);
    for i in 1 .. l {
        lhs3 = lhs3 * pairing(pk.X, sig.B[i] * m[i]);
    }
    let rhs3 = pairing(mpk.g, sig.c);

    return (lhs1 == rhs1) && (lhs2a == rhs2a) && (result2b == true) && (lhs3 == rhs3);
}

// NIZK protocol for proving knowledge of a signature

// Prover first randomizes the signature
pub fn prover_gen_blind(sig: &SignatureD) -> SignatureD {
    let rng = &mut rand::thread_rng();
    let r = Fr::random(rng);
    let rpr = Fr::random(rng);

    let a = sig.a * r;
    let b = sig.b * r;
    let c = (sig.c * r) * rpr;
    let mut A: Vec<G2> = Vec::new();
    let mut B: Vec<G2> = Vec::new();
    for i in 1 .. l {
        A.push(sig.A[i] * r);
        B.push(sig.B[i] * r);
    }

    let bsig = SignatureD { a: a, A: A, b: b, B: B, c: c };
    return bsig;
}

pub fn verify_proof_for_blind_sigs(mpk: &PublicParams, pk: &PublicKeyD, sig: &SignatureD) {
    let vx = pairing(pk.X, sig.a);
    let vxy = pairing(pk.X, sig.b);
    // generate vector
    let mut vxyi: Vec<GT> = Vec::new();
    for i in 1 .. l {
        vxyi.push(pairing(pk.X, sig.B[i]));
    }
    let vs = pairing(mpk.g, sig.c);

    //
}