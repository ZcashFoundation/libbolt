// clsigs.rs
extern crate serde;

use std::fmt;
use std::str;
use rand::{thread_rng, Rng};
use bn::{Group, Fr, G1, G2, Gt, pairing};
use debug_elem_in_hex;
use debug_g1_in_hex;
use debug_g2_in_hex;
use debug_gt_in_hex;
use concat_g2_to_vector;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use sodiumoxide::crypto::hash::sha512;
use sodiumoxide::randombytes;
use serialization_wrappers;
use serde_with;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct PublicParams {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
    pub g1: G1,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_two")]
    pub g2: G2
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
    X: G1,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
    Y: G1
}

impl PublicKey {
    pub fn encode(&self) -> Vec<u8> {
        let mut output_buf = Vec::new();
        let x_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();
        let y_vec: Vec<u8> = encode(&self.Y, Infinite).unwrap();
        output_buf.extend(x_vec);
        output_buf.extend(y_vec);
        return output_buf;
    }
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

#[derive(Copy, Clone, Serialize)]
pub struct SecretKey {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_fr")]
    x: Fr,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_fr")]
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

#[derive(Clone, Serialize)]
pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey
}

#[derive(Serialize)]
pub struct Signature {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable")]
    a: G2,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable")]
    b: G2,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable")]
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

// scheme A - for a single message

pub fn setup_a() -> PublicParams {
    let rng = &mut thread_rng();
    let g1 = G1::random(rng);
    let g2 = G2::random(rng);
    let mpk = PublicParams { g1: g1, g2: g2 };
    return mpk;
}

pub fn keygen_a(mpk : &PublicParams) -> KeyPair {
    let rng = &mut thread_rng();
    let x = Fr::random(rng);
    let y = Fr::random(rng);
    let sk = SecretKey { x: x, y: y };
    let pk = PublicKey { X: mpk.g1 * x,
                         Y: mpk.g1 * y
                        };
    return KeyPair { sk: sk, pk: pk }
}

pub fn sign_a(sk: &SecretKey, m: Fr) -> Signature {
    let rng = &mut thread_rng();
    let a = G2::random(rng);

    let b = a * sk.y;
    let c = a * (sk.x + (m * sk.x * sk.y));
    let sig = Signature { a: a, b: b, c: c };
    return sig;
}

pub fn verify_a(mpk: &PublicParams, pk: &PublicKey, m: Fr, sig: &Signature) -> bool {
    let lhs1 = pairing(pk.Y, sig.a);
    let rhs1 = pairing(mpk.g1, sig.b);
    let lhs2 = pairing(pk.X, sig.a) * (pairing(pk.X, sig.b).pow(m));
    let rhs2 = pairing(mpk.g1, sig.c);
    return (lhs1 == rhs1) && (lhs2 == rhs2);
}

// scheme D - for a vector of messages
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKeyD {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
    pub X: G1,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
    pub Y: G1,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable_vec", deserialize_with = "serialization_wrappers::deserialize_g_one_vec")]
    pub Z: Vec<G1>,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable_vec", deserialize_with = "serialization_wrappers::deserialize_g_two_vec")]
    pub Z2: Vec<G2>,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable_vec", deserialize_with = "serialization_wrappers::deserialize_g_one_vec")]
    pub W: Vec<G1>
}

impl PublicKeyD {
    pub fn encode(&self) -> Vec<u8> {
        let mut output_buf = Vec::new();
        let x_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();
        let y_vec: Vec<u8> = encode(&self.Y, Infinite).unwrap();

        output_buf.extend(x_vec);
        output_buf.extend(y_vec);
        for i in 0 .. self.Z.len() {
            let zi_vec: Vec<u8> = encode(&self.Z[i], Infinite).unwrap();
            output_buf.extend(zi_vec);
            let z2i_vec: Vec<u8> = encode(&self.Z2[i], Infinite).unwrap();
            output_buf.extend(z2i_vec);
            let w_vec: Vec<u8> = encode(&self.W[i], Infinite).unwrap();
            output_buf.extend(w_vec);
        }
        return output_buf;
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKeyD {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_fr")]
    pub x: Fr,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_fr")]
    pub y: Fr,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable_vec", deserialize_with = "serialization_wrappers::deserialize_fr_vec")]
    pub z: Vec<Fr>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPairD {
    pub sk: SecretKeyD,
    pub pk: PublicKeyD
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignatureD {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_two")]
    pub a: G2,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable_vec", deserialize_with = "serialization_wrappers::deserialize_g_two_vec")]
    pub A: Vec<G2>,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_two")]
    pub b: G2,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable_vec", deserialize_with = "serialization_wrappers::deserialize_g_two_vec")]
    pub B: Vec<G2>,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_two")]
    pub c: G2
}

impl SignatureD {
    pub fn new(_a: G2, _A: Vec<G2>, _b: G2, _B: Vec<G2>, _c: G2) -> SignatureD {
        SignatureD {
            a: _a, A: _A, b: _b, B: _B, c: _c
        }
    }

    pub fn hash(&self, prefix: &str) -> Fr {
        let mut output_buf: Vec<u8> = Vec::new();
        output_buf.extend_from_slice(prefix.as_bytes());
        concat_g2_to_vector(&mut output_buf, &self.a);
        concat_g2_to_vector(&mut output_buf, &self.b);
        concat_g2_to_vector(&mut output_buf, &self.c);
        assert_eq!(self.A.len(), self.B.len());
        for i in 0 .. self.A.len() {
            concat_g2_to_vector(&mut output_buf, &self.A[i]);
            concat_g2_to_vector(&mut output_buf, &self.B[i]);
        }

        // println!("DEBUG: signature len => {}", output_buf.len());
        // let's hash the final output_buf
        let sha2_digest = sha512::hash(output_buf.as_slice());

        let mut hash_buf: [u8; 64] = [0; 64];
        hash_buf.copy_from_slice(&sha2_digest[0..64]);
        return Fr::interpret(&hash_buf);
    }
}

pub fn setup_d() -> PublicParams {
    let rng = &mut thread_rng();
    let g1 = G1::random(rng);
    let g2 = G2::random(rng);
    let mpk = PublicParams { g1: g1, g2: g2 };
    return mpk;
}

pub fn keygen_d(mpk : &PublicParams, l: usize) -> KeyPairD {
    let rng = &mut thread_rng();
    let x = Fr::random(rng);
    let y = Fr::random(rng);
    let X = mpk.g1 * x;
    let Y = mpk.g1 * y;
    let mut z: Vec<Fr> = Vec::new();
    let mut Z: Vec<G1> = Vec::new();
    let mut Z2: Vec<G2> = Vec::new();
    let mut W: Vec<G1> = Vec::new();
    // generate the vector ck of sym keys
    for i in 0 .. l {
        let _z = Fr::random(rng);
        let _Z = mpk.g1 * _z;
        let _Z2 = mpk.g2 * _z;
        let _W = Y * _z;
        z.push(_z);
        Z.push(_Z);
        Z2.push(_Z2);
        W.push(_W);
    }
    // plus one to Z2


    let sk = SecretKeyD { x: x, y: y, z: z };
    let pk = PublicKeyD { X: X, Y: Y, Z: Z, Z2: Z2, W: W };
    return KeyPairD { sk: sk, pk: pk }
}

pub fn sign_d(mpk: &PublicParams, sk: &SecretKeyD, m: &Vec<Fr>) -> SignatureD {
    assert!(m.len() <= sk.z.len()+1);
    let l = m.len();

    let rng = &mut thread_rng();
    //let a = mpk.g2 * Fr::random(rng); // G2::random(rng);
    let a = G2::random(rng);
    let mut A: Vec<G2> = Vec::new();
    let b = a * sk.y;
    let mut B: Vec<G2> = Vec::new();
    let mut c = (a * (sk.x + (m[0] * sk.x * sk.y)));

    for i in 0 .. l-1 {
        let _A = a * sk.z[i];
        let _B = _A * sk.y;
        A.push(_A);
        B.push(_B);
        c = c + (_A * (m[i+1] * sk.x * sk.y));
    }

    let sig = SignatureD { a: a, A: A, b: b, B: B, c: c };
    return sig;
}

pub fn verify_d_unoptimized(mpk: &PublicParams, pk: &PublicKeyD, m: &Vec<Fr>, sig: &SignatureD) -> bool {
    let l = m.len();
    // lhs2a and rhs2a checks that sig.b was formed correctly
    let lhs2a = pairing(pk.Y, sig.a); // eq2a
    let rhs2a = pairing(mpk.g1, sig.b);

    let mut result1 = true;
    let mut result2b = true;
    // lhs3 and rhs3 checks that sig.c was formed correctly
    let mut lhs3 = pairing(pk.X, sig.a) * pairing(pk.X, sig.b * m[0]); // eq3
    let rhs3 = pairing(mpk.g1, sig.c);

    for i in 0 .. l-1 {
        // checks that {sig.A}_i was formed correctly
        let lhs1 = pairing(pk.Z[i], sig.a); // eq1
        let rhs1 = pairing(mpk.g1, sig.A[i]);
        if (lhs1 != rhs1) {
            result1 = false;
        }
        let lhs2b = pairing(pk.Y, sig.A[i]); // eq2b
        let rhs2b = pairing(mpk.g1, sig.B[i]);
        if lhs2b != rhs2b {
            result2b = false;
        }
        lhs3 = lhs3 * pairing(pk.X, sig.B[i] * m[i+1]); // eq3
    }

    return result1 && (lhs2a == rhs2a) && result2b && (lhs3 == rhs3);
}

// optimized but does not include small exps for security
pub fn verify_d(mpk: &PublicParams, pk: &PublicKeyD, m: &Vec<Fr>, sig: &SignatureD) -> bool {
    let l = m.len();
    let mut Zis = G1::zero();
    let mut Ais = G2::zero();
    let mut Bis = G2::zero();
    let mut _lhs3 = G2::zero();
    for i in 0 .. l-1 {
        // checks that {sig.A}_i was formed correctly
        let Zis = Zis + pk.Z[i];
        let Ais = Ais + sig.A[i];
        let Bis = Bis + sig.B[i];
        _lhs3 = _lhs3 + (sig.B[i] * m[i+1]);
    }

    return pairing(Zis, sig.a) *
             pairing(pk.Y, Ais + sig.a).inverse() *
              pairing(pk.X, sig.a + (sig.b * m[0]) + _lhs3).inverse() ==
               pairing(mpk.g1, Ais + -Bis + -sig.b + -sig.c);
}

// NIZK protocol for proving knowledge of a signature
pub fn hash_g2_to_fr(x: &G2) -> Fr {
    // TODO: change to serde (instead of rustc_serialize)
    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
    let sha2_digest = sha512::hash(x_vec.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

pub fn hash_gt_to_fr(x: &Gt) -> Fr {
    // TODO: change to serde (instead of rustc_serialize)
    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
    let sha2_digest = sha512::hash(x_vec.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bn::{Fr, Group};

    #[test]
    fn scheme_a_sign_and_verify_works() {
        // test ability to sign/verify a single message
        let rng = &mut thread_rng();

        let mpk = setup_a();
        let keypair = keygen_a(&mpk);

        let mut m1 = Fr::random(rng);
        let mut m2 = Fr::random(rng);

        let signature = sign_a(&keypair.sk, m1);

        assert!(verify_a(&mpk, &keypair.pk, m1, &signature) == true);
        assert!(verify_a(&mpk, &keypair.pk, m2, &signature) == false);
    }

    #[test]
    fn scheme_d_sign_and_verify_works() {
        // test ability to sign/verify a vector of messages
        let rng = &mut thread_rng();

        let mpk = setup_d();
        let l = 3;
        let keypair = keygen_d(&mpk, l);

        let mut m1 : Vec<Fr> = Vec::new();
        let mut m2 : Vec<Fr> = Vec::new();

        for i in 0 .. l+1 {
            m1.push(Fr::random(rng));
            m2.push(Fr::random(rng));
        }

        let signature = sign_d(&mpk, &keypair.sk, &m1);

        assert!(verify_d(&mpk, &keypair.pk, &m1, &signature) == true);
        assert!(verify_d_unoptimized(&mpk, &keypair.pk, &m1, &signature) == true);
        assert!(verify_d(&mpk, &keypair.pk, &m2, &signature) == false);
    }
}

