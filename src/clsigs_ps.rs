// clsigs_ps.rs
// CL Sigs - Pointcheval Sanders ('06)
extern crate serde;

use std::fmt;
use std::str;
use rand::{thread_rng, Rng};
use bn::{Group, Fr, G1, G2, Gt, pairing};
use debug_elem_in_hex;
use debug_g1_in_hex;
use debug_g2_in_hex;
use debug_gt_in_hex;
use concat_g1_to_vector;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use sodiumoxide::crypto::hash::sha512;
use sodiumoxide::randombytes;
use serialization_wrappers;
use serde_with;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct PublicParamsPS {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
    pub g1: G1,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_two")]
    pub g2: G2
}

//#[derive(Copy, Clone, Serialize, Deserialize)]
//pub struct PublicKey {
//    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
//    X: G1,
//    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
//    Y: G1
//}
//
//impl PublicKey {
//    pub fn encode(&self) -> Vec<u8> {
//        let mut output_buf = Vec::new();
//        let x_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();
//        let y_vec: Vec<u8> = encode(&self.Y, Infinite).unwrap();
//        output_buf.extend(x_vec);
//        output_buf.extend(y_vec);
//        return output_buf;
//    }
//}
//
//
//impl fmt::Display for PublicKey {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        let x_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();
//        let y_vec: Vec<u8> = encode(&self.Y, Infinite).unwrap();
//        let mut x_s = String::new();
//        for x in x_vec.iter() {
//            x_s = format!("{}{:x}", x_s, x);
//        }
//
//        let mut y_s = String::new();
//        for y in y_vec.iter() {
//            y_s = format!("{}{:x}", y_s, y);
//        }
//
//        write!(f, "PK : (X=0x{}, Y=0x{})", x_s, y_s)
//    }
//}
//
//#[derive(Copy, Clone, Serialize)]
//pub struct SecretKey {
//    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_fr")]
//    x: Fr,
//    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_fr")]
//    y: Fr
//}
//
//impl SecretKey {
//    pub fn encode(&self) -> Vec<u8> {
//        let mut output_buf = Vec::new();
//        let x_vec: Vec<u8> = encode(&self.x, Infinite).unwrap();
//        let y_vec: Vec<u8> = encode(&self.y, Infinite).unwrap();
//        output_buf.extend(x_vec);
//        output_buf.extend(y_vec);
//        return output_buf;
//    }
//}
//
//#[derive(Clone, Serialize)]
//pub struct KeyPair {
//    pub sk: SecretKey,
//    pub pk: PublicKey
//}
//
//#[derive(Serialize)]
//pub struct Signature {
//    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable")]
//    a: G2,
//    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable")]
//    b: G2,
//    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable")]
//    c: G2
//}


// CL PS scheme - for a vector of messages
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKeyPS {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_two")]
    pub X: G2,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable_vec", deserialize_with = "serialization_wrappers::deserialize_g_two_vec")]
    pub Y: Vec<G2>,
}

impl PublicKeyPS {
    pub fn encode(&self) -> Vec<u8> {
        let mut output_buf = Vec::new();
        let x_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();

        output_buf.extend(x_vec);
        for i in 0 .. self.Y.len() {
            let yi_vec: Vec<u8> = encode(&self.Y[i], Infinite).unwrap();
            output_buf.extend(yi_vec);
        }
        return output_buf;
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKeyPS {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_fr")]
    pub x: Fr,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable_vec", deserialize_with = "serialization_wrappers::deserialize_fr_vec")]
    pub y: Vec<Fr>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPairPS {
    pub sk: SecretKeyPS,
    pub pk: PublicKeyPS
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignaturePS {
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
    pub h: G1,
    #[serde(serialize_with = "serialization_wrappers::serialize_generic_encodable", deserialize_with = "serialization_wrappers::deserialize_g_one")]
    pub H: G1
}

impl SignaturePS {
    pub fn new(_h: G1, _H: G1) -> SignaturePS {
        SignaturePS {
            h: _h, H: _H
        }
    }

    pub fn hash(&self, prefix: &str) -> Fr {
        let mut output_buf: Vec<u8> = Vec::new();
        output_buf.extend_from_slice(prefix.as_bytes());
        concat_g1_to_vector(&mut output_buf, &self.h);
        concat_g1_to_vector(&mut output_buf, &self.H);

        // println!("DEBUG: signature len => {}", output_buf.len());
        // let's hash the final output_buf
        let sha2_digest = sha512::hash(output_buf.as_slice());

        let mut hash_buf: [u8; 64] = [0; 64];
        hash_buf.copy_from_slice(&sha2_digest[0..64]);
        return Fr::interpret(&hash_buf);
    }
}

// display CL signature (PS)
impl fmt::Display for SignaturePS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let a_vec: Vec<u8> = encode(&self.h, Infinite).unwrap();
        let b_vec: Vec<u8> = encode(&self.H, Infinite).unwrap();

        let mut a_s = String::new();
        for x in a_vec.iter() {
            a_s = format!("{}{:x}", a_s, x);
        }

        let mut b_s = String::new();
        for y in b_vec.iter() {
            b_s = format!("{}{:x}", b_s, y);
        }

        write!(f, "SignaturePS : (\nh = 0x{},\nH = 0x{}\n)", a_s, b_s)
    }
}

/////

pub fn setup_ps() -> PublicParamsPS {
    let rng = &mut thread_rng();
    let g1 = G1::random(rng);
    let g2 = G2::random(rng);
    let mpk = PublicParamsPS { g1: g1, g2: g2 };
    return mpk;
}

pub fn keygen_ps(mpk : &PublicParamsPS, l: usize) -> KeyPairPS {
    let rng = &mut thread_rng();
    let x = Fr::random(rng);
    let X = mpk.g2 * x;
    let mut y: Vec<Fr> = Vec::new();
    let mut Y: Vec<G2> = Vec::new();

    for i in 0 .. l {
        let _y = Fr::random(rng);
        let _Y = mpk.g2 * _y;
        y.push(_y);
        Y.push(_Y);
    }

    let sk = SecretKeyPS { x: x, y: y };
    let pk = PublicKeyPS { X: X, Y: Y };
    return KeyPairPS { sk: sk, pk: pk }
}

pub fn sign_ps(mpk: &PublicParamsPS, sk: &SecretKeyPS, m: &Vec<Fr>) -> SignaturePS {
    assert!(m.len() <= sk.y.len()+1);
    let l = m.len();

    let rng = &mut thread_rng();

    let h = G1::random(rng);
    let mut s = Fr::from_str("0").unwrap();
    for i in 0 .. sk.y.len() {
        s = s + (sk.y[i] * m[i]);
    }

    let H = h * (sk.x + s);
    let sig = SignaturePS { h: h, H: H };
    println!("SigPS => {}", sig);
    return sig;
}

pub fn verify_ps(mpk: &PublicParamsPS, pk: &PublicKeyPS, m: &Vec<Fr>, sig: &SignaturePS) -> bool {
    let l = m.len();

    // sig_1 != 1 and e(sig_1, X * \prod{i=1}^\ell Y_i * m_i) =?= e(sig_2, g)
    let mut L = G2::zero();
    for i in 0 .. l {
        L = L + (pk.Y[i] * m[i]);
    }
    let lhs = pairing(sig.h, pk.X + L);

    let rhs = pairing(sig.H, mpk.g2);

    return sig.h != G1::one() && lhs == rhs;
}

//// NIZK protocol for proving knowledge of a signature
//pub fn hash_g2_to_fr(x: &G2) -> Fr {
//    // TODO: change to serde (instead of rustc_serialize)
//    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
//    let sha2_digest = sha512::hash(x_vec.as_slice());
//
//    let mut hash_buf: [u8; 64] = [0; 64];
//    hash_buf.copy_from_slice(&sha2_digest[0..64]);
//    return Fr::interpret(&hash_buf);
//}
//
//pub fn hash_gt_to_fr(x: &Gt) -> Fr {
//    // TODO: change to serde (instead of rustc_serialize)
//    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
//    let sha2_digest = sha512::hash(x_vec.as_slice());
//
//    let mut hash_buf: [u8; 64] = [0; 64];
//    hash_buf.copy_from_slice(&sha2_digest[0..64]);
//    return Fr::interpret(&hash_buf);
//}

#[cfg(test)]
mod tests {
    use super::*;
    use bn::{Fr, Group};

//    #[test]
//    fn scheme_ps_sign_and_verify_works() {
//        // test ability to sign/verify a single message
//        let rng = &mut thread_rng();
//
//        let mpk = setup_ps();
//        let keypair = keygen_ps(&mpk);
//
//        let mut m1 = Fr::random(rng);
//        let mut m2 = Fr::random(rng);
//
//        let signature = sign_ps(&keypair.sk, m1);
//
//        assert!(verify_ps(&mpk, &keypair.pk, m1, &signature) == true);
//        assert!(verify_ps(&mpk, &keypair.pk, m2, &signature) == false);
//    }

    #[test]
    fn scheme_ps_sign_and_verify_works() {
        // test ability to sign/verify a vector of messages
        let rng = &mut thread_rng();

        let mpk = setup_ps();
        let l = 5;
        let keypair = keygen_ps(&mpk, l);

        let mut m1 : Vec<Fr> = Vec::new();
        let mut m2 : Vec<Fr> = Vec::new();

        for i in 0 .. l {
            m1.push(Fr::random(rng));
            m2.push(Fr::random(rng));
        }

        let signature = sign_ps(&mpk, &keypair.sk, &m1);

        assert!(verify_ps(&mpk, &keypair.pk, &m1, &signature) == true);
        assert!(verify_ps(&mpk, &keypair.pk, &m2, &signature) == false);
    }
}

