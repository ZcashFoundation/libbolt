use super::*;
use sodiumoxide::crypto::hash::sha512;
use pairing::{Engine, CurveProjective};
use ff::{PrimeField};
use rand::Rng;
use ped92::CSMultiParams;
use secp256k1::{Signature, PublicKey};
use cl::Signature as clSignature;

pub fn is_vec_fr_equal<E: Engine>(a: &Vec<E::Fr>, b: &Vec<E::Fr>) -> bool {
    (a.len() == b.len()) &&
        a.iter()
         .zip(b)
         .all(|(a, b)| a == b)
}

pub fn is_vec_g1_equal<E: Engine>(a: &Vec<E::G1>, b: &Vec<E::G1>) -> bool {
    (a.len() == b.len()) &&
        a.iter()
         .zip(b)
         .all(|(a, b)| a == b)
}

pub fn is_vec_g2_equal<E: Engine>(a: &Vec<E::G2>, b: &Vec<E::G2>) -> bool {
    (a.len() == b.len()) &&
        a.iter()
         .zip(b)
         .all(|(a, b)| a == b)
}


pub fn hash_g1_to_fr<E: Engine>(x: &Vec<E::G1>) -> E::Fr {
    let mut x_vec: Vec<u8> = Vec::new();
    for i in x.iter() {
        x_vec.extend(format!("{}", i).bytes());
    }
    hash_to_fr::<E>(x_vec)
}

pub fn hash_g2_to_fr<E: Engine>(x: &E::G2) -> E::Fr {
    let mut x_vec: Vec<u8> = Vec::new();
    x_vec.extend(format!("{}", x).bytes());
    hash_to_fr::<E>(x_vec)
}

pub fn fmt_bytes_to_int(bytearray: [u8; 64]) -> String {
    let mut result: String = "".to_string();
    for byte in bytearray.iter() {
        // Decide if you want upper- or lowercase results,
        // padding the values to two characters, spaces
        // between bytes, etc.
        let s = format!("{}", *byte as u8);
        result = result + &s;
    }
    let s = match result.starts_with('0') {
        true => result[1..].to_string(),
        false => result.to_string()
    };
    return s;
}

pub fn hash_to_fr<E: Engine>(mut byteVec: Vec<u8>) -> E::Fr {
    let sha2_digest = sha512::hash(byteVec.as_slice());
    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    let hexresult = fmt_bytes_to_int(hash_buf);
    let result = E::Fr::from_str(&hexresult);
    return result.unwrap();
}

pub fn hash_pubkey_to_fr<E: Engine>(wpk: &secp256k1::PublicKey) -> E::Fr {
    let x_slice = wpk.serialize_uncompressed();
    let sha2_digest = sha512::hash(&x_slice);

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    let hexresult = fmt_bytes_to_int(hash_buf);
    let result = E::Fr::from_str(&hexresult);
    return result.unwrap();
}

pub fn convert_int_to_fr<E: Engine>(value: i32) -> E::Fr {
    if value > 0 {
        return E::Fr::from_str(value.to_string().as_str()).unwrap();
    } else {
        // negative value
        let value2 = value * -1;
        let mut res = E::Fr::zero();
        let val = E::Fr::from_str(value2.to_string().as_str()).unwrap();
        res.sub_assign(&val);
        // TODO: look at how to do negation
        return res;
    }
}

pub fn compute_pub_key_fingerprint(wpk: &secp256k1::PublicKey) -> String {
    let x_slice = wpk.serialize();
    let sha2_digest = sha512::hash(&x_slice);
    let h = format!("{:x}", HexSlice::new(&sha2_digest[0..16]));
    return h;
}

pub fn hash_buffer_to_fr<'a, E: Engine>(prefix: &'a str, buf: &[u8; 64]) -> E::Fr {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(prefix.as_bytes());
    input_buf.extend_from_slice(buf);

    let sha2_digest = sha512::hash(&input_buf.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    let hexresult = fmt_bytes_to_int(hash_buf);
    let result = E::Fr::from_str(&hexresult);
    return result.unwrap();
}


#[derive(Clone, Serialize, Deserialize)]
pub struct RevokedMessage {
    pub msgtype: String,
    pub wpk: secp256k1::PublicKey
    //pub sig: Option<[u8; 64]> // represents revocation token serialized compact bytes
}

impl RevokedMessage {
    pub fn new(_msgtype: String, _wpk: secp256k1::PublicKey) -> RevokedMessage {
        RevokedMessage {
            msgtype: _msgtype, wpk: _wpk
        }
    }

    pub fn hash<E: Engine>(&self) -> Vec<E::Fr> {
        let mut v: Vec<E::Fr> = Vec::new();
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        v.push(hash_to_fr::<E>(input_buf));
        v.push(hash_pubkey_to_fr::<E>(&self.wpk));
        return v;
    }

    // return a message digest (32-bytes)
    pub fn hash_to_slice(&self) -> [u8; 32] {
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        input_buf.extend_from_slice(&self.wpk.serialize_uncompressed());

        let sha2_digest = sha512::hash(input_buf.as_slice());
        let mut hash_buf: [u8; 32] = [0; 32];
        hash_buf.copy_from_slice(&sha2_digest[0..32]);
        return hash_buf;
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, G2, Fr};
    use pairing::CurveProjective;
    use ff::Field;

    #[test]
    fn hash_g2_to_fr_works() {
        let mut two = G2::one();
        two.double();
        assert_eq!(format!("{}", hash_g2_to_fr::<Bls12>(&two).into_repr()),
                   "0x27cd26f702a777dbf782534ae6bf2ec4aa6cb4617c8366f10f59bef13beb8c56");
    }

    #[test]
    fn hash_to_fr_works() {
        let mut two = G2::one();
        two.double();
        let mut x_vec: Vec<u8> = Vec::new();
        x_vec.extend(format!("{}", two).bytes());
        assert_eq!(format!("{}", hash_to_fr::<Bls12>(x_vec).into_repr()),
                   "0x27cd26f702a777dbf782534ae6bf2ec4aa6cb4617c8366f10f59bef13beb8c56");
    }

    #[test]
    fn fmt_byte_to_int_works() {
        assert_eq!(fmt_bytes_to_int([12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123]),
                   "122352312313431223523123134312235231231343122352312313431223523123134312235231231343122352312313431223523123134312235231231343122352312313431223523123");
    }

    #[test]
    fn convert_int_to_fr_works() {
        assert_eq!(format!("{}", convert_int_to_fr::<Bls12>(1).into_repr()),
                   "0x0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(format!("{}", convert_int_to_fr::<Bls12>(-1).into_repr()),
                   "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
        assert_eq!(format!("{}", convert_int_to_fr::<Bls12>(365).into_repr()),
                   "0x000000000000000000000000000000000000000000000000000000000000016d");
    }
}
