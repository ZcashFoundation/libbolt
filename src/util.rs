use super::*;
use sodiumoxide::crypto::hash::sha512;
use pairing::{Engine, CurveProjective};
use ff::PrimeField;
use rand::Rng;
use ped92::CSMultiParams;

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
        result = result + &format!("{}", *byte as u8);
    }
    result.to_string()
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
        let res = E::Fr::from_str(value2.to_string().as_str()).unwrap();
        // TODO: look at how to do negation
        return res;
    }
}

pub struct CommitmentProof<E: Engine> {
    pub T: E::G1,
    pub z: Vec<E::Fr>
}

impl<E: Engine> CommitmentProof<E> {
    pub fn new<R: Rng>(csprng: &mut R, com_params: &CSMultiParams<E>, com: &E::G1, wallet: &Vec<E::Fr>, r: &E::Fr) -> Self {
        let mut Tvals = E::G1::zero();
        let mut t = Vec::<E::Fr>::with_capacity(com_params.pub_bases1.len() - 1);
        for g in com_params.pub_bases1.clone() {
            let ti = E::Fr::rand(csprng);
            t.push(ti);
            let mut gt = g.clone();
            gt.mul_assign(ti.into_repr());
            Tvals.add_assign(&gt);
        }

        // compute the challenge
        let x: Vec<E::G1> = vec![Tvals, com.clone()];
        let challenge = hash_g1_to_fr::<E>(&x);

        // compute the response
        let mut z: Vec<E::Fr> = Vec::new();
        let mut z0 = r.clone();
        z0.mul_assign(&challenge);
        z0.add_assign(&t[0]);
        z.push(z0);

        for i in 1..t.len() {
            let mut zi = wallet[i - 1].clone();
            zi.mul_assign(&challenge);
            zi.add_assign(&t[i]);
            z.push(zi);
        }

        CommitmentProof {
            T: Tvals, z: z
        }
    }
}

///
/// Verify PoK for the opening of a commitment
///
pub fn verify<E: Engine>(com_params: &CSMultiParams<E>, com: &E::G1, proof: &CommitmentProof<E>) -> bool {

    let mut comc = com.clone();
    let T = proof.T.clone();
    let xvec: Vec<E::G1> = vec![T, comc];
    let challenge = hash_g1_to_fr::<E>(&xvec);

    comc.mul_assign(challenge.into_repr());
    comc.add_assign(&T);

    let mut x = E::G1::zero();
    for i in 0..proof.z.len() {
        let mut base = com_params.pub_bases1[i].clone();
        base.mul_assign(proof.z[i].into_repr());
        x.add_assign(&base);
    }

    return comc == x;
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
}
