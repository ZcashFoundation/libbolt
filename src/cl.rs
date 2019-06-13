// cl.rs
// CL Sigs - Pointcheval Sanders ('06)
extern crate pairing;
extern crate rand;

use super::*;
use pairing::{CurveAffine, CurveProjective, Engine};
use rand::Rng;

#[derive(Clone)]
pub struct PublicParams<E: Engine> {
    pub g1: E::G1,
    pub g2: E::G2
}

#[derive(Clone)]
pub struct SecretKey<E: Engine> {
    pub x: E::Fr,
    pub y: Vec<E::Fr>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey<E: Engine> {
    pub X: E::G2,
    pub Y: Vec<E::G2>,
}

#[derive(Clone)]
pub struct Signature<E: Engine> {
    pub h: E::G1,
    pub H: E::G1
}

#[derive(Clone)]
pub struct KeyPair<E: Engine> {
    pub secret: SecretKey<E>,
    pub public: PublicKey<E>
}

impl<E: Engine> SecretKey<E> {
    pub fn generate<R: Rng>(csprng: &mut R, l: usize) -> Self {
        let mut y: Vec<E::Fr> = Vec::new();
        for i in 0 .. l {
            let _y = E::Fr::rand(csprng);
            y.push(_y);
        }

        SecretKey { x: E::Fr::rand(csprng), y: y }
    }

    pub fn sign<R: Rng>(&self, csprng: &mut R, message: &Vec<E::Fr>) -> Signature<E> {
        let h = E::G1::rand(csprng);
        let mut s = E::Fr::zero();
        // assert(self.y.len() == message.len());
        for i in 0 .. self.y.len() {
            // s = s + (self.y[i] * message[i]);
            let mut res_yi = self.y[i];
            res_yi.mul_assign(&message[i]);
            s.add_assign(&res_yi);
        }

        // h ^ (x + s)
        let mut res_x = self.x;
        res_x.add_assign(&s);

        let mut H = h;
        H.mul_assign(res_x);

        Signature { h: h, H: H }
    }

    pub fn blind<R: Rng>(&self, csprng: &mut R, signature: &Signature<E>) -> Signature<E> {
        let r = E::Fr::rand(csprng);
        let t = E::Fr::rand(csprng);
        let mut h1 = signature.h;
        h1.mul_assign(r); // sigma1 ^ r

        let mut h = signature.h;
        let mut H1 = signature.H;
        h.mul_assign(t); // sigma1 ^ t
        H1.add_assign(&h); // (sigma2 * sigma1 ^ t)

        // (sigma2 * sigma1 ^ t) ^ r
        H1.mul_assign(r);
        Signature { h: h1, H: H1 }
    }
}


//impl<E: Engine> PublicKey<E> {
//    pub fn encode(&self) -> Vec<u8> {
//        let mut output_buf = Vec::new();
//        let x_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();
//
//        output_buf.extend(x_vec);
//        for i in 0 .. self.Y.len() {
//            let yi_vec: Vec<u8> = encode(&self.Y[i], Infinite).unwrap();
//            output_buf.extend(yi_vec);
//        }
//        return output_buf;
//    }
//}

//impl fmt::Display for PublicKey {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        let a_vec: Vec<u8> = encode(&self.X, Infinite).unwrap();
//
//        let mut a_s = String::new();
//        for x in a_vec.iter() {
//            a_s = format!("{}{:x}", a_s, x);
//        }
//
//        let mut Y = String::new();
//
//        for i in 0 .. self.Y.len() {
//            let b_vec: Vec<u8> = encode(&self.Y, Infinite).unwrap();
//            let mut b_s = String::new();
//            for y in b_vec.iter() {
//                b_s = format!("{}{:x}", b_s, y);
//            }
//        }
//        write!(f, "PublicKey : (\nX = 0x{},\n{}\n)", a_s, Y)
//    }
//}

impl<E: Engine> PublicKey<E> {
    pub fn from_secret(mpk: &PublicParams<E>, secret: &SecretKey<E>) -> Self {
        let mut Y: Vec<E::G2> = Vec::new();
        for i in 0 .. secret.y.len() {
            // Y[i] = g2 ^ y[i]
            let mut g2 = mpk.g2;
            g2.mul_assign(secret.y[i]);
            Y.push(g2);
        }
        // X = g2 ^ x
        let mut X = mpk.g2;
        X.mul_assign(secret.x);
        PublicKey {
            X: X,
            Y: Y
        }
    }

    pub fn verify(&self, mpk: &PublicParams<E>, message: &Vec<E::Fr>, signature: &Signature<E>) -> bool {
        let mut L = E::G2::zero();
        for i in 0 .. self.Y.len() {
            // L = L + self.Y[i].mul(message[i]);
            let mut Y = self.Y[i];
            Y.mul_assign(message[i]); // Y_i ^ m_i
            L.add_assign(&Y); // L += Y_i ^m_i
        }

        let mut X2 = self.X;
        X2.add_assign(&L); // X2 = X + L
        let lhs = E::pairing(signature.h, X2);
        let rhs = E::pairing(signature.H, mpk.g2);
        signature.h != E::G1::one() && lhs == rhs
    }
}



pub fn setup<R: Rng, E: Engine>(csprng: &mut R) -> PublicParams<E> {
    let g1 = E::G1::rand(csprng);
    let g2 = E::G2::rand(csprng);
    let mpk = PublicParams { g1: g1, g2: g2 };
    return mpk;
}

impl<E: Engine> KeyPair<E> {
    pub fn generate<R: Rng>(csprng: &mut R, mpk: &PublicParams<E>, l: usize) -> Self {
        let secret = SecretKey::generate(csprng, l);
        let public = PublicKey::from_secret(mpk, &secret);
        KeyPair { secret, public }
    }

    pub fn sign<R: Rng>(&self, csprng: &mut R, message: &Vec<E::Fr>) -> Signature<E> {
        self.secret.sign(csprng, message)
    }

    pub fn verify(&self, mpk: &PublicParams<E>, message: &Vec<E::Fr>, signature: &Signature<E>) -> bool {
        self.public.verify(mpk, message, signature)
    }

    pub fn blind<R: Rng>(&self, csprng: &mut R, signature: &Signature<E>) -> Signature<E> {
        self.secret.blind(csprng, signature)
    }
}

//impl<E: Engine> SignaturePS<E> {
//    pub fn new(_h: E::G1, _H: E::G1) -> SignaturePS {
//        SignaturePS {
//            h: _h, H: _H
//        }
//    }
//
//    pub fn hash(&self, prefix: &str) -> Fr {
//        let mut output_buf: Vec<u8> = Vec::new();
//        output_buf.extend_from_slice(prefix.as_bytes());
//        concat_g1_to_vector(&mut output_buf, &self.h);
//        concat_g1_to_vector(&mut output_buf, &self.H);
//
//        // println!("DEBUG: signature len => {}", output_buf.len());
//        // let's hash the final output_buf
//        let sha2_digest = sha512::hash(output_buf.as_slice());
//
//        let mut hash_buf: [u8; 64] = [0; 64];
//        hash_buf.copy_from_slice(&sha2_digest[0..64]);
//        return Fr::interpret(&hash_buf);
//    }
//}

/*
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
*/

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Rand;
    use pairing::bls12_381::{Bls12, Fr};
    use rand::{SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn sign_and_verify() {
        // let mut rng = XorShiftRng::seed_from_u64(0xbc4f6d44d62f276c);
        // let mut rng = XorShiftRng::seed_from_u64(0xb963afd05455863d);
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = KeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let mut message1 : Vec<Fr> = Vec::new();
        let mut message2 : Vec<Fr> = Vec::new();

        for i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }

        let sig = keypair.sign(&mut rng, &message1);
        assert_eq!(keypair.verify(&mpk, &message1, &sig), true);
        assert_eq!(keypair.verify(&mpk, &message2, &sig), false);
    }

//    #[test]
//    fn scheme_ps_sign_and_verify_works() {
//        // test ability to sign/verify a vector of messages
//        let rng = &mut thread_rng();
//
//        let mpk = setup_ps();
//        let l = 5;
//        let keypair = keygen_ps(&mpk, l);
//
//        let mut m1 : Vec<Fr> = Vec::new();
//        let mut m2 : Vec<Fr> = Vec::new();
//
//        for i in 0 .. l {
//            m1.push(Fr::random(rng));
//            m2.push(Fr::random(rng));
//        }
//
//        let signature = sign_ps(&mpk, &keypair.sk, &m1);
//
//        assert!(verify_ps(&mpk, &keypair.pk, &m1, &signature) == true);
//        assert!(verify_ps(&mpk, &keypair.pk, &m2, &signature) == false);
//    }
}

