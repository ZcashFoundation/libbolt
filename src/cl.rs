// cl.rs
// CL Sigs - Pointcheval Sanders ('06)
extern crate pairing;
extern crate rand;

use super::*;
use pairing::{CurveAffine, CurveProjective, Engine};
use rand::Rng;
use ped92::Commitment;

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

//#[derive(Clone, Serialize, Deserialize)]
#[derive(Clone)]
pub struct PublicKey<E: Engine> {
    pub X: E::G2,
    pub Y: Vec<E::G2>,
}

//#[derive(Clone, Serialize, Deserialize)]
#[derive(Clone)]
pub struct BlindPublicKey<E: Engine> {
    pub X1: E::G1,
    pub X2: E::G2,
    pub Y1: Vec<E::G1>,
    pub Y2: Vec<E::G2>,
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

#[derive(Clone)]
pub struct BlindKeyPair<E: Engine> {
    pub secret: SecretKey<E>,
    pub public: BlindPublicKey<E>
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
        // check vector length first
        assert_eq!(self.y.len(), message.len());
        for i in 0 .. message.len() {
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

    pub fn blind<R: Rng>(&self, csprng: &mut R, bf: &E::Fr, signature: &Signature<E>) -> Signature<E> {
        let r = E::Fr::rand(csprng);
        let t = bf.clone();
        let mut h1 = signature.h;
        h1.mul_assign(r); // sigma1 ^ r

        let mut h = signature.h;
        let mut H1 = signature.H;
        h.mul_assign(t); // sigma1 ^ t (blinding factor)
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

impl<E: Engine> BlindPublicKey<E>  {
    pub fn from_secret(mpk: &PublicParams<E>, secret: &SecretKey<E>) -> Self {
        let mut Y1: Vec<E::G1> = Vec::new();
        let mut Y2: Vec<E::G2> = Vec::new();
        for i in 0..secret.y.len() {
            // Y[i] = g2 ^ y[i]
            let mut g1y = mpk.g1;
            let mut g2y = mpk.g2;
            g1y.mul_assign(secret.y[i]);
            g2y.mul_assign(secret.y[i]);
            Y1.push(g1y);
            Y2.push(g2y);
        }
        // X1 = g1 ^ x
        let mut X1 = mpk.g1;
        X1.mul_assign(secret.x);
        // X2 = g2 ^ x
        let mut X2 = mpk.g2;
        X2.mul_assign(secret.x);
        BlindPublicKey {
            X1: X1,
            X2: X2,
            Y1: Y1,
            Y2: Y2
        }
    }

    pub fn verify(&self, mpk: &PublicParams<E>, message: &Vec<E::Fr>, signature: &Signature<E>) -> bool {
        let mut L = E::G2::zero();
        let l = self.Y2.len();
        assert_eq!(message.len(), l + 1);

        for i in 0 .. l {
            // L = L + self.Y[i].mul(message[i]);
            let mut Y = self.Y2[i];
            Y.mul_assign(message[i]); // Y_i ^ m_i
            L.add_assign(&Y); // L += Y_i ^m_i
        }

        // Y_(l+1) ^ t
        let mut Yt = mpk.g2;
        Yt.mul_assign(message[l]);
        L.add_assign(&Yt);

        let mut X2 = self.X2;
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

///
/// KeyPair - implements the standard CL signature variant by Pointcheval-Sanders - Section 3.1
///
impl<E: Engine> KeyPair<E> {
    pub fn generate<R: Rng>(csprng: &mut R, mpk: &PublicParams<E>, l: usize) -> Self {
        let secret = SecretKey::generate(csprng, l);
        let public = PublicKey::from_secret(mpk, &secret);
        KeyPair { secret, public }
    }

    /// sign a vector of messages (of size l)
    pub fn sign<R: Rng>(&self, csprng: &mut R, message: &Vec<E::Fr>) -> Signature<E> {
        self.secret.sign(csprng, message)
    }

    pub fn verify(&self, mpk: &PublicParams<E>, message: &Vec<E::Fr>, signature: &Signature<E>) -> bool {
        self.public.verify(mpk, message, signature)
    }
}

///
/// BlindingKeyPair - implements the blinding signature scheme in Pointcheval-Sanders - Section 3.1.1
///
impl<E: Engine> BlindKeyPair<E> {
    /// generate public/private keypair given public params and size of vectors
    pub fn generate<R: Rng>(csprng: &mut R, mpk: &PublicParams<E>, l: usize) -> Self {
        let secret = SecretKey::generate(csprng, l);
        let public = BlindPublicKey::from_secret(mpk, &secret);
        BlindKeyPair { secret, public }
    }

    /// extract unblinded public key
    pub fn get_public_key(&self, mpk: &PublicParams<E>) -> PublicKey<E> {
        PublicKey::from_secret(mpk, &self.secret)
    }

    /// sign a vector of messages
    pub fn sign<R: Rng>(&self, csprng: &mut R, message: &Vec<E::Fr>) -> Signature<E> {
        self.secret.sign(csprng, message)
    }

    /// sign a commitment of a vector of messages
    pub fn sign_blind<R: Rng>(&self, csprng: &mut R, mpk: &PublicParams<E>, com: Commitment<E>) -> Signature<E> {
        let u = E::Fr::rand(csprng);
        let mut h1 = mpk.g1;
        h1.mul_assign(u); // g1 ^ u

        let mut com1 = com.c1.clone();
        let mut H1 = self.public.X1.clone();
        H1.add_assign(&com1); // (X * com ^ g)
        H1.mul_assign(u); // com ^ u (blinding factor)

        Signature { h: h1, H: H1 }
    }

    /// computes a blind signature from an existing one
    pub fn blind<R: Rng>(&self, csprng: &mut R, bf: &E::Fr, signature: &Signature<E>) -> Signature<E> {
        self.secret.blind(csprng, bf, signature)
    }

    /// unblinds a signature given knowledge of blinding factor, t. Output should be
    /// verifiable with standard signature scheme.
    pub fn unblind(&self, bf: &E::Fr, signature: &Signature<E>) -> Signature<E> {
        let mut H = signature.h;
        let inv_bf = bf.inverse().unwrap();

        // sigma2 / sigma1 ^ t
        H.mul_assign(inv_bf);
        H.add_assign(&signature.H);

        Signature { h: signature.h, H: H }
    }

    /// verify a blinded signature without unblinding it first
    pub fn verify(&self, mpk: &PublicParams<E>, message: &Vec<E::Fr>, bf: &E::Fr, signature: &Signature<E>) -> bool {
        let mut m = message.clone();
        let t = bf.clone();
        m.push(t);
        self.public.verify(mpk, &m, signature)
    }
}

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
    use ped92::CSMultiParams;

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

    #[test]
    fn blind_sign_and_verify() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let public_key = keypair.get_public_key(&mpk);

        let mut message1 : Vec<Fr> = Vec::new();
        let mut message2 : Vec<Fr> = Vec::new();

        for i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }

        let sig = keypair.sign(&mut rng, &message1);
        assert_eq!(public_key.verify(&mpk, &message1, &sig), true);
        assert_eq!(public_key.verify(&mpk, &message2, &sig), false);

        let t = Fr::rand(&mut rng);
        let blind_sig = keypair.blind(&mut rng, &t,&sig);

        // pick another blinding factor
        let t1 = Fr::rand(&mut rng);

        // verify blind signatures and provide blinding factor as input
        assert_eq!(keypair.verify(&mpk,&message1, &t,&blind_sig), true);
        assert_eq!(keypair.verify(&mpk,&message2, &t,&blind_sig), false);
        assert_eq!(keypair.verify(&mpk,&message1, &t1,&blind_sig), false);
    }

    #[test]
    fn blind_sign_and_verify_works() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let public_key = keypair.get_public_key(&mpk);

        let mut message1 : Vec<Fr> = Vec::new();
        let mut message2 : Vec<Fr> = Vec::new();

        for i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }
        let mut com_bases1 = vec! {mpk.g1};
        com_bases1.append(&mut keypair.public.Y1.clone());

        let mut com_bases2 = vec! {mpk.g2};
        com_bases2.append(&mut keypair.public.Y2.clone());

        let com_params = CSMultiParams { pub_bases1: com_bases1, pub_bases2: com_bases2};
        let t = Fr::rand(rng);
        let com = com_params.commit(rng, &message1, &t);

        let signature = keypair.sign_blind(rng, &mpk, com);

        let unblinded_sig = keypair.unblind(&t, &signature);

        let t1 = Fr::rand(&mut rng);

        assert_eq!(keypair.verify(&mpk,&message1, &t,&unblinded_sig), true);
        assert_eq!(keypair.verify(&mpk,&message1, &t, &signature), true);
        assert_eq!(keypair.verify(&mpk,&message2, &t,&unblinded_sig), false);
        assert_eq!(keypair.verify(&mpk,&message2, &t,&signature), false);
        assert_eq!(keypair.verify(&mpk,&message1, &t1,&unblinded_sig), false);
        assert_eq!(keypair.verify(&mpk,&message1, &t1,&signature), false);
    }

}

