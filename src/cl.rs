// cl.rs
// CL Sigs - Pointcheval Sanders ('06)
extern crate pairing;
extern crate rand;

use super::*;
use pairing::{CurveAffine, CurveProjective, Engine};
use ff::{PrimeField, ScalarEngine};
use rand::Rng;
use ped92::{Commitment, CSMultiParams};
use std::fmt::LowerHex;
use serde::{Serialize, Deserialize};
use serde::ser::{Serializer, SerializeStruct, SerializeSeq};
use util;
use ccs08;
use bincode::serde::serialize;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PublicParams<E: Engine> {
    pub g1: E::G1,
    pub g2: E::G2,
}

impl<E: Engine> PartialEq for PublicParams<E> {
    fn eq(&self, other: &PublicParams<E>) -> bool {
        self.g1 == other.g1 && self.g2 == other.g2
    }
}


#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SecretKey<E: Engine> {
    pub x: E::Fr,
    pub y: Vec<E::Fr>,
}

impl<E: Engine> fmt::Display for SecretKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        let mut y_str = String::new();
        let mut i = 0;
        for y in self.y.iter() {
            y_str = format!("{}\n{} => {}", y_str, i, y);
            i += 1;
        }

        write!(f, "SK : \nx={},\ny=[{}\n]", self.x, y_str)
    }
}

impl<E: Engine> PartialEq for SecretKey<E> {
    fn eq(&self, other: &SecretKey<E>) -> bool {
        self.x == other.x && util::is_vec_fr_equal::<E>(&self.y, &other.y)
    }
}


#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PublicKey<E: Engine> {
    pub X: E::G2,
    pub Y: Vec<E::G2>,
}

impl<E: Engine> fmt::Display for PublicKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        let mut y_s = String::new();
        let mut i = 0;
        for y in self.Y.iter() {
            y_s = format!("{}\n{} => {}", y_s, i, y);
            i += 1;
        }

        write!(f, "PK : \nX={},\nY=[{}\n]", self.X, y_s)
    }
}

impl<E: Engine> PartialEq for PublicKey<E> {
    fn eq(&self, other: &PublicKey<E>) -> bool {
        self.X == other.X && util::is_vec_g2_equal::<E>(&self.Y, &other.Y)
    }
}


#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlindPublicKey<E: Engine> {
    pub X1: E::G1,
    pub X2: E::G2,
    pub Y1: Vec<E::G1>,
    pub Y2: Vec<E::G2>,
}

impl<E: Engine> fmt::Display for BlindPublicKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        let mut y1_str = String::new();
        for y in self.Y1.iter() {
            y1_str = format!("{}\n{}", y1_str, y);
        }

        let mut y2_str = String::new();
        for y in self.Y2.iter() {
            y2_str = format!("{}\n{}", y2_str, y);
        }

        write!(f, "Blind PK : \nX1={},\nX2{},\nY1=[{}\n],\nY2=[{}\n]", self.X1, self.X2, y1_str, y2_str)
    }
}

impl<E: Engine> PartialEq for BlindPublicKey<E> {
    fn eq(&self, other: &BlindPublicKey<E>) -> bool {
        self.X1 == other.X1 && self.X2 == other.X2 &&
            util::is_vec_g1_equal::<E>(&self.Y1, &other.Y1) &&
            util::is_vec_g2_equal::<E>(&self.Y2, &other.Y2)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Signature<E: Engine> {
    pub h: E::G1,
    pub H: E::G1,
}

impl<E: Engine> PartialEq for Signature<E> {
    fn eq(&self, other: &Signature<E>) -> bool {
        self.h == other.h && self.H == other.H
    }
}

#[derive(Clone)]
pub struct KeyPair<E: Engine> {
    pub secret: SecretKey<E>,
    pub public: PublicKey<E>,
}

//#[derive(Clone, Serialize, Deserialize)]
//#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
//<E as pairing::Engine>::G1: serde::Serialize, \
//<E as pairing::Engine>::G2: serde::Serialize"
//))]
//#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
//<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
//<E as pairing::Engine>::G2: serde::Deserialize<'de>"
//))]
//pub struct TestStruct<E: Engine> {
//    pub mpk: PublicParams<E>,
//    pub keypair: BlindKeyPair<E>,
//    pub comParams: CSMultiParams<E>,
//    pub rpParamsBC: ccs08::RPPublicParams<E>,
//    pub rpParamsBM: ccs08::RPPublicParams<E>
//}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct BlindKeyPair<E: Engine> {
    pub secret: SecretKey<E>,
    pub public: BlindPublicKey<E>,
}

#[derive(Clone)]
pub struct ProofState<E: Engine> {
    pub v: E::Fr,
    pub s: E::Fr,
    pub t: Vec<E::Fr>,
    pub tt: E::Fr,
    pub a: E::Fqk,
    pub blindSig: Signature<E>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignatureProof<E: Engine> {
    pub zx: E::Fr,
    pub zsig: Vec<E::Fr>,
    pub zv: E::Fr,
    pub a: E::Fqk,
}


impl<E: Engine> SecretKey<E> {
    pub fn generate<R: Rng>(csprng: &mut R, l: usize) -> Self {
        let mut y: Vec<E::Fr> = Vec::new();
        for i in 0..l {
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
        for i in 0..message.len() {
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

///
/// Interface for CL PS signature variant
///
impl<E: Engine> PublicKey<E> {
    pub fn from_secret(mpk: &PublicParams<E>, secret: &SecretKey<E>) -> Self {
        let mut Y: Vec<E::G2> = Vec::new();
        for i in 0..secret.y.len() {
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
            Y: Y,
        }
    }

    pub fn verify(&self, mpk: &PublicParams<E>, message: &Vec<E::Fr>, signature: &Signature<E>) -> bool {
        let mut L = E::G2::zero();
        let mut l = self.Y.len();
        let diff = (l - message.len());

        l = match diff > 0 {
            true => message.len(),
            false => l
        };

        for i in 0..l {
            if (i < message.len()) { // bounds check on message vector
                // L = L + self.Y[i].mul(message[i]);
                let mut Y = self.Y[i];
                Y.mul_assign(message[i]); // Y_i ^ m_i
                L.add_assign(&Y); // L += Y_i ^m_i
            }
        }

        let mut X2 = self.X;
        X2.add_assign(&L); // X2 = X + L
        let lhs = E::pairing(signature.h, X2);
        let rhs = E::pairing(signature.H, mpk.g2);
        signature.h != E::G1::one() && lhs == rhs
    }
}

///
/// Interface for blind sigs based on CL PS variant
///
impl<E: Engine> BlindPublicKey<E> {
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
            Y2: Y2,
        }
    }

    pub fn verify(&self, mpk: &PublicParams<E>, message: &Vec<E::Fr>, signature: &Signature<E>) -> bool {
        let mut L = E::G2::zero();
        let mut l = self.Y2.len();
        //println!("verify - m.len = {}, l = {}", message.len(), l);
        assert!(message.len() <= l + 1);
        let mut last_elem = l;

        let last_elem = match l == message.len() {
            true => message.len() - 1,
            false => l
        };

        let l = match l == message.len() {
            true => message.len() - 1,
            false => l
        };

        for i in 0..l {
            // L = L + self.Y[i].mul(message[i]);
            let mut Y = self.Y2[i];
            Y.mul_assign(message[i]); // Y_i ^ m_i
            L.add_assign(&Y); // L += Y_i ^m_i
        }

        // Y_(l+1) ^ t
        let mut Yt = mpk.g2.clone();
        Yt.mul_assign(message[last_elem]);
        L.add_assign(&Yt);

        let mut X2 = self.X2.clone();
        X2.add_assign(&L); // X2 = X + L
        let lhs = E::pairing(signature.h, X2);
        let rhs = E::pairing(signature.H, mpk.g2);

        signature.h != E::G1::one() && lhs == rhs
    }

    /// Verify a proof of knowledge of a signature
    /// Takes in a proof generated by prove_response(), a blind signature, and a challenge
    /// outputs: boolean
    pub fn verify_proof(&self, mpk: &PublicParams<E>, blindSig: Signature<E>, p: SignatureProof<E>, challenge: E::Fr) -> bool {
        let mut gx = E::pairing(blindSig.h, self.X2);
        gx = gx.pow(p.zx.into_repr());
        for j in 0..self.Y2.len() {
            let mut gy = E::pairing(blindSig.h, self.Y2[j]);
            gy = gy.pow(p.zsig[j].into_repr());
            gx.mul_assign(&gy);
        }
        let mut h = E::pairing(blindSig.h, mpk.g2);
        h = h.pow(p.zv.into_repr());
        gx.mul_assign(&h);
        let mut g = E::pairing(blindSig.H, mpk.g2);
        g = g.pow(challenge.into_repr());
        g.mul_assign(&p.a);
        gx == g
    }
}


pub fn setup<R: Rng, E: Engine>(csprng: &mut R) -> PublicParams<E> {
    let g1 = E::G1::rand(csprng);
    let g2 = E::G2::rand(csprng);
    let mpk = PublicParams { g1: g1, g2: g2 };
    return mpk;
}

///
/// KeyPair - implements the standard CL signature variant by PS - Section 3.1
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
/// BlindingKeyPair - implements the blinding signature scheme in PS - Section 3.1.1
///
impl<E: Engine> BlindKeyPair<E> {
    /// generate public/private keypair given public params and size of vectors
    pub fn generate<R: Rng>(csprng: &mut R, mpk: &PublicParams<E>, l: usize) -> Self {
        let secret = SecretKey::generate(csprng, l);
        let public = BlindPublicKey::from_secret(mpk, &secret);
        BlindKeyPair { secret, public }
    }

    pub fn generate_cs_multi_params(&self, mpk: &PublicParams<E>) -> CSMultiParams<E> {
        let mut com_bases = vec! {mpk.g1};
        com_bases.append(&mut self.public.Y1.clone());

        CSMultiParams { pub_bases: com_bases }
    }

    /// extract unblinded public key
    pub fn get_public_key(&self, mpk: &PublicParams<E>) -> PublicKey<E> {
        PublicKey::from_secret(mpk, &self.secret)
    }

    /// sign a vector of messages
    pub fn sign<R: Rng>(&self, csprng: &mut R, message: &Vec<E::Fr>) -> Signature<E> {
        self.secret.sign(csprng, message)
    }

    /// randomize signature
    pub fn rerandomize_signature<R: Rng>(&self, csprng: &mut R, signature: &Signature<E>) -> Signature<E> {
        let r = E::Fr::rand(csprng);
        let mut h = signature.h.clone();
        let mut H = signature.H.clone();
        h.mul_assign(r.clone());
        H.mul_assign(r);
        Signature { h, H }
    }

    /// sign a commitment of a vector of messages
    pub fn sign_blind<R: Rng>(&self, csprng: &mut R, mpk: &PublicParams<E>, com: Commitment<E>) -> Signature<E> {
        let u = E::Fr::rand(csprng);
        let mut h1 = mpk.g1;
        h1.mul_assign(u); // g1 ^ u

        let mut com1 = com.c.clone();
        let mut H1 = self.public.X1.clone();
        H1.add_assign(&com1); // (X * com)
        H1.mul_assign(u); // (X * com) ^ u (blinding factor)

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
        let mut inv_bf = bf.clone();
        inv_bf.negate();

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

    /// prove knowledge of a signature: commitment phase
    /// returns the proof state, including commitment a and a blind signature blindSig
    pub fn prove_commitment<R: Rng>(&self, rng: &mut R, mpk: &PublicParams<E>, signature: &Signature<E>,
                                    tOptional: Option<Vec<E::Fr>>, ttOptional: Option<E::Fr>) -> ProofState<E> {
        let v = E::Fr::rand(rng);
        let blindSig = self.blind(rng, &v, signature);
        let s = E::Fr::rand(rng);
        let mut t = tOptional.unwrap_or(Vec::<E::Fr>::with_capacity(self.public.Y2.len()));
        let tt = ttOptional.unwrap_or(E::Fr::rand(rng));
        let mut gx = E::pairing(blindSig.h, self.public.X2);
        gx = gx.pow(s.into_repr());
        for j in 0..self.public.Y2.len() {
            if t.len() == j {
                t.push(E::Fr::rand(rng));
            }
            let mut gy = E::pairing(blindSig.h, self.public.Y2[j]);
            gy = gy.pow(t[j].into_repr());
            gx.mul_assign(&gy);
        }
        let mut h = E::pairing(blindSig.h, mpk.g2);
        h = h.pow(tt.into_repr());
        gx.mul_assign(&h);
        ProofState { v, s, t, tt, a: gx, blindSig }
    }

    /// prove knowledge of a signature: response phase
    /// returns a proof that can be send to the verifier together with the challenge and the blind signature
    pub fn prove_response(&self, ps: &ProofState<E>, challenge: E::Fr, message: &mut Vec<E::Fr>) -> SignatureProof<E> {
        let mut zsig = ps.t.clone();
        let z_len = zsig.len();

        for i in 0..message.len() {
            if i < z_len {
                let mut message1 = message[i];
                message1.mul_assign(&challenge);
                zsig[i].add_assign(&message1);
            }
        }

        let mut zx = ps.s.clone();
        zx.add_assign(&challenge);
        let mut zv = ps.tt.clone();
        let mut vic = ps.v.clone();
        vic.mul_assign(&challenge);
        zv.add_assign(&vic);
        SignatureProof { zsig, zx, zv, a: ps.a }
    }
}


// display CL signature (PS)
impl<E: Engine> fmt::Display for Signature<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signature : \n(h = {},\nH = {})", self.h, self.H)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use ff::Rand;
    use pairing::bls12_381::{Bls12, Fr, G1, G2};
    use rand::SeedableRng;
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

        println!("SECRET KEY => {}", keypair.secret);
        println!("PUBLIC KEY => {}", keypair.public);

        let mut message1: Vec<Fr> = Vec::new();
        let mut message2: Vec<Fr> = Vec::new();

        for i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }

        let sig = keypair.sign(&mut rng, &message1);
        println!("{}", sig);
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

        let mut message1: Vec<Fr> = Vec::new();
        let mut message2: Vec<Fr> = Vec::new();

        for i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }

        let sig = keypair.sign(&mut rng, &message1);
        assert_eq!(public_key.verify(&mpk, &message1, &sig), true);
        assert_eq!(public_key.verify(&mpk, &message2, &sig), false);

        let t = Fr::rand(&mut rng);
        let blind_sig = keypair.blind(&mut rng, &t, &sig);

        // pick another blinding factor
        let t1 = Fr::rand(&mut rng);

        // verify blind signatures and provide blinding factor as input
        assert_eq!(keypair.verify(&mpk, &message1, &t, &blind_sig), true);
        assert_eq!(keypair.verify(&mpk, &message2, &t, &blind_sig), false);
        assert_eq!(keypair.verify(&mpk, &message1, &t1, &blind_sig), false);

        let rand_sig = keypair.rerandomize_signature(&mut rng, &sig);
        assert_eq!(public_key.verify(&mpk, &message1, &rand_sig), true);
    }

    #[test]
    fn blind_unblind_works() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let mut message1: Vec<Fr> = Vec::new();

        for i in 0..l {
            message1.push(Fr::rand(&mut rng));
        }

        let signature = keypair.sign(rng, &message1);
        let r = Fr::rand(rng);
        let blind_sig = keypair.blind(rng, &r, &signature);
        let signature1 = keypair.unblind(&r, &blind_sig);

        assert_eq!(keypair.get_public_key(&mpk).verify(&mpk, &message1, &signature1), true);
        assert_eq!(keypair.get_public_key(&mpk).verify(&mpk, &message1, &blind_sig), false);
        assert_eq!(keypair.verify(&mpk, &message1, &r, &blind_sig), true);
    }

    #[test]
    fn blind_sign_and_verify_works() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let public_key = keypair.get_public_key(&mpk);

        let mut message1: Vec<Fr> = Vec::new();
        let mut message2: Vec<Fr> = Vec::new();

        for i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }

        let com_params = keypair.generate_cs_multi_params(&mpk);
        let t = Fr::rand(rng);
        let com = com_params.commit(&message1, &t);

        let signature = keypair.sign_blind(rng, &mpk, com);

        let unblinded_sig = keypair.unblind(&t, &signature);

        let t1 = Fr::rand(&mut rng);

        assert_eq!(keypair.get_public_key(&mpk).verify(&mpk, &message1, &unblinded_sig), true);
        assert_eq!(keypair.verify(&mpk, &message1, &t, &signature), true);
        assert_eq!(keypair.get_public_key(&mpk).verify(&mpk, &message2, &unblinded_sig), false);
        assert_eq!(keypair.verify(&mpk, &message2, &t, &signature), false);
        assert_eq!(keypair.verify(&mpk, &message1, &t1, &signature), false);
    }

    #[test]
    fn proof_of_knowledge_of_signature() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let public_key = keypair.get_public_key(&mpk);

        let mut message1: Vec<Fr> = Vec::new();

        for i in 0..l {
            message1.push(Fr::rand(&mut rng));
        }

        let sig = keypair.sign(&mut rng, &message1);
        let proof_state = keypair.prove_commitment(rng, &mpk, &sig, None, None);
        let challenge = Fr::rand(&mut rng);
        let proof = keypair.prove_response(&proof_state.clone(), challenge, &mut message1);

        assert_eq!(keypair.public.verify_proof(&mpk, proof_state.blindSig, proof, challenge), true);
    }

    #[test]
    fn test_cl_basic_serialize() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = KeyPair::<Bls12>::generate(&mut rng, &mpk, l);
        let blindkeypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let serialized = serde_json::to_vec(&mpk).unwrap();
        //println!("serialized = {:?}", serialized.len());

        let mpk_des: PublicParams<Bls12> = serde_json::from_slice(&serialized).unwrap();
        //println!("{}", mpk_des);

        //println!("SK => {}", &keypair.secret);
        let sk_serialized = serde_json::to_vec(&keypair.secret).unwrap();
        //println!("sk_serialized = {:?}", sk_serialized.len());

        let sk_des: SecretKey<Bls12> = serde_json::from_slice(&sk_serialized).unwrap();
        //println!("{}", sk_des);
        assert_eq!(sk_des, keypair.secret);

        //println!("PK => {}", &keypair.public);
        let pk_serialized = serde_json::to_vec(&keypair.public).unwrap();
        //println!("pk_serialized = {:?}", pk_serialized.len());

        let pk_des: PublicKey<Bls12> = serde_json::from_slice(&pk_serialized).unwrap();
        //assert_eq!(pk_des, keypair.public);

        //println!("{}", &blindkeypair.public);
        let bpk_ser = serde_json::to_vec(&blindkeypair.public).unwrap();
        //println!("blind pk_ser = {:?}", bpk_ser.len());

        let bpk_des: BlindPublicKey<Bls12> = serde_json::from_slice(&bpk_ser).unwrap();
        assert_eq!(bpk_des, blindkeypair.public);

        let unblind_pk = blindkeypair.get_public_key(&mpk);
        //println!("{}", &unblind_pk);
        let upk_serialized = serde_json::to_vec(&unblind_pk).unwrap();
        //println!("upk_serialized = {:?}", upk_serialized.len());

        let upk_des: PublicKey<Bls12> = serde_json::from_slice(&upk_serialized).unwrap();

        assert_eq!(upk_des, unblind_pk);
        assert_ne!(upk_des, keypair.public);
    }
}

