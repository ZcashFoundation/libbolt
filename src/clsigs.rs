#![feature(test)]
// clsigs.rs
use std::fmt;
use std::str;
//use std::default;
use rand;
use bn::{Group, Fr, G1, G2, Gt, pairing};
use debug_elem_in_hex;
use debug_g1_in_hex;
use debug_g2_in_hex;
use debug_gt_in_hex;
use concat_to_vector;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use sodiumoxide::crypto::hash::sha512;


pub struct PublicParams {
    pub g1: G1,
    pub g2: G2
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

#[derive(Clone)]
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

// scheme A - for a single message

pub fn setupA() -> PublicParams {
    let rng = &mut rand::thread_rng();
    let g1 = G1::random(rng);
    let g2 = G2::random(rng);
    let mpk = PublicParams { g1: g1, g2: g2 };
    return mpk;
}

pub fn keygenA(mpk : &PublicParams) -> KeyPair {
    let rng = &mut rand::thread_rng();
    let x = Fr::random(rng);
    let y = Fr::random(rng);
    let sk = SecretKey { x: x, y: y };
    let pk = PublicKey { X: mpk.g1 * x,
                         Y: mpk.g1 * y
                        };
    return KeyPair { sk: sk, pk: pk }
}

pub fn signA(sk: &SecretKey, m: Fr) -> Signature {
    let rng = &mut rand::thread_rng();
    let a = G2::random(rng);

    let b = a * sk.y;
    let c = a * (sk.x + (m * sk.x * sk.y));
    let sig = Signature { a: a, b: b, c: c };
    return sig;
}

pub fn verifyA(mpk: &PublicParams, pk: &PublicKey, m: Fr, sig: &Signature) -> bool {
    let lhs1 = pairing(pk.Y, sig.a);
    let rhs1 = pairing(mpk.g1, sig.b);
    let lhs2 = pairing(pk.X, sig.a) * (pairing(pk.X, sig.b).pow(m));
    let rhs2 = pairing(mpk.g1, sig.c);
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
#[derive(Clone)]
pub struct PublicKeyD {
    pub X: G1,
    pub Y: G1,
    pub Z: Vec<G1>,
    pub Z2: Vec<G2>,
    pub W: Vec<G1>
}

#[derive(Clone)]
pub struct SecretKeyD {
    x: Fr,
    y: Fr,
    z: Vec<Fr>
}

#[derive(Clone)]
pub struct KeyPairD {
    pub sk: SecretKeyD,
    pub pk: PublicKeyD
}

#[derive(Clone)]
pub struct SignatureD {
    a: G2,
    A: Vec<G2>,
    b: G2,
    B: Vec<G2>,
    c: G2
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
        concat_to_vector(&mut output_buf, &self.a);
        concat_to_vector(&mut output_buf, &self.b);
        concat_to_vector(&mut output_buf, &self.c);
        assert_eq!(self.A.len(), self.B.len());
        for i in 0 .. self.A.len() {
            concat_to_vector(&mut output_buf, &self.A[i]);
            concat_to_vector(&mut output_buf, &self.B[i]);
        }

        // println!("DEBUG: signature len => {}", output_buf.len());
        // let's hash the final output_buf
        let sha2_digest = sha512::hash(output_buf.as_slice());

        let mut hash_buf: [u8; 64] = [0; 64];
        hash_buf.copy_from_slice(&sha2_digest[0..64]);
        return Fr::interpret(&hash_buf);
    }
}

pub fn setupD() -> PublicParams {
    let rng = &mut rand::thread_rng();
    let g1 = G1::random(rng);
    let g2 = G2::random(rng);
    let mpk = PublicParams { g1: g1, g2: g2 };
    return mpk;
}

pub fn keygenD(mpk : &PublicParams, l: usize) -> KeyPairD {
    let rng = &mut rand::thread_rng();
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

    let sk = SecretKeyD { x: x, y: y, z: z };
    let pk = PublicKeyD { X: X, Y: Y, Z: Z, Z2: Z2, W: W };
    return KeyPairD { sk: sk, pk: pk }
}

pub fn signD(mpk: &PublicParams, sk: &SecretKeyD, m: &Vec<Fr>) -> SignatureD {
    assert_eq!(m.len(), sk.z.len()+1);
    let l = m.len();

    let rng = &mut rand::thread_rng();
    let a = mpk.g2 * Fr::random(rng); // G2::random(rng);
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
    // Ok(sig);
    return sig;
}

pub fn verifyD(mpk: &PublicParams, pk: &PublicKeyD, m: &Vec<Fr>, sig: &SignatureD) -> bool {
    assert_eq!(m.len(), sig.A.len()+1);
    assert_eq!(m.len(), sig.B.len()+1);

    let l = m.len();
    // lhs2a and rhs2a checks that sig.b was formed correctly
    let lhs2a = pairing(pk.Y, sig.a);
    let rhs2a = pairing(mpk.g1, sig.b);

    let mut result1 = true;
    let mut result2b = true;
    // lhs3 and rhs3 checks that sig.c was formed correctly
    let mut lhs3 = pairing(pk.X, sig.a) * pairing(pk.X, sig.b * m[0]);
    let rhs3 = pairing(mpk.g1, sig.c);

    for i in 0 .. l-1 {
        // checks that {sig.A}_i was formed correctly
        let lhs1 = pairing(pk.Z[i], sig.a);
        let rhs1 = pairing(mpk.g1, sig.A[i]);
        if (lhs1 != rhs1) {
            result1 = false;
        }
        let lhs2b = pairing(pk.Y, sig.A[i]);
        let rhs2b = pairing(mpk.g1, sig.B[i]);
        if lhs2b != rhs2b {
            result2b = false;
        }
        lhs3 = lhs3 * pairing(pk.X, sig.B[i] * m[i+1]);
    }

//    let mut lhs3 = pairing(pk.X, sig.a) * pairing(pk.X, sig.b * m[0]);
//    for i in 1 .. l {
//        lhs3 = lhs3 * pairing(pk.X, sig.B[i] * m[i]);
//    }
    return (result1 == true) && (lhs2a == rhs2a) && (result2b == true) && (lhs3 == rhs3);
}

pub fn add_two(a: i32) -> i32 {
    a + 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    #[test]
    fn it_works() {
        assert_eq!(4, add_two(2));
    }

    #[bench]
    fn bench_add_two(b: &mut Bencher) {
        b.iter(|| add_two(2));
    }
}

// NIZK protocol for proving knowledge of a signature
pub fn hashG2ToFr(x: &G2) -> Fr {
    // TODO: change to serde (instead of rustc_serialize)
    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
    let sha2_digest = sha512::hash(x_vec.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

pub fn hashGtToFr(x: &Gt) -> Fr {
    // TODO: change to serde (instead of rustc_serialize)
    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
    let sha2_digest = sha512::hash(x_vec.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}


pub struct ProofCV {
    T: G2,
    C: G2,
    s: Vec<Fr>,
    pub_bases: Vec<G2>
}

// NIZK for PoK of the opening of a commitment M = g^m0 * Z1^m1 * ... * Zl^ml
pub fn bs_gen_nizk_proof(x: &Vec<Fr>, pub_bases: &Vec<G2>, C: G2) -> ProofCV {
    let rng = &mut rand::thread_rng();
    let l = x.len();
    let mut t: Vec<Fr> = Vec::new();
    for i in 0 .. l {
        t.push(Fr::random(rng));
    }

    // compute the T
    let mut T = pub_bases[0] * t[0];
    for i in 1 .. l {
        T = T + (pub_bases[i] * t[i]);
    }

    // hash T to get the challenge
    let c = hashG2ToFr(&T);
    let msg = "challenge -> c";
    debug_elem_in_hex(msg, &c);

    // compute s values
    let mut s: Vec<Fr> = Vec::new();
    for i in 0 .. l {
        //println!("(gen proof) i => {}", i);
        let _s = (x[i] * c) + t[i];
        s.push(_s);
    }

    return ProofCV { T: T, C: C, s: s, pub_bases: pub_bases.clone() };
}

pub fn bs_gen_signature(mpk: &PublicParams, sk: &SecretKeyD, proof: &ProofCV) -> SignatureD {
   if bs_verify_nizk_proof(&proof) {
        return part2_compute_signature(&mpk, &sk, proof.C);
   } else {
       panic!("Invalid proof: could not verify the NIZK proof");
   }
}

pub fn bs_verify_nizk_proof(proof: &ProofCV) -> bool {
    // if proof is valid, then call part
    let c = hashG2ToFr(&proof.T);
    let mut msg = "(in verify proof) challenge -> c";
    debug_elem_in_hex(msg, &c);

    let l = proof.s.len();
    assert!(l > 1);

    let mut lhs = proof.pub_bases[0] * proof.s[0];
    for i in 1 .. l {
        //println!("(in verify proof) i => {}", i);
        lhs = lhs + (proof.pub_bases[i] * proof.s[i]);
    }
    msg = "(in verify proof) lhs => ";
    debug_g2_in_hex(msg, &lhs);

    let rhs = (proof.C * c) + proof.T;
    msg = "(in verify proof) rhs => ";
    debug_g2_in_hex(msg, &rhs);
    return lhs == rhs;
}

// internal function
fn part2_compute_signature(mpk: &PublicParams, sk: &SecretKeyD, M: G2) -> SignatureD {
    let rng = &mut rand::thread_rng();
    let alpha = Fr::random(rng);
    let a = mpk.g2 * alpha;
    let mut A: Vec<G2> = Vec::new();
    let mut B: Vec<G2> = Vec::new();
    let l = sk.z.len();

    for i in 0 .. l {
        let _A = a * sk.z[i];
        let _B = _A * sk.y;
        A.push(_A);
        B.push(_B);
    }

    let b = a * sk.y;
    let c = (a * sk.x) + (M * (alpha * sk.x * sk.y));
    let sig = SignatureD { a: a, A: A, b: b, B: B, c: c };
    return sig;
}

// Prover first randomizes the signature
pub fn prover_generate_blinded_sig(sig: &SignatureD) -> SignatureD {
    let rng = &mut rand::thread_rng();
    let r = Fr::random(rng);
    let rpr = Fr::random(rng);

    let a = sig.a * r;
    let b = sig.b * r;
    let c = (sig.c * r) * rpr;
    let mut A: Vec<G2> = Vec::new();
    let mut B: Vec<G2> = Vec::new();
    assert!(sig.A.len() == sig.B.len());
    let l = sig.A.len();

    for i in 0 .. l {
        A.push(sig.A[i] * r);
        B.push(sig.B[i] * r);
    }

    let bsig = SignatureD { a: a, A: A, b: b, B: B, c: c };
    return bsig;
}

// TODO: generate proof for the
pub struct CommonParams {
    vx: Gt,
    vxy: Gt,
    vxyi: Vec<Gt>,
    pub vs: Gt
}

pub struct ProofVS {
    T: Gt,
    A: Gt,
    s: Vec<Fr>,
    pub_bases: Vec<Gt>
}

pub fn gen_common_params(mpk: &PublicParams, pk: &PublicKeyD, sig: &SignatureD) -> CommonParams {
    let l = sig.B.len();

    let vx = pairing(pk.X, sig.a);
    let vxy = pairing(pk.X, sig.b);
    // generate vector
    let mut vxyi: Vec<Gt> = Vec::new();
    for i in 0 .. l {
        vxyi.push(pairing(pk.X, sig.B[i]));
    }
    let vs = pairing(mpk.g1, sig.c);

//    let lhs = vx * vxy.pow(m[0]) * vxyi[0].pow(m[1]) * vxyi[1].pow(m[2]) * vxyi[2].pow(m[3]);
//    assert!(lhs == vs);
//    println!("Validated the statement (without blinding)");

    return CommonParams { vx: vx, vxy: vxy, vxyi: vxyi, vs: vs };
}

pub fn vs_gen_nizk_proof(x: &Vec<Fr>, cp: &CommonParams, A: Gt) -> ProofVS {
    let rng = &mut rand::thread_rng();
    let l = x.len() + 1;
    let mut t: Vec<Fr> = Vec::new();
    for i in 0 .. l {
        t.push(Fr::random(rng));
    }

    let mut pub_bases: Vec<Gt> = Vec::new();
    pub_bases.push(cp.vx); // 1
    pub_bases.push(cp.vxy); // u_0
    for i in 0 .. cp.vxyi.len() {
        pub_bases.push(cp.vxyi[i]); // u_1 ... u_l
    }
    println!("(vs_gen_nizk_proof) Number of secrets: {}", l);
    println!("(vs_gen_nizk_proof) Number of bases: {}", pub_bases.len());

    // compute the T
    let mut T = pub_bases[0].pow(t[0]);  // vx ^ t0
    for i in 1 .. l {
        T = T * (pub_bases[i].pow(t[i])); // vxy{i} ^ t{i}
    }

    // hash T to get the challenge
    let c = hashGtToFr(&T);
    let msg = "(gen nizk proof) challenge -> c";
    debug_elem_in_hex(msg, &c);

    // compute s values
    let mut s: Vec<Fr> = Vec::new();
    let _s = c + t[0]; // for vx s0 = (1*c + t[0])
    s.push(_s);
    for i in 1 .. l {
        println!("(gen nizk proof) i => {}", i);
        let _s = (x[i-1] * c) + t[i];
        s.push(_s);
    }
//    println!("(gen nizk proof) i => {}", l-1);
//    s.push((x[l-1] * c) + t[l-1]);

    return ProofVS { T: T, A: A, s: s, pub_bases: pub_bases };
}

fn part1_verify_proof_vs(proof: &ProofVS) -> bool {
    // if proof is valid, then call part
    let c = hashGtToFr(&proof.T);
    let mut msg = "(in verify proof) challenge -> c";
    debug_elem_in_hex(msg, &c);

    let l = proof.s.len();
    assert!(l > 1);

    println!("(in verify proof) i => 0");
    let mut lhs = proof.pub_bases[0].pow(proof.s[0]);
    for i in 1 .. l {
        println!("(in verify proof) i => {}", i);
        lhs = lhs * (proof.pub_bases[i].pow(proof.s[i]));
    }
    // debug
    msg = "(in verify proof) lhs => ";
    debug_gt_in_hex(msg, &lhs);

    let rhs = proof.A.pow(c) * proof.T;
    // debug
    msg = "(in verify proof) rhs => ";
    debug_gt_in_hex(msg, &rhs);
    return lhs == rhs;
}


pub fn vs_verify_blind_sig(mpk: &PublicParams, pk: &PublicKeyD, proof: &ProofVS, sig: &SignatureD) -> bool {

    let result = part1_verify_proof_vs(&proof);
    let mut result1 = true;
    let mut result3 = true;

    // verify second condition
    let lhs2 = pairing(pk.Y, sig.a);
    let rhs2 = pairing(mpk.g1, sig.b);
    let result2 = (lhs2 == rhs2);

    assert_eq!(sig.A.len(), sig.B.len());
    let l = sig.A.len();

    for i in 0 .. l {
        let lhs1 = pairing(pk.Z[i], sig.a);
        let rhs1 = pairing(mpk.g1, sig.A[i]);
        if lhs1 != rhs1 {
            result1 = false;
        }

        let lhs3 = pairing(pk.Y, sig.A[i]);
        let rhs3 = pairing(mpk.g1, sig.B[i]);

        if lhs3 != rhs3 {
            result3 = false;
        }
    }

    if !result {
        println!("ERROR: Failed to verify proof");
    }
    if !result1 {
        println!("ERROR: Failed to verify pairing eq 1");
    }
    if !result2 {
        println!("ERROR: Failed to verify pairing eq 2");
    }
    if !result3 {
        println!("ERROR: Failed to verify pairing eq 3");
    }

    return result1 && result2 && result3;
}