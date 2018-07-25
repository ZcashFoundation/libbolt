#![feature(test)]
// clproto.rs

use std::fmt;
use std::str;
use rand::{thread_rng, Rng};
use bn::{Group, Fr, G1, G2, Gt, pairing};
use clsigs;
use commit_scheme;
use debug_elem_in_hex;
use debug_g1_in_hex;
use debug_g2_in_hex;
use debug_gt_in_hex;
use concat_to_vector;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use clsigs::{PublicParams, SignatureD, PublicKeyD, SecretKeyD, hashG2ToFr, hashGtToFr};

#[derive(Clone)]
pub struct ProofCV {
    pub T: G2,
    pub C: G2,
    pub s: Vec<Fr>,
    pub num_secrets: usize,
    pub pub_bases: Vec<G2>
}

// NIZK for PoK of the opening of a commitment M = g^m0 * Z1^m1 * ... * Zl^ml
pub fn bs_gen_nizk_proof(x: &Vec<Fr>, pub_bases: &Vec<G2>, C: G2) -> ProofCV {
    let rng = &mut thread_rng();
    let l = x.len(); // number of secrets
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
    // debug
    //let msg = "challenge -> c";
    //debug_elem_in_hex(msg, &c);

    // compute s values
    let mut s: Vec<Fr> = Vec::new();
    for i in 0 .. l {
        //println!("(gen proof) i => {}", i);
        let _s = (x[i] * c) + t[i];
        s.push(_s);
    }

    return ProofCV { T: T, C: C, s: s, pub_bases: pub_bases.clone(), num_secrets: l };
}

pub fn bs_check_proof_and_gen_signature(mpk: &PublicParams, sk: &SecretKeyD, proof: &ProofCV) -> SignatureD {
   if bs_verify_nizk_proof(&proof) {
        return bs_compute_blind_signature(&mpk, &sk, proof.C, proof.num_secrets);
   } else {
       panic!("Invalid proof: could not verify the NIZK proof");
   }
}

pub fn bs_verify_nizk_proof(proof: &ProofCV) -> bool {
    // if proof is valid, then call part
    let c = hashG2ToFr(&proof.T);
    // debug
    //let mut msg = "(in verify proof) challenge -> c";
    //debug_elem_in_hex(msg, &c);

    let l = proof.s.len(); // number of s values
    assert!(l <= proof.pub_bases.len());

    let mut lhs = proof.pub_bases[0] * proof.s[0];
    for i in 1 .. l {
        //println!("(in verify proof) i => {}", i);
        lhs = lhs + (proof.pub_bases[i] * proof.s[i]);
    }
    // debug
    //msg = "(in verify proof) lhs => ";
    //debug_g2_in_hex(msg, &lhs);

    let rhs = (proof.C * c) + proof.T;
    // debug
    //msg = "(in verify proof) rhs => ";
    //debug_g2_in_hex(msg, &rhs);
    return lhs == rhs;
}

// internal function
pub fn bs_compute_blind_signature(mpk: &PublicParams, sk: &SecretKeyD, M: G2, num_secrets: usize) -> SignatureD {
    let rng = &mut thread_rng();
    let alpha = Fr::random(rng);
    let a = mpk.g2 * alpha;
    let mut A: Vec<G2> = Vec::new();
    let mut B: Vec<G2> = Vec::new();
    //println!("Num secrets: {}", num_secrets);
    //println!("sk z len: {}", sk.z.len());
    assert!(sk.z.len() <= num_secrets);
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
    let rng = &mut thread_rng();
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
#[derive(Clone)]
pub struct CommonParams {
    vx: Gt,
    vxy: Gt,
    vxyi: Vec<Gt>,
    pub vs: Gt
}

#[derive(Clone)]
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
    let rng = &mut thread_rng();
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
    //println!("(vs_gen_nizk_proof) Number of secrets: {}", l);
    //println!("(vs_gen_nizk_proof) Number of bases: {}", pub_bases.len());

    // compute the T
    let mut T = pub_bases[0].pow(t[0]);  // vx ^ t0
    for i in 1 .. l {
        T = T * (pub_bases[i].pow(t[i])); // vxy{i} ^ t{i}
    }

    // hash T to get the challenge
    let c = hashGtToFr(&T);
    // debug
    //let msg = "(gen nizk proof) challenge -> c";
    //debug_elem_in_hex(msg, &c);

    // compute s values
    let mut s: Vec<Fr> = Vec::new();
    let _s = c + t[0]; // for vx => s0 = (1*c + t[0])
    s.push(_s);
    for i in 1 .. l {
        //println!("(gen nizk proof) i => {}", i);
        let _s = (x[i-1] * c) + t[i];
        s.push(_s);
    }

    return ProofVS { T: T, A: A, s: s, pub_bases: pub_bases };
}

fn part1_verify_proof_vs(proof: &ProofVS) -> bool {
    // if proof is valid, then call part
    let c = hashGtToFr(&proof.T);
    // debug
    //let mut msg = "(in verify proof) challenge -> c";
    //debug_elem_in_hex(msg, &c);

    let l = proof.s.len();
    assert!(l > 1);

    //println!("(in verify proof) i => 0");
    let mut lhs = proof.pub_bases[0].pow(proof.s[0]);
    for i in 1 .. l {
        //println!("(in verify proof) i => {}", i);
        lhs = lhs * (proof.pub_bases[i].pow(proof.s[i]));
    }
    // debug
    //msg = "(in verify proof) lhs => ";
    //debug_gt_in_hex(msg, &lhs);

    let rhs = proof.A.pow(c) * proof.T;
    // debug
    //msg = "(in verify proof) rhs => ";
    //debug_gt_in_hex(msg, &rhs);
    return lhs == rhs;
}

pub fn vs_verify_blind_sig(mpk: &PublicParams, pk: &PublicKeyD, proof: &ProofVS, sig: &SignatureD) -> bool {

    let result0 = part1_verify_proof_vs(&proof);
    let mut result1 = true;
    let mut result3 = true;

    // verify second condition
    let lhs2 = pairing(pk.Y, sig.a);
    let rhs2 = pairing(mpk.g1, sig.b);
    let result2 = lhs2 == rhs2;

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

    if !result0 {
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

    return result0 && result1 && result2 && result3;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};
    use bn::{Fr, Group};
    use clsigs;
    use commit_scheme;
    use debug_g2_in_hex;

    #[test]
    fn efficient_protocols_for_cl_signatures() {
        let rng = &mut rand::thread_rng();

        let mpk = clsigs::setupD();
        let l = 3;
        let m_keypair = clsigs::keygenD(&mpk, l);
        let mut m1 : Vec<Fr> = Vec::new();

        for i in 0 .. l+1 {
            m1.push(Fr::random(rng));
        }

        let b = m_keypair.pk.Z2.len();
        let mut bases: Vec<G2> = Vec::new();
        bases.push(mpk.g2);
        for i in 0 .. b {
            bases.push(m_keypair.pk.Z2[i]);
        }

        // generate sample commitment
        //let mut m: Vec<Fr> = Vec::new();
        let mut C = mpk.g2 * m1[0];
        for i in 0 .. b {
            //println!("index: {}", i);
            C = C + (m_keypair.pk.Z2[i] * m1[i+1]);
        }
        let msg = "Sample Commit output:";
        debug_g2_in_hex(msg, &C);

        let cm_csp = commit_scheme::setup(b, m_keypair.pk.Z2.clone(), mpk.g2.clone());
        let r = m1[0];
        let w_com = commit_scheme::commit(&cm_csp, &m1, r);

        assert!(commit_scheme::decommit(&cm_csp, &w_com, &m1));

        let proof = bs_gen_nizk_proof(&m1, &cm_csp.pub_bases, w_com.c);

        let int_sig = bs_check_proof_and_gen_signature(&mpk, &m_keypair.sk, &proof);

        assert!(clsigs::verifyD(&mpk, &m_keypair.pk, &m1, &int_sig) == true);

        let blind_sigs = prover_generate_blinded_sig(&int_sig);
        let common_params1 = gen_common_params(&mpk, &m_keypair.pk, &int_sig);

        let proof_vs = vs_gen_nizk_proof(&m1, &common_params1, common_params1.vs);
        assert!(vs_verify_blind_sig(&mpk, &m_keypair.pk, &proof_vs, &blind_sigs) == true);
    }
}