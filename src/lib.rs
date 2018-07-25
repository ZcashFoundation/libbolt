//! This crate is an experimental implementation of Blind Off-chain
//! lightweight transactions (BOLT).
//!
//! It builds on academic work done by Ian Miers and Matthew Green -
//! https://eprint.iacr.org/2016/701.
//!
//! Libbolt relies on BN curves at 128-bit security, as implemented in
//! [`bn module`](https://github.com/zcash-hackworks/bn).
//!
#![feature(extern_prelude)]

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))] extern crate test;

extern crate bn;
extern crate rand;
extern crate rand_core;
extern crate bincode;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate secp256k1;
extern crate time;
extern crate bulletproofs;
extern crate curve25519_dalek;

use std::fmt;
use std::str;
//use std::result;
use bn::{Group, Fr, G1, G2, Gt};
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use sodiumoxide::randombytes;
use sodiumoxide::crypto::hash::sha512;
use std::collections::HashMap;
use time::PreciseTime;
//use rand::{rngs::OsRng, Rng};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::ProofTranscript;
use bulletproofs::RangeProof;
use bulletproofs::{Generators, PedersenGenerators};

pub mod prf;
pub mod sym;
pub mod ote;
pub mod clsigs;
pub mod commit_scheme;

const E_MIN: i32 = 1;
const E_MAX: i32 = 255;

//pub fn hash_string(s: &str) -> String {
//    let digest = sha256::hash(s.as_bytes());
//    format!("{:X}", HexSlice::new(&digest))
//}

pub fn debug_elem_in_hex(prefix: &str, r: &Fr) {
    let encoded: Vec<u8> = encode(&r, Infinite).unwrap();
    print!("{} (hex) = 0x", prefix);
    for e in encoded.iter() {
        print!("{:x}", e);
    }
    print!("\n");
}

pub fn debug_g1_in_hex(prefix: &str, g: &G1) {
    let encoded: Vec<u8> = encode(&g, Infinite).unwrap();
    print!("{} (hex) = 0x", prefix);
    for e in encoded.iter() {
        print!("{:x}", e);
    }
    print!("\n");
}

pub fn debug_g2_in_hex(prefix: &str, g: &G2) {
    let encoded: Vec<u8> = encode(&g, Infinite).unwrap();
    print!("{} (hex) = 0x", prefix);
    for e in encoded.iter() {
        print!("{:x}", e);
    }
    print!("\n");
}

pub fn debug_gt_in_hex(prefix: &str, g: &Gt) {
    let encoded: Vec<u8> = encode(&g, Infinite).unwrap();
    print!("{} (hex) = 0x", prefix);
    for e in encoded.iter() {
        print!("{:x}", e);
    }
    print!("\n");
}


struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    fn new<T>(data: &'a T) -> HexSlice<'a>
        where T: ?Sized + AsRef<[u8]> + 'a
    {
        HexSlice(data.as_ref())
    }
}

impl<'a> fmt::LowerHex for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            // Decide if you want upper- or lowercase results,
            // padding the values to two characters, spaces
            // between bytes, etc.
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl<'a> fmt::UpperHex for HexSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            // Decide if you want upper- or lowercase results,
            // padding the values to two characters, spaces
            // between bytes, etc.
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}

pub fn print(g: &G1) -> String {
    let c_vec: Vec<u8> = encode(g, Infinite).unwrap();
    let mut c_s = String::new();
    for x in c_vec.iter() {
        c_s = format!("{}{:x}", c_s, x);
    }

    return c_s;
}

// OLD RefundMessage
//impl<'a> RefundMessage<'a> {
//    pub fn new(_c_id: Fr, _index: i32) -> RefundMessage<'a> {
//        RefundMessage {
//            prefix: "refund", c_id: _c_id, index: _index,
//        }
//    }
//
//    pub fn hash(&self) -> Fr {
//        let mut input_buf = Vec::new();
//        input_buf.extend_from_slice(self.prefix.as_bytes());
//        let c_id_vec: Vec<u8> = encode(&self.c_id, Infinite).unwrap();
//        // encode cId in the vector
//        input_buf.extend(c_id_vec);
//        // encoee the balance as a hex string
//        let b = format!("{:x}", self.index);
//        input_buf.extend_from_slice(b.as_bytes());
//        // TODO: add the ck vector (l-bit key)
////        let mut in_str = String::new();
////        for y in input_buf.iter() {
////            in_str = format!("{}{:x}", in_str, y);
////        }
////        println!("input_buf: {}", in_str);
//
//        // hash the inputs via SHA256
//        let sha2_digest = sha512::hash(input_buf.as_slice());
//        // println!("hash: {:?}", sha2_digest);
//        // let h = format!("{:x}", HexSlice::new(&sha2_digest));
//        let mut hash_buf: [u8; 64] = [0; 64];
//        hash_buf.copy_from_slice(&sha2_digest[0..64]);
//        return Fr::interpret(&hash_buf);
//    }
//}

// spend message (for unidirectional scheme)
#[derive(Clone)]
pub struct SpendMessage<'a> {
    prefix: &'a str,
    j: i32,
    s: G1,
    u: G1,
    pi: Proof,
    ck: sym::SymKey
}

impl<'a> SpendMessage<'a> {
    pub fn new(_j: i32, _s: G1, _u: G1, _pi: Proof, _ck: sym::SymKey) -> SpendMessage<'a> {
        SpendMessage {
            prefix: "spend", j: _j, s: _s, u: _u, pi: _pi, ck: _ck,
        }
    }

    pub fn hash(&self) -> Fr {
        // hash into a Fr element
        let rng = &mut rand::thread_rng();
        return Fr::random(rng);
    }
}

#[derive(Copy, Clone)]
pub struct Message {
    sk: clsigs::SecretKey, // the secret key for the signature scheme (Is it possible to make this a generic field?)
    k1: Fr, // seed 1 for PRF
    k2: Fr, // seed 2 for PRF
    balance: i32 // the balance for the user
}

impl Message {
    pub fn new(_sk: clsigs::SecretKey, _k1: Fr, _k2: Fr, _balance: i32) -> Message {
        Message {
            sk: _sk, k1: _k1, k2: _k2, balance: _balance,
        }
    }

    pub fn hash(&self) -> Vec<Fr> {
        let mut input_buf = self.sk.encode();
        let mut v: Vec<Fr> = Vec::new();

        v.push(convertToFr(&input_buf));
//        let k1_vec: Vec<u8> = encode(&self.k1, Infinite).unwrap();
//        let k2_vec: Vec<u8> = encode(&self.k2, Infinite).unwrap();
        // encode k1 in the vector
        v.push(self.k1.clone());
        v.push(self.k2.clone());
        // convert the balance into a Fr
        let bal = Fr::from_str(self.balance.to_string().as_str()).unwrap();
        v.push(bal);

        return v;
    }
}

////////////////////////////////// Utilities //////////////////////////////////

pub fn concat_to_vector(output: &mut Vec<u8>, t: &G2) {
    let t_vec: Vec<u8> = encode(t, Infinite).unwrap();
    output.extend(t_vec);
}

#[derive(Copy, Clone)]
pub struct Proof {
    T: G1,
    c: Fr,
    s1: Fr,
    s2: Fr
}

pub fn hashG1ToFr(x: &G1) -> Fr {
    // TODO: use serde (instead of rustc_serialize)
    let x_vec: Vec<u8> = encode(&x, Infinite).unwrap();
    let sha2_digest = sha512::hash(x_vec.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

pub fn hashPubKeyToFr(wpk: &secp256k1::PublicKey) -> Fr {
    let x_slice = wpk.serialize_uncompressed();
    let sha2_digest = sha512::hash(&x_slice);

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

pub fn computePubKeyFingerprint(wpk: &secp256k1::PublicKey) -> String {
    let x_slice = wpk.serialize();
    let sha2_digest = sha512::hash(&x_slice);
    let h = format!("{:x}", HexSlice::new(&sha2_digest[0..16]));
    return h;
}

pub fn hashBufferToFr<'a>(prefix: &'a str, buf: &[u8; 64]) -> Fr {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(prefix.as_bytes());
    input_buf.extend_from_slice(buf);

    let sha2_digest = sha512::hash(&input_buf.as_slice());

    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

fn convertToFr(input_buf: &Vec<u8>) -> Fr {
    // hash the inputs via SHA256
    let sha2_digest = sha512::hash(input_buf.as_slice());
    // println!("hash: {:?}", sha2_digest);
    // let h = format!("{:x}", HexSlice::new(&sha2_digest));
    let mut hash_buf: [u8; 64] = [0; 64];
    hash_buf.copy_from_slice(&sha2_digest[0..64]);
    return Fr::interpret(&hash_buf);
}

fn convertStrToFr<'a>(input: &'a str) -> Fr {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(input.as_bytes());
    return convertToFr(&input_buf);
}

// refund message
#[derive(Clone)]
pub struct RefundMessage {
    pub msgtype: String, // purpose type of message
    pub wpk: secp256k1::PublicKey,
    pub balance: usize, // the balance
    pub r: Option<Fr>, // randomness from customer wallet
    pub rt: Option<clsigs::SignatureD> // refund token
}

impl RefundMessage {
    pub fn new(_msgtype: String, _wpk: secp256k1::PublicKey,
               _balance: usize, _r: Option<Fr>, _rt: Option<clsigs::SignatureD>) -> RefundMessage {
        RefundMessage {
            msgtype: _msgtype, wpk: _wpk, balance: _balance, r: _r, rt: _rt
        }
    }

    pub fn hash(&self) -> Vec<Fr> {
        let mut v: Vec<Fr> = Vec::new();
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        v.push(convertToFr(&input_buf));

        v.push(hashPubKeyToFr(&self.wpk));

        // encoee the balance as a hex string
        let b = format!("{:x}", self.balance);
        let mut b_buf = Vec::new();
        b_buf.extend_from_slice(b.as_bytes());
        v.push(convertToFr(&b_buf));

        //let r_vec: Vec<u8> = encode(&self.r, Infinite).unwrap();
        if !self.r.is_none() {
            v.push(self.r.unwrap().clone());
        }

        if !self.rt.is_none() {
            let rt = {
                &self.rt.clone()
            };
            let rt_ref = rt.as_ref();
            v.push(rt_ref.unwrap().hash(&self.msgtype));
        }

        return v;
    }
}

//#[derive(Clone)]
pub struct RevokedMessage {
    pub msgtype: String,
    pub wpk: secp256k1::PublicKey,
    pub sig: Option<[u8; 64]> // represents revocation token serialized compact bytes
}

impl RevokedMessage {
    pub fn new(_msgtype: String, _wpk: secp256k1::PublicKey, _sig: Option<[u8; 64]>) -> RevokedMessage {
        RevokedMessage {
            msgtype: _msgtype, wpk: _wpk, sig: _sig
        }
    }

    pub fn hash(&self) -> Vec<Fr> {
        let mut v: Vec<Fr> = Vec::new();
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        v.push(convertToFr(&input_buf));

        v.push(hashPubKeyToFr(&self.wpk));

        if !self.sig.is_none() {
            // TODO: make sure we can call hashBufferToFr with sig
            v.push(hashBufferToFr(&self.msgtype, &self.sig.unwrap()));
        }
        return v;
    }

    // return a message digest (32-bytes)
    pub fn hash_to_slice(&self) -> [u8; 32] {
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        input_buf.extend_from_slice(&self.wpk.serialize_uncompressed());
        let sha2_digest = sha512::hash(input_buf.as_slice());
        // println!("hash: {:?}", sha2_digest);
        // let h = format!("{:x}", HexSlice::new(&sha2_digest));
        let mut hash_buf: [u8; 32] = [0; 32];
        hash_buf.copy_from_slice(&sha2_digest[0..32]);
        return hash_buf;
    }
}

////////////////////////////////// Utilities //////////////////////////////////

/////////////////////////////// Unidirectional ////////////////////////////////

pub mod unidirectional {
    use std::fmt;
    use rand::{Rng, thread_rng};
    use rand_core::RngCore;
    use bn::{Group, Fr};
    use sym;
    use commit_scheme;
    use clsigs;
    use Message;
    use sodiumoxide::randombytes;

    pub struct PublicParams {
        cl_mpk: clsigs::PublicParams,
        l: usize
        // TODO: add NIZK proof system pub params
    }

    pub struct ChannelToken {
        w_com: commit_scheme::Commitment,
        pk: clsigs::PublicKey
    }

    pub struct CustSecretKey {
        sk: clsigs::SecretKey, // the secret key for the signature scheme (Is it possible to make this a generic field?)
        k1: Fr, // seed 1 for PRF
        k2: Fr, // seed 2 for PRF
        r: Fr, // random coins for commitment scheme
        balance: i32, // the balance for the user
        ck_vec: Vec<sym::SymKey>
    }

    pub struct MerchSecretKey {
        sk: clsigs::SecretKey,
        balance: i32
    }

    pub struct InitCustomerData {
        T: ChannelToken,
        csk: CustSecretKey
    }

    pub struct InitMerchantData {
        T: clsigs::PublicKey,
        csk: MerchSecretKey
    }

    pub fn setup() -> PublicParams {
        let cl_mpk = clsigs::setupD();
        let l = 4;
        // let nizk = "nizk proof system";
        let pp = PublicParams { cl_mpk: cl_mpk, l: l };
        return pp;
    }

    pub fn keygen(pp: &PublicParams) -> clsigs::KeyPairD {
        // TODO: figure out what we need from public params to generate keys
        println!("Run Keygen...");
        let keypair = clsigs::keygenD(&pp.cl_mpk, pp.l);
        return keypair;
    }

    pub fn init_customer(pp: &PublicParams, cm_pk: commit_scheme::CSParams,
                         b0_customer: i32, b0_merchant: i32,
                         keypair: &clsigs::KeyPair) -> InitCustomerData {
        println!("Run Init customer...");
        sym::init_mod();
        let rng = &mut rand::thread_rng();
        // pick two distinct seeds
        let l = 256;
        let k1 = Fr::random(rng);
        let k2 = Fr::random(rng);
        let r = Fr::random(rng);
        let msg = Message::new(keypair.sk, k1, k2, b0_customer);

        let mut ck_vec: Vec<sym::SymKey> = Vec::new();
        // generate the vector ck of sym keys
        for i in 1 .. b0_customer {
            let ck = sym::keygen(l);
            ck_vec.push(ck);
        }

        // TODO: get bidirectional setup
        let w_com = commit_scheme::commit(&cm_pk, &msg.hash(), r);
        let t_c = ChannelToken { w_com: w_com, pk: keypair.pk };
        let csk_c = CustSecretKey { sk: keypair.sk, k1: k1, k2: k2, r: r, balance: b0_customer, ck_vec: ck_vec };
        return InitCustomerData { T: t_c, csk: csk_c };
    }

    pub fn init_merchant(pp: &PublicParams, b0_merchant: i32, keypair: &clsigs::KeyPair) -> InitMerchantData {
        println!("Run Init merchant...");
        let csk_m = MerchSecretKey { sk: keypair.sk, balance: b0_merchant };
        return InitMerchantData { T: keypair.pk, csk: csk_m };
    }

//    pub fn establish_customer(pp: &PublicParams, t_m: &clsigs::PublicKey, csk_c: &CustSecretKey) {
//        println ! ("Run establish_customer algorithm...");
//        // set sk_0 to random bytes of length l
//        // let sk_0 = random_bytes(pp.l);
//        let buf_len: usize = pp.l_bits as usize;
//        let mut sk0 = vec![0; buf_len];
//        randombytes::randombytes_into(&mut sk0);
//
//        let pi1 = create_nizk_proof_one(csk_c.sk, csk_c.k1, csk_c.k2, );
//    }
}

/////////////////////////////// Unidirectional ////////////////////////////////

/////////////////////////////// Bidirectional ////////////////////////////////
pub mod bidirectional {
    use std::fmt;
    use PreciseTime;
    //use rand::prelude::*;
    //use rand::{rngs::OsRng, Rng};
    //use rand::prelude::thread_rng;
    //use rand::{Rng, thread_rng};
    use rand::{rngs::OsRng, Rng};
    use rand_core::RngCore;
    //use rand::{thread_rng, Rng};
    use bn::{Group, Fr, G1, G2, Gt};
    use sym;
    use commit_scheme;
    use clsigs;
    use Message;
    use sodiumoxide;
    use sodiumoxide::randombytes;
    use secp256k1;
    use secp256k1::*;
    use RefundMessage;
    use RevokedMessage;
    use HashMap;
    use hashPubKeyToFr;
    use hashBufferToFr;
    use debug_elem_in_hex;
    use debug_gt_in_hex;
    use convertToFr;
    use convertStrToFr;
    use computePubKeyFingerprint;
    use E_MIN;
    use E_MAX;
    use bulletproofs;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use bulletproofs::ProofTranscript;
    use bulletproofs::RangeProof;
    use bulletproofs::{Generators, PedersenGenerators};

    fn print_secret_vector(x: &Vec<Fr>) {
        for i in 0 .. x.len() {
            let msg = format!("x[{}] => ", i);
            debug_elem_in_hex(&msg, &x[i]);
        }
    }

    fn print_public_bases_vector(g: &Vec<Gt>) {
        for i in 0 .. g.len() {
            let msg = format!("g[{}] => ", i);
            debug_gt_in_hex(&msg, &g[i]);
        }
    }

    pub struct PublicParams {
        cl_mpk: clsigs::PublicParams,
        l: usize, // messages for committment
        range_proof_gens: bulletproofs::Generators,
        range_proof_bits: usize,
        extra_verify: bool // extra verification for certain points in the establish/pay protocol
    }

    pub struct ChannelToken {
        w_com: commit_scheme::Commitment,
        pk: clsigs::PublicKeyD
    }

    // TODO: add display method to print structure (similar to Commitment)

    // proof of wallet signature, blind signature on wallet and common params for NIZK
    #[derive(Clone)]
    pub struct CustomerWalletProof {
        proof_cv: clsigs::ProofCV, // proof of knowledge of committed values
        proof_vs: clsigs::ProofVS, // proof of knowledge of valid signature
        blind_sig: clsigs::SignatureD, // a blind signature
        common_params: clsigs::CommonParams, // common params for NIZK
    }

    pub struct CustomerWallet {
        sk: clsigs::SecretKeyD, // the secret key for the signature scheme (Is it possible to make this a generic field?)
        cid: Fr, // channel Id
        wpk: secp256k1::PublicKey, // signature verification key
        wsk: secp256k1::SecretKey, // signature signing key
        h_wpk: Fr,
        r: Fr, // random coins for commitment scheme
        pub balance: i32, // the balance for the user
        merchant_balance: i32,
        signature: Option<clsigs::SignatureD>,
        proof: Option<CustomerWalletProof>, // proof of knowledge computed after obtaining signature on wallet contents in zero-knowledge
        refund_token: Option<clsigs::SignatureD>
    }

    // TODO: add display method to print structure (similar to Commitment)
    pub struct MerchSecretKey {
        sk: clsigs::SecretKeyD, // merchant signing key
        pub balance: i32
    }

    pub struct InitCustomerData {
        pub T: ChannelToken,
        pub csk: CustomerWallet,
        pub bases: Vec<G2>,
    }

    pub struct InitMerchantData {
        pub T: clsigs::PublicKeyD,
        pub csk: MerchSecretKey,
        pub bases: Vec<G2>
    }

    // TODO: add method to display contents of the channel state
    // should include contents of the channel state
    pub struct PubKeyMap {
        wpk: secp256k1::PublicKey,
        revoke_token: Option<secp256k1::Signature>
    }

    pub struct ChannelState {
        keys: HashMap<String, PubKeyMap>,
        R: i32,
        pub name: String,
        pub cid: Fr,
        pub pay_init: bool,
        pub channel_established: bool
    }

    pub struct ChannelClosure_C {
        pub message: RefundMessage,
        signature: clsigs::SignatureD
    }

    pub struct ChannelClosure_M {
        message: RevokedMessage,
        signature: clsigs::SignatureD
    }

    // proof of valid balance
    pub struct ProofVB {
        range_proof: bulletproofs::RangeProof,
        value_commitment: RistrettoPoint
    }

    pub struct PaymentProof {
        proof2a: clsigs::ProofCV, // PoK of committed values in new wallet
        proof2b: clsigs::ProofCV, // PoK of committed values in old wallet (minus wpk)
        proof2c: clsigs::ProofVS, // PoK of old wallet signature (that includes wpk)
        proof3: ProofVB, // range proof that balance - balance_inc is between (0, val_max)
        balance_inc: i32, // balance increment
        w_com: commit_scheme::Commitment, // commitment for new wallet
        old_com_base: G2,
        wpk: secp256k1::PublicKey, // verification key for old wallet
        wallet_sig: clsigs::SignatureD // blinded signature for old wallet
    }

    pub struct RevokeToken {
        message: RevokedMessage,
        pub signature: secp256k1::Signature
    }

    pub fn init() {
        sodiumoxide::init();
    }

    pub fn setup(_extra_verify: bool) -> PublicParams {
        // TODO: provide option for generating CRS parameters
        let cl_mpk = clsigs::setupD();
        let l = 4;
        // let nizk = "nizk proof system";
        let n = 32; // bitsize: 32-bit (0, 2^32-1)
        let num_rand_values = 1;
        let generators = Generators::new(PedersenGenerators::default(), n, num_rand_values);

        let pp = PublicParams { cl_mpk: cl_mpk, l: l, range_proof_gens: generators, range_proof_bits: n, extra_verify: _extra_verify };
        return pp;
    }

    pub fn keygen(pp: &PublicParams) -> clsigs::KeyPairD {
        // TODO: figure out what we need from public params to generate keys
        println!("Run Keygen...");
        let keypair = clsigs::keygenD(&pp.cl_mpk, pp.l);
        return keypair;
    }

    fn generate_channel_id() -> Fr {
        let rng = &mut rand::thread_rng();
        return Fr::random(rng);
    }

    pub fn generate_commit_setup(pp: &PublicParams, pk: &clsigs::PublicKeyD) -> commit_scheme::CSParams {
        let g2 = pp.cl_mpk.g2.clone();
        let bases = pk.Z2.clone();
        let cm_csp = commit_scheme::setup(pp.l, bases, g2);
        return cm_csp;
    }

    pub fn init_customer(pp: &PublicParams, channel: &ChannelState, b0_customer: i32, b0_merchant: i32,
                         cm_csp: &commit_scheme::CSParams, keypair: &clsigs::KeyPairD) -> InitCustomerData {
        let rng = &mut rand::thread_rng();
        // generate verification key and signing key (for wallet)
        let mut schnorr = secp256k1::Secp256k1::new();
        schnorr.randomize(rng);
        let (wsk, wpk) = schnorr.generate_keypair(rng);
        let h_wpk = hashPubKeyToFr(&wpk);
        // convert balance into Fr
        let b0 = Fr::from_str(b0_customer.to_string().as_str()).unwrap();
        // randomness for commitment
        let r = Fr::random(rng);
        // retreive the channel id
        let cid = channel.cid.clone();

        let mut x: Vec<Fr> = Vec::new();
        x.push(r); // set randomness for commitment
        x.push(cid);
        x.push(b0);
        x.push(h_wpk);

        let w_com = commit_scheme::commit(&cm_csp,  &x, r);
        let t_c = ChannelToken { w_com: w_com, pk: keypair.pk.clone() };
        let csk_c = CustomerWallet { sk: keypair.sk.clone(), cid: cid, wpk: wpk, wsk: wsk, h_wpk: h_wpk,
                                    r: r, balance: b0_customer, merchant_balance: b0_merchant,
                                    proof: None, signature: None, refund_token: None };
        return InitCustomerData { T: t_c, csk: csk_c, bases: cm_csp.pub_bases.clone() };
    }

    pub fn init_merchant(pp: &PublicParams, b0_merchant: i32, keypair: &clsigs::KeyPairD) -> InitMerchantData {
        let cm_csp = generate_commit_setup(&pp, &keypair.pk);
        let csk_m = MerchSecretKey { sk: keypair.sk.clone(), balance: b0_merchant };
        return InitMerchantData { T: keypair.pk.clone(), csk: csk_m, bases: cm_csp.pub_bases };
    }

    pub fn init_channel(name: String) -> ChannelState {
        let cid = generate_channel_id();
        let keys = HashMap::new(); // will store wpks/revoke_tokens
        return ChannelState { keys: keys, R: 0, name: name, cid: cid, channel_established: false, pay_init: false }
    }

    //// begin of establish channel protocol
    pub fn establish_customer_phase1(pp: &PublicParams, c_data: &InitCustomerData,
                                     m_data: &InitMerchantData) -> clsigs::ProofCV {
        // obtain customer init data
        let t_c = &c_data.T;
        let csk_c = &c_data.csk;
        let pub_bases = &m_data.bases;

        //let h_wpk = hashPubKeyToFr(&csk_c.wpk);
        let h_wpk = csk_c.h_wpk;
        let b0 = Fr::from_str(csk_c.balance.to_string().as_str()).unwrap();
        // collect secrets
        let mut x: Vec<Fr> = Vec::new();
        x.push(t_c.w_com.r); // set randomness used to generate commitment
        x.push(csk_c.cid);
        x.push(b0);
        x.push(h_wpk);
        //println!("establish_customer_phase1 - secrets for original wallet");
        //print_secret_vector(&x);

        // generate proof of knowledge for committed values
        let proof_1 = clsigs::bs_gen_nizk_proof(&x, &pub_bases, t_c.w_com.c);
        return proof_1;
    }

    // the merchant calls this method after obtaining proof from the customer
    pub fn establish_merchant_phase2(pp: &PublicParams, state: &mut ChannelState, m_data: &InitMerchantData,
                                     proof: &clsigs::ProofCV) -> clsigs::SignatureD {
        // verifies proof and produces
        let wallet_sig = clsigs::bs_check_proof_and_gen_signature(&pp.cl_mpk, &m_data.csk.sk, &proof);
        state.channel_established = true;
        return wallet_sig;
    }

    pub fn establish_customer_final(pp: &PublicParams, pk_m: &clsigs::PublicKeyD,
                                    w: &mut CustomerWallet, sig: clsigs::SignatureD) -> bool {
        if w.signature.is_none() {
            if pp.extra_verify {
                let mut x: Vec<Fr> = Vec::new();
                x.push(w.r.clone());
                x.push(w.cid.clone());
                x.push(Fr::from_str(w.balance.to_string().as_str()).unwrap());
                x.push(w.h_wpk.clone());

                //println!("establish_customer_final - print secrets");
                //print_secret_vector(&x);

                assert!(clsigs::verifyD(&pp.cl_mpk, &pk_m, &x, &sig));
            }
            w.signature = Some(sig);
            println!("establish_customer_final - verified merchant signature on initial wallet with {}", w.balance);
            return true;
        }
        // must be an old wallet
        return false;
    }
    ///// end of establish channel protocol

    ///// begin of pay protocol
    pub fn pay_by_customer_phase1_precompute(pp: &PublicParams, T: &ChannelToken, pk_m: &clsigs::PublicKeyD, old_w: &mut CustomerWallet) -> bool {
        // generate proof of knowledge of valid signature on previous wallet signature
        let old_wallet_sig = &old_w.signature;

        let cid = old_w.cid.clone();
        let old_r = &old_w.r;
        let old_wallet_sig = &old_w.signature;

        let wallet_sig = old_wallet_sig.clone().unwrap();
        // retrieve old balance
        let old_balance = Fr::from_str(old_w.balance.to_string().as_str()).unwrap();

        let old_h_wpk = old_w.h_wpk;
        // added the blinding factor to list of secrets
        let mut old_x: Vec<Fr> = Vec::new();

        old_x.push(old_w.r.clone()); // set randomness for commitment
        old_x.push(cid);
        old_x.push(old_balance);
        old_x.push(old_h_wpk);

        // retrieve the commitment scheme parameters based on merchant's PK
        let cm_csp = generate_commit_setup(&pp, &pk_m);

        // proof of committed values not including the old wpk since we are revealing it
        // to the merchant
        let index = 3;
        let old_w_com_pr = T.w_com.c - (cm_csp.pub_bases[index] * old_h_wpk);
        let proof_old_cv = clsigs::bs_gen_nizk_proof(&old_x, &cm_csp.pub_bases, old_w_com_pr);

        let blind_sig = clsigs::prover_generate_blinded_sig(&wallet_sig);
        let common_params = clsigs::gen_common_params(&pp.cl_mpk, &pk_m, &wallet_sig);
        //println!("payment_by_customer_phase1 - secrets for old wallet");
        //print_secret_vector(&old_x);

        let proof_vs = clsigs::vs_gen_nizk_proof(&old_x, &common_params, common_params.vs);

        let proof = CustomerWalletProof { proof_cv: proof_old_cv, proof_vs: proof_vs,
                                          blind_sig: blind_sig, common_params: common_params };
        old_w.proof = Some(proof);
        return true;
    }

    pub fn pay_by_customer_phase1(pp: &PublicParams, T: &ChannelToken, pk_m: &clsigs::PublicKeyD,
                                  old_w: &CustomerWallet, balance_increment: i32) -> (ChannelToken, CustomerWallet, PaymentProof) {
        //println!("pay_by_customer_phase1 - generate new wallet commit, PoK of commit values, and PoK of old wallet.");
        // get balance, keypair, commitment randomness and wallet sig
        let mut rng = &mut rand::thread_rng();

        if old_w.proof.is_none() {
           panic!("You have not executed the pay_by_customer_phase1_precompute!");
        }
        let wallet_proof = old_w.proof.clone().unwrap();
        let bal = old_w.balance;

        // generate new keypair
        let mut schnorr = secp256k1::Secp256k1::new();
        schnorr.randomize(rng);
        let (wsk, wpk) = schnorr.generate_keypair(rng);
        let h_wpk = hashPubKeyToFr(&wpk);

        // new sample randomness r'
        let r_pr = Fr::random(rng);
        // retrieve the commitment scheme parameters based on merchant's PK
        let cm_csp = generate_commit_setup(&pp, &pk_m);
        // retrieve the current payment channel id
        let cid = old_w.cid.clone();
        // convert balance into Fr (B - e)
        let updated_balance = bal - balance_increment;
        if updated_balance < 0 {
            panic!("pay_by_customer_phase1 - insufficient funds to make payment!");
        }
        // record the potential to payment
        let merchant_balance = old_w.merchant_balance + balance_increment;

        let updated_balance_pr = Fr::from_str(updated_balance.to_string().as_str()).unwrap();

        let mut new_wallet_sec: Vec<Fr> = Vec::new();
        new_wallet_sec.push(r_pr); // set randomness for commitment
        new_wallet_sec.push(cid);
        new_wallet_sec.push(updated_balance_pr);
        new_wallet_sec.push(h_wpk);

        let w_com = commit_scheme::commit(&cm_csp, &new_wallet_sec, r_pr);

        // generate proof of knowledge for committed values
        let proof_cv = clsigs::bs_gen_nizk_proof(&new_wallet_sec, &cm_csp.pub_bases, w_com.c);
        let index = new_wallet_sec.len() - 1;

        // bullet proof integration here to generate the range proof
        let mut osrng = OsRng::new().unwrap();
        let mut transcript = ProofTranscript::new(b"BOLT Range Proof");
        let value = updated_balance as u64;
        let val_blinding = Scalar::random(&mut osrng);
        let range_proof = RangeProof::prove_single(&pp.range_proof_gens, &mut transcript,
                                                   &mut osrng, value, &val_blinding,
                                                   pp.range_proof_bits).unwrap();
        let pg = &pp.range_proof_gens.pedersen_generators;
        let value_cm = pg.commit(Scalar::from_u64(value), val_blinding);

        let proof_rp = ProofVB { range_proof: range_proof, value_commitment: value_cm };

        // create payment proof which includes params to reveal wpk from old wallet
        let payment_proof = PaymentProof {
                                proof2a: proof_cv, // proof of knowledge for committed values
                                proof2b: wallet_proof.proof_cv, // PoK of committed values (minus h(wpk))
                                proof2c: wallet_proof.proof_vs, // PoK of signature on old wallet
                                proof3: proof_rp, // range proof that the updated_balance is within a public range
                                w_com: w_com,
                                balance_inc: balance_increment, // epsilon - increment/decrement
                                old_com_base: cm_csp.pub_bases[index], // base Z
                                wpk: old_w.wpk.clone(), // showing public key for old wallet
                                wallet_sig: wallet_proof.blind_sig // blinded signature for old wallet
                            };
        // create new wallet structure (w/o signature or refund token)
        let t_c = ChannelToken { w_com: w_com, pk: T.pk.clone() };
        let csk_c = CustomerWallet { sk: old_w.sk.clone(), cid: cid, wpk: wpk, wsk: wsk, h_wpk: h_wpk,
                            r: r_pr, balance: updated_balance, merchant_balance: merchant_balance,
                            proof: None, signature: None, refund_token: None };
        return (t_c, csk_c, payment_proof);
    }

    // NOTE regarding balance increments
    // a positive increment => increment merchant balance, and decrement customer balance
    // a negative increment => decrement merchant balance, and increment customer balance
    pub fn pay_by_merchant_phase1(pp: &PublicParams, mut state: &mut ChannelState, proof: &PaymentProof,
                                  m_data: &InitMerchantData) -> clsigs::SignatureD {
        let blind_sigs = &proof.wallet_sig;
        let proof_cv = &proof.proof2a;
        let proof_old_cv = &proof.proof2b;
        let proof_vs = &proof.proof2c;
        // get merchant keypair
        let pk_m = &m_data.T;
        let sk_m = &m_data.csk.sk;

        // let's first confirm that proof of knowledge of signature on old wallet is valid
        // let proof_vs_old_wallet = clsigs::vs_verify_blind_sig(&pp.cl_mpk, &pk_m, &proof_vs, &blind_sigs);
        let proof_vs_old_wallet = true;

        // add specified wpk to make the proof valid
        // NOTE: if valid, then wpk is indeed the wallet public key for the wallet
        let new_C = proof_old_cv.C + (proof.old_com_base * hashPubKeyToFr(&proof.wpk));
        let new_proof_old_cv = clsigs::ProofCV { T: proof_old_cv.T,
                                         C: new_C,
                                         s: proof_old_cv.s.clone(),
                                         pub_bases: proof_old_cv.pub_bases.clone(),
                                         num_secrets: proof_old_cv.num_secrets };
        let is_wpk_valid_reveal = clsigs::bs_verify_nizk_proof(&new_proof_old_cv);
        if !is_wpk_valid_reveal {
            panic!("pay_by_merchant_phase1 - nizk PoK of committed values that reveals wpk!");
        }

        let is_existing_wpk = exist_in_merchant_state(&state, &proof.wpk, None);
        let is_within_range = proof.balance_inc >= E_MIN && proof.balance_inc <= E_MAX;
        // check the range proof of the updated balance
        let mut osrng = OsRng::new().unwrap();
        let mut transcript = ProofTranscript::new(b"BOLT Range Proof");
        let is_range_proof_valid = proof.proof3.range_proof.verify(&[proof.proof3.value_commitment],
                                                                   &pp.range_proof_gens,
                                                                   &mut transcript,
                                                                   &mut osrng,
                                                                   pp.range_proof_bits).is_ok();

        // if above is is_wpk_valid_reveal => true, then we can proceed to
        // check that the proof of valid signature and then
        if proof_vs_old_wallet && !is_existing_wpk && is_within_range && is_range_proof_valid {
            println!("Proof of knowledge of signature is valid!");
            if proof.balance_inc < 0 {
                // negative increment
                state.R = 1;
            } else {
                // postiive increment
                state.R = -1; // -1 denotes \bot here
            }
        } else {
            panic!("pay_by_merchant_phase1 - Verification failure for old wallet signature contents!");
        }

        // now we can verify the proof of knowledge for committed values in new wallet
        if clsigs::bs_verify_nizk_proof(&proof_cv) {
            // generate refund token on new wallet
            let i = pk_m.Z2.len()-1;
            let c_refund = proof_cv.C + (pk_m.Z2[i] * convertStrToFr("refund"));
            // generating partially blind signature on refund || wpk' || B - e
            let rt_w = clsigs::bs_compute_blind_signature(&pp.cl_mpk, &sk_m, c_refund, proof_cv.num_secrets + 1); // proof_cv.C
            println!("pay_by_merchant_phase1 - Proof of knowledge of commitment on new wallet is valid");
            update_merchant_state(&mut state, &proof.wpk, None);
            state.pay_init = true;
            return rt_w;
        }

        // let's update the merchant's wallet balance now
        panic!("pay_by_merchant_phase1 - NIZK verification failed for new wallet commitment!");
    }

    pub fn pay_by_customer_phase2(pp: &PublicParams, old_w: &CustomerWallet, new_w: &CustomerWallet,
                                  pk_m: &clsigs::PublicKeyD, rt_w: &clsigs::SignatureD) -> RevokeToken {
        // (1) verify the refund token (rt_w) against the new wallet contents
        let mut x: Vec<Fr> = Vec::new();
        x.push(new_w.r.clone());
        x.push(new_w.cid.clone());
        x.push(Fr::from_str(new_w.balance.to_string().as_str()).unwrap());
        x.push(hashPubKeyToFr(&new_w.wpk));
        x.push(convertStrToFr("refund"));

        let is_rt_w_valid = clsigs::verifyD(&pp.cl_mpk, &pk_m, &x, &rt_w);

        if is_rt_w_valid {
            println!("Refund token is valid against the new wallet!");
            let schnorr = secp256k1::Secp256k1::new();
            let rm = RevokedMessage::new(String::from("revoked"), old_w.wpk, None);
            let msg = secp256k1::Message::from_slice(&rm.hash_to_slice()).unwrap();
            // msg = "revoked"|| old_wpk (for old wallet)
            let rv_w = schnorr.sign(&msg, &old_w.wsk);
            // return the revocation token
            return RevokeToken { message: rm, signature: rv_w };
        }
        panic!("pay_by_customer_phase2 - Merchant did not provide a valid refund token!");
    }

    pub fn pay_by_merchant_phase2(pp: &PublicParams, mut state: &mut ChannelState,
                                  proof: &PaymentProof, m_data: &mut InitMerchantData,
                                  rv: &RevokeToken) -> clsigs::SignatureD {
        let proof_cv = &proof.proof2a;
        let sk_m = &m_data.csk.sk;
        let schnorr = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_slice(&rv.message.hash_to_slice()).unwrap();
        // verify that the revocation token is valid
        let is_rv_valid = schnorr.verify(&msg, &rv.signature, &proof.wpk).is_ok();

        if clsigs::bs_verify_nizk_proof(&proof_cv) && is_rv_valid {
            // update merchant state with (wpk, sigma_rev)
            update_merchant_state(&mut state, &proof.wpk, Some(rv.signature));
            let new_wallet_sig = clsigs::bs_compute_blind_signature(&pp.cl_mpk, &sk_m, proof_cv.C, proof_cv.num_secrets);
            m_data.csk.balance += proof.balance_inc;
            state.R = 2;
            return new_wallet_sig;
        }

        panic!("pay_by_merchant_phase2 - Customer did not provide valid revocation token!");
    }

    pub fn pay_by_customer_final(pp: &PublicParams, pk_m: &clsigs::PublicKeyD,
                                     c_data: &mut InitCustomerData, mut new_t: ChannelToken,
                                     mut new_w: CustomerWallet, sig: clsigs::SignatureD) -> bool {
        if new_w.signature.is_none() {
            if pp.extra_verify {
                let mut x: Vec<Fr> = Vec::new();
                x.push(new_w.r.clone());
                x.push(new_w.cid.clone());
                x.push(Fr::from_str(new_w.balance.to_string().as_str()).unwrap());
                x.push(hashPubKeyToFr(&new_w.wpk));

                //println!("payment_by_customer_final - print secrets");
                //print_secret_vector(&x);

                assert!(clsigs::verifyD(&pp.cl_mpk, &pk_m, &x, &sig));
            }
            // update signature in new wallet
            new_w.signature = Some(sig);
            // update csk in new wallet
            c_data.csk = new_w;
            // update the channel token
            c_data.T = new_t;
            return true;
        }
        // must be an old wallet
        return false;
    }

    ///// end of pay protocol

    // for customer => on input a wallet w, it outputs a customer channel closure message rc_c
    pub fn customer_refund(pp: &PublicParams, state: &ChannelState, pk_m: &clsigs::PublicKeyD,
                           w: &CustomerWallet) -> ChannelClosure_C {
        let m;
        let balance = w.balance as usize;
        if !state.pay_init {
            // pay protocol not invoked so take the balance
            m = RefundMessage::new(String::from("refundUnsigned"), w.wpk, balance, Some(w.r), None);
        } else {
            // if channel has already been activated, then take unspent funds
            m = RefundMessage::new(String::from("refundToken"), w.wpk, balance, None, w.refund_token.clone());
        }

        // generate signature on the balance/channel id, etc to obtain funds back
        let m_vec = m.hash();
        let sigma = clsigs::signD(&pp.cl_mpk, &w.sk, &m_vec);
        return ChannelClosure_C { message: m, signature: sigma };
    }

    fn exist_in_merchant_state(state: &ChannelState, wpk: &secp256k1::PublicKey, rev: Option<secp256k1::Signature>) -> bool {
        if state.keys.is_empty() {
            return false;
        }

        let fingerprint = computePubKeyFingerprint(wpk);
        if state.keys.contains_key(&fingerprint) {
            let pub_key = state.keys.get(&fingerprint).unwrap();
            if pub_key.revoke_token.is_none() {
                // let's just check the public key
                return pub_key.wpk == *wpk;
            }
            if !rev.is_none() {
                return pub_key.wpk == *wpk && pub_key.revoke_token.unwrap() == rev.unwrap();
            }
            return pub_key.wpk == *wpk;
        }

        return false;
    }

    fn update_merchant_state(state: &mut ChannelState, wpk: &secp256k1::PublicKey, rev: Option<secp256k1::Signature>) -> bool {
        let fingerprint = computePubKeyFingerprint(wpk);
        //println!("Print fingerprint: {}", fingerprint);
        if !rev.is_none() {
            let cust_pub_key = PubKeyMap { wpk: wpk.clone(), revoke_token: Some(rev.unwrap().clone()) };
            state.keys.insert(fingerprint, cust_pub_key);
        } else {
            let cust_pub_key = PubKeyMap { wpk: wpk.clone(), revoke_token: None };
            state.keys.insert(fingerprint, cust_pub_key);
        }
        return true;
    }

    // for merchant => on input the merchant's current state S_old and a customer channel closure message,
    // outputs a merchant channel closure message rc_m and updated merchant state S_new
    pub fn merchant_refute(pp: &PublicParams, T_c: &ChannelToken, m_data: &InitMerchantData,
                  state: &mut ChannelState, rc_c: &ChannelClosure_C, rv_token: &secp256k1::Signature)  -> Option<ChannelClosure_M> {
        let is_valid = clsigs::verifyD(&pp.cl_mpk, &T_c.pk, &rc_c.message.hash(), &rc_c.signature);
        if is_valid {
            let wpk = rc_c.message.wpk;
            let balance = rc_c.message.balance;
            if exist_in_merchant_state(&state, &wpk, Some(*rv_token)) {
                let mut s = secp256k1::Secp256k1::new();
                let ser_rv_token = rv_token.serialize_compact(&s);
                let rm = RevokedMessage::new(String::from("revoked"), wpk, Some(ser_rv_token));
                // sign the revoked message
                let signature = clsigs::signD(&pp.cl_mpk, &m_data.csk.sk, &rm.hash());
                return Some(ChannelClosure_M { message: rm, signature: signature });
            } else {
                // update state to include the user's wallet key
                assert!(update_merchant_state(state, &wpk, Some(*rv_token)));
                return None;
            }
        } else {
            panic!("Signature on customer closure message is invalid!");
        }
    }

    // on input the customer and merchant channel tokens T_c, T_m
    // along with closure messages rc_c, rc_m
    // this will be executed by the network --> using new opcodes (makes sure
    // only one person is right)
    pub fn resolve(pp: &PublicParams, c: &InitCustomerData, m: &InitMerchantData, // cust and merch
                   rc_c: Option<ChannelClosure_C>, rc_m: Option<ChannelClosure_M>,
                   rt_w: Option<clsigs::SignatureD>) -> (i32, i32) {
        let total_balance = c.csk.balance + m.csk.balance;
        if rc_c.is_none() && rc_m.is_none() {
            panic!("resolve - Did not specify channel closure messages for either customer or merchant!");
        }

        if rc_c.is_none() {
            // customer did not specify channel closure message
            return (0, total_balance);
        }

        // TODO: use matching instead
//        match rc_c.unwrap() {
//            Some(v) => foo,
//            _ => return (0, 0);
//        }

        let pk_c = &c.T.pk; // get public key for customer
        let pk_m = &m.T; // get public key for merchant

        let rc_cust = rc_c.unwrap();
        let rcc_valid = clsigs::verifyD(&pp.cl_mpk, &pk_c, &rc_cust.message.hash(), &rc_cust.signature);
        if !rcc_valid {
            panic!("resolve - rc_c signature is invalid!");
        }
        let msg = &rc_cust.message;
        let w_com = &c.T.w_com;

        if msg.msgtype == "refundUnsigned" {
            // assert the validity of the w_com
            let cm_csp = generate_commit_setup(&pp, &pk_m);

            let h_wpk = hashPubKeyToFr(&c.csk.wpk);
            // convert balance into Fr
            let balance = Fr::from_str(c.csk.balance.to_string().as_str()).unwrap();

            let mut x: Vec<Fr> = Vec::new();
            x.push(w_com.r); // Token if decommit is valid
            x.push(c.csk.cid);
            x.push(h_wpk);
            x.push(balance);

            // check that w_com is a valid commitment
            if !commit_scheme::decommit(&cm_csp, &w_com, &x) {
                // if this fails, then customer gets 0 and merchant gets full channel balance
                println!("resolve - failed verify commitment on wallet");
                return (0, total_balance);
            }
        } else if msg.msgtype == "refundToken" {
            // check that the refund token for specified wallet is valid
            let rt_valid = clsigs::verifyD(&pp.cl_mpk, &pk_c, &msg.hash(), &rt_w.unwrap());
            if !rt_valid {
                // refund token signature not valid, so pay full channel balance to merchant
                return (0, total_balance)
            }
        }

        if !rc_m.is_none() {
            let rc_merch = rc_m.unwrap();
            let refute_valid = clsigs::verifyD(&pp.cl_mpk, &pk_m, &rc_merch.message.hash(), &rc_merch.signature);
            if !refute_valid {
                // refutation is invalid, so return customer balance and merchant balance - claimed value
                let claimed_value = 0; // TODO: figure out where this value comes from
                return (c.csk.balance, m.csk.balance - claimed_value); // TODO: ensure merchant balance > 0
            } else {
                // if refutation is valid
                return (0, total_balance);
            }
        }

        panic!("resolve - Did not specify channel closure messages for either customer or merchant!");
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::{Rng, thread_rng};
    use test::{Bencher, black_box};

    #[bench]
    pub fn bench_one(bh: &mut Bencher) {
        println!("Hello World!");
    }
}
