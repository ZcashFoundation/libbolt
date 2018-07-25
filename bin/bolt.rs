extern crate bn;
extern crate rand;
extern crate rand_core;
extern crate libbolt;
extern crate bincode;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate time;
extern crate secp256k1;

use std::fmt;
use rand::{Rng, thread_rng};
use rand_core::RngCore;
use bn::{Group, Fr, G1, G2, pairing};
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};

use libbolt::prf;
use libbolt::sym;
use libbolt::ote;
use libbolt::clsigs;
use libbolt::commit_scheme;
use libbolt::bidirectional;
use time::PreciseTime;

macro_rules! measure {
    ($x: expr) => {
        {
            let s = PreciseTime::now();
            let res = $x;
            let e = PreciseTime::now();
            (res, s.to(e))
        };
    }
}


macro_rules! measure_ret_mut {
    ($x: expr) => {
        {
            let s = PreciseTime::now();
            let mut handle = $x;
            let e = PreciseTime::now();
            (handle, s.to(e))
        };
    }
}

fn main() {
    let rng = &mut rand::thread_rng();

    // Test the CL sigs
    // CL sig tests
    let mpk = clsigs::setupD();
    let l = 3;
    let c_keypair = clsigs::keygenD(&mpk, l);
    let m_keypair = clsigs::keygenD(&mpk, l);

    //println!("{}", keypair.pk);

    let mut m1 : Vec<Fr> = Vec::new();
    let mut m2 : Vec<Fr> = Vec::new();
    let mut m3 : Vec<Fr> = Vec::new();

    for i in 0 .. l+1 {
        m1.push(Fr::random(rng));
        m2.push(Fr::random(rng));
        m3.push(Fr::random(rng));
    }

    let signature = clsigs::signD(&mpk, &m_keypair.sk, &m1);
    //println!("{}", signature);

    println!("Checking CL sig verification...");

    let (res1, verify1) = measure!(clsigs::verifyD(&mpk, &m_keypair.pk, &m1, &signature));
    assert!(res1 == true);
    println!("{} seconds for verifying valid signatures.", verify1);

    let (res2, verify2) = measure!(clsigs::verifyD(&mpk, &m_keypair.pk, &m2, &signature));
    assert!(res2 == false);
    println!("{} seconds for verifying invalid signatures.", verify2);

    let (res3, verify3) = measure!(clsigs::verifyD(&mpk, &c_keypair.pk, &m1, &signature));
    assert!(res3 == false);
    println!("Invalid sig - verify time 3: {}", verify3);

    let (res4, verify4) = measure!(clsigs::verifyD(&mpk, &m_keypair.pk, &m3, &signature));
    assert!(res4 == false);
    println!("Invalid sig - verify time 4: {}", verify4);

//    let s1 = signature.hash("prefix type1");
//    let s2 = signature.hash("prefix type2");
//    let p1 = "Hash of signature 1: ";
//    libbolt::debug_elem_in_hex(p1, &s1);
//    let p2 = "Hash of signature 2: ";
//    libbolt::debug_elem_in_hex(p2, &s2);
//
//    let mut schnorr = secp256k1::Secp256k1::new();
//    schnorr.randomize(rng);
//    let (wsk, wpk) = schnorr.generate_keypair(rng).unwrap();
//
//    let balance = 100;
//    let r = Fr::random(rng);
//    let cid = Fr::random(rng);
//    let refund_message1 = libbolt::RefundMessage::new(String::from("refundUnsigned"), wpk, balance, Some(r), None);
//    let rm1 = refund_message1.hash();
//    println!("RefundMessage => {}", refund_message1.msgtype);
//    for i in 0 .. rm1.len() {
//        let p = format!("rm1[{}] = ", i);
//        libbolt::debug_elem_in_hex(&p, &rm1[i]);
//    }
//
//    let refund_message2 = libbolt::RefundMessage::new(String::from("refundToken"), wpk, balance+15, None, Some(signature));
//    let rm2 = refund_message2.hash();
//    println!("RefundMessage (token) => {}", refund_message2.msgtype);
//    for i in 0 .. rm2.len() {
//        let p = format!("rm2[{}] = ", i);
//        libbolt::debug_elem_in_hex(&p, &rm2[i]);
//    }



//        println!("******************************************");
//        let b = m_keypair.pk.Z2.len();
//        let mut bases: Vec<G2> = Vec::new();
//        bases.push(mpk.g2);
//        for i in 0 .. b {
//            bases.push(m_keypair.pk.Z2[i]);
//        }
//
//        // generate sample commitment
//        //let mut m: Vec<Fr> = Vec::new();
//        let mut C = mpk.g2 * m1[0];
//        for i in 0 .. b {
//            //println!("index: {}", i);
//            C = C + (m_keypair.pk.Z2[i] * m1[i+1]);
//        }
//        let msg = "Sample Commit output:";
//        libbolt::debug_g2_in_hex(msg, &C);
//
//        let cm_csp = commit_scheme::setup(b, m_keypair.pk.Z2.clone(), mpk.g2.clone());
//        let r = m1[0];
//        let w_com = commit_scheme::commit(&cm_csp, &m1, r);
//
//        assert!(commit_scheme::decommit(&cm_csp, &w_com, &m1));
//
//        //let msg = "Commmit Scheme output:";
//        //libbolt::debug_g2_in_hex(msg, &w_com.c);
//
//        //assert_eq!(C, w_com.c);
//        println!("Commitment scheme consistent!!");
//        let proof = clsigs::bs_gen_nizk_proof(&m1, &cm_csp.pub_bases, w_com.c);
//        // old -> let proof = clsigs::bs_gen_nizk_proof(&m1, &bases, C);
//
//        let int_sig = clsigs::bs_check_proof_and_gen_signature(&mpk, &m_keypair.sk, &proof);
//
//        println!("Generated signature interactively!");
//
//
//        let proof = clsigs::bs_gen_nizk_proof(&m1, &bases, C);
//
//        let int_sig = clsigs::bs_check_proof_and_gen_signature(&mpk, &m_keypair.sk, &proof);
//
//        println!("Generated signature interactively!");
//        // int_sig = interactively generated signature
//        assert!(clsigs::verifyD(&mpk, &m_keypair.pk, &m1, &int_sig) == true);
//
//        println!("Verified interactively produced signature!");
//
//        let blind_sigs = clsigs::prover_generate_blinded_sig(&int_sig);
//        let common_params1 = clsigs::gen_common_params(&mpk, &m_keypair.pk, &int_sig);
//        println!("Verified blind signature directly!");
//
//        let proof_vs = clsigs::vs_gen_nizk_proof(&m1, &common_params1, common_params1.vs);
//        assert!(clsigs::vs_verify_blind_sig(&mpk, &m_keypair.pk, &proof_vs, &blind_sigs));
//
//        println!("Verified blind signature (via NIZK)!");


    println!("******************************************");
// libbolt tests below

    //println!("[1a] libbolt - setup bidirecitonal scheme params");
    let (pp, setup_time1) = measure!(bidirectional::setup(false));

    //println!("[1b] libbolt - generate the initial channel state");
    let mut channel = bidirectional::init_channel(String::from("A -> B"));

    println!("Setup time: {}", setup_time1);

    //let msg = "Open Channel ID: ";
    //libbolt::debug_elem_in_hex(msg, &channel.cid);

    let b0_cust = 50;
    let b0_merch = 50;

    // generate long-lived keypair for merchant -- used to identify
    // it to all customers
    //println!("[2] libbolt - generate long-lived key pair for merchant");
    let (merch_keypair, keygen_time1) = measure!(bidirectional::keygen(&pp));

    // customer gnerates an ephemeral keypair for use on a single channel
    println!("[3] libbolt - generate ephemeral key pair for customer (use with one channel)");
    let (cust_keypair, keygen_time2) = measure!(bidirectional::keygen(&pp));

    // each party executes the init algorithm on the agreed initial challence balance
    // in order to derive the channel tokens
    println!("[5a] libbolt - initialize on the merchant side with balance {}", b0_merch);
    let (mut init_merch_data, initm_time) = measure_ret_mut!(bidirectional::init_merchant(&pp, b0_merch, &merch_keypair));
    println!(">> TIME for init_merchant: {}", initm_time);

    println!("[5b] libbolt - initialize on the customer side with balance {}", b0_cust);
    let cm_csp = bidirectional::generate_commit_setup(&pp, &merch_keypair.pk);
    let (mut init_cust_data, initc_time) = measure_ret_mut!(bidirectional::init_customer(&pp, &channel, b0_cust, b0_merch, &cm_csp, &cust_keypair));
    println!(">> TIME for init_customer: {}", initc_time);

    println!("[6a] libbolt - entering the establish protocol for the channel");
    let (proof1, est_cust_time1) = measure!(bidirectional::establish_customer_phase1(&pp, &init_cust_data, &init_merch_data));
    println!(">> TIME for establish_customer_phase1: {}", est_cust_time1);

    println!("[6b] libbolt - obtain the wallet signature from the merchant");
    let (wallet_sig, est_merch_time2) = measure!(bidirectional::establish_merchant_phase2(&pp, &mut channel, &init_merch_data, &proof1));
    println!(">> TIME for establish_merchant_phase2: {}", est_merch_time2);

    println!("[6c] libbolt - complete channel establishment");
    assert!(bidirectional::establish_customer_final(&pp, &merch_keypair.pk, &mut init_cust_data.csk, wallet_sig));

    assert!(channel.channel_established);

    println!("Channel has been established!");
    println!("******************************************");

    println!("******************************************");
    println!("Testing the pay protocol..");
    // let's test the pay protocol
    assert!(bidirectional::pay_by_customer_phase1_precompute(&pp, &init_cust_data.T, &merch_keypair.pk, &mut init_cust_data.csk));
    let s = PreciseTime::now();
    let (t_c, new_wallet, pay_proof) = bidirectional::pay_by_customer_phase1(&pp, &init_cust_data.T, // channel token
                                                                        &merch_keypair.pk, // merchant pub key
                                                                        &init_cust_data.csk, // wallet
                                                                        5); // balance increment
    let e = PreciseTime::now();
    println!(">> TIME for pay_by_customer_phase1: {}", s.to(e));

    // get the refund token (rt_w)
    let (rt_w, pay_merch_time1) = measure!(bidirectional::pay_by_merchant_phase1(&pp, &mut channel, &pay_proof, &init_merch_data));
    println!(">> TIME for pay_by_merchant_phase1: {}", pay_merch_time1);

    // get the revocation token (rv_w) on the old public key (wpk)
    let (rv_w, pay_cust_time2) = measure!(bidirectional::pay_by_customer_phase2(&pp, &init_cust_data.csk, &new_wallet, &merch_keypair.pk, &rt_w));
    println!(">> TIME for pay_by_customer_phase2: {}", pay_cust_time2);

    // get the new wallet sig (new_wallet_sig) on the new wallet
    let (new_wallet_sig, pay_merch_time2) = measure!(bidirectional::pay_by_merchant_phase2(&pp, &mut channel, &pay_proof, &mut init_merch_data, &rv_w));
    println!(">> TIME for pay_by_merchant_phase2: {}", pay_merch_time2);

    assert!(bidirectional::pay_by_customer_final(&pp, &merch_keypair.pk, &mut init_cust_data, t_c, new_wallet, new_wallet_sig));

    {
        // scope localizes the immutable borrow here (for debug purposes only)
        let cust_wallet = &init_cust_data.csk;
        let merch_wallet = &init_merch_data.csk;
        println!("Customer balance: {}", cust_wallet.balance);
        println!("Merchant balance: {}", merch_wallet.balance);
    }

    assert!(bidirectional::pay_by_customer_phase1_precompute(&pp, &init_cust_data.T, &merch_keypair.pk, &mut init_cust_data.csk));
    let (t_c1, new_wallet1, pay_proof1) = bidirectional::pay_by_customer_phase1(&pp, &init_cust_data.T, // channel token
                                                                        &merch_keypair.pk, // merchant pub key
                                                                        &init_cust_data.csk, // wallet
                                                                        10); // balance increment

    // get the refund token (rt_w)
    let rt_w1 = bidirectional::pay_by_merchant_phase1(&pp, &mut channel, &pay_proof1, &init_merch_data);

    // get the revocation token (rv_w) on the old public key (wpk)
    let rv_w1 = bidirectional::pay_by_customer_phase2(&pp, &init_cust_data.csk, &new_wallet1, &merch_keypair.pk, &rt_w1);

    // get the new wallet sig (new_wallet_sig) on the new wallet
    let new_wallet_sig1 = bidirectional::pay_by_merchant_phase2(&pp, &mut channel, &pay_proof1, &mut init_merch_data, &rv_w1);

    assert!(bidirectional::pay_by_customer_final(&pp, &merch_keypair.pk, &mut init_cust_data, t_c1, new_wallet1, new_wallet_sig1));

    {
        let cust_wallet = &init_cust_data.csk;
        let merch_wallet = &init_merch_data.csk;
        println!("Updated balances...");
        println!("Customer balance: {}", cust_wallet.balance);
        println!("Merchant balance: {}", merch_wallet.balance);
        let updated_cust_bal = b0_cust - 15;
        let updated_merch_bal = b0_merch + 15;
        assert_eq!(updated_cust_bal, cust_wallet.balance);
        assert_eq!(updated_merch_bal, merch_wallet.balance);
    }
    println!("Pay protocol complete!");

    println!("******************************************");
    println!("Testing the dispute algorithms...");

    {
        let cust_wallet = &init_cust_data.csk;
        // get channel closure message
        let rc_c = bidirectional::customer_refund(&pp, &channel, &merch_keypair.pk, &cust_wallet);
        println!("Obtained the channel closure message: {}", rc_c.message.msgtype);

        let channel_token = &init_cust_data.T;
        let rc_m = bidirectional::merchant_refute(&pp, &channel_token, &init_merch_data, &mut channel, &rc_c, &rv_w1.signature);
        println!("Merchant has refuted the refund request!");


        let (new_b0_cust, new_b0_merch) = bidirectional::resolve(&pp, &init_cust_data, &init_merch_data,
                                                                 Some(rc_c), rc_m, Some(rt_w1));
        println!("Resolved! Customer = {}, Merchant = {}", new_b0_cust, new_b0_merch);

    }
}
