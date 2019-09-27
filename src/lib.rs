//! This crate is an experimental implementation of Blind Off-chain
//! lightweight transactions (BOLT).
//!
//! It builds on academic work done by Ian Miers and Matthew Green -
//! https://eprint.iacr.org/2016/701.
//!
//! Libbolt relies on BLS12-381 curves at 128-bit security, as implemented in a fork of
//! [`pairing module`](https://github.com/boltlabs-inc/pairing).
//!
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused_parens)]
#![allow(non_upper_case_globals)]
#![allow(unused_results)]
#![allow(missing_docs)]
#![feature(exclusive_range_pattern)]

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))]
extern crate test;

extern crate ff;
extern crate pairing;
extern crate rand;
extern crate rand_core;

extern crate bincode;
extern crate sodiumoxide;
extern crate secp256k1;
extern crate time;
extern crate sha2;

extern crate serde;
extern crate serde_with;

extern crate libc;

#[cfg(test)]
extern crate rand_xorshift;
extern crate core;

pub mod sym;
pub mod cl;
pub mod ccs08;
pub mod ped92;
pub mod channels;
pub mod nizk;
pub mod util;
pub mod wallet;
pub mod ffishim;

use std::fmt;
use std::str;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use sodiumoxide::randombytes;
use sodiumoxide::crypto::hash::sha512;
use sha2::Sha512;
use std::collections::HashMap;
use ff::{Rand, Field};

use serde::{Serialize, Deserialize};
use serde::de::{Deserializer, Unexpected, Error};

////////////////////////////////// Utilities //////////////////////////////////

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

pub type BoltResult<T> = Result<Option<T>, String>;

#[macro_export]
macro_rules! handle_bolt_result {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(_) => None,
    });
}

////////////////////////////////// Utilities //////////////////////////////////

/////////////////////////////// Bidirectional ////////////////////////////////
pub mod bidirectional {
    use rand::Rng;
    use util;
    use wallet;
    use pairing::Engine;
    use sodiumoxide;
    use cl;
    // for blind signature
    use secp256k1;
    // for on-chain keys
    use HashMap;
    use sodiumoxide::crypto::hash::sha512;
    use sha2::Sha512;

    use serde::{Serialize, Deserialize};
    use util::{RevokedMessage, hash_to_slice};
    pub use ped92::Commitment;
    pub use cl::{PublicKey, Signature};
    pub use BoltResult;
    pub use channels::{ChannelState, ChannelToken, CustomerState, MerchantState, ChannelcloseM,
                       PubKeyMap, ChannelParams, BoltError, ResultBoltType};
    pub use nizk::NIZKProof;
    pub use wallet::Wallet;
    pub use cl::PublicParams;
    pub use ped92::CommitmentProof;

    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
    <E as pairing::Engine>::G1: serde::Serialize"))]
    #[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
    <E as pairing::Engine>::G1: serde::Deserialize<'de>"))]
    pub struct ChannelcloseC<E: Engine> {
        pub wpk: secp256k1::PublicKey,
        pub message: wallet::Wallet<E>,
        pub signature: cl::Signature<E>,
    }

    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
    <E as pairing::Engine>::G1: serde::Serialize, \
    <E as pairing::Engine>::G2: serde::Serialize, \
    <E as pairing::Engine>::Fqk: serde::Serialize"
    ))]
    #[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
    <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
    <E as pairing::Engine>::G2: serde::Deserialize<'de>,\
    <E as pairing::Engine>::Fqk: serde::Deserialize<'de>"
    ))]
    pub struct Payment<E: Engine> {
        proof: NIZKProof<E>,
        com: Commitment<E>,
        wpk: secp256k1::PublicKey,
        amount: i64,
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct RevokeToken {
        message: util::RevokedMessage,
        pub signature: secp256k1::Signature,
    }

    pub fn init() {
        sodiumoxide::init();
    }

    ///
    /// init_merchant - takes as input the public params, merchant balance and keypair.
    /// Generates merchant data which consists of channel token and merchant state.
    ///
    pub fn init_merchant<'a, R: Rng, E: Engine>(csprng: &mut R, channel_state: &mut ChannelState<E>, name: &'a str) -> (ChannelToken<E>, MerchantState<E>, ChannelState<E>) {
        // create new merchant state
        let merch_name = String::from(name);
        let (mut merch_state, mut channel_state) = MerchantState::<E>::new(csprng, channel_state, merch_name);
        // initialize the merchant state
        let channel_token = merch_state.init(csprng, &mut channel_state);

        return (channel_token, merch_state, channel_state.clone());
    }

    ///
    /// init_customer - takes as input the public params, channel state, commitment params, keypair,
    /// and initial balance for customer and merchant. Generate initial customer channel token,
    /// and wallet commitment.
    ///
    pub fn init_customer<'a, R: Rng, E: Engine>(csprng: &mut R, channel_token: &mut ChannelToken<E>,
                                                b0_cust: i64, b0_merch: i64, name: &'a str) -> CustomerState<E> {
        assert!(b0_cust >= 0);
        assert!(b0_merch >= 0);

        let cust_name = String::from(name);
        return CustomerState::<E>::new(csprng, channel_token, b0_cust, b0_merch, cust_name);
    }

    ///
    /// establish_customer_generate_proof (Phase 1) - takes as input the public params, customer state and
    /// common public bases from merchant. Generates a PoK of the committed values in the
    /// new wallet.
    ///
    pub fn establish_customer_generate_proof<R: Rng, E: Engine>(csprng: &mut R, channel_token: &ChannelToken<E>, cust_state: &CustomerState<E>) -> (Commitment<E>, CommitmentProof<E>) {
        let cust_com_proof = cust_state.generate_proof(csprng, channel_token);
        return (cust_state.w_com.clone(), cust_com_proof);
    }

    ///
    /// establish_merchant_issue_close_token (Phase 1) - takes as input the channel state,
    /// PoK of committed values from the customer. Generates close token (a blinded
    /// signature) over the contents of the customer's wallet.
    ///
    pub fn establish_merchant_issue_close_token<R: Rng, E: Engine>(csprng: &mut R, channel_state: &ChannelState<E>,
                                                                   com: &Commitment<E>, com_proof: &CommitmentProof<E>,
                                                                   pkc: &E::Fr, init_cust_balance: i64, init_merch_balance: i64,
                                                                   merch_state: &MerchantState<E>) -> BoltResult<cl::Signature<E>> {
        // verifies proof of committed values and derives blind signature on the committed values to the customer's initial wallet
        match merch_state.verify_proof(csprng, channel_state, com, com_proof, pkc, init_cust_balance, init_merch_balance) {
            Ok(n) => Ok(Some(n.0)), // just close token
            Err(err) => Err(String::from(err.to_string()))
        }
    }

    ///
    /// establish_merchant_issue_pay_token (Phase 1) - takes as input the channel state,
    /// the commitment from the customer. Generates close token (a blinded
    /// signature) over the contents of the customer's wallet.
    ///
    pub fn establish_merchant_issue_pay_token<R: Rng, E: Engine>(csprng: &mut R, channel_state: &ChannelState<E>,
                                                                 com: &Commitment<E>, merch_state: &MerchantState<E>) -> cl::Signature<E> {
        let cp = channel_state.cp.as_ref().unwrap();
        let pay_token = merch_state.issue_pay_token(csprng, cp, com, false);
        return pay_token;
    }

    ///
    /// establish_customer_final - takes as input the channel state, customer state,
    /// and pay token (blinded sig) obtained from merchant. Add the returned
    /// blinded signature to the wallet.
    ///
    pub fn establish_customer_final<E: Engine>(channel_state: &mut ChannelState<E>, cust_state: &mut CustomerState<E>, pay_token: &cl::Signature<E>) -> bool {
        // verify the pay-token first
        if !cust_state.verify_pay_token(&channel_state, pay_token) {
            println!("establish_customer_final - Failed to verify the pay-token");
            return false;
        }

        // only if both tokens have been stored
        if (cust_state.has_tokens()) {
            // must be an old wallet
            channel_state.channel_established = true;
        }
        return channel_state.channel_established;
    }
    ///// end of establish channel protocol


    ///
    /// generate_payment_proof (phase 1) - takes as input the public params, channel state, channel token,
    /// merchant public keys, old wallet and balance increment. Generate a new wallet commitment
    /// PoK of the committed values in new wallet and PoK of old wallet. Return new channel token,
    /// new wallet (minus blind signature and refund token) and payment proof.
    ///
    pub fn generate_payment_proof<R: Rng, E: Engine>(csprng: &mut R, channel_state: &ChannelState<E>, cust_state: &CustomerState<E>, amount: i64) -> (Payment<E>, CustomerState<E>) {
        let tx_fee = channel_state.get_channel_fee();
        let payment_amount = match tx_fee > 0 {
            true => amount + tx_fee,
            false => amount
        };
        let (proof, com, wpk, new_cust_state) = cust_state.generate_payment(csprng, &channel_state, payment_amount);
        let payment = Payment { proof, com, wpk, amount };
        return (payment, new_cust_state);
    }

    ///
    /// verify_payment (phase 1) - takes as input the public params, channel state, payment proof
    /// and merchant keys. If proof is valid, then merchant returns the refund token
    /// (i.e., partially blind signature on IOU with updated balance)
    ///
    pub fn verify_payment_proof<R: Rng, E: Engine>(csprng: &mut R, channel_state: &ChannelState<E>,
                                                   payment: &Payment<E>, merch_state: &mut MerchantState<E>) -> cl::Signature<E> {
        // if payment proof verifies, then returns close-token and records wpk => pay-token
        // if valid revoke_token is provided later for wpk, then release pay-token
        let tx_fee = channel_state.get_channel_fee();
        let payment_amount = match tx_fee > 0 {
            true => payment.amount + tx_fee,
            false => payment.amount
        };
        let new_close_token = merch_state.verify_payment(csprng, &channel_state,
                                                         &payment.proof, &payment.com, &payment.wpk, payment_amount).unwrap();
        // store the wpk since it has been revealed
        update_merchant_state(&mut merch_state.keys, &payment.wpk, None);
        return new_close_token;
    }

    ///
    /// Verify third party payment proof from two bi-directional channel payments with intermediary
    ///
//    pub fn verify_third_party_payment(pp: &PublicParams, fee: i64, proof1: &BalanceProof, proof2: &BalanceProof) -> bool {
//        if proof1.third_party && proof2.third_party {
//            let vcom1 = &proof1.proof_vcom.as_ref().unwrap();
//            let vcom2 = &proof2.proof_vcom.as_ref().unwrap();
//            let rproof1 = &proof1.proof_vrange.as_ref().unwrap();
//            let rproof2 = &proof2.proof_vrange.as_ref().unwrap();
//            let pc_gens1 = PedersenGens::default();
//            let pc_gens2 = PedersenGens::default();
//            let mut transcript1 = Transcript::new(b"Range Proof for Balance Increment");
//            let range_proof1_valid = rproof1.range_proof.0.verify_single(&pp.bp_gens, &pc_gens1,
//                                                                  &mut transcript1,
//                                                                  &rproof1.range_proof.1,
//                                                                  pp.range_proof_bits).is_ok();
//
//            let mut transcript2 = Transcript::new(b"Range Proof for Balance Increment");
//            let range_proof2_valid = rproof2.range_proof.0.verify_single(&pp.bp_gens, &pc_gens2,
//                                                                 &mut transcript2,
//                                                                 &rproof2.range_proof.1,
//                                                                 pp.range_proof_bits).is_ok();
//
//            let len = vcom1.pub_bases.len();
//            assert!(len >= 2 && vcom1.pub_bases.len() == vcom2.pub_bases.len());
//
//            // g^(e1 + -e2 + fee) * h^(r1 + r2) ==> should be equal to g^(fee) * h^(r1 + r2)
//            // lets add commitments for vcom1 and vcom2 to check
//            let added_commits = vcom1.C + vcom2.C;
//            let tx_fee = vcom1.pub_bases[1] * -convert_int_to_fr(fee);
//            // compute h^r1 + r2
//            let h_r1_r2 = (vcom1.pub_bases[0] * proof1.vcom.unwrap().r) +
//                (vcom2.pub_bases[0] * proof2.vcom.unwrap().r) + tx_fee;
//
//            let is_pay_plus_fee = added_commits == h_r1_r2;
//            return clproto::bs_verify_nizk_proof(&vcom1) &&
//                clproto::bs_verify_nizk_proof(&vcom2) &&
//                range_proof1_valid && range_proof2_valid &&
//                is_pay_plus_fee;
//        }
//        panic!("verify_third_party_payment - third-party payment not enabled for both proofs");
//    }


    ///
    /// generate_revoke_token (phase 2) - takes as input the public params, old wallet, new wallet,
    /// merchant's verification key and refund token. If the refund token is valid, generate
    /// a revocation token for the old wallet public key.
    ///
    pub fn generate_revoke_token<E: Engine>(channel_state: &ChannelState<E>,
                                            old_cust_state: &mut CustomerState<E>,
                                            new_cust_state: CustomerState<E>,
                                            new_close_token: &cl::Signature<E>) -> RevokeToken {
        // let's update the old wallet
        assert!(old_cust_state.update(new_cust_state));
        // generate the token after verifying that the close token is valid
        let (message, signature) = old_cust_state.generate_revoke_token(channel_state, new_close_token).unwrap();
        // return the revoke token (msg + sig pair)
        return RevokeToken { message, signature };
    }

    ///
    /// verify_revoke_token (phase 2) - takes as input revoke message and signature,
    /// merchant state, from the customer. If the revocation token is valid,
    /// generate a new signature for the new wallet (from the PoK of committed values in new wallet).
    ///
    pub fn verify_revoke_token<E: Engine>(rt: &RevokeToken, merch_state: &mut MerchantState<E>) -> BoltResult<cl::Signature<E>> {
        let pay_token_result = merch_state.verify_revoke_token(&rt.signature, &rt.message, &rt.message.wpk);
        let new_pay_token = match pay_token_result {
            Ok(n) => n,
            Err(err) => return Err(String::from(err.to_string()))
        };
        update_merchant_state(&mut merch_state.keys, &rt.message.wpk, Some(rt.signature.clone()));
        Ok(Some(new_pay_token))
    }

    ///// end of pay protocol

    // for customer => on input a wallet w, it outputs a customer channel closure message
    ///
    /// customer_close - takes as input the channel state, merchant's verification
    /// key, and customer state. Generates a channel closure message for customer.
    ///
    pub fn customer_close<E: Engine>(channel_state: &ChannelState<E>, cust_state: &CustomerState<E>) -> ChannelcloseC<E> {
        if !channel_state.channel_established {
            panic!("Cannot close a channel that has not been established!");
        }

        let mut wallet = cust_state.get_wallet();
        let close_token = cust_state.get_close_token();

        let cp = channel_state.cp.as_ref().unwrap();
        let pk = cp.pub_params.pk.get_pub_key();
        let close_wallet = wallet.with_close(String::from("close"));

        assert!(pk.verify(&cp.pub_params.mpk, &close_wallet, &close_token));
        ChannelcloseC { wpk: cust_state.wpk, message: wallet, signature: close_token }
    }

    fn update_merchant_state(db: &mut HashMap<String, PubKeyMap>, wpk: &secp256k1::PublicKey, rev: Option<secp256k1::Signature>) {
        let fingerprint = util::compute_pub_key_fingerprint(wpk);
        //println!("Print fingerprint: {}", fingerprint);
        if !rev.is_none() {
            let cust_pub_key = PubKeyMap { wpk: wpk.clone(), revoke_token: Some(rev.unwrap().clone()) };
            db.insert(fingerprint, cust_pub_key);
        } else {
            let cust_pub_key = PubKeyMap { wpk: wpk.clone(), revoke_token: None };
            db.insert(fingerprint, cust_pub_key);
        }
    }

    ///
    /// merchant_close - takes as input the channel state, channel token, customer close msg/sig,
    /// Returns tokens for merchant close transaction (only if customer close message is found to be a
    /// double spend). If not, then None is returned.
    ///
    pub fn merchant_close<E: Engine>(channel_state: &ChannelState<E>,
                                     channel_token: &ChannelToken<E>,
                                     cust_close: &ChannelcloseC<E>,
                                     merch_state: &MerchantState<E>) -> BoltResult<PubKeyMap> {
        if (!channel_state.channel_established) {
            return Err(String::from("merchant_close - Channel not established! Cannot generate channel closure message."));
        }

        let cp = channel_state.cp.as_ref().unwrap();
        let pk = cp.pub_params.pk.get_pub_key();
        let mut wallet = cust_close.message.clone();
        let close_wallet = wallet.with_close(String::from("close")).clone();
        let close_token = cust_close.signature.clone();

        let is_valid = pk.verify(&channel_token.mpk, &close_wallet, &close_token);

        if is_valid {
            let wpk = cust_close.wpk;
            // found the wpk, which means old close token
            let fingerprint = util::compute_pub_key_fingerprint(&wpk);
            if merch_state.keys.contains_key(&fingerprint) {
                let revoked_state = merch_state.keys.get(&fingerprint).unwrap();
                if !revoked_state.revoke_token.is_none() {
                    let revoke_token = revoked_state.revoke_token.unwrap().clone();
                    // verify the revoked state first before returning
                    let secp = secp256k1::Secp256k1::new();
                    let revoke_msg = RevokedMessage::new(String::from("revoked"), wpk.clone());
                    let msg = secp256k1::Message::from_slice(&revoke_msg.hash_to_slice()).unwrap();
                    // verify that the revocation token is valid
                    if secp.verify(&msg, &revoke_token, &wpk).is_ok() {
                        // compute signature on
                        return Ok(Some(revoked_state.clone()));
                    }
                }
                return Err(String::from("merchant_close - Found wpk but could not find the revoke token. Merchant abort detected."));
            }
            return Err(String::from("merchant_close - Could not find entry for wpk & revoke token pair. Valid close!"));
        }
        Err(String::from("merchant_close - Customer close message not valid!"))
    }

    ///
    /// Used in open-channel WTP for validating that a close_token is a valid signature under <
    ///
    pub fn wtp_verify_cust_close_message<E: Engine>(channel_token: &ChannelToken<E>, wpk: &secp256k1::PublicKey, close_msg: &wallet::Wallet<E>, close_token: &Signature<E>) -> bool {
        // close_msg => <pkc> || <wpk> || <balance-cust> || <balance-merch> || CLOSE
        // close_token = regular CL signature on close_msg
        // channel_token => <pk_c, CL_PK_m, pk_m, mpk, comParams>

        // (1) check that channel token and close msg are consistent (e.g., close_msg.pk_c == H(channel_token.pk_c) &&
        let pk_c = channel_token.pk_c.unwrap();
        let chan_token_pk_c = util::hash_pubkey_to_fr::<E>(&pk_c);
        let chan_token_wpk = util::hash_pubkey_to_fr::<E>(&wpk);

        let pkc_thesame = (close_msg.pkc == chan_token_pk_c);
        // (2) check that wpk matches what's in the close msg
        let wpk_thesame = (close_msg.wpk == chan_token_wpk);
        return pkc_thesame && wpk_thesame && channel_token.cl_pk_m.verify(&channel_token.mpk, &close_msg.as_fr_vec(), &close_token);
    }

    ///
    /// Used in merch-close WTP for validating that revoke_token is a valid signature under <wpk> and the <revoked || wpk> message
    ///
    pub fn wtp_verify_revoke_message(wpk: &secp256k1::PublicKey, revoke_token: &secp256k1::Signature) -> bool {
        let secp = secp256k1::Secp256k1::verification_only();
        let revoke_msg = RevokedMessage::new(String::from("revoked"), wpk.clone());
        let msg = secp256k1::Message::from_slice(&revoke_msg.hash_to_slice()).unwrap();
        // verify that the revocation token is valid with respect to revoked || wpk
        return secp.verify(&msg, &revoke_token, &wpk).is_ok();
    }

    ///
    /// Used in merch-close WTP for validating that merch_sig is a valid signature under <merch_pk> on <dest_addr || revoke-token> message
    ///
    pub fn wtp_verify_merch_close_message<E: Engine>(channel_token: &ChannelToken<E>, merch_close: &ChannelcloseM) -> bool {
        let secp = secp256k1::Secp256k1::verification_only();
        let mut msg = Vec::new();
        msg.extend(merch_close.address.as_bytes());
        if !merch_close.revoke.is_none() {
            // serialize signature in DER format
            let r = merch_close.revoke.unwrap().serialize_der().to_vec();
            msg.extend(r);
        }
        let msg2 = secp256k1::Message::from_slice(&hash_to_slice(&msg)).unwrap();
        // verify that merch sig is valid with respect to dest_address
        return secp.verify(&msg2, &merch_close.signature, &channel_token.pk_m).is_ok();
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::{Rng, thread_rng};
    use test::{Bencher, black_box};

    #[bench]
    pub fn bench_one(bh: &mut Bencher) {
        println!("Run benchmark tests here!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Rand;
    use pairing::bls12_381::Bls12;
    use rand::Rng;
    use channels::ChannelState;
    use util::hash_pubkey_to_fr;

    fn setup_new_channel_helper(channel_state: &mut bidirectional::ChannelState<Bls12>,
                                init_cust_bal: i64, init_merch_bal: i64)
                                -> (bidirectional::ChannelToken<Bls12>, bidirectional::MerchantState<Bls12>, bidirectional::CustomerState<Bls12>, bidirectional::ChannelState<Bls12>) {
        let mut rng = &mut rand::thread_rng();
        let merch_name = "Bob";
        let cust_name = "Alice";

        let b0_cust = init_cust_bal;
        let b0_merch = init_merch_bal;

        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let (mut channel_token, mut merch_state, mut channel_state) = bidirectional::init_merchant(rng, channel_state, merch_name);

        // initialize on the customer side with balance: b0_cust
        let cust_state = bidirectional::init_customer(rng, &mut channel_token, b0_cust, b0_merch, cust_name);

        return (channel_token, merch_state, cust_state, channel_state);
    }

    fn execute_establish_protocol_helper(channel_state: &mut bidirectional::ChannelState<Bls12>,
                                         channel_token: &mut bidirectional::ChannelToken<Bls12>,
                                         cust_balance: i64,
                                         merch_balance: i64,
                                         merch_state: &mut bidirectional::MerchantState<Bls12>,
                                         cust_state: &mut bidirectional::CustomerState<Bls12>) {
        let mut rng = &mut rand::thread_rng();

        // lets establish the channel
        let (com, com_proof) = bidirectional::establish_customer_generate_proof(rng, channel_token, cust_state);

        // obtain close token for closing out channel
        //let pk_h = hash_pubkey_to_fr::<Bls12>(&cust_state.pk_c.clone());
        let pk_c = cust_state.get_public_key();
        let option = bidirectional::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof, &pk_c,
                                                                                            cust_balance, merch_balance, &merch_state);
        let close_token = match option {
            Ok(n) => n.unwrap(),
            Err(e) => panic!("Failed - bidirectional::establish_merchant_issue_close_token(): {}", e)
        };
        assert!(cust_state.verify_close_token(&channel_state, &close_token));

        // wait for funding tx to be confirmed, etc

        // obtain payment token for pay protocol
        let pay_token = bidirectional::establish_merchant_issue_pay_token(rng, &channel_state, &com, &merch_state);
        //assert!(cust_state.verify_pay_token(&channel_state, &pay_token));

        assert!(bidirectional::establish_customer_final(channel_state, cust_state, &pay_token));
        println!("Channel established!");
    }

    fn execute_payment_protocol_helper(channel_state: &mut bidirectional::ChannelState<Bls12>,
                                       channel_token: &mut bidirectional::ChannelToken<Bls12>,
                                       merch_state: &mut bidirectional::MerchantState<Bls12>,
                                       cust_state: &mut bidirectional::CustomerState<Bls12>,
                                       payment_increment: i64) {
        let mut rng = &mut rand::thread_rng();

        let (payment, new_cust_state) = bidirectional::generate_payment_proof(rng, channel_state, &cust_state, payment_increment);

        let new_close_token = bidirectional::verify_payment_proof(rng, &channel_state, &payment, merch_state);

        let revoke_token = bidirectional::generate_revoke_token(&channel_state, cust_state, new_cust_state, &new_close_token);

        // send revoke token and get pay-token in response
        let new_pay_token_result: BoltResult<cl::Signature<Bls12>> = bidirectional::verify_revoke_token(&revoke_token, merch_state);
        let new_pay_token = handle_bolt_result!(new_pay_token_result);

        // verify the pay token and update internal state
        assert!(cust_state.verify_pay_token(&channel_state, &new_pay_token.unwrap()));
    }

    #[test]
    fn bidirectional_payment_basics_work() {
        // just bidirectional case (w/o third party)
        let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
        let mut rng = &mut rand::thread_rng();

        let total_owed = 40;
        let b0_customer = 90;
        let b0_merchant = 20;
        let payment_increment = 20;

        let (mut channel_token, mut merch_state, mut channel_state) = bidirectional::init_merchant(rng, &mut channel_state, "Merchant Bob");

        let mut cust_state = bidirectional::init_customer(rng, &mut channel_token, b0_customer, b0_merchant, "Alice");

        println!("{}", cust_state);

        // lets establish the channel
        let (com, com_proof) = bidirectional::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_state);

        // obtain close token for closing out channel
        let pk_h = hash_pubkey_to_fr::<Bls12>(&cust_state.pk_c.clone());
        let option = bidirectional::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof, &pk_h,
                                                                         b0_customer, b0_merchant, &merch_state);
        let close_token = match option {
            Ok(n) => n.unwrap(),
            Err(e) => panic!("Failed - bidirectional::establish_merchant_issue_close_token(): {}", e)
        };
        assert!(cust_state.verify_close_token(&channel_state, &close_token));

        // wait for funding tx to be confirmed, etc

        // obtain payment token for pay protocol
        let pay_token = bidirectional::establish_merchant_issue_pay_token(rng, &channel_state, &com, &merch_state);
        //assert!(cust_state.verify_pay_token(&channel_state, &pay_token));

        assert!(bidirectional::establish_customer_final(&mut channel_state, &mut cust_state, &pay_token));
        println!("Channel established!");

        let (payment, new_cust_state) = bidirectional::generate_payment_proof(rng, &channel_state, &cust_state, 10);

        let new_close_token = bidirectional::verify_payment_proof(rng, &channel_state, &payment, &mut merch_state);

        let revoke_token = bidirectional::generate_revoke_token(&channel_state, &mut cust_state, new_cust_state, &new_close_token);

        // send revoke token and get pay-token in response
        let new_pay_token_result: BoltResult<cl::Signature<Bls12>> = bidirectional::verify_revoke_token(&revoke_token, &mut merch_state);
        let new_pay_token = handle_bolt_result!(new_pay_token_result);

        // verify the pay token and update internal state
        assert!(cust_state.verify_pay_token(&channel_state, &new_pay_token.unwrap()));

        println!("Successful payment!");

        let cust_close = bidirectional::customer_close(&channel_state, &cust_state);
        println!("Obtained the channel close message");
        println!("{}", cust_close.message);
        println!("{}", cust_close.signature);
    }

    #[test]
    fn bidirectional_multiple_payments_work() {
        let total_owed = 40;
        let b0_customer = 380;
        let b0_merchant = 20;
        let payment_increment = 20;

        let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
        let mut rng = &mut rand::thread_rng();

        // set fee for channel
        let fee = 5;
        channel_state.set_channel_fee(fee);

        let (mut channel_token, mut merch_state, mut cust_state, mut channel_state) = setup_new_channel_helper(&mut channel_state, b0_customer, b0_merchant);

        // run establish protocol for customer and merchant channel
        execute_establish_protocol_helper(&mut channel_state, &mut channel_token, b0_customer, b0_merchant, &mut merch_state, &mut cust_state);

        assert!(channel_state.channel_established);

        {
            // make multiple payments in a loop
            let num_payments = total_owed / payment_increment;
            for i in 0..num_payments {
                execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, payment_increment);
            }

            {
                // scope localizes the immutable borrow here (for debug purposes only)
                println!("Customer balance: {:?}", &cust_state.cust_balance);
                println!("Merchant balance: {:?}", &cust_state.merch_balance);
                let total_owed_with_fees = (fee * num_payments) + total_owed;
                assert!(cust_state.cust_balance == (b0_customer - total_owed_with_fees) && cust_state.merch_balance == total_owed_with_fees + b0_merchant);
            }

            let cust_close_msg = bidirectional::customer_close(&channel_state, &cust_state);
            println!("Obtained the channel close message");
            println!("{}", cust_close_msg.message);
            println!("{}", cust_close_msg.signature);
        }
    }

    #[test]
    fn bidirectional_payment_negative_payment_works() {
        // just bidirectional case (w/o third party)
        let total_owed = -20;
        let b0_customer = 90;
        let b0_merchant = 30;
        let payment_increment = -20;

        let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
        let mut rng = &mut rand::thread_rng();

        let (mut channel_token, mut merch_state, mut cust_state, mut channel_state) = setup_new_channel_helper(&mut channel_state, b0_customer, b0_merchant);

        // run establish protocol for customer and merchant channel
        execute_establish_protocol_helper(&mut channel_state, &mut channel_token, b0_customer, b0_merchant, &mut merch_state, &mut cust_state);
        assert!(channel_state.channel_established);

        {
            execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, payment_increment);

            {
                // scope localizes the immutable borrow here (for debug purposes only)
                println!("Customer balance: {:?}", &cust_state.cust_balance);
                println!("Merchant balance: {:?}", &cust_state.merch_balance);
                assert!(cust_state.cust_balance == (b0_customer - total_owed) && cust_state.merch_balance == total_owed + b0_merchant);
            }
        }
    }

    #[test]
    fn bidirectional_merchant_close_detects_double_spends() {
        let mut rng = &mut rand::thread_rng();

        let b0_customer = rng.gen_range(100, 1000);
        let b0_merchant = 10;
        let pay_increment = 20;

        let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);

        let (mut channel_token, mut merch_state, mut cust_state, mut channel_state) = setup_new_channel_helper(&mut channel_state, b0_customer, b0_merchant);

        // run establish protocol for customer and merchant channel
        execute_establish_protocol_helper(&mut channel_state, &mut channel_token, b0_customer, b0_merchant, &mut merch_state, &mut cust_state);

        assert!(channel_state.channel_established);

        // let's make a few payments then exit channel (will post an old channel state
        execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, pay_increment);

        execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, pay_increment);

        // let's close then move state forward
        let old_cust_close_msg = bidirectional::customer_close(&channel_state, &cust_state);

        execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, pay_increment);

        execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, pay_increment);
        let cur_cust_close_msg = bidirectional::customer_close(&channel_state, &cust_state);

        let merch_close_result = bidirectional::merchant_close(&channel_state,
                                                               &channel_token,
                                                               &old_cust_close_msg,
                                                               &merch_state);
        let merch_close_msg = match merch_close_result {
            Ok(n) => n.unwrap(),
            Err(err) => panic!("Merchant close msg: {}", err)
        };

        println!("Double spend attempt by customer! Evidence below...");
        println!("Merchant close: wpk = {}", merch_close_msg.wpk);
        println!("Merchant close: revoke_token = {}", merch_close_msg.revoke_token.unwrap());
    }

    #[test]
    #[should_panic]
    fn bidirectional_merchant_close_works() {
        let mut rng = &mut rand::thread_rng();

        let b0_customer = rng.gen_range(100, 1000);
        let b0_merchant = 10;
        let pay_increment = 20;

        let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);

        let (mut channel_token, mut merch_state, mut cust_state, mut channel_state) = setup_new_channel_helper(&mut channel_state, b0_customer, b0_merchant);

        // run establish protocol for customer and merchant channel
        execute_establish_protocol_helper(&mut channel_state, &mut channel_token, b0_customer, b0_merchant, &mut merch_state, &mut cust_state);

        assert!(channel_state.channel_established);

        // let's make a few payments then exit channel (will post an old channel state
        execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, pay_increment);

        execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, pay_increment);

        execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, pay_increment);

        execute_payment_protocol_helper(&mut channel_state, &mut channel_token, &mut merch_state, &mut cust_state, pay_increment);

        let cust_close_msg = bidirectional::customer_close(&channel_state, &cust_state);

        let merch_close_result = bidirectional::merchant_close(&channel_state,
                                                               &channel_token,
                                                               &cust_close_msg,
                                                               &merch_state);
        let merch_close_msg = match merch_close_result {
            Ok(n) => n.unwrap(),
            Err(err) => panic!("Merchant close msg: {}", err)
        };
    }


//    fn execute_third_party_pay_protocol_helper(pp: &bidirectional::PublicParams,
//                                   channel1: &mut bidirectional::ChannelState, channel2: &mut bidirectional::ChannelState,
//                                   merch_keys: &cl::KeyPairD, merch1_data: &mut bidirectional::InitMerchantData,
//                                   merch2_data: &mut bidirectional::InitMerchantData,
//                                   cust1_keys: &cl::KeyPairD, cust1_data: &mut bidirectional::InitCustomerData,
//                                   cust2_keys: &cl::KeyPairD, cust2_data: &mut bidirectional::InitCustomerData,
//                                   payment_increment: i64) {
//        // let's test the pay protocol
//        bidirectional::pay_by_customer_phase1_precompute(&pp, &cust1_data.channel_token, &merch_keys.pk, &mut cust1_data.csk);
//        bidirectional::pay_by_customer_phase1_precompute(&pp, &cust2_data.channel_token, &merch_keys.pk, &mut cust2_data.csk);
//
//        println!("Channel 1 fee: {}", channel1.get_channel_fee());
//        let (t_c1, new_wallet1, pay_proof1) = bidirectional::pay_by_customer_phase1(&pp, &channel1,
//                                                                            &cust1_data.channel_token, // channel token
//                                                                            &merch_keys.pk, // merchant pub key
//                                                                            &cust1_data.csk, // wallet
//                                                                            payment_increment); // balance increment
//        println!("Channel 2 fee: {}", channel2.get_channel_fee());
//        let (t_c2, new_wallet2, pay_proof2) = bidirectional::pay_by_customer_phase1(&pp, &channel2,
//                                                                    &cust2_data.channel_token, // channel token
//                                                                    &merch_keys.pk, // merchant pub key
//                                                                    &cust2_data.csk, // wallet
//                                                                    -payment_increment); // balance decrement
//
//        // validate pay_proof1 and pay_proof2 (and the channel state for the fee paying channel, if fee > 0)
//        let tx_fee = channel1.get_channel_fee() + channel2.get_channel_fee();
//        assert!(bidirectional::verify_third_party_payment(&pp, tx_fee, &pay_proof1.bal_proof, &pay_proof2.bal_proof));
//
//        // get the refund token (rt_w)
//        let rt_w1 = bidirectional::pay_by_merchant_phase1(&pp, channel1, &pay_proof1, &merch1_data);
//
//        // get the refund token (rt_w)
//        let rt_w2 = bidirectional::pay_by_merchant_phase1(&pp, channel2, &pay_proof2, &merch2_data);
//
//        // get the revocation token (rv_w) on the old public key (wpk)
//        let rv_w1 = bidirectional::pay_by_customer_phase2(&pp, &cust1_data.csk, &new_wallet1, &merch_keys.pk, &rt_w1);
//
//        // get the revocation token (rv_w) on the old public key (wpk)
//        let rv_w2 = bidirectional::pay_by_customer_phase2(&pp, &cust2_data.csk, &new_wallet2, &merch_keys.pk, &rt_w2);
//
//        // get the new wallet sig (new_wallet_sig) on the new wallet
//        let new_wallet_sig1 = bidirectional::pay_by_merchant_phase2(&pp, channel1, &pay_proof1, merch1_data, &rv_w1);
//
//        // get the new wallet sig (new_wallet_sig) on the new wallet
//        let new_wallet_sig2 = bidirectional::pay_by_merchant_phase2(&pp, channel2, &pay_proof2, merch2_data, &rv_w2);
//
//        assert!(bidirectional::pay_by_customer_final(&pp, &merch_keys.pk, cust1_data, t_c1, new_wallet1, rt_w1, new_wallet_sig1));
//
//        assert!(bidirectional::pay_by_customer_final(&pp, &merch_keys.pk, cust2_data, t_c2, new_wallet2, rt_w2, new_wallet_sig2));
//    }
//
//    #[test]
//    #[ignore]
//    fn third_party_payment_basics_work() {
//        let pp = bidirectional::setup(true);
//
//        // third party -- so indicate so in the channel state
//        let mut channel_a = bidirectional::ChannelState::new(String::from("Channel A <-> I"), true);
//        let mut channel_b = bidirectional::ChannelState::new(String::from("Channel B <-> I"), true);
//
//        let fee = 2;
//        channel_a.set_channel_fee(fee);
//
//        let total_payment = 20;
//        let b0_alice = 30;
//        let b0_bob = 30;
//        let b0_merchant_a = 40;
//        let b0_merchant_b = 40;
//
//        let (merch_keys, mut merch_data_a, alice_keys, mut alice_data) = setup_new_channel_helper(&pp, &mut channel_a, b0_alice, b0_merchant_a);
//
//        let (mut merch_data_b, bob_keys, mut bob_data) =
//            setup_new_channel_existing_merchant_helper(&pp, &mut channel_b, b0_bob, b0_merchant_b, &merch_keys);
//
//        // run establish protocol for alice and merchant channel
//        execute_establish_protocol_helper(&pp, &mut channel_a, &merch_keys, &mut merch_data_a, &alice_keys, &mut alice_data);
//
//        // run establish protocol for bob and merchant channel
//        execute_establish_protocol_helper(&pp, &mut channel_b, &merch_keys, &mut merch_data_b, &bob_keys, &mut bob_data);
//
//        assert!(channel_a.channel_established);
//        assert!(channel_b.channel_established);
//
//        // alice can pay bob through the merchant
//        execute_third_party_pay_protocol_helper(&pp, &mut channel_a, &mut channel_b,
//                                                &merch_keys, &mut merch_data_a, &mut merch_data_b,
//                                                &alice_keys, &mut alice_data, &bob_keys, &mut bob_data, total_payment);
//
//        println!("Customer alice balance: {}", alice_data.csk.balance);
//        println!("Merchant channel balance with alice: {}", merch_data_a.csk.balance);
//        println!("Customer bob balance: {}", bob_data.csk.balance);
//        println!("Merchant channel balance with bob: {}", merch_data_b.csk.balance);
//    }

    #[test]
    fn serialization_tests() {
        let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
        let mut rng = &mut rand::thread_rng();

        let serialized = serde_json::to_string(&channel_state).unwrap();
        println!("new channel state len: {}", &serialized.len());

        let chan_state: bidirectional::ChannelState<Bls12> = serde_json::from_str(&serialized).unwrap();

        let (mut channel_token, mut merch_state, mut channel_state) = bidirectional::init_merchant(rng, &mut channel_state, "Merchant A");

        let b0_cust = 100;
        let b0_merch = 10;
        let cust_state = bidirectional::init_customer(rng, &mut channel_token, b0_cust, b0_merch, "Customer A");

        let serlalized_ct = serde_json::to_string(&channel_token).unwrap();

        println!("serialized ct: {:?}", &serlalized_ct);

        let des_ct: bidirectional::ChannelToken<Bls12> = serde_json::from_str(&serlalized_ct).unwrap();

        //println!("des_ct: {}", &des_ct);

        let serlalized_cw = serde_json::to_string(&cust_state).unwrap();

        println!("serialized cw: {:?}", &serlalized_cw);

        let des_cw: bidirectional::CustomerState<Bls12> = serde_json::from_str(&serlalized_cw).unwrap();
    }
}
