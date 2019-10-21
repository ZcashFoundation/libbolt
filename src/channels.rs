/*
 * Implement for Bolt protocols:
 * - initializing channel state and generating cust/merch wallets
 * - establish protocol
 * - pay protocol
 * - channel close algorithms (WIP)
 */

extern crate pairing;
extern crate rand;

use super::*;
use pairing::Engine;
use cl::{BlindKeyPair, Signature};
use ped92::{Commitment, CSMultiParams, CommitmentProof};
use util::{hash_pubkey_to_fr, hash_to_fr, RevokedMessage, hash_to_slice};
use rand::Rng;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use nizk::{NIZKPublicParams, NIZKSecretParams, NIZKProof};
use wallet::Wallet;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct BoltError {
    details: String
}
pub type ResultBoltType<E> = Result<E, BoltError>;

impl BoltError {
    fn new(msg: &str) -> BoltError {
        BoltError { details: msg.to_string() }
    }
}

impl fmt::Display for BoltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for BoltError {
    fn description(&self) -> &str {
        &self.details
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct PubKeyMap {
    pub wpk: secp256k1::PublicKey,
    pub revoke_token: Option<secp256k1::Signature>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct ChannelParams<E: Engine> {
    pub pub_params: NIZKPublicParams<E>,
    l: usize,
    // messages for commitment
    extra_verify: bool, // extra verification for certain points in the establish/pay protocol
}


#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct ChannelState<E: Engine> {
    R: i32,
    tx_fee: i64,
    pub cp: Option<ChannelParams<E>>,
    pub name: String,
    pub pay_init: bool,
    pub channel_established: bool,
    pub third_party: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct ChannelToken<E: Engine> {
    pub pk_c: Option<secp256k1::PublicKey>,
    // pk_c
    pub pk_m: secp256k1::PublicKey,
    // pk_m
    pub cl_pk_m: cl::PublicKey<E>,
    // PK_m (used for verifying blind signatures)
    pub mpk: cl::PublicParams<E>,
    // mpk for PK_m
    pub comParams: CSMultiParams<E>,
}

impl<E: Engine> ChannelToken<E> {
    pub fn set_customer_pk(&mut self, pk_c: &secp256k1::PublicKey) {
        self.pk_c = Some(pk_c.clone());
    }

    pub fn is_init(&self) -> bool {
        return !self.pk_c.is_none();
    }

    pub fn compute_channel_id(&self) -> E::Fr
        where <E as pairing::Engine>::G1: serde::Serialize,
              <E as pairing::Engine>::G2: serde::Serialize,
              <E as ff::ScalarEngine>::Fr: serde::Serialize
    {
        if self.pk_c.is_none() {
            panic!("pk_c is not initialized yet");
        }
        let input = serde_json::to_vec(&self).unwrap();

        return hash_to_fr::<E>(input);
    }

    // add a method to compute hash on chain: SHA256 + RIPEMD160?
}
// add methods to check if channel token is initialized
// (only if

///
/// Channel state for generating/loading channel parameters and generating keypairs
///
impl<E: Engine> ChannelState<E> {
    pub fn new(name: String, third_party_support: bool) -> ChannelState<E> {
        ChannelState {
            R: 0,
            tx_fee: 0,
            cp: None,
            name: name.to_string(),
            pay_init: false,
            channel_established: false,
            third_party: third_party_support,
        }
    }

    ///
    /// keygen - takes as input public parameters and generates a digital signature keypair
    ///
    pub fn keygen<R: Rng>(&mut self, csprng: &mut R, _id: String) -> cl::BlindKeyPair<E> {
        let cp = self.cp.as_ref();
        let keypair = BlindKeyPair::<E>::generate(csprng, &cp.unwrap().pub_params.mpk, cp.unwrap().l);
        // print the keypair as well
        return keypair;
    }

    pub fn load_params(&mut self, _cp: &ChannelParams<E>) {
        // load external params
    }

    pub fn set_channel_fee(&mut self, fee: i64) {
        self.tx_fee = fee;
    }

    pub fn get_channel_fee(&self) -> i64 {
        return self.tx_fee as i64;
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
struct WalletKeyPair {
    pub wpk: secp256k1::PublicKey,
    pub wsk: secp256k1::SecretKey,
}

///
/// Customer state
///
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct CustomerState<E: Engine> {
    pub name: String,
    pub pk_c: secp256k1::PublicKey,
    sk_c: secp256k1::SecretKey,
    pub cust_balance: i64,
    //
    pub merch_balance: i64,
    pub wpk: secp256k1::PublicKey,
    // keypair bound to the wallet
    wsk: secp256k1::SecretKey,
    old_kp: Option<WalletKeyPair>,
    // old wallet key pair
    t: E::Fr,
    // randomness used to form the commitment
    wallet: Wallet<E>,
    // vector of field elements that represent wallet
    pub w_com: Commitment<E>,
    // commitment to the current state of the wallet
    index: i32,
    close_tokens: HashMap<i32, Signature<E>>,
    pay_tokens: HashMap<i32, Signature<E>>,
}

impl<E: Engine> CustomerState<E> {
    pub fn new<R: Rng>(csprng: &mut R, channel_token: &mut ChannelToken<E>, cust_bal: i64, merch_bal: i64, name: String) -> Self
        where <E as pairing::Engine>::G1: serde::Serialize,
              <E as pairing::Engine>::G2: serde::Serialize,
              <E as ff::ScalarEngine>::Fr: serde::Serialize
    {
        let mut kp = secp256k1::Secp256k1::new();
        kp.randomize(csprng);

        // generate the keypair for the channel
        let (sk_c, pk_c) = kp.generate_keypair(csprng);
        // generate the keypair for the initial wallet
        let (wsk, wpk) = kp.generate_keypair(csprng);
        // hash the wallet pub key
        let wpk_h = hash_pubkey_to_fr::<E>(&wpk);
        channel_token.set_customer_pk(&pk_c);
        // compute the channel ID
        let channelId = channel_token.compute_channel_id();
        // randomness for commitment
        let t = E::Fr::rand(csprng);
        // initialize wallet vector
        let wallet = Wallet { channelId: channelId, wpk: wpk_h, bc: cust_bal, bm: merch_bal, close: None };

        let w_com = channel_token.comParams.commit(&wallet.as_fr_vec(), &t);

        assert!(channel_token.is_init());

        let ct_db = HashMap::new();
        let pt_db = HashMap::new();

        return CustomerState {
            name: name,
            pk_c: pk_c,
            sk_c: sk_c,
            cust_balance: cust_bal,
            merch_balance: merch_bal,
            wpk: wpk,
            wsk: wsk,
            old_kp: None,
            t: t,
            w_com: w_com,
            wallet: wallet,
            index: 0,
            close_tokens: ct_db,
            pay_tokens: pt_db,
        };
    }

    pub fn get_wallet(&self) -> Wallet<E> {
        return self.wallet.clone();
    }

    pub fn get_public_key(&self) -> E::Fr {
        // hash the channel pub key
        let pk_h = hash_pubkey_to_fr::<E>(&self.pk_c);
        return pk_h;
    }

    pub fn get_close_token(&self) -> cl::Signature<E> {
        let index = self.index;
        let close_token = self.close_tokens.get(&index).unwrap();
        // rerandomize first
        return close_token.clone();
    }

    // generate nizk proof of knowledge of commitment opening
    pub fn generate_proof<R: Rng>(&self, csprng: &mut R, channel_token: &ChannelToken<E>) -> CommitmentProof<E> {
        // generate proof and do a partial reveal of channelId and bc/bm (init balances)
        return CommitmentProof::<E>::new(csprng, &channel_token.comParams, &self.w_com.c, &self.wallet.as_fr_vec(), &self.t, &vec![1, 3, 4]);
    }

    pub fn verify_close_token(&mut self, channel: &ChannelState<E>, close_token: &Signature<E>) -> bool {
        // add a prefix to the wallet for close-message
        let close_wallet = self.wallet.with_close(String::from("close"));
        let cp = channel.cp.as_ref().unwrap();
        let mpk = cp.pub_params.mpk.clone();
        //println!("verify_close_token - Wallet: {}", &self.wallet);

        let is_close_valid = cp.pub_params.pk.verify_blind(&mpk, &close_wallet, &self.t, &close_token);
        if is_close_valid {
            //println!("verify_close_token - Blinded close token is valid!!");
            let unblind_close_token = cp.pub_params.pk.unblind(&self.t, &close_token);
            let pk = cp.pub_params.pk.get_pub_key();
            let is_valid = pk.verify(&mpk, &close_wallet, &unblind_close_token);
            if is_valid {
                // record the unblinded close token
                self.close_tokens.insert(self.index, unblind_close_token);
            }
            return is_valid;
        }

        //println!("Customer - Verification failed for close token!");
        return is_close_valid;
    }

    pub fn verify_pay_token(&mut self, channel: &ChannelState<E>, pay_token: &Signature<E>) -> bool {
        // unblind and verify signature
        let cp = channel.cp.as_ref().unwrap();
        let mpk = cp.pub_params.mpk.clone();
        // we don't want to include "close" prefix here (even if it is set)
        let wallet = self.wallet.without_close();
        //println!("verify_pay_token - Wallet: {}", &self.wallet);

        let is_pay_valid = cp.pub_params.pk.verify_blind(&mpk, &wallet, &self.t, &pay_token);
        if is_pay_valid {
            //println!("verify_pay_token - Blinded pay token is valid!!");
            let unblind_pay_token = cp.pub_params.pk.unblind(&self.t, &pay_token);
            let pk = cp.pub_params.pk.get_pub_key();
            let is_valid = pk.verify(&mpk, &wallet, &unblind_pay_token);
            if is_valid {
                self.pay_tokens.insert(self.index, unblind_pay_token);
            }
            return is_valid;
        }

        //println!("Customer - Verification failed for pay token!");
        return is_pay_valid;
    }

    pub fn has_tokens(&self) -> bool {
        let index = self.index;
        let is_ct = self.close_tokens.get(&index).is_some();
        let is_pt = self.pay_tokens.get(&index).is_some();
        return is_ct && is_pt;
    }

    // for channel pay
    pub fn generate_payment<R: Rng>(&self, csprng: &mut R, channel: &ChannelState<E>, amount: i64) -> (NIZKProof<E>, Commitment<E>, secp256k1::PublicKey, CustomerState<E>) {
        // 1 - chooose new wpk/wsk pair
        let mut kp = secp256k1::Secp256k1::new();
        kp.randomize(csprng);
        let (new_wsk, new_wpk) = kp.generate_keypair(csprng);
        let wpk_h = hash_pubkey_to_fr::<E>(&new_wpk);

        // 2 - form new wallet and commitment
        let new_cust_bal = self.cust_balance - amount;
        let new_merch_bal = self.merch_balance + amount;
        let new_t = E::Fr::rand(csprng);

        let cp = channel.cp.as_ref().unwrap();
        let old_wallet = Wallet { channelId: self.wallet.channelId.clone(), wpk: self.wallet.wpk.clone(), bc: self.cust_balance, bm: self.merch_balance, close: None };
        let new_wallet = Wallet { channelId: self.wallet.channelId.clone(), wpk: wpk_h, bc: new_cust_bal, bm: new_merch_bal, close: Some(self.wallet.close.unwrap()) };
        let new_wcom = cp.pub_params.comParams.commit(&new_wallet.as_fr_vec(), &new_t);

        // 3 - generate new blinded and randomized pay token
        let i = self.index;
        let prev_pay_token = self.pay_tokens.get(&i).unwrap();
        //println!("Found prev pay token: {}", prev_pay_token);

        let pay_proof = cp.pub_params.prove(csprng, old_wallet, new_wallet.clone(),
                                            new_wcom.clone(), new_t, &prev_pay_token);

        // update internal state after proof has been verified by remote
        let new_cw = CustomerState {
            name: self.name.clone(),
            pk_c: self.pk_c.clone(),
            sk_c: self.sk_c.clone(),
            cust_balance: new_cust_bal,
            merch_balance: new_merch_bal,
            wpk: new_wpk,
            wsk: new_wsk,
            old_kp: Some(WalletKeyPair { wpk: self.wpk.clone(), wsk: self.wsk.clone() }),
            t: new_t,
            w_com: new_wcom.clone(),
            wallet: new_wallet.clone(),
            index: self.index, // increment index here
            close_tokens: self.close_tokens.clone(),
            pay_tokens: self.pay_tokens.clone(),
        };

        return (pay_proof, new_wcom, self.wpk, new_cw);
    }

    // update the internal state of the customer wallet
    pub fn update(&mut self, new_wallet: CustomerState<E>) -> bool {
        // update everything except for the wpk/wsk pair
        assert!(self.name == new_wallet.name);
        self.cust_balance = new_wallet.cust_balance;
        self.merch_balance = new_wallet.merch_balance;
        self.t = new_wallet.t;
        self.old_kp = new_wallet.old_kp;
        self.wpk = new_wallet.wpk;
        self.wsk = new_wallet.wsk;
        self.w_com = new_wallet.w_com;
        self.wallet = new_wallet.wallet;
        self.index = new_wallet.index;
        self.close_tokens = new_wallet.close_tokens;
        self.pay_tokens = new_wallet.pay_tokens;

        return true;
    }

    pub fn generate_revoke_token(&mut self, channel: &ChannelState<E>, close_token: &Signature<E>) -> ResultBoltType<(RevokedMessage, secp256k1::Signature)> {
        if self.verify_close_token(channel, close_token) {
            let old_wallet = self.old_kp.unwrap();
            // proceed with generating the close token
            let secp = secp256k1::Secp256k1::new();
            let rm = RevokedMessage::new(String::from("revoked"), old_wallet.wpk);
            let revoke_msg = secp256k1::Message::from_slice(&rm.hash_to_slice()).unwrap();
            // msg = "revoked"|| old wsk (for old wallet)
            let revoke_token = secp.sign(&revoke_msg, &old_wallet.wsk);

            return Ok((rm, revoke_token));
        }

        Err(BoltError::new("generate_revoke_token - could not verify the close token."))
    }
}

impl<E: Engine> fmt::Display for CustomerState<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut content = format!("id = {}\n", &self.name);
        content = format!("{}pk = {}\n", content, &self.pk_c);
        content = format!("{}sk = {}\n", content, &self.sk_c);
        content = format!("{}cust-bal = {}\n", content, &self.cust_balance);
        content = format!("{}merch-bal = {}\n", content, &self.merch_balance);
        content = format!("{}wpk = {}\nwsk = {}\n", content, &self.wpk, &self.wsk);
        if (!self.old_kp.is_none()) {
            let old_kp = self.old_kp.unwrap();
            content = format!("{}revoked: wpk = {}\nrevoked: wsk = {}\n", content, &old_kp.wpk, &old_kp.wsk);
        }
        content = format!("{}t = {}\n", content, &self.t);
        content = format!("{}wallet = {}\n", content, &self.wallet);
        content = format!("{}w_com = {}\n", content, &self.w_com);
        let close_token = self.close_tokens.get(&self.index);
        let pay_token = self.pay_tokens.get(&self.index);
        if (!close_token.is_none()) {
            content = format!("{}close_token = {}\n", content, &self.close_tokens.get(&self.index).unwrap());
        }
        if (!pay_token.is_none()) {
            content = format!("{}pay_token = {}\n", content, &self.pay_tokens.get(&self.index).unwrap());
        }
        write!(f, "CustomerState : (\n{}\n)", &content)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelcloseM {
    pub address: String,
    pub revoke: Option<secp256k1::Signature>,
    pub signature: secp256k1::Signature,
}

///
/// Merchant State
///
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
<E as pairing::Engine>::G1: serde::Serialize, \
<E as pairing::Engine>::G2: serde::Serialize"
))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
<E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct MerchantState<E: Engine> {
    id: String,
    keypair: cl::BlindKeyPair<E>,
    nizkParams: NIZKSecretParams<E>,
    pk: secp256k1::PublicKey,
    // pk_m
    sk: secp256k1::SecretKey,
    // sk_m
    comParams: CSMultiParams<E>,
    pub keys: HashMap<String, PubKeyMap>,
    pub pay_tokens: HashMap<String, cl::Signature<E>>,
}

impl<E: Engine> MerchantState<E> {
    pub fn new<R: Rng>(csprng: &mut R, channel: &mut ChannelState<E>, id: String) -> (Self, ChannelState<E>) {
        let l = 5;
        // generate keys here
        let mut tx_kp = secp256k1::Secp256k1::new();
        tx_kp.randomize(csprng);
        let (wsk, wpk) = tx_kp.generate_keypair(csprng);
        let mut ch = channel.clone();
        let nizkParams = NIZKSecretParams::<E>::setup(csprng, l);
        ch.cp = Some(ChannelParams::<E> { pub_params: nizkParams.pubParams.clone(), l, extra_verify: true });

        (MerchantState {
            id: id.clone(),
            keypair: nizkParams.keypair.clone(),
            nizkParams: nizkParams.clone(),
            pk: wpk,
            sk: wsk,
            comParams: nizkParams.pubParams.comParams.clone(),
            keys: HashMap::new(), // store wpks/revoke_tokens
            pay_tokens: HashMap::new(),
        }, ch)
    }

    pub fn init(&mut self, channel: &mut ChannelState<E>) -> ChannelToken<E> {
        let cp = channel.cp.as_ref().unwrap(); // if not set, then panic!
        let mpk = cp.pub_params.mpk.clone();
        let cl_pk = self.keypair.get_public_key(&mpk);

        return ChannelToken {
            pk_c: None,
            cl_pk_m: cl_pk.clone(), // extract the regular public key
            pk_m: self.pk.clone(),
            mpk: mpk,
            comParams: self.comParams.clone(),
        };
    }

    pub fn issue_close_token<R: Rng>(&self, csprng: &mut R, cp: &ChannelParams<E>, com: &Commitment<E>, extend_close: bool) -> Signature<E> {
        //println!("issue_close_token => generating token");
        let x = hash_to_fr::<E>(String::from("close").into_bytes());
        let close_com = match extend_close {
            true => self.comParams.extend_commit(com, &x),
            false => com.clone()
        };
        //println!("com for close-token: {}", &close_com);
        return self.keypair.sign_blind(csprng, &cp.pub_params.mpk, close_com);
    }

    pub fn issue_pay_token<R: Rng>(&self, csprng: &mut R, cp: &ChannelParams<E>, com: &Commitment<E>, remove_close: bool) -> Signature<E> {
        //println!("issue_pay_token => generating token");
        let x = hash_to_fr::<E>(String::from("close").into_bytes());
        let pay_com = match remove_close {
            true => self.comParams.remove_commit(com, &x),
            false => com.clone()
        };
        //println!("com for pay-token: {}", &pay_com);
        return self.keypair.sign_blind(csprng, &cp.pub_params.mpk, pay_com);
    }

    pub fn verify_proof<R: Rng>(&self, csprng: &mut R, channel: &ChannelState<E>, com: &Commitment<E>, com_proof: &CommitmentProof<E>, channelId: &E::Fr, cust_balance: i64, merch_balance: i64) -> ResultBoltType<(Signature<E>, Signature<E>)> {
        let is_valid = nizk::verify_opening(&self.comParams, &com.c, &com_proof, &channelId, cust_balance, merch_balance);
        let cp = channel.cp.as_ref().unwrap();
        if is_valid {
            let close_token = self.issue_close_token(csprng, cp, com, true);
            let pay_token = self.issue_pay_token(csprng, cp, com, false);
            return Ok((close_token, pay_token));
        }
        Err(BoltError::new("verify_proof - Failed to verify PoK of commitment opening"))
    }

    fn store_wpk_with_token(&mut self, wpk: &secp256k1::PublicKey, pay_token: Signature<E>) {
        // compute fingerprint on wpk
        let wpk_str = util::compute_pub_key_fingerprint(&wpk);
        self.pay_tokens.insert(wpk_str, pay_token);
    }

    fn get_pay_token(&self, wpk: &secp256k1::PublicKey) -> Signature<E> {
        let wpk_str = util::compute_pub_key_fingerprint(&wpk);
        return self.pay_tokens.get(&wpk_str).unwrap().clone();
    }

    pub fn verify_payment<R: Rng>(&mut self, csprng: &mut R, channel: &ChannelState<E>, proof: &NIZKProof<E>, com: &Commitment<E>, wpk: &secp256k1::PublicKey, amount: i64) -> ResultBoltType<Signature<E>> {
        let cp = channel.cp.as_ref().unwrap();
        let pay_proof = proof.clone();
        let prev_wpk = hash_pubkey_to_fr::<E>(&wpk);
        let epsilon = util::convert_int_to_fr::<E>(amount);

        if self.nizkParams.verify(pay_proof, epsilon, com, prev_wpk) {
            // 1 - proceed with generating close and pay token
            let close_token = self.issue_close_token(csprng, cp, com, false);
            let pay_token = self.issue_pay_token(csprng, cp, com, true);
            // let's store the pay token with the wpk for now
            self.store_wpk_with_token(wpk, pay_token);
            return Ok(close_token);
        }
        Err(BoltError::new("verify_payment - Failed to validate NIZK PoK for payment."))
    }

    pub fn verify_revoke_token(&self, revoke_token: &secp256k1::Signature, revoke_msg: &RevokedMessage, wpk: &secp256k1::PublicKey) -> ResultBoltType<Signature<E>> {
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_slice(&revoke_msg.hash_to_slice()).unwrap();
        // verify that the revocation token is valid
        if secp.verify(&msg, revoke_token, wpk).is_ok() {
            return Ok(self.get_pay_token(wpk));
        }
        Err(BoltError::new("verify_revoke_token - Failed to verify the revoke token for wpk!"))
    }

    pub fn sign_revoke_message(&self, address: String, revoke_token: &Option<secp256k1::Signature>) -> ChannelcloseM {
        let secp = secp256k1::Secp256k1::signing_only();
        let mut msg = Vec::new();
        msg.extend(address.as_bytes());
        if !revoke_token.is_none() {
            let r = revoke_token.unwrap().serialize_der().to_vec();
            msg.extend(r);
        }
        let msg2 = secp256k1::Message::from_slice(&hash_to_slice(&msg)).unwrap();
        let merch_sig = secp.sign(&msg2, &self.sk);
        return ChannelcloseM { address: address.clone(), revoke: revoke_token.clone(), signature: merch_sig };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    #[test]
    fn channel_util_works() {
        let mut channel = ChannelState::<Bls12>::new(String::from("Channel A <-> B"), false);
        let rng = &mut rand::thread_rng();

        let b0_cust = 100;
        let b0_merch = 20;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let (mut merch_state, mut channel) = MerchantState::<Bls12>::new(rng, &mut channel, String::from("Merchant B"));

        // initialize the merchant wallet with the balance
        let mut channel_token = merch_state.init(&mut channel);

        // retrieve commitment setup params (using merchant long lived pk params)
        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerState::<Bls12>::new(rng, &mut channel_token, b0_cust, b0_merch, String::from("Alice"));

        // lets establish the channel
        let cust_com_proof = cust_state.generate_proof(rng, &mut channel_token);

        // first return the close token, then wait for escrow-tx confirmation
        // then send the pay-token after confirmation
        let channelId = channel_token.compute_channel_id();
        assert_eq!(channelId, cust_state.get_wallet().channelId);
        let (close_token, pay_token) = merch_state.verify_proof(rng, &channel, &cust_state.w_com, &cust_com_proof, &channelId, b0_cust, b0_merch).unwrap();
        // unblind tokens and verify signatures
        assert!(cust_state.verify_close_token(&channel, &close_token));

        assert!(cust_state.verify_pay_token(&channel, &pay_token));

        println!("Done!");

        // pay protocol tests
        let amount = 10;
        let (pay_proof, new_com, old_wpk, new_cw) = cust_state.generate_payment(rng, &channel, amount);

        // new pay_token is not sent until revoke_token is obtained from the customer
        let new_close_token = merch_state.verify_payment(rng, &channel, &pay_proof, &new_com, &old_wpk, amount).unwrap();

        //println!("1 -  Updated close Token : {}", new_close_token);
        // unblind tokens and verify signatures

        // assuming the pay_proof checks out, can go ahead and update internal state of cust_state
        assert!(cust_state.update(new_cw));
        //println!("2 - updated customer wallet!");

        assert!(cust_state.verify_close_token(&channel, &new_close_token));
        //println!("3 - verified the close token!");

        // invalidate the previous state only if close token checks out
        let (revoke_msg, revoke_sig) = cust_state.generate_revoke_token(&channel, &new_close_token).unwrap();
        //println!("4 - Generated revoke token successfully.");

        //println!("5 - Revoke token => {}", revoke_token);

        let new_pay_token = merch_state.verify_revoke_token(&revoke_sig, &revoke_msg, &old_wpk).unwrap();
        assert!(cust_state.verify_pay_token(&channel, &new_pay_token));

        //println!("Validated revoke token!");
    }

    #[test]
    #[should_panic(expected = "pk_c is not initialized yet")]
    fn compute_channel_id_panics() {
        let mut channel = ChannelState::<Bls12>::new(String::from("Channel A <-> B"), false);
        let rng = &mut rand::thread_rng();

        // initialize on the merchant side with balance: b0_merch
        let (mut merch_state, mut channel) = MerchantState::<Bls12>::new(rng, &mut channel, String::from("Merchant B"));

        // initialize the merchant wallet with the balance
        let channel_token = merch_state.init(&mut channel);

        let _channelId = channel_token.compute_channel_id();
    }
}
