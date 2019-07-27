/*
 * Implement for Bolt protocols:
 * - initializing channel state and generating cust/merch wallets (almost done)
 * - establish protocol (WIP)
 * - pay protocol (WIP)
 * - channel close algorithms (WIP)
 */

extern crate pairing;
extern crate rand;

use super::*;
use pairing::{Engine, CurveProjective};
use pairing::bls12_381::{Bls12};
use ff::PrimeField;
use cl::{BlindKeyPair, KeyPair, Signature, PublicParams, setup};
use ped92::{CSParams, Commitment, CSMultiParams};
use util::{hash_pubkey_to_fr, convert_int_to_fr, hash_to_fr, CommitmentProof};
use rand::Rng;
use std::collections::HashMap;
use std::fmt::Display;
use serde::{Serialize, Deserialize};
use serialization_wrappers::WalletCommitmentAndParamsWrapper;
use std::ptr::hash;
use nizk::{NIZKPublicParams, Proof};
use wallet::Wallet;

#[derive(Clone, Serialize, Deserialize)]
struct PubKeyMap {
    wpk: secp256k1::PublicKey,
    revoke_token: Option<secp256k1::Signature>
}

//#[derive(Clone, Serialize, Deserialize)]
#[derive(Clone)]
pub struct ChannelParams<E: Engine> {
    pub pub_params: NIZKPublicParams<E>,
    l: usize, // messages for commitment
    extra_verify: bool // extra verification for certain points in the establish/pay protocol
}


//#[derive(Clone, Serialize, Deserialize)]
#[derive(Clone)]
pub struct ChannelState<E: Engine> {
    keys: HashMap<String, PubKeyMap>,
    R: i32,
    tx_fee: i32,
    pub cp: Option<ChannelParams<E>>,
    pub name: String,
    pub pay_init: bool,
    pub channel_established: bool,
    pub third_party: bool
}

#[derive(Clone)]
pub struct ChannelToken<E: Engine> {
    pub pk_c: Option<secp256k1::PublicKey>, // pk_c
    pub blind_pk_m: cl::BlindPublicKey<E>, // PK_m
    pub pk_m: secp256k1::PublicKey, // pk_m
    pub comParams: CSMultiParams<E>,
    is_initialized: bool
}

impl<E: Engine> ChannelToken<E> {
    pub fn is_init(&mut self) -> bool {
        return self.is_initialized
    }

    pub fn set_customer_pk(&mut self, pk_c: &secp256k1::PublicKey) {
        self.pk_c = Some(pk_c.clone());
        self.is_initialized = true;
    }
}
// add methods to check if channel token is initialized
// (only if

///
/// Channel state for generating/loading channel parameters and generating keypairs
///
impl<E: Engine> ChannelState<E> {

    pub fn new(name: String, third_party_support: bool) -> ChannelState<E> {
        ChannelState {
            keys: HashMap::new(), // store wpks/revoke_tokens
            R: 0,
            tx_fee: 0,
            cp: None,
            name: name.to_string(),
            pay_init: false,
            channel_established: false,
            third_party: third_party_support
        }
    }

    pub fn init() {
        sodiumoxide::init();
    }

    ///
    /// setup - generate public parameters for bidirectional payment channels
    ///
    pub fn setup<R: Rng>(&mut self, csprng: &mut R) {
        let l = 5;
        let pubParams = NIZKPublicParams::<E>::setup(csprng, l);
        let num_rand_values = 1;

        let cp = ChannelParams { pub_params: pubParams, l: l, extra_verify: true };
        self.cp = Some(cp);
    }

    ///
    /// keygen - takes as input public parameters and generates a digital signature keypair
    ///
    pub fn keygen<R: Rng>(&mut self, csprng: &mut R, id: String) -> cl::BlindKeyPair<E> {
        let cp = self.cp.as_ref();
        let keypair = BlindKeyPair::<E>::generate(csprng, &cp.unwrap().pub_params.mpk, cp.unwrap().l);
        println!("Generating keypair for '{}'", id);
        // print the keypair as well
        return keypair;
    }

    pub fn load_params(&mut self, cp: &ChannelParams<E>) {
        // load external params
    }

    pub fn set_channel_fee(&mut self, fee: i32) {
        self.tx_fee = fee;
    }

    pub fn get_channel_fee(&self) -> i32 {
        return self.tx_fee as i32;
    }
}

#[derive(Copy, Clone)]
struct WalletKeyPair {
    pub wpk: secp256k1::PublicKey,
    pub wsk: secp256k1::SecretKey
}

///
/// Customer wallet consists of a keypair (NEW)
///
pub struct CustomerWallet<E: Engine> {
    pub pk_c: secp256k1::PublicKey,
    sk_c: secp256k1::SecretKey,
    cust_balance: i32, //
    merch_balance: i32,
    pub wpk: secp256k1::PublicKey, // keypair bound to the wallet
    wsk: secp256k1::SecretKey,
    old_kp: Option<WalletKeyPair>, // old wallet key pair
    r: E::Fr, // randomness used to form the commitment
    wallet: Wallet<E>, // vector of field elements that represent wallet
    pub w_com: Commitment<E>, // commitment to the current state of the wallet
    index: i32,
    close_tokens: HashMap<i32, Signature<E>>,
    pay_tokens: HashMap<i32, Signature<E>>
}

impl<E: Engine> CustomerWallet<E> {
    pub fn new<R: Rng>(csprng: &mut R, channel: &mut ChannelState<E>, channel_token: &mut ChannelToken<E>, cust_bal: i32, merch_bal: i32) -> Self {
        assert!(!channel_token.is_init());
        let mut kp = secp256k1::Secp256k1::new();
        kp.randomize(csprng);

        // generate the keypair for the channel
        let (sk_c, pk_c) = kp.generate_keypair(csprng);
        // generate the keypair for the initial wallet
        let (wsk, wpk) = kp.generate_keypair(csprng);
        // hash the wallet pub key
        let wpk_h = hash_pubkey_to_fr::<E>(&wpk);
        // hash the channel pub key
        let pk_h = hash_pubkey_to_fr::<E>(&pk_c);

        // convert balance into Fr
        let cust_b0 = convert_int_to_fr::<E>(cust_bal);
        let merch_b0 = convert_int_to_fr::<E>(merch_bal);
        // randomness for commitment
        let r = E::Fr::rand(csprng);
        // initialize wallet vector
        let wallet = Wallet {  pkc: pk_h, wpk: wpk_h, bc: cust_bal, bm: merch_bal, close: None };

        let w_com = channel_token.comParams.commit(&wallet.as_fr_vec(), &r);

        channel_token.set_customer_pk(&pk_c);

        assert!(channel_token.is_init());

        let mut ct_db= HashMap::new();
        let mut pt_db= HashMap::new();

        println!("Customer wallet formed -> now returning the structure to the caller.");
        return CustomerWallet {
            pk_c: pk_c,
            sk_c: sk_c,
            cust_balance: cust_bal,
            merch_balance: merch_bal,
            wpk: wpk,
            wsk: wsk,
            old_kp: None,
            r: r,
            w_com: w_com,
            wallet: wallet,
            index: 1,
            close_tokens: ct_db,
            pay_tokens: pt_db
        }
    }

    // generate nizk proof of knowledge of commitment opening
    pub fn generate_proof<R: Rng>(&mut self, csprng: &mut R, channel_token: &ChannelToken<E>) -> CommitmentProof<E> {
        return CommitmentProof::<E>::new(csprng, &channel_token.comParams, &self.w_com.c, &self.wallet.as_fr_vec(), &self.r);
    }

    pub fn verify_close_token(&mut self, channel: &ChannelState<E>, close_token: &Signature<E>) -> bool {
        // add a prefix to the wallet for close-message
        let close_wallet = self.wallet.with_close(String::from("close"));
        let cp = channel.cp.as_ref().unwrap();
        let mpk = cp.pub_params.mpk.clone();

        let is_close_valid = cp.pub_params.keypair.verify(&mpk, &close_wallet, &self.r, &close_token);
        if is_close_valid {
            println!("verify_close_token - Blinded close token is valid!!");
            let pk = cp.pub_params.keypair.get_public_key(&mpk);
            let unblind_close_token = cp.pub_params.keypair.unblind(&self.r, &close_token);
            let is_valid = pk.verify(&mpk, &close_wallet, &unblind_close_token);
            if is_valid {
                // record the unblinded close token
                self.close_tokens.insert( self.index - 1, unblind_close_token);
            }
            return is_valid;
        }

        panic!("Channel establish - Verification failed for close token!");
    }

    pub fn verify_pay_token(&mut self, channel: &ChannelState<E>, pay_token: &Signature<E>) -> bool {
        // unblind and verify signature
        let cp = channel.cp.as_ref().unwrap();
        let mpk = cp.pub_params.mpk.clone();
        let wallet = self.wallet.as_fr_vec();

        let is_pay_valid = cp.pub_params.keypair.verify(&mpk, &wallet, &self.r, &pay_token);
        if is_pay_valid {
            println!("verify_pay_token - Blinded pay token is valid!!");
            let unblind_pay_token = cp.pub_params.keypair.unblind(&self.r, &pay_token);
            let pk = cp.pub_params.keypair.get_public_key(&mpk);
            let is_valid = pk.verify(&mpk, &wallet, &unblind_pay_token);
            if is_valid {
                self.pay_tokens.insert(self.index - 1, unblind_pay_token);
            }
            return is_valid;
        }

        panic!("verify_pay_token - Channel establish - Verification failed for pay token!") ;
    }

    // for channel pay
    pub fn generate_payment<R: Rng>(&mut self, csprng: &mut R, channel: &ChannelState<E>, amount: i32) -> (Proof<E>, Commitment<E>, secp256k1::PublicKey, CustomerWallet<E>) {
        // 1 - chooose new wpk/wsk pair
        let mut kp = secp256k1::Secp256k1::new();
        kp.randomize(csprng);
        let (new_wsk, new_wpk) = kp.generate_keypair(csprng);
        let wpk_h = hash_pubkey_to_fr::<E>(&new_wpk);

        // 2 - form new wallet and commitment
        let new_cust_bal= self.cust_balance - amount;
        let new_merch_bal = self.merch_balance + amount;
        let new_r = E::Fr::rand(csprng);

        println!("old wallet close => {}", self.wallet.close.unwrap());

        let cp = channel.cp.as_ref().unwrap();
        let old_wallet = Wallet { pkc: self.wallet.pkc.clone(), wpk: self.wallet.wpk.clone(), bc: self.cust_balance, bm: self.merch_balance, close: None };
        let new_wallet = Wallet {  pkc: self.wallet.pkc.clone(), wpk: wpk_h, bc: new_cust_bal, bm: new_merch_bal, close: Some(self.wallet.close.unwrap()) };
        let new_wcom = cp.pub_params.comParams.commit(&new_wallet.as_fr_vec(), &new_r);

        // 3 - generate new blinded and randomized pay token
        let i = self.index - 1;
        let mut prev_pay_token = self.pay_tokens.get(&i).unwrap();

        println!("OLD {}", &self.wallet);
        println!("NEW {}", &new_wallet);
        println!("{}", &prev_pay_token);

        let pay_proof = cp.pub_params.prove(csprng, self.r.clone(), old_wallet, new_wallet.clone(),
                          new_wcom.clone(), new_r, &prev_pay_token);

        // update internal state after proof has been verified by remote
        let new_cw = CustomerWallet {
            pk_c: self.pk_c.clone(),
            sk_c: self.sk_c.clone(),
            cust_balance: new_cust_bal,
            merch_balance: new_merch_bal,
            wpk: new_wpk,
            wsk: new_wsk,
            old_kp: Some(WalletKeyPair { wpk: self.wpk.clone(), wsk: self.wsk.clone() }),
            r: new_r,
            w_com: new_wcom.clone(),
            wallet: new_wallet.clone(),
            index: self.index + 1, // increment index here
            close_tokens: self.close_tokens.clone(),
            pay_tokens: self.pay_tokens.clone()
        };

        return (pay_proof, new_wcom, self.wpk, new_cw);
    }

    // update the internal state of the customer wallet
    pub fn update(&mut self, new_wallet: CustomerWallet<E>) -> bool {
        // update everything except for the wpk/wsk pair
        self.cust_balance = new_wallet.cust_balance;
        self.merch_balance = new_wallet.merch_balance;
        self.r = new_wallet.r;
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

    pub fn generate_revoke_token(&mut self, channel: &ChannelState<E>, close_token: &Signature<E>) -> (secp256k1::Message, secp256k1::Signature) {
        if self.verify_close_token(channel, close_token) {
            let old_wallet = self.old_kp.unwrap();
            // proceed with generating the close token
            let secp = secp256k1::Secp256k1::new();
            let rm = RevokedMessage::new(String::from("revoked"), old_wallet.wpk, None);
            let revoke_msg = secp256k1::Message::from_slice(&rm.hash_to_slice()).unwrap();
            // msg = "revoked"|| old wsk (for old wallet)
            let revoke_token = secp.sign(&revoke_msg, &old_wallet.wsk);

            return (revoke_msg, revoke_token);
        }

        panic!("generate_revoke_token - could not verify the close token.");
    }

}

impl<E: Engine> fmt::Display for CustomerWallet<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut content = String::new();
        content = format!("pk = {}\n", &self.pk_c);
        content = format!("{}sk = {}\n", content, &self.sk_c);
        content = format!("{}cust-bal = {}\n", content, &self.cust_balance);
        content = format!("{}merch-bal = {}\n", content, &self.merch_balance);
        write!(f, "CustomerWallet : (\n{}\n)", &content)
    }
}


///
/// Merchant wallet (NEW)
///
pub struct MerchantWallet<E: Engine> {
    keypair: cl::BlindKeyPair<E>,
    balance: i32,
    pk: secp256k1::PublicKey, // pk_m
    sk: secp256k1::SecretKey, // sk_m
    comParams: CSMultiParams<E>
}

impl<E: Engine> MerchantWallet<E> {
    pub fn new<R: Rng>(csprng: &mut R, channel: &mut ChannelState<E>, id: String) -> Self {
        // generate keys here
        let mut tx_kp = secp256k1::Secp256k1::new();
        tx_kp.randomize(csprng);
        let (wsk, wpk) = tx_kp.generate_keypair(csprng);
        let cp = channel.cp.as_ref().unwrap(); // if not set, then panic!

        MerchantWallet {
            keypair: cp.pub_params.keypair.clone(),
            balance: 0,
            pk: wpk,
            sk: wsk,
            comParams: cp.pub_params.comParams.clone()
        }
    }

    pub fn init<R: Rng>(&mut self, csprng: &mut R, channel: &mut ChannelState<E>) -> ChannelToken<E> {
        return ChannelToken {
            pk_c: None,
            blind_pk_m: self.keypair.public.clone(),
            pk_m: self.pk.clone(),
            comParams: self.comParams.clone(),
            is_initialized: false
        }
    }

    pub fn issue_close_token<R: Rng>(&self, csprng: &mut R, cp: &ChannelParams<E>, com: &Commitment<E>, extend: bool) -> Signature<E> {
        println!("issue_close_token => generating token");
        let x = hash_to_fr::<E>(String::from("close").into_bytes() );
        let close_com = match extend {
            true => self.comParams.extend_commit(com, &x),
            false => com.clone()
        };
        return self.keypair.sign_blind(csprng, &cp.pub_params.mpk, close_com);
    }

    pub fn issue_pay_token<R: Rng>(&self, csprng: &mut R, cp: &ChannelParams<E>, com: &Commitment<E>) -> Signature<E> {
        println!("issue_pay_token => generating token");
        return self.keypair.sign_blind(csprng, &cp.pub_params.mpk, com.clone());
    }

    pub fn verify_proof<R: Rng>(&self, csprng: &mut R, channel: &ChannelState<E>, com: &Commitment<E>, com_proof: &CommitmentProof<E>) -> (Signature<E>, Signature<E>) {
        let is_valid = util::verify(&self.comParams, &com.c, &com_proof);
        let cp = channel.cp.as_ref().unwrap();
        if is_valid {
            println!("Commitment PoK is valid!");
            let close_token = self.issue_close_token(csprng, cp, com, true);
            let pay_token = self.issue_pay_token(csprng, cp, com);
            return (close_token, pay_token);
        }
        panic!("verify_proof - Failed to verify PoK of commitment opening");
    }

    pub fn verify_payment<R: Rng>(&self, csprng: &mut R, channel: &ChannelState<E>, proof: &Proof<E>, com: &Commitment<E>, wpk: &secp256k1::PublicKey, amount: i32) -> (Signature<E>, Signature<E>) {
        let cp = channel.cp.as_ref().unwrap();
        let pay_proof = proof.clone();
        let prev_wpk = hash_pubkey_to_fr::<E>(&wpk);
        let epsilon = E::Fr::from_str(&amount.to_string()).unwrap();

        if cp.pub_params.verify(pay_proof, epsilon, com, prev_wpk) {

            // 1 - proceed with generating close token
            let close_token = self.issue_close_token(csprng, cp, com, false);
            let pay_token = self.issue_pay_token(csprng, cp, com);
            return (close_token, pay_token);
        }

        panic!("verify_payment - Failed to validate NIZK PoK for payment.");
    }

//    pub fn verify_revoke_token(&self, revoke_token: &RevokedMessage, revoke_msg: &secp256k1::Message) -> bool {
//        return true;
//    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Rand;
    use pairing::bls12_381::{Bls12};
    use rand::{SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn channel_util_works() {
        println!("Initializing channels...");
        let mut channel = ChannelState::<Bls12>::new(String::from("Channel A <-> B"), false);
        let mut rng = &mut rand::thread_rng();

        // run setup to generate the public parameters
        channel.setup(&mut rng); // or load_setup params

        let b0_cust = 100;
        let b0_merch = 20;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let mut merch_wallet = MerchantWallet::<Bls12>::new(rng, &mut channel, String::from("Merchant B"));

        // initialize the merchant wallet with the balance
        let mut channel_token = merch_wallet.init(rng, &mut channel);

        // retrieve commitment setup params (using merchant long lived pk params)
        // initialize on the customer side with balance: b0_cust
        let mut cust_wallet = CustomerWallet::<Bls12>::new(rng, &mut channel, &mut channel_token, b0_cust, b0_merch);

        // lets establish the channel
        let cust_com_proof = cust_wallet.generate_proof(rng, &mut channel_token);

        // first return the close token, then wait for escrow-tx confirmation
        // then send the pay-token after confirmation
        let (close_token, pay_token) = merch_wallet.verify_proof(rng, &channel, &cust_wallet.w_com, &cust_com_proof);

        // unblind tokens and verify signatures
        assert!(cust_wallet.verify_pay_token(&channel, &pay_token));

        assert!(cust_wallet.verify_close_token(&channel, &close_token));

        println!("Done!");

        // pay protocol tests
        let amount = 10;
        let (pay_proof, new_com, old_wpk, new_cw) = cust_wallet.generate_payment(rng, &channel, amount);

        println!("{}", new_com);
        println!("wpk => {}", old_wpk);
        println!("{}", new_cw);

        // new pay_token is not sent until revoke_token is obtained from the customer
        let (new_close_token, new_pay_token) = merch_wallet.verify_payment(rng, &channel, &pay_proof, &new_com, &old_wpk, amount);

        println!("Close Token : {}", new_close_token);
        // unblind tokens and verify signatures

        // assuming the pay_proof checks out, can go ahead and update internal state of cust_wallet
        assert!(cust_wallet.update(new_cw));

        // invalidate the previous state only if close token checks out
        let (revoke_msg, revoke_token) = cust_wallet.generate_revoke_token(&channel, &new_close_token);

        assert!(cust_wallet.verify_pay_token(&channel, &new_pay_token));

        println!("Revoke token => {}", revoke_token);

        //assert!(merch_wallet.verify_revoke_token(&revoke_token, &revoke_msg));
    }
}
