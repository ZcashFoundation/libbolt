extern crate bn;
extern crate rand;
extern crate libbolt;
extern crate bincode;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate time;
extern crate secp256k1;

use std::fmt;
use bn::{Group, Fr, G1, G2, pairing};
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};

use libbolt::prf;
use libbolt::sym;
use libbolt::ote;
use libbolt::clsigs;
use libbolt::commit_scheme;
use time::PreciseTime;
use libbolt::bidirectional;

#[doc(hidden)]
#[macro_export]
macro_rules! __compute_formula_scalarlist {
    // Unbracket a statement
    (($publics:ident, $scalars:ident) ($($x:tt)*)) => {
        // Add a trailing +
        __compute_formula_scalarlist!(($publics,$scalars) $($x)* +)
    };
    // Inner part of the formula: give a list of &Scalars
    // Since there's a trailing +, we can just generate the list as normal...
    (($publics:ident, $scalars:ident)
     $( $point:ident * $scalar:ident +)+ ) => {
        &[ $( $scalars.$scalar ,)* ]
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __compute_formula_pointlist {
    // Unbracket a statement
    (($publics:ident, $scalars:ident) ($($x:tt)*)) => {
        // Add a trailing +
        __compute_formula_pointlist!(($publics,$scalars) $($x)* +)
    };
    // Inner part of the formula: give a list of &Scalars
    // Since there's a trailing +, we can just generate the list as normal...
    (($publics:ident, $scalars:ident)
     $( $point:ident * $scalar:ident +)* ) => {
        &[ $( *($publics.$point) ,)* ]
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __compute_commitments_consttime {
    (($publics:ident, $scalars:ident) $($lhs:ident = $statement:tt),+) => {
        Commitments {
            $( $lhs :
               multiscalar_mult(
                   __compute_formula_scalarlist!(($publics, $scalars) $statement),
                   __compute_formula_pointlist!(($publics, $scalars) $statement),
               )
            ),+
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __recompute_commitments_vartime {
    (($publics:ident, $scalars:ident, $minus_c:ident) $($lhs:ident = $statement:tt),+) => {
        Commitments {
            $( $lhs :
               multiscalar_mult(
                   __compute_formula_scalarlist!(($publics, $scalars) $statement)
                       .into_iter()
                       .chain(iter::once(&($minus_c)))
                   ,
                   __compute_formula_pointlist!(($publics, $scalars) $statement)
                       .into_iter()
                       .chain(iter::once($publics.$lhs))
               )
            ),+
        }
    }
}

#[macro_export]
macro_rules! generate_nipk {
(
    $proof_module_name:ident // Name of the module to create
    ,
    ( $($secret:ident),+ ) // Secret variables, sep by commas
    ,
    ( $($public:ident),+ ) // Public variables, sep by commas
    :
    // List of statements to prove
    // Format: LHS = ( ... RHS expr ... ),
    $($lhs:ident = $statement:tt),+
) => {
    mod $proof_module_name {
        extern crate sodiumoxide;

        use bn::{Group, Fr, G1};
        use self::sodiumoxide::crypto::hash;
        use rand::Rng;
        use std::iter;
        use bincode::SizeLimit::Infinite;
        use bincode::rustc_serialize::encode;

        #[derive(Copy, Clone)]
        pub struct Secrets<'a> {
            // Create a parameter for each secret value
            $(
                pub $secret : &'a Fr,
            )+
        }

        #[derive(Copy, Clone)]
        pub struct Publics<'a> {
            // Create a parameter for each public value
            $(
                pub $public : &'a G1,
            )+
        }

        // Hack because we can't concat identifiers,
        // so do responses.x instead of responses_x
        // rand.x instead of rand_x, etc.

        struct Commitments {$($lhs: G1,)+ }
        struct Randomnesses {$($secret : Fr,)+}
        // #[derive(Serialize, Deserialize)]
        struct Responses {$($secret : Fr,)+}

        //#[derive(Serialize, Deserialize)]
        pub struct Proof {
            challenge: Fr,
            responses: Responses,
        }

        impl Proof {
            /// Create a `Proof`, in constant time, from the given
            /// `Publics` and `Secrets`.
            #[allow(dead_code)]
            pub fn create<R: Rng>(
                rng: &mut R,
                publics: Publics,
                secrets: Secrets,
            ) -> Proof {
                let rand = Randomnesses{
                    $(
                        $secret : Fr::random(rng),
                    )+
                };
                // $statement_rhs = `X * x + Y * y + Z * z`
                // should become
                // `publics.X * rand.x + publics.Y * rand.y + publics.Z * rand.z`
                let commitments: Commitments;
                commitments = __compute_commitments_consttime!(
                    (publics, rand) $($lhs = $statement),*
                );

                let mut hash_state = hash::State::new();

                $(
                    //let tmp$public: Vec<u8> = encode(&publics.$public, Infinite).unwrap();
                    hash_state.update((encode(&publics.$public, Infinite).unwrap()).as_slice());
                    //hash_state.update(publics.$public.as_bytes());
                )+
                $(
                    //let tmp$lhs: Vec<u8> = encode(&commitments.$lhs, Infinite).unwrap();
                    hash_state.update((encode(&commitments.$lhs, Infinite).unwrap()).as_slice());
                    //hash_state.update(commitments.$lhs.as_bytes());
                )+

                let digest = hash_state.finalize();
                let mut digest_buf: [u8; 64] = [0; 64];
                digest_buf.copy_from_slice(&digest[0..64]);
                let challenge = Fr::interpret(&digest_buf); // Scalar::from_hash(hash);

                let responses = Responses{
                    $(
                        $secret : (challenge * *secrets.$secret) + rand.$secret,
                    )+
                };

                Proof{ challenge: challenge, responses: responses }
            }

            /// Verify the `Proof` using the public parameters `Publics`.
            #[allow(dead_code)]
            pub fn verify(&self, publics: Publics) -> Result<(),()> {
                // `A = X * x + Y * y`
                // should become
                // `publics.X * responses.x + publics.Y * responses.y - publics.A * self.challenge`
                let responses = &self.responses;
                let minus_c = -self.challenge;
                let commitments = __recompute_commitments_vartime!(
                    (publics, responses, minus_c) $($lhs = $statement),*
                );

                let mut hash_state = hash::State::new();
                // Add each public point into the hash
                $(
                    //let tmp$public: Vec<u8> = encode(&publics.$public, Infinite).unwrap();
                    //hash_state.update(publics.$public.as_bytes());
                    hash_state.update((encode(&publics.$public, Infinite).unwrap()).as_slice());
                )+
                // Add each (recomputed) commitment into the hash
                $(
                    //let tmp$lhs: Vec<u8> = encode(&commitments.$lhs, Infinite).unwrap();
                    hash_state.update((encode(&commitments.$lhs, Infinite).unwrap()).as_slice());
                )*

                let digest = hash_state.finalize();
                let mut digest_buf: [u8; 64] = [0; 64];
                digest_buf.copy_from_slice(&digest[0..64]);
                // Recompute challenge
                let challenge = Fr::interpret(&digest_buf); // Scalar::from_hash(hash);

                if challenge == self.challenge { Ok(()) } else { Err(()) }
            }
        }

        #[cfg(test)]
        mod bench {
            extern crate test;

            use $crate::rand;

            use super::*;

            use self::test::Bencher;

            #[bench]
            #[allow(dead_code)]
            fn create(b: &mut Bencher) {
                let rng = &mut rand::thread_rng();
                //let mut rng = OsRng::new().unwrap();

                // Need somewhere to actually put the public points
                struct DummyPublics { $( pub $public : G1, )+ }
                let dummy_publics = DummyPublics {
                    $( $public : G1::random(&mut rng) , )+
                };

                let publics = Publics {
                    $( $public : &dummy_publics.$public , )+
                };

                struct DummySecrets { $( pub $secret : Fr, )+ }
                let dummy_secrets = DummySecrets {
                    $( $secret : Fr::random(&mut rng) , )+
                };

                let secrets = Secrets {
                    $( $secret : &dummy_secrets.$secret , )+
                };

                b.iter(|| Proof::create(&mut rng, publics, secrets));
            }

            #[bench]
            #[allow(dead_code)]
            fn verify(b: &mut Bencher) {
                let mut rng = OsRng::new().unwrap();

                // Need somewhere to actually put the public points
                struct DummyPublics { $( pub $public : G1, )+ }
                let dummy_publics = DummyPublics {
                    $( $public : G1::random(&mut rng) , )+
                };

                let publics = Publics {
                    $( $public : &dummy_publics.$public , )+
                };

                struct DummySecrets { $( pub $secret : Fr, )+ }
                let dummy_secrets = DummySecrets {
                    $( $secret : Fr::random(&mut rng) , )+
                };

                let secrets = Secrets {
                    $( $secret : &dummy_secrets.$secret , )+
                };

                let p = Proof::create(&mut rng, publics, secrets);

                b.iter(|| p.verify(publics));
            }
        }
    }
}
}

fn main() {
    let rng = &mut rand::thread_rng();

    // Generate private keys
    let alice_sk = Fr::random(rng);
    //println!("alice_sk: {}", alice_sk);
    let bob_sk = Fr::random(rng);
    let carol_sk = Fr::random(rng);

    // Generate public keys in G1 and G2
    let (alice_pk1, alice_pk2) = (G1::one() * alice_sk, G2::one() * alice_sk);
    let (bob_pk1, bob_pk2) = (G1::one() * bob_sk, G2::one() * bob_sk);
    let (carol_pk1, carol_pk2) = (G1::one() * carol_sk, G2::one() * carol_sk);

    // Each party computes the shared secret
    let alice_ss = pairing(bob_pk1, carol_pk2).pow(alice_sk);
    let bob_ss = pairing(carol_pk1, alice_pk2).pow(bob_sk);
    let carol_ss = pairing(alice_pk1, bob_pk2).pow(carol_sk);

    assert!(alice_ss == bob_ss && bob_ss == carol_ss);
    println!("All bn unit tests succeeded!");


    println!("******************************************");

    // Test the PRF
    let s = Fr::random(rng);
    let key = prf::initPRF(s, None);

    let x = Fr::random(rng);
    let y = prf::compute(&key, x);

    println!("Compute y = 0x{}", libbolt::print(&y));

    // Test the OTE scheme
    let k = ote::keygen();
    let X = G1::random(rng);
    let Y = G1::random(rng);
    let m = ote::OTMessage { m1: X, m2: Y };
    let c = ote::otenc(k, &m);
    let orig_m = ote::otdec(k, &c);

    assert!(m.m1 == orig_m.m1 && m.m2 == orig_m.m2);
    println!("OTE scheme works as expected!");

    // Test the CL sigs
    // CL sig tests
    let mpk = clsigs::setupD();
    let l = 3;
    let c_keypair = clsigs::keygenD(&mpk, l);
    let m_keypair = clsigs::keygenD(&mpk, l);

    //println!("{}", keypair.pk);

//    let msg1 = libbolt::RefundMessage::new(alice_sk, 10).hash(); // TODO: add ck (l-bit key)
//    let msg2 = libbolt::RefundMessage::new(alice_sk, 11).hash(); // TODO: add ck (l-bit key)
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
    let start1 = PreciseTime::now();
    assert!(clsigs::verifyD(&mpk, &m_keypair.pk, &m1, &signature) == true);
    let end1 = PreciseTime::now();
    assert!(clsigs::verifyD(&mpk, &m_keypair.pk, &m2, &signature) == false);
    let end2 = PreciseTime::now();
    assert!(clsigs::verifyD(&mpk, &c_keypair.pk, &m1, &signature) == false);
//    assert!(clsigs::verifyD(&mpk, &keypair.pk, &m3, &signature) == false);

    println!("CL signatures verified!");
    println!("{} seconds for verifying valid signatures.", start1.to(end1));
    println!("{} seconds for verifying invalid signatures.", end1.to(end2));

    let s1 = signature.hash("prefix type1");
    let s2 = signature.hash("prefix type2");
    let p1 = "Hash of signature 1: ";
    libbolt::debug_elem_in_hex(p1, &s1);
    let p2 = "Hash of signature 2: ";
    libbolt::debug_elem_in_hex(p2, &s2);

    let mut schnorr = secp256k1::Secp256k1::new();
    schnorr.randomize(rng);
    let (wsk, wpk) = schnorr.generate_keypair(rng).unwrap();

    let balance = 100;
    let r = Fr::random(rng);
    let cid = Fr::random(rng);
    let refund_message1 = libbolt::RefundMessage::new("refundUnsigned", cid, wpk, balance, Some(&r), None);
    let rm1 = refund_message1.hash();
    println!("RefundMessage => {}", refund_message1.msgtype);
    for i in 0 .. rm1.len() {
        let p = format!("rm1[{}] = ", i);
        libbolt::debug_elem_in_hex(&p, &rm1[i]);
    }

    let refund_message2 = libbolt::RefundMessage::new("refundToken", cid, wpk, balance+15, None, Some(&signature));
    let rm2 = refund_message2.hash();
    println!("RefundMessage (token) => {}", refund_message2.msgtype);
    for i in 0 .. rm2.len() {
        let p = format!("rm2[{}] = ", i);
        libbolt::debug_elem_in_hex(&p, &rm2[i]);
    }


    //assert!(clsigs::verifyD(&mpk, &keypair.pk, &m1, &signature) == true);


        println!("******************************************");
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
            println!("index: {}", i);
            C = C + (m_keypair.pk.Z2[i] * m1[i+1]);
        }
        let msg = "Sample Commit output:";
        libbolt::debug_g2_in_hex(msg, &C);

        let cm_csp = commit_scheme::setup(b, m_keypair.pk.Z2.clone(), mpk.g2.clone());
        let r = m1[0];
        let w_com = commit_scheme::commit(&cm_csp, &m1, r);

        assert!(commit_scheme::decommit(&cm_csp, &w_com, &m1));

        //let msg = "Commmit Scheme output:";
        //libbolt::debug_g2_in_hex(msg, &w_com.c);

        //assert_eq!(C, w_com.c);
        println!("Commitment scheme consistent!!");
        let proof = clsigs::bs_gen_nizk_proof(&m1, &cm_csp.pub_bases, w_com.c);
        // old -> let proof = clsigs::bs_gen_nizk_proof(&m1, &bases, C);

        let int_sig = clsigs::bs_gen_signature(&mpk, &m_keypair.sk, &proof);

        println!("Generated signature interactively!");


        let proof = clsigs::bs_gen_nizk_proof(&m1, &bases, C);

        let int_sig = clsigs::bs_gen_signature(&mpk, &m_keypair.sk, &proof);

        println!("Generated signature interactively!");
        // int_sig = interactively generated signature
        assert!(clsigs::verifyD(&mpk, &m_keypair.pk, &m1, &int_sig) == true);

        println!("Verified interactively produced signature!");

        let (r_bf, blind_sigs) = clsigs::prover_generate_blinded_sig(&int_sig);
        let common_params = clsigs::gen_common_params(&mpk, &m_keypair.pk, &blind_sigs);
        //assert!(clsigs::verifyD(&mpk, &keypair.pk, &m1, &blind_sigs) == true);
        //println!("Verified blind signature directly!");

        let proof_vs = clsigs::vs_gen_nizk_proof(&m1, &common_params, common_params.vs.pow(r_bf));
        assert!(clsigs::vs_verify_blind_sig(&mpk, &m_keypair.pk, &proof_vs, &blind_sigs));

        println!("Verified blind signature (via NIZK)!");


//    println!("******************************************");
//
//    println!("[1] libbolt - setup bidirecitonal scheme params");
//    let pp = bidirectional::setup();
//
//    // generate long-lived keypair for merchant -- used to identify
//    // it to all customers
//    println!("[2] libbolt - generate long-lived key pair for merchant");
//    let merch_keypair = bidirectional::keygen(&pp);
//
//    // customer gnerates an ephemeral keypair for use on a single channel
//    println!("[3] libbolt - generate ephemeral key pair for customer (use with one channel)");
//    let cust_keypair = bidirectional::keygen(&pp);
//
//    println!("[4] libbolt - generate the initial channel state");
//    let b0_cust = 10;
//    let b0_merch = 15;
//    let mut channel = bidirectional::init_channel("A -> B");
//    let msg = "Open Channel ID: ";
//    libbolt::debug_elem_in_hex(msg, &channel.cid);
//
//    // each party executes the init algorithm on the agreed initial challence balance
//    // in order to derive the channel tokens
//    println!("[5a] libbolt - initialize on the merchant side with balance {}", b0_merch);
//    let mut init_merch_data = bidirectional::init_merchant(&pp, b0_merch, &merch_keypair);
//
//    println!("[5b] libbolt - initialize on the customer side with balance {}", b0_cust);
//    let cm_csp = bidirectional::generate_commit_setup(&pp, &merch_keypair.pk);
//    let mut init_cust_data = bidirectional::init_customer(&pp, &channel, b0_cust, &cm_csp, &cust_keypair);
//
//    println!("[6a] libbolt - entering the establish protocol for the channel");
//    let proof1 = bidirectional::establish_customer_phase1(&pp, &init_cust_data, &init_merch_data);
//
//    println!("[6b] libbolt - obtain the wallet signature from the merchant");
//    let wallet_sig = bidirectional::establish_merchant_phase2(&pp, &mut channel, &init_merch_data, &proof1);
//
//    println!("[6c] libbolt - complete channel establishment");
//    bidirectional::establish_customer_phase3(&pp, wallet_sig, &merch_keypair.pk, &mut init_cust_data.csk);
//
//    assert!(channel.channel_established);
//
//    println!("Channel has been established!");
//    println!("******************************************");
//
//    println!("******************************************");
//    println!("Testing the pay protocol..");
//    // let's test the pay protocol
//    let channel_token = &init_cust_data.T;
//    let wallet = &init_cust_data.csk;
//    let pay_proof = bidirectional::payment_by_customer_phase1(&pp, &channel_token, &wallet, 5);
//
//    bidirectional::payment_by_merchant_phase2(&pp, &pay_proof, &init_merch_data, )
}
