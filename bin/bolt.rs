extern crate bn;
extern crate rand;
extern crate libbolt;
extern crate bincode;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use std::fmt;
use bn::{Group, Fr, G1, G2, pairing};
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};

use libbolt::prf;
use libbolt::sym;
use libbolt::ote;
use libbolt::clsigs;
use libbolt::commit_scheme;

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

    let s = Fr::random(rng);
    let key = prf::initPRF(s, None);

    let x = Fr::random(rng);
    let y = prf::compute(&key, x);

    println!("Compute y = 0x{}", libbolt::print(&y));

//    let rng = &mut rand::thread_rng();
//    let G = G1::random(rng); // &dalek_constants::RISTRETTO_BASEPOINT_POINT;
//    let H = G1::random(rng); // RistrettoPoint::hash_from_bytes::<Sha256>(G.compress().as_bytes());
//
//    // simple ZKP
//    generate_nipk!{dleq, (x), (A, G) : A = (G * x) }
//
//    let x = Fr::from_str("89327492234").unwrap();
//    let A =  G * x;
//    let B = H * x;
//
//    let publics = dleq::Publics{A: &A, G: G};
//    let secrets = dleq::Secrets{x: &x};


//    generate_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }
//
//    let x = Fr::from_str("89327492234").unwrap();
//    let A =  G * x;
//    let B = H * x;
//
//    let publics = dleq::Publics{A: &A, B: &B, G: G, H: &H};
//    let secrets = dleq::Secrets{x: &x};
//
//    let proof = dleq::Proof::create(&mut rng, publics, secrets);
//    // serialize to bincode representation
//    let proof_bytes = bincode::serialize(&proof, bincode::Infinite).unwrap();
//    // parse bytes back to memory
//    let parsed_proof: dleq::Proof
//        = bincode::deserialize(&proof_bytes).unwrap();
//
//    assert!(parsed_proof.verify(publics).is_ok());

    println!("******************************************");

//    sym::init();
//    // SymKeyEnc tests
//    let l = 128; // TODO: figure out how to apply this to secretbox
//    let key1 = sym::keygen(l);
//    //let key2 = sym::keygen(l);
//
//    // println!("key: {:?}", key);
//
//    let pt1 = String::from("hello world");
//    let ciphertext = sym::encrypt(&key1, &pt1);
//    println!("{}", ciphertext);
//
//    let pt2 = sym::decrypt(&key1, &ciphertext);
//    println!("Recovered plaintext: {}", pt2);
//    assert!(pt1 == pt2);
//
////    let pt3 = sym::decrypt(&key2, &ciphertext);
////    assert!(pt1 != pt3);
//    println!("SymKeyEnc is complete!");
//    println!("******************************************");
//
//    // CL sig tests
//    let mpk = clsigs::setup();
//    let keypair = clsigs::keygen(&mpk);
//    println!("{}", keypair.pk);
//
//    let msg1 = libbolt::RefundMessage::new(alice_sk, 10).hash(); // TODO: add ck (l-bit key)
//    let msg2 = libbolt::RefundMessage::new(alice_sk, 11).hash(); // TODO: add ck (l-bit key)
//    let signature = clsigs::sign(&keypair.sk, msg1);
//    println!("{}", signature);
//    assert!(clsigs::verify(&mpk, &keypair.pk, msg1, &signature) == true);
//    assert!(clsigs::verify(&mpk, &keypair.pk, msg2, &signature) == false);
//
//    println!("CL signature verified!");
//
//    println!("******************************************");
//    // commitment scheme tests
//    let pk = commit_scheme::setup();
//    // let sk = libbolt::SecretKeySigs { x: Fr::random(rng), y: Fr::random(rng) };
//    // let msg = String::from("Hello, World!");
//    let msg1 = libbolt::Message::new(keypair.sk, alice_sk, bob_sk, 10).hash();
//    let msg2 = libbolt::Message::new(keypair.sk, alice_sk, bob_sk, 11).hash();
//    let msg3 = libbolt::Message::new(keypair.sk, bob_sk, alice_sk, 10).hash();
//
//    let cm = commit_scheme::commit(&pk, msg1, None);
//
//    assert!(commit_scheme::decommit(&pk, &cm, msg1) == true);
//    assert!(commit_scheme::decommit(&pk, &cm, msg2) == false);
//    assert!(commit_scheme::decommit(&pk, &cm, msg3) == false);
//    println!("Commitment scheme works!");
//
//    println!("******************************************");

    // TODO: write tests
}
