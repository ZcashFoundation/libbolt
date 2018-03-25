extern crate bn;
extern crate rand;
extern crate libbolt;
use bn::{Group, Fr, G1, G2, pairing};

use libbolt::sym;
use libbolt::clsigs;
use libbolt::commit_scheme;

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
    sym::init();
    // SymKeyEnc tests
    let l = 128; // TODO: figure out how to apply this to secretbox
    let key1 = sym::keygen(l);
    let key2 = sym::keygen(l);

    // println!("key: {:?}", key);

    let pt1 = String::from("hello world");
    let ciphertext = sym::encrypt(&key1, &pt1);
    println!("{}", ciphertext);

    let pt2 = sym::decrypt(&key1, &ciphertext);
    println!("Recovered plaintext: {}", pt2);
    assert!(pt1 == pt2);

//    let pt3 = sym::decrypt(&key2, &ciphertext);
//    assert!(pt1 != pt3);
    println!("SymKeyEnc is complete!");
    println!("******************************************");

    // CL sig tests
    let mpk = clsigs::setup();
    let keypair = clsigs::keygen(&mpk);
    println!("{}", keypair.pk);

    let msg1 = libbolt::RefundMessage::new(alice_sk, 10).hash(); // TODO: add ck (l-bit key)
    let msg2 = libbolt::RefundMessage::new(alice_sk, 11).hash(); // TODO: add ck (l-bit key)
    let signature = clsigs::sign(&keypair.sk, msg1);
    println!("{}", signature);
    assert!(clsigs::verify(&mpk, &keypair.pk, msg1, &signature) == true);
    assert!(clsigs::verify(&mpk, &keypair.pk, msg2, &signature) == false);

    println!("CL signature verified!");

    println!("******************************************");
    // commitment scheme tests
    let pk = commit_scheme::setup();
    // let sk = libbolt::SecretKeySigs { x: Fr::random(rng), y: Fr::random(rng) };
    // let msg = String::from("Hello, World!");
    let msg1 = commit_scheme::Message::new(keypair.sk, alice_sk, bob_sk, 10);
    let msg2 = commit_scheme::Message::new(keypair.sk, alice_sk, bob_sk, 11);
    let msg3 = commit_scheme::Message::new(keypair.sk, bob_sk, alice_sk, 10);

    let cm = commit_scheme::commit(&pk, &msg1);

    assert!(commit_scheme::decommit(&pk, &cm, &msg1) == true);
    assert!(commit_scheme::decommit(&pk, &cm, &msg2) == false);
    assert!(commit_scheme::decommit(&pk, &cm, &msg3) == false);
    println!("Commitment scheme works!");

    println!("******************************************");

    // TODO: write tests
}
