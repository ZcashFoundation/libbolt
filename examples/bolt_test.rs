extern crate rand;
extern crate rand_core;
extern crate bolt;
extern crate ff;
extern crate pairing;
extern crate time;
extern crate secp256k1;

use bolt::bidirectional;
use std::time::Instant;
use pairing::bls12_381::{Bls12};
use bolt::handle_bolt_result;

macro_rules! measure_one_arg {
    ($x: expr) => {
        {
            let s = Instant::now();
            let res = $x;
            let e = s.elapsed();
            (res, e.as_millis())
        };
    }
}

macro_rules! measure_two_arg {
    ($x: expr) => {
        {
            let s = Instant::now();
            let (res1, res2) = $x;
            let e = s.elapsed();
            (res1, res2, e.as_millis())
        };
    }
}


macro_rules! measure_ret_mut {
    ($x: expr) => {
        {
            let s = Instant::now();
            let mut handle = $x;
            let e = s.elapsed();
            (handle, s.as_millis())
        };
    }
}

fn main() {
    println!("******************************************");
    let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
    let mut rng = &mut rand::thread_rng();

    channel_state.setup(&mut rng); // or load_setup params

    let b0_customer = 150;
    let b0_merchant = 10;
    let pay_inc = 20;
    let pay_inc2 = 10;

    let (mut channel_token, mut merch_state) = bidirectional::init_merchant(rng, &mut channel_state, "Merchant Bob");
    // initialize the balance for merch_state
    merch_state.init_balance(b0_merchant);

    let mut cust_state = bidirectional::init_customer(rng, &mut channel_state, &mut channel_token, b0_customer, b0_merchant, "Alice");

    println!("{}", cust_state);

    // lets establish the channel
    let (com, com_proof, est_time) = measure_two_arg!(bidirectional::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_state));
    println!(">> Time to generate proof for establish: {} ms", est_time);

    // obtain close token for closing out channel
    let option = bidirectional::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof,
                                                                                         b0_customer, b0_merchant, &merch_state);
    let close_token= match option {
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

    let (payment, new_cust_state, pay_time) = measure_two_arg!(bidirectional::generate_payment_proof(rng, &channel_state, &cust_state, pay_inc));
    println!(">> Time to generate payment proof: {} ms", pay_time);

    let (new_close_token, verify_time) = measure_one_arg!(bidirectional::verify_payment_proof(rng, &channel_state, &payment, &mut merch_state));
    println!(">> Time to verify payment proof: {} ms", verify_time);

    let revoke_token = bidirectional::generate_revoke_token(&channel_state, &mut cust_state, new_cust_state, &new_close_token);

    // send revoke token and get pay-token in response
    let new_pay_token_result = bidirectional::verify_revoke_token(&revoke_token, &mut merch_state);
    let new_pay_token = handle_bolt_result!(new_pay_token_result);

    // verify the pay token and update internal state
    assert!(cust_state.verify_pay_token(&channel_state, &new_pay_token.unwrap()));

    println!("******************************************");

    let (payment2, new_cust_state2, pay_time2) = measure_two_arg!(bidirectional::generate_payment_proof(rng, &channel_state, &cust_state, pay_inc2));
    println!(">> Time to generate payment proof 2: {} ms", pay_time2);

    let (new_close_token2, verify_time2) = measure_one_arg!(bidirectional::verify_payment_proof(rng, &channel_state, &payment2, &mut merch_state));
    println!(">> Time to verify payment proof 2: {} ms", verify_time2);

    let revoke_token2 = bidirectional::generate_revoke_token(&channel_state, &mut cust_state, new_cust_state2, &new_close_token2);

    // send revoke token and get pay-token in response
    let new_pay_token_result2 = bidirectional::verify_revoke_token(&revoke_token2, &mut merch_state);
    let new_pay_token2 = handle_bolt_result!(new_pay_token_result2);

    // verify the pay token and update internal state
    assert!(cust_state.verify_pay_token(&channel_state, &new_pay_token2.unwrap()));

    println!("Final Cust state: {}", cust_state);

}
