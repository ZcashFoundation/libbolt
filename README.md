# libbolt

A pure-Rust library implementation of BOLT: Blind Off-chain Lightweight Transactions.

BOLT is a system for conducting **privacy-preserving off-chain payments** between pairs of individual parties. BOLT is designed to provide a Layer 2 payment protocol for privacy-preserving cryptocurrencies such as Zcash, by allowing individuals to establish and use payment channels for instantaneous payments that do not require an on-chain transaction.

# WARNING

The libbolt library is a proof of concept implementation that relies on experimental libraries and dependencies at the moment. It is not suitable for production software yet.

# NOTE

Active development of libbolt is ongoing at [Bolt Labs, Inc](https://github.com/boltlabs-inc/libbolt) to instantiate on a cryptocurrency. We will submit pull requests periodically when new features are complete.

# Dependencies

* secp256k1
* ff
* pairing
* serde
* sha2

Note that the above rust dependencies will be compiled and installed as a result of running the `make` command.

# Rust Nightly Setup

Please keep in mind we are currently working with nightly Rust for now which gives access to the nightly compiler and experimental features.

	rustup install nightly
	
To run a quick test of the nightly toolchain, run the following command:

	rustup run nightly rustc --version

Optionally, to make this the default globally, run the following command:

	rustup default nightly

We will switch to the stable release channel once libbolt (and dependencies) are ready for production use.

# Build & Install

Please ensure you have installed the libsodium library for your platform. See install instructions [here](https://download.libsodium.org/doc/installation/index.html).

To build the library and execute basic examples, run `make` 

# Tests

To run libbolt unit tests, run `make test`

# Benchmarks

To run libbolt benchmarks, run `make bench`

# Usage

To use the libbolt library, add the `libbolt` crate to your dependency file in `Cargo.toml` as follows:

```toml
[dependencies]
bolt = "0.3.0"
```

Then add an extern declaration at the root of your crate as follows:
```rust
extern crate bolt;
```

# API

The libbolt library provides APIs for two types of payment channels:

* bidirectional payment channels
* third-party payments

## Bidirectional Payment Channels

A bidirectional payment channel enables two parties to exchange arbitrary positive and negative amounts. 

### Channel Setup and Key Generation

The first part of setting up bi-directional payment channels involve generating initial setup parameters using curve BLS12-381 with channel state.
	
	use bolt::bidirectional;
		
	// generate the initial channel state 
	// second argument represents third-party mode
    let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
    let mut rng = &mut rand::thread_rng();
    
    // generate fresh public parameters
    channel_state.setup(&mut rng); 

### Initialization

To initialize state/keys for both parties, call the ``bidirectional::init_merchant()`` and ``bidirectional::init_customer()``:
	
	let b0_merch = 10;
	let b0_cust = 100;

	// initialize the merchant state and initialize with balance
    let (mut channel_token, mut merch_state, mut channel_state) = bidirectional::init_merchant(rng, &mut channel_state, "Bob");
				    
    // generate the customer state using the channel token from the merchant
	let mut cust_state = bidirectional::init_customer(rng, // rng
	                                              &mut channel_token, // channel token
	                                              b0_cust, // init customer balance
	                                              b0_merch, // init merchant balance
	                                              "Alice")); // channel name/purpose


### Establish Protocol

When opening a payment channel, execute the establishment protocol API to escrow funds privately as follows:

    // establish the channel by generating initial state commitment proof
    let (com, com_proof) = bidirectional::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_state);
    
    // obtain close token for closing out channel
    let close_token = bidirectional::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof, &merch_state);
    
    // customer verifies that close-token
    assert!(cust_state.verify_close_token(&channel_state, &close_token));
    
    // form funding tx and wait for network confirmation
    
    // obtain payment token after confirming funding tx
    let pay_token = bidirectional::establish_merchant_issue_pay_token(rng, &channel_state, &com, &merch_state);
        
    // customer 
    assert!(bidirectional::establish_final(&mut channel_state, &mut cust_state, &pay_token));   
    		
	// confirm that the channel state is now established
	assert!(channel_state.channel_established);
	
### Pay protocol		

To spend on the channel, execute the pay protocol API (can be executed as many times as necessary):

	// phase 1 - payment proof and new cust state
    let (payment, new_cust_state) = bidirectional::generate_payment_proof(rng, &channel_state, &cust_state, 10);

	// phase 1 - merchant verifies the payment proof and returns a close-token   
    let new_close_token = bidirectional::verify_payment_proof(rng, &channel_state, &payment, &mut merch_state);
 
    // phase 2 - verify the close-token, update cust state and generate a revoke token for previous cust state state
    let revoke_token = bidirectional::generate_revoke_token(&channel_state, &mut cust_state, new_cust_state, &new_close_token);
    
    // phase 2 - merchant verifies the revoke token and sends back the pay-token in response
    let new_pay_token = bidirectional::verify_revoke_token(&revoke_token, &mut merch_state);
    
    // final - customer verifies the pay token and updates internal state
    assert!(cust_state.verify_pay_token(&channel_state, &new_pay_token));


### Channel Closure Algorithms

To close a channel, the customer must execute the `bidirectional::customer_refund()` routine as follows:

	let cust_close_msg = bidirectional::customer_close(&channel_state, &cust_state);
	
If the customer broadcasts an outdated version of his state, then the merchant can dispute this claim by executing the `bidirectional::merchant_retute()` routine as follows:

	let merch_close = bidirectional::merchant_close(&channel_state, &channel_token, &cust_close_msg, &merch_state);
	                                                         
## Third-party Payments

The bidirectional payment channels can be used to construct third-party payments in which a party **A** pays a second party **B** through an untrusted intermediary (**I**) to which both **A** and **B** have already established a channel. With BOLT, the intermediary learns nothing about the payment from **A** to **B** and cannot link transactions to individual users. 

To enable third-party payment support, initialize each payment channel as follows:
			
	// create the channel state for each channel and indicate third-party support 
	let mut channel_state = bidirectional::ChannelState::<Bls12>::new(String::from("Third-party Channels"), true);
	
Moreover, the intermediary can set a channel fee as follows:
	
	channel_state.set_channel_fee(5);

The channel establishment still works as described before and the pay protocol includes an additional step to verify that the payments on both channels cancel out or include a channel fee (if specified).

	
	...
	
	let payment_amount = 20;
	// get payment proof on first channel with party A and H
	let (sender_payment, new_cust_stateA) = bidirectional::generate_payment_proof(rng, &channel_state,
                                                                        &cust_stateA,
	                                                                    payment_amount); // bal inc
	// get payment proof on second channel with party B and H
	let (receiver_payment, new_cust_stateB) = bidirectional::generate_payment_proof(rng, &channel_state,
                                                                        &cust_stateB,                                                
                                                                        -payment_amount); // bal dec
                                                               	
    // intermediary executes the following on the two payment proofs
	// verifies that the payment proof is valid & cancels out and results in hub's fee    
    let close_token_result = bidirectional::verify_multiple_payment_proofs(rng, &channel_state, 
                                                                           &sender_payment, 
                                                                           &receiver_payment, 
                                                                           &mut merch_state);
                                                                           
    // alice gets a close token and bob gets a conditional token which requires alice's revoke token to be valid                                                                           
    let (alice_close_token, bob_cond_close_token) = handle_bolt_result!(close_token_result).unwrap();
	
    // both alice and bob generate a revoke token
    let revoke_token_alice = bidirectional::generate_revoke_token(&channel_state, 
                                                                  &mut cust_stateA, 
                                                                  new_cust_stateA, 
                                                                  &alice_close_token);
    let revoke_token_bob = bidirectional::generate_revoke_token(&channel_state,
                                                                  &mut cust_stateB, 
                                                                  new_cust_stateB, 
                                                                  &bob_cond_close_token);
	
    // send both revoke tokens to intermediary and receive pay-tokens (one for sender and another for receiver)
    let new_pay_tokens: BoltResult<(cl::Signature<Bls12>,cl::Signature<Bls12>)> = \
                        bidirectional::verify_multiple_revoke_tokens(&revoke_token_sender, 
                                                                     &revoke_token_receiver, 
                                                                     &mut merch_state);
                                                                     	
	...

See the `intermediary_payment_basics_works()` unit test in `src/lib.rs` for more details.

# Documentation (TODO)

Build the api documentation by simply running `make doc`. Documentation will be generated in your local `target/doc` directory.

For the libbolt design documentation, see the `docs/bolt_design.pdf` document.

# Contributions

To contribute code improvements, please checkout the repository, make your changes and submit a pull request.

	git clone https://github.com/ZcashFoundation/libbolt.git

# TODOs

Here are some TODOs (not in any particular order):

* Add more unit tests for other dispute resolution scenarios and third-party test cases
	
# License

Licensed under MIT (LICENSE-MIT or http://opensource.org/licenses/MIT)
