# libbolt

A pure-Rust library implementation of BOLT: Blind Off-chain Lightweight Transactions.

BOLT is a system for conducting **privacy-preserving off-chain payments** between pairs of individual parties. BOLT is designed to provide a Layer 2 payment protocol for privacy-preserving cryptocurrencies such as Zcash, by allowing individuals to establish and use payment channels for instantaneous payments that do not require an on-chain transaction.

# WARNING

The libbolt library is a proof of concept implementation that relies on experimental libraries and dependencies at the moment. It is not suitable for production software yet.

# Dependencies

* secp256k1
* sodiumoxide
* bn
* bulletproofs

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

To build the library and execute basic tests, run `make` 

# Tests

To run libbolt unit tests, run `make test`

# Benchmarks

To run libbolt benchmarks, run `make bench`

# Usage

To use the libbolt library, add the `libbolt` crate to your dependency file in `Cargo.toml` as follows:

```toml
[dependencies]
libbolt = "0.1.0"
```

Then add an extern declaration at the root of your crate as follows:
```rust
extern crate libbolt;
```

# API

The libbolt library provides APIs for three types of payment channels:

* unidirectional payment channels (*work in progress*)
* bidirectional payment channels
* third-party payments

## Unidirectional Payment Channels

**TODO**

## Bidirectional Payment Channels

A bidirectional payment channel enables two parties to exchange arbitrary positive and negative amounts. 

### Channel Setup and Key Generation

The first part of setting up bi-directional payment channels involve generating initial setup parameters, channel state and key generation for both parties.
	
	use libbolt::bidirectional;
	
	// setup bidirectional scheme params
	let pp = bidirectional::setup(true);
	
	// generate the initial channel state 
	// second argument represents third-party mode
	let mut channel = bidirectional::ChannelState::new(String::from("My New Channel A"), false);

To generate keys for both parties, call the `bidirectional::keygen()` routine with the public parameters as input.
	
	// merchant generates a long-lived key pair
	let m_keypair = bidirectional::keygen(&pp);
	
	// customer generates an ephemeral keypair for use on a single channel
	let c_keypair = bidirectional::keygen(&pp);

### Initialization

To initialize the channel for both parties, do the following:
	
	let b0_merch = 10;
	let b0_cust = 100;
	// initialize on the merchant side with balance, b0_merch
	let mut m_data = bidirectional::init_merchant(&pp, b0_merch, &m_keypair));
		
	 // generate the public params for the commitment scheme
	let cm_csp = bidirectional::generate_commit_setup(&pp, &m_keypair.pk);
	    
	// initialize on the customer side with balance, b0_cust    
	let mut c_data = bidirectional::init_customer(&pp, // public params
	                                              &channel, // channel state
	                                              b0_cust, // init customer balance
	                                              b0_merch, // init merchant balance
	                                              &cm_csp, // commitment pub params
	                                              &c_keypair)); // customer keypair


### Establish Protocol

When opening a payment channel, execute the establishment protocol API to escrow funds privately as follows:

	// entering the establish protocol for the channel
	let proof1 = bidirectional::establish_customer_phase1(&pp, &c_data, &m_data.bases);
	
	// obtain the wallet signature from the merchant
	let w_sig = bidirectional::establish_merchant_phase2(&pp, &mut channel, &m_data, &proof1));
	
	// complete channel establishment");
	assert!(bidirectional::establish_customer_final(&pp, &m_keypair.pk, &mut c_data.csk, w_sig));
		
	// confirm that the channel state is now established
	assert!(channel.channel_established);
	
### Pay protocol		

To spend on the channel, execute the pay protocol API (can be executed as many times as necessary):
		
	// precomputation phase that customer does offline prior to a spend
	bidirectional::pay_by_customer_phase1_precompute(&pp, &c_data.channel_token, &m_keypair.pk, &mut c_data.csk);
		
	// generate new channel token, new wallet and payment proof
	// send the payment proof to the merchant
	let (t_c, new_w, pay_proof) = bidirectional::pay_by_customer_phase1(&pp, &channel, 
	                                                                    &c_data.channel_token, // channel token
	                                                                    &m_keypair.pk, // merchant verification key
	                                                                    &c_data.csk, // current wallet
	                                                                    5); // balance increment
		                                    
	// get the refund token (rt_w) from the merchant
	let rt_w = bidirectional::pay_by_merchant_phase1(&pp, &mut channel, &pay_proof, &m_data));
	
	// generate the revocation token (rv_w) on the old public key (wpk)
	let rv_w = bidirectional::pay_by_customer_phase2(&pp, &c_data.csk, &new_w, &m_keypair.pk, &rt_w));
	
	// get the signature on the new wallet from merchant
	let new_w_sig = bidirectional::pay_by_merchant_phase2(&pp, &mut channel, &pay_proof, &mut m_data, &rv_w));
		
	// complete the final step of pay protocol - verify merchant signature on wallet 
	assert!(bidirectional::pay_by_customer_final(&pp, &m_keypair.pk, &mut c_data, t_c, new_w, new_w_sig));

### Channel Closure Algorithms

To close a channel, the customer must execute the `bidirectional::customer_refund()` routine as follows:

	let cust_wallet = &c_data.csk;
	let rc_c = bidirectional::customer_refund(&pp, &channel, &m_keypair.pk, &cust_wallet);
	
The merchant can dispute a customer's claim by executing the `bidirectional::merchant_retute()` routine as follows:

	let channel_token = &c_data.channel_token;
	let rc_m = bidirectional::merchant_refute(&pp, &mut channel, &channel_token, &m_data, &rc_c, &rv_w.signature);

	
To resolve a dispute between a customer and a merchant, the following routine is executed by the network:
	
	let (new_b0_cust, new_b0_merch) = bidirectional::resolve(&pp, &c_data, &m_data,
	                                                         Some(rc_c), Some(rc_m), Some(rt_w));
	                                                         
`new_b0_cust` and `new_b0_merch` represent the new balances for the customer and merchant (respectively).

## Third-party Payment Support

The bidirectional payment channels can be used to construct third-party payments in which a party **A** pays a second party **B** through an untrusted intermediary (**I**) to which both **A** and **B** have already established a channel. With BOLT, the intermediary learns nothing about the payment from **A** to **B** and cannot link transactions to individual users. 

To enable third-party payment support, initialize each payment channel as follows:
		
		
	let pp = bidirectional::setup(true);
	
	// create the channel state for each channel and indicate third-party support 
	let mut channel_a = bidirectional::ChannelState::new(String::from("Channel A -> I"), true);
	let mut channel_b = bidirectional::ChannelState::new(String::from("Channel B -> I"), true);
	
Moreover, the intermediary can set a channel fee as follows:
	
	channel_a.set_channel_fee(5);

The channel establishment still works as described before and the pay protocol includes an additional step to verify that the payments on both channels cancel out or include a channel fee (if specified).

	
	...
	
	let payment_amount = 20;
	// get payment proof on first channel with party A (and I)
	let (t_c1, new_w1, pay_proof1) = bidirectional::pay_by_customer_phase1(&pp, &channel_a,
	                                                                    &c1_data.channel_token, // channel token
	                                                                    &merch_keys.pk, // merchant pub key
	                                                                    &c1_data.csk, // wallet
	                                                                    payment_amount); // bal inc
	// get payment proof on second channel with party B (and I)
	let (t_c2, new_w2, pay_proof2) = bidirectional::pay_by_customer_phase1(&pp, &channel2,
                                                                           &c2_data.channel_token, // channel token
	                                                                       &m_keys.pk, // merchant pub key
	                                                                       &c2_data.csk, // wallet
                                                                          -payment_amount); // bal dec
                                                               
	// verify that the payment proof is valid and cancels out or results in a fee
	let tx_fee = channel_a.get_channel_fee() + channel_b.get_channel_fee();
	assert!(bidirectional::verify_third_party_payment(&pp, tx_fee, &pay_proof1.bal_proof, &pay_proof2.bal_proof));
	
	...


# Documentation

Build the api documentation by simply running `make doc`. Documentation will be generated in your local `target/doc` directory.

For the libbolt design documentation, see the `docs/bolt_design.pdf` document.

# Contributions

To contribute code improvements, please checkout the repository, make your changes and submit a pull request.

	git clone https://github.com/yeletech/libbolt.git

# TODOs

Here are some TODOs (not in any particular order):

* Serialization support for libbolt structures such as `CustomerWallet`, `PaymentProof`, and so on.
* Support for other curves (e.g., pairing library from Zcash)
* Finish unidirectional channel construction
* Fix warnings
* Add more unit tests for other dispute resolution scenarios and pay protocol (to ensure appopriate aborts), third-party test cases, etc.
	
# License

Licensed under MIT (LICENSE-MIT or http://opensource.org/licenses/MIT)
