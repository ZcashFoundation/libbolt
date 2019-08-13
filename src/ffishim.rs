#[no_mangle]
pub mod ffishim {
    extern crate libc;

    use bidirectional;
    use ff::Rand;
    use pairing::bls12_381::{Bls12};

    use serde::{Serialize, Deserialize};

    use libc::{c_uchar, c_char}; // c_char
    use std::ffi::{CStr, CString};
    use std::str;
    use std::mem;

    fn error_message(s: String) -> *mut c_char {
        let ser = ["{\'error\':\'", serde_json::to_string(&s).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    macro_rules! bolt_try {
        ($e:expr) => (match $e {
            Ok(val) => val.unwrap(),
            Err(err) => return error_message(err),
        });
    }

    fn deserialize_object<'a, T>(serialized: *mut c_char) -> T
	where
	    T: Deserialize<'a>,
	{  // TODO make this a result with nice error handling
	    let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
	    let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
	    serde_json::from_str(&string).unwrap()
	}

    fn deserialize_optional_object<'a, T>(serialized: *mut c_char) -> Option<T>
    where
        T: Deserialize<'a>,
    {  // TODO make this a result with nice error handling
        let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
        let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
        Some(serde_json::from_str(&string).unwrap())
    }

    #[no_mangle]
    pub extern fn ffishim_free_string(pointer: *mut c_char) {
        unsafe{
            if pointer.is_null() { return }
            CString::from_raw(pointer)
        };
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_channel_setup(channel_name: *const c_char, third_party_support: u32) -> *mut c_char {
        let bytes = unsafe { CStr::from_ptr(channel_name).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let mut tps = false;
        if third_party_support > 1 {
            tps = true;
        }
        let mut channel_state = bidirectional::ChannelState::<Bls12>::new(name.to_string(), tps);
        let mut rng = &mut rand::thread_rng();

        channel_state.setup(&mut rng);
        let ser = ["{\'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // INIT

    #[no_mangle]
    pub extern fn ffishim_bidirectional_init_merchant(ser_channel_state: *mut c_char, balance: i32, name_ptr: *const c_char) -> *mut c_char {
        let mut rng = &mut rand::thread_rng();
        let mut channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);

	    let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
	    let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let (channel_token, mut merch_wallet) = bidirectional::init_merchant(rng, &mut channel_state, name);
        // initialize the balance for merch_wallet
        merch_wallet.init_balance(balance);

        let ser = ["{\'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(), "\', \'merch_wallet\':\'", serde_json::to_string(&merch_wallet).unwrap().as_str() ,"\'}"].concat();

        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_init_customer(ser_channel_state: *mut c_char, ser_channel_token: *mut c_char, balance_customer: i32,  balance_merchant: i32, name_ptr: *const c_char) -> *mut c_char {
        let mut rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);
        // Deserialize the channel token
        let mut channel_token: bidirectional::ChannelToken<Bls12> = deserialize_object(ser_channel_token);
        // Deserialize the name
	    let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
	    let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        // We change the channel state
        let cust_wallet = bidirectional::init_customer(rng, &channel_state, &mut channel_token, balance_customer, balance_merchant, name);
        let ser = ["{\'cust_wallet\':\'", serde_json::to_string(&cust_wallet).unwrap().as_str(), "\', \'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // ESTABLISH

    #[no_mangle] // bidirectional::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_wallet);
    pub extern fn ffishim_bidirectional_establish_customer_generate_proof(ser_channel_token: *mut c_char,
                                                                          ser_customer_wallet: *mut c_char) -> *mut c_char {
        let mut rng = &mut rand::thread_rng();
         // Deserialize the channel token
        let mut channel_token: bidirectional::ChannelToken<Bls12> = deserialize_object(ser_channel_token);

        // Deserialize the cust wallet
        let mut cust_wallet: bidirectional::CustomerWallet<Bls12> = deserialize_object(ser_customer_wallet);

        let (com, com_proof) = bidirectional::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_wallet);

        let ser = ["{\'cust_wallet\':\'", serde_json::to_string(&cust_wallet).unwrap().as_str(),
                          "\', \'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(),
                          "\', \'com\':\'", serde_json::to_string(&com).unwrap().as_str(),
                          "\', \'com_proof\':\'", serde_json::to_string(&com_proof).unwrap().as_str(),
                          "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_establish_merchant_issue_close_token(ser_channel_state: *mut c_char, ser_com: *mut c_char, ser_com_proof: *mut c_char, ser_merch_wallet: *mut c_char) -> *mut c_char {
        let mut rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);

        // Deserialize the com proof
        let com: bidirectional::Commitment<Bls12> = deserialize_object(ser_com);

        // Deserialize the com proof
        let com_proof: bidirectional::CommitmentProof<Bls12> = deserialize_object(ser_com_proof);

        // Deserialize the merchant wallet
        let merch_wallet: bidirectional::MerchantWallet<Bls12> = deserialize_object(ser_merch_wallet);

        let close_token = bolt_try!(bidirectional::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof, &merch_wallet));

        let ser = ["{\'close_token\':\'", serde_json::to_string(&close_token).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_establish_merchant_issue_pay_token(ser_channel_state: *mut c_char, ser_com: *mut c_char, ser_merch_wallet: *mut c_char) -> *mut c_char {
        let mut rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);

        // Deserialize the com proof
        let com: bidirectional::Commitment<Bls12> = deserialize_object(ser_com);

        // Deserialize the merchant wallet
        let merch_wallet: bidirectional::MerchantWallet<Bls12> = deserialize_object(ser_merch_wallet);

        let pay_token = bidirectional::establish_merchant_issue_pay_token(rng, &channel_state, &com, &merch_wallet);

        let ser = ["{\'pay_token\':\'", serde_json::to_string(&pay_token).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_verify_close_token(ser_channel_state: *mut c_char, ser_customer_wallet: *mut c_char, ser_close_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let mut channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);

        // Deserialize the cust wallet
        let mut cust_wallet: bidirectional::CustomerWallet<Bls12> = deserialize_object(ser_customer_wallet);

        // Deserialize the close token
        let close_token: bidirectional::Signature<Bls12> = deserialize_object(ser_close_token);

        let is_close_token_valid = cust_wallet.verify_close_token(&mut channel_state, &close_token);

        let ser = ["{\'cust_wallet\':\'", serde_json::to_string(&cust_wallet).unwrap().as_str(),
                          "\', \'is_token_valid\':\'", serde_json::to_string(&is_close_token_valid).unwrap().as_str(),
                          "\', \'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }


    #[no_mangle]
    pub extern fn ffishim_bidirectional_establish_customer_final(ser_channel_state: *mut c_char, ser_customer_wallet: *mut c_char, ser_pay_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let mut channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);

        // Deserialize the cust wallet
        let mut cust_wallet: bidirectional::CustomerWallet<Bls12> = deserialize_object(ser_customer_wallet);

        // Deserialize the custdata
        let pay_token: bidirectional::Signature<Bls12> = deserialize_object(ser_pay_token);

        let is_channel_established = bidirectional::establish_customer_final(&mut channel_state, &mut cust_wallet, &pay_token);

        let ser = ["{\'cust_wallet\':\'", serde_json::to_string(&cust_wallet).unwrap().as_str(),
                          "\', \'is_established\':\'", serde_json::to_string(&is_channel_established).unwrap().as_str(),
                          "\', \'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // PAY

    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_generate_payment_proof(ser_channel_state: *mut c_char,
                                                                   ser_customer_wallet: *mut c_char,
                                                                   amount: i32) -> *mut c_char {
        let mut rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);

        // Deserialize the cust wallet
        let cust_wallet: bidirectional::CustomerWallet<Bls12> = deserialize_object(ser_customer_wallet);

        let (payment, new_cust_wallet) = bidirectional::generate_payment_proof(rng, &channel_state, &cust_wallet, amount);
        let ser = ["{\'payment\':\'", serde_json::to_string(&payment).unwrap().as_str(),
                          "\', \'cust_wallet\':\'", serde_json::to_string(&new_cust_wallet).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_verify_payment_proof(ser_channel_state: *mut c_char,
                                                                 ser_pay_proof: *mut c_char,
                                                                 ser_merch_wallet: *mut c_char) -> *mut c_char {
        let mut rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);

        // Deserialize the payment proof
        let payment: bidirectional::Payment<Bls12> = deserialize_object(ser_pay_proof);

        // Deserialize the merch wallet
        let mut merch_wallet: bidirectional::MerchantWallet<Bls12> = deserialize_object(ser_merch_wallet);

        let close_token = bidirectional::verify_payment_proof(rng, &channel_state, &payment, &mut merch_wallet);
        let ser = ["{\'close_token\':\'", serde_json::to_string(&close_token).unwrap().as_str(),
                          "\', \'merch_wallet\':\'", serde_json::to_string(&merch_wallet).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_generate_revoke_token(ser_channel_state: *mut c_char,
                                                                  ser_cust_wallet: *mut c_char,
                                                                  ser_new_cust_wallet: *mut c_char,
                                                                  ser_close_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);
        // Deserialize the cust wallet
        let mut cust_wallet: bidirectional::CustomerWallet<Bls12> = deserialize_object(ser_cust_wallet);
        // Deserialize the cust wallet
        let new_cust_wallet: bidirectional::CustomerWallet<Bls12> = deserialize_object(ser_new_cust_wallet);
        // Deserialize the close token
        let close_token: bidirectional::Signature<Bls12> = deserialize_object(ser_close_token);

        let revoke_token = bidirectional::generate_revoke_token(&channel_state, &mut cust_wallet, new_cust_wallet, &close_token);
        let ser = ["{\'revoke_token\':\'", serde_json::to_string(&revoke_token).unwrap().as_str(),
                          "\', \'cust_wallet\':\'", serde_json::to_string(&cust_wallet).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_verify_revoke_token(ser_revoke_token: *mut c_char,
                                                                ser_merch_wallet: *mut c_char) -> *mut c_char {
        // Deserialize the revoke token
        let revoke_token: bidirectional::RevokeToken = deserialize_object(ser_revoke_token);
        // Deserialize the cust wallet
        let mut merch_wallet: bidirectional::MerchantWallet<Bls12> = deserialize_object(ser_merch_wallet);
        // send revoke token and get pay-token in response
        let pay_token = bidirectional::verify_revoke_token(&revoke_token, &mut merch_wallet);
        let ser = ["{\'pay_token\':\'", serde_json::to_string(&pay_token).unwrap().as_str(),
                          "\', \'merch_wallet\':\'", serde_json::to_string(&merch_wallet).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }


    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_verify_payment_token(ser_channel_state: *mut c_char, ser_cust_wallet: *mut c_char, ser_pay_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);
        // Deserialize the cust wallet
        let mut cust_wallet: bidirectional::CustomerWallet<Bls12> = deserialize_object(ser_cust_wallet);
        // Deserialize the pay token
        let pay_token: bidirectional::Signature<Bls12> = deserialize_object(ser_pay_token);

        // verify the pay token and update internal state
        let is_pay_valid = cust_wallet.verify_pay_token(&channel_state, &pay_token);
        let ser = ["{\'cust_wallet\':\'", serde_json::to_string(&cust_wallet).unwrap().as_str(),
                          "\', \'is_pay_valid\':\'", serde_json::to_string(&is_pay_valid).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // CLOSE

    #[no_mangle]
    pub extern fn ffishim_bidirectional_customer_close(ser_channel_state: *mut c_char,
                                                        ser_cust_wallet: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state: bidirectional::ChannelState<Bls12> = deserialize_object(ser_channel_state);
        // Deserialize the cust wallet
        let cust_wallet: bidirectional::CustomerWallet<Bls12> = deserialize_object(ser_cust_wallet);

        let cust_close = bidirectional::customer_close(&channel_state, &cust_wallet);
        let ser = ["{\'cust_close\':\'", serde_json::to_string(&cust_close).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

}

//    #[no_mangle]
//    pub extern fn ffishim_bidirectional_merchant_refund(serialized_pp: *mut c_char, serialized_channel: *mut c_char, serialized_channel_token: *mut c_char, serialized_merchant_data: *mut c_char,  serialized_channel_closure: *mut c_char, serialized_revoke_token: *mut c_char) -> *mut c_char {
//        // Deserialize the pp
//        let deserialized_pp: bidirectional::PublicParams = deserialize_object(serialized_pp);
//
//        // Deserialize the channel state
//        let mut deserialized_channel_state: bidirectional::ChannelState = deserialize_object(serialized_channel);
//
//        // Deserialize the channel token
//        let deserialized_channel_token: bidirectional::ChannelToken = deserialize_object(serialized_channel_token);
//
//        // Deserialize the merchant data
//        let deserialized_merchant_data: bidirectional::InitMerchantData = deserialize_object(serialized_merchant_data);
//
//        // Deserialize the closure
//        let deserialized_channel_closure: bidirectional::ChannelclosureC = deserialize_object(serialized_channel_closure);
//
//        // Deserialize the revoke_token
//        let deserialized_revoke_token: secp256k1::Signature = deserialize_object(serialized_revoke_token);
//
//        let rc_m = bidirectional::merchant_refute(&deserialized_pp, &mut deserialized_channel_state, &deserialized_channel_token, &deserialized_merchant_data, &deserialized_channel_closure, &deserialized_revoke_token);
//        let ser = ["{\'rc_m\':\'", serde_json::to_string(&rc_m).unwrap().as_str(), "\', \'state\':\'", serde_json::to_string(&deserialized_channel_state).unwrap().as_str(), "\'}"].concat();
//        let cser = CString::new(ser).unwrap();
//        cser.into_raw()
//    }
//
//    #[no_mangle]
//    pub extern fn ffishim_bidirectional_resolve(serialized_pp: *mut c_char, serialized_customer_data: *mut c_char, serialized_merchant_data: *mut c_char, serialized_closure_customer: *mut c_char,  serialized_closure_merchant: *mut c_char) -> *mut c_char {
//        // Deserialize the pp
//        let deserialized_pp: bidirectional::PublicParams = deserialize_object(serialized_pp);
//
//        // Deserialize the custdata
//        let deserialized_customer_data: bidirectional::InitCustomerData = deserialize_object(serialized_customer_data);
//
//        // Deserialize the merchant data
//        let deserialized_merchant_data: bidirectional::InitMerchantData = deserialize_object(serialized_merchant_data);
//
//        //TODO handle none()
//
//        // Deserialize the client closure
//        let deserialized_closure_customer: bidirectional::ChannelclosureC = deserialize_object(serialized_closure_customer);
//
//        // Deserialize the merchant closure
//        let deserialized_closure_merchant: bidirectional::ChannelclosureM = deserialize_object(serialized_closure_merchant);
//
//        let (new_b0_cust, new_b0_merch) = bidirectional::resolve(&deserialized_pp, &deserialized_customer_data, &deserialized_merchant_data, Some(deserialized_closure_customer), Some(deserialized_closure_merchant));
//        let ser = ["{\'new_b0_cust\':\'", new_b0_cust.to_string().as_str(), "\', \'new_b0_merch\':\'", new_b0_merch.to_string().as_str(), "\'}"].concat();
//        let cser = CString::new(ser).unwrap();
//        cser.into_raw()
//    }
//
//    #[no_mangle]
//    pub extern fn ffishim_commit_scheme_decommit(serialized_csp: *mut c_char, serialized_commitment: *mut c_char, serialized_x: *mut c_char) -> *mut c_char {
//        // Deserialize the csp
//        let deserialized_csp: commit_scheme::CSParams = deserialize_object(serialized_csp);
//
//        // Deserialize the commit
//        let deserialized_commitment: commit_scheme::Commitment = deserialize_object(serialized_commitment);
//
//        // Deserialize the vec<fr> x
//        let deserialized_x: serialization_wrappers::VecFrWrapper = deserialize_object(serialized_x);
//            // Wrapper struct is required because Serde needs something to annotate
//
//        let ser = match commit_scheme::decommit(&deserialized_csp, &deserialized_commitment, &deserialized_x.0) {
//            false => "{\'return_value\':\'false\'}",
//            true => "{\'return_value\':\'true\'}",
//        };
//        let cser = CString::new(ser).unwrap();
//        cser.into_raw()
//    }
//
//    #[no_mangle]
//    pub extern fn ffishim_validate_channel_open(serialized_channel_token: *mut c_char, serialized_messages: *mut c_char) -> *mut c_char {
//
//        // Deserialize the channel token
//        let deserialized_channel_token: serialization_wrappers::WalletCommitmentAndParamsWrapper = deserialize_object(serialized_channel_token);
//
//        // Deserialize the vec<fr> x
//        let deserialized_messages: serialization_wrappers::VecFrWrapper = deserialize_object(serialized_messages);
//
//        let ser = match commit_scheme::decommit(&deserialized_channel_token.params, &deserialized_channel_token.com, &deserialized_messages.0) {
//            false => "{\'return_value\':\'false\'}",
//            true => "{\'return_value\':\'true\'}",
//        };
//        let cser = CString::new(ser).unwrap();
//        cser.into_raw()
//    }
//
//    #[no_mangle]
//    pub extern fn ffishim_validate_channel_close(serialized_pp: *mut c_char, serialized_closure_customer: *mut c_char, serialized_merchant_public_key: *mut c_char) -> *mut c_char {
//        // Deserialize the pp
//        let deserialized_pp: bidirectional::PublicParams = deserialize_object(serialized_pp);
//
//        // Deserialize the customer closure
//        let deserialized_closure_customer: bidirectional::ChannelclosureC = deserialize_object(serialized_closure_customer);
//
//        // Deserialize the merchant keypair
//        let deserialized_merchant_public_key: cl::PublicKey = deserialize_object(serialized_merchant_public_key);
//
//        //validate signature
//        let ser = match cl::verify_d(&deserialized_pp.cl_mpk, &deserialized_merchant_public_key, &deserialized_closure_customer.message.hash(), &deserialized_closure_customer.signature) {
//            false => "{\'return_value\':\'false\'}",
//            true => "{\'return_value\':\'true\'}",
//        };
//        let cser = CString::new(ser).unwrap();
//        cser.into_raw()
//    }
