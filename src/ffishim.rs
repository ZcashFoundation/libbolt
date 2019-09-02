#[no_mangle]
pub mod ffishim {
    extern crate libc;

    use bidirectional;
    use ff::Rand;
    use pairing::bls12_381::{Bls12};

    use serde::Deserialize;

    use libc::c_char;
    use std::ffi::{CStr, CString};
    use std::str;
    use channels::{ChannelcloseM, ResultBoltType, BoltError};
    use std::alloc::handle_alloc_error;

    fn error_message(s: String) -> *mut c_char {
        let ser = ["{\'error\':", serde_json::to_string(&s).unwrap().as_str(), "}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    macro_rules! bolt_try {
        ($e:expr) => (match $e {
            Ok(val) => val.unwrap(),
            Err(err) => return error_message(err),
        });
    }

    macro_rules! handle_errors {
        ($e:expr) => (match $e {
            Ok(val) => val,
            Err(err) => return error_message(err.to_string()),
        });
    }

    pub type ResultSerdeType<T> = Result<T, serde_json::error::Error>;

//    fn deserialize_object<'a, T>(serialized: *mut c_char) -> T
//	where
//	    T: Deserialize<'a>,
//	{
//	    let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
//	    let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
//	    serde_json::from_str(&string).unwrap()
//	}
//
//    fn deserialize_optional_object<'a, T>(serialized: *mut c_char) -> Option<T>
//    where
//        T: Deserialize<'a>,
//    {
//        let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
//        let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
//        Some(serde_json::from_str(&string).unwrap())
//    }

    fn deserialize_result_object<'a, T>(serialized: *mut c_char) -> ResultSerdeType<T>
    where
        T: Deserialize<'a>,
    {
        let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
        let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
        serde_json::from_str(&string)
    }

    #[no_mangle]
    pub extern fn ffishim_free_string(pointer: *mut c_char) {
        unsafe{
            if pointer.is_null() { return }
            CString::from_raw(pointer)
        };
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_wtp_check_wpk(ser_wpk: *mut c_char) -> *mut c_char {
        let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
        let wpk = handle_errors!(wpk_result);

        let res = true;
        let ser = ["{\'result\':\'", serde_json::to_string(&res).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()

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
        let rng = &mut rand::thread_rng();
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

	    let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
	    let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let (channel_token, mut merch_state) = bidirectional::init_merchant(rng, &mut channel_state, name);
        // initialize the balance for merch_state
        merch_state.init_balance(balance);

        let ser = ["{\'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(), "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str() ,"\'}"].concat();

        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_init_customer(ser_channel_state: *mut c_char, ser_channel_token: *mut c_char, balance_customer: i32,  balance_merchant: i32, name_ptr: *const c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<bidirectional::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let mut channel_token = handle_errors!(channel_token_result);

        // Deserialize the name
	    let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
	    let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        // We change the channel state
        let cust_state = bidirectional::init_customer(rng, &channel_state, &mut channel_token, balance_customer, balance_merchant, name);
        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\', \'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // ESTABLISH

    #[no_mangle] // bidirectional::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_state);
    pub extern fn ffishim_bidirectional_establish_customer_generate_proof(ser_channel_token: *mut c_char, ser_customer_wallet: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
         // Deserialize the channel token
        let channel_token_result: ResultSerdeType<bidirectional::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let mut channel_token = handle_errors!(channel_token_result);

        // Deserialize the cust wallet
        let cust_state_result: ResultSerdeType<bidirectional::CustomerState<Bls12>> = deserialize_result_object(ser_customer_wallet);
        let mut cust_state= handle_errors!(cust_state_result);

        let (com, com_proof) = bidirectional::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_state);

        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(),
                          "\', \'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(),
                          "\', \'com\':\'", serde_json::to_string(&com).unwrap().as_str(),
                          "\', \'com_proof\':\'", serde_json::to_string(&com_proof).unwrap().as_str(),
                          "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_establish_merchant_issue_close_token(ser_channel_state: *mut c_char, ser_com: *mut c_char, ser_com_proof: *mut c_char, init_cust_bal: i32, init_merch_bal: i32, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the com proof
        let com_result: ResultSerdeType<bidirectional::Commitment<Bls12>> = deserialize_result_object(ser_com);
        let com = handle_errors!(com_result);

        // Deserialize the com proof
        let com_proof_result: ResultSerdeType<bidirectional::CommitmentProof<Bls12>> = deserialize_result_object(ser_com_proof);
        let com_proof = handle_errors!(com_proof_result);

        // Deserialize the merchant wallet
        let merch_state_result: ResultSerdeType<bidirectional::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        let close_token = bolt_try!(bidirectional::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof, init_cust_bal, init_merch_bal, &merch_state));

        let ser = ["{\'close_token\':\'", serde_json::to_string(&close_token).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_establish_merchant_issue_pay_token(ser_channel_state: *mut c_char, ser_com: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the commitment
        let com_result: ResultSerdeType<bidirectional::Commitment<Bls12>> = deserialize_result_object(ser_com);
        let com= handle_errors!(com_result);

        // Deserialize the merchant wallet
        let merch_state_result: ResultSerdeType<bidirectional::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        let pay_token = bidirectional::establish_merchant_issue_pay_token(rng, &channel_state, &com, &merch_state);

        let ser = ["{\'pay_token\':\'", serde_json::to_string(&pay_token).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_verify_close_token(ser_channel_state: *mut c_char, ser_customer_wallet: *mut c_char, ser_close_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);
        
        // Deserialize the cust wallet
        let cust_state_result: ResultSerdeType<bidirectional::CustomerState<Bls12>> = deserialize_result_object(ser_customer_wallet);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the close token
        let close_result: ResultSerdeType<bidirectional::Signature<Bls12>> = deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_result);

        let is_close_token_valid = cust_state.verify_close_token(&mut channel_state, &close_token);

        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(),
                          "\', \'is_token_valid\':\'", serde_json::to_string(&is_close_token_valid).unwrap().as_str(),
                          "\', \'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }


    #[no_mangle]
    pub extern fn ffishim_bidirectional_establish_customer_final(ser_channel_state: *mut c_char, ser_customer_wallet: *mut c_char, ser_pay_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust wallet
        let cust_state_result: ResultSerdeType<bidirectional::CustomerState<Bls12>> = deserialize_result_object(ser_customer_wallet);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the custdata
        let pay_token_result: ResultSerdeType<bidirectional::Signature<Bls12>> = deserialize_result_object(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);

        let is_channel_established = bidirectional::establish_customer_final(&mut channel_state, &mut cust_state, &pay_token);

        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(),
                          "\', \'is_established\':\'", serde_json::to_string(&is_channel_established).unwrap().as_str(),
                          "\', \'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // PAY

    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_generate_payment_proof(ser_channel_state: *mut c_char, ser_customer_wallet: *mut c_char, amount: i32) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust wallet
        let cust_state_result: ResultSerdeType<bidirectional::CustomerState<Bls12>> = deserialize_result_object(ser_customer_wallet);
        let cust_state = handle_errors!(cust_state_result);

        // Generate the payment proof
        let (payment, new_cust_state) = bidirectional::generate_payment_proof(rng, &channel_state, &cust_state, amount);
        // Serialize the results and return to caller
        let ser = ["{\'payment\':\'", serde_json::to_string(&payment).unwrap().as_str(),
                          "\', \'cust_state\':\'", serde_json::to_string(&new_cust_state).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_verify_payment_proof(ser_channel_state: *mut c_char, ser_pay_proof: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the payment proof
        let payment_result: ResultSerdeType<bidirectional::Payment<Bls12>> = deserialize_result_object(ser_pay_proof);
        let payment = handle_errors!(payment_result);

        // Deserialize the merch wallet
        let merch_state_result: ResultSerdeType<bidirectional::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let close_token = bidirectional::verify_payment_proof(rng, &channel_state, &payment, &mut merch_state);
        let ser = ["{\'close_token\':\'", serde_json::to_string(&close_token).unwrap().as_str(),
                          "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_generate_revoke_token(ser_channel_state: *mut c_char, ser_cust_state: *mut c_char, ser_new_cust_state: *mut c_char, ser_close_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust wallet
        let cust_state_result: ResultSerdeType<bidirectional::CustomerState<Bls12>> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the cust wallet
        let new_cust_state_result: ResultSerdeType<bidirectional::CustomerState<Bls12>> = deserialize_result_object(ser_new_cust_state);
        let new_cust_state = handle_errors!(new_cust_state_result);

        // Deserialize the close token
        let close_token_result: ResultSerdeType<bidirectional::Signature<Bls12>> = deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_token_result);

        let revoke_token = bidirectional::generate_revoke_token(&channel_state, &mut cust_state, new_cust_state, &close_token);
        let ser = ["{\'revoke_token\':\'", serde_json::to_string(&revoke_token).unwrap().as_str(),
                          "\', \'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_verify_revoke_token(ser_revoke_token: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize the revoke token
        let revoke_token_result: ResultSerdeType<bidirectional::RevokeToken> = deserialize_result_object(ser_revoke_token);
        let revoke_token= handle_errors!(revoke_token_result);

        // Deserialize the cust wallet
        let merch_state_result: ResultSerdeType<bidirectional::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // send revoke token and get pay-token in response
        let pay_token = bidirectional::verify_revoke_token(&revoke_token, &mut merch_state);
        let ser = ["{\'pay_token\':\'", serde_json::to_string(&pay_token).unwrap().as_str(),
                          "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str() ,"\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }


    #[no_mangle]
    pub extern fn ffishim_bidirectional_pay_verify_payment_token(ser_channel_state: *mut c_char, ser_cust_state: *mut c_char, ser_pay_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust wallet
        let cust_state_result: ResultSerdeType<bidirectional::CustomerState<Bls12>> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the pay token
        let pay_token_result: ResultSerdeType<bidirectional::Signature<Bls12>> = deserialize_result_object(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);

        // verify the pay token and update internal state
        let is_pay_valid = cust_state.verify_pay_token(&channel_state, &pay_token);
        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(),
                          "\', \'is_pay_valid\':\'", serde_json::to_string(&is_pay_valid).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // CLOSE

    #[no_mangle]
    pub extern fn ffishim_bidirectional_customer_close(ser_channel_state: *mut c_char, ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust wallet
        let cust_state_result: ResultSerdeType<bidirectional::CustomerState<Bls12>> = deserialize_result_object(ser_cust_state);
        let cust_state = handle_errors!(cust_state_result);

        let cust_close = bidirectional::customer_close(&channel_state, &cust_state);
        let ser = ["{\'cust_close\':\'", serde_json::to_string(&cust_close).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_merchant_close(ser_channel_state: *mut c_char, ser_channel_token: *mut c_char, ser_address: *const c_char, ser_cust_close: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<bidirectional::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

         // Deserialize the channel token
        let channel_token_result: ResultSerdeType<bidirectional::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the customer close structure
        let cust_close_result: ResultSerdeType<bidirectional::ChannelcloseC<Bls12>> = deserialize_result_object(ser_cust_close);
        let cust_close = handle_errors!(cust_close_result);

        // Deserialize the merch wallet
        let merch_state_result: ResultSerdeType<bidirectional::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        // Deserialize the destination address as a string
        let ser_addr_bytes = unsafe { CStr::from_ptr(ser_address).to_bytes() };
        let address: &str = str::from_utf8(ser_addr_bytes).unwrap(); // make sure the bytes are UTF-8

        let option = bidirectional::merchant_close(&channel_state, &channel_token, &cust_close, &merch_state);
        let keys = match option {
            Ok(n) => n.unwrap(),
            Err(err) => return error_message(err),
        };

        let merch_close: bidirectional::ChannelcloseM = merch_state.sign_revoke_message(address.to_string(), &keys.revoke_token);

        let ser = ["{\'wpk\':\'", serde_json::to_string(&keys.wpk).unwrap().as_str(),
                "\', \'merch_close\':\'", serde_json::to_string(&merch_close).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_wtp_verify_cust_close_message(ser_channel_token: *mut c_char, ser_wpk: *mut c_char, ser_close_msg: *mut c_char, ser_close_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<bidirectional::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the wpk
        let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
        let wpk = handle_errors!(wpk_result);

        // Deserialize the close wallet
        let close_msg_result: ResultSerdeType<bidirectional::Wallet<Bls12>> = deserialize_result_object(ser_close_msg);
        let close_msg = handle_errors!(close_msg_result);

        // Deserialize the close token
        let close_token_result: ResultSerdeType<bidirectional::Signature<Bls12>> = deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_token_result);

        // check the signatures
        let token_valid = bidirectional::wtp_verify_cust_close_message(&channel_token, &wpk, &close_msg, &close_token);
        let ser = ["{\"result\":\"", serde_json::to_string(&token_valid).unwrap().as_str(), "\"}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_bidirectional_wtp_verify_merch_close_message(ser_channel_token: *mut c_char, ser_wpk: *mut c_char, ser_merch_close: *mut c_char) -> *mut c_char {
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<bidirectional::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the wpk
        let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
        let wpk = handle_errors!(wpk_result);

        // Deserialize the merch close
        //let revoke_token: secp256k1::Signature = deserialize_object(ser_revoke_token);
        let merch_close_result: ResultSerdeType<bidirectional::ChannelcloseM> = deserialize_result_object(ser_merch_close);
        let merch_close = handle_errors!(merch_close_result);

        let revoke_token_valid = bidirectional::wtp_verify_revoke_message(&wpk, &merch_close.revoke.unwrap());
        let merch_close_valid = bidirectional::wtp_verify_merch_close_message(&channel_token, &merch_close);
        let token_valid = revoke_token_valid && merch_close_valid;

        let ser = ["{\'result\':\'", serde_json::to_string(&token_valid).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }
}
