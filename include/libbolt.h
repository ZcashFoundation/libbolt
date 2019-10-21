#ifndef LIBBOLT_INCLUDE_H_
#define LIBBOLT_INCLUDE_H_

#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

using namespace rapidjson;

extern "C" {
#endif

// channel init
char* ffishim_bidirectional_channel_setup(const char *channel_name, unsigned int third_party_support);
char* ffishim_bidirectional_init_merchant(const char *ser_channel_state, const char *name_ptr);
char* ffishim_bidirectional_init_customer(const char *ser_channel_token, long long int balance_customer,  long long int balance_merchant, const char *name_ptr);

// channel establish protocol routines
char* ffishim_bidirectional_establish_customer_generate_proof(const char *ser_channel_token, const char *ser_customer_wallet);
char* ffishim_bidirectional_establish_merchant_issue_close_token(const char *ser_channel_state, const char *ser_com, const char *ser_com_proof, const char *ser_pk_c, long long int init_cust_bal, long long int init_merch_bal, const char *ser_merch_state);
char* ffishim_bidirectional_establish_merchant_issue_pay_token(const char *ser_channel_state, const char *ser_com, const char *ser_merch_state);
char* ffishim_bidirectional_verify_close_token(const char *ser_channel_state, const char *ser_customer_wallet, const char *ser_close_token);
char* ffishim_bidirectional_establish_customer_final(const char *ser_channel_state, const char *ser_customer_wallet, const char *ser_pay_token);

// channel pay protocol routines
char* ffishim_bidirectional_pay_generate_payment_proof(const char *ser_channel_state, const char *ser_customer_wallet, long long int amount);
char* ffishim_bidirectional_pay_verify_payment_proof(const char *ser_channel_state, const char *ser_pay_proof, const char *ser_merch_state);
char* ffishim_bidirectional_pay_verify_multiple_payment_proofs(const char *ser_channel_state, const char *ser_sender_pay_proof, const char *ser_receiver_pay_proof, const char *ser_merch_state);
char* ffishim_bidirectional_pay_generate_revoke_token(const char *ser_channel_state, const char *ser_cust_state, const char *ser_new_cust_state, const char *ser_close_token);
char* ffishim_bidirectional_pay_verify_revoke_token(const char *ser_revoke_token, const char *ser_merch_state);
char* ffishim_bidirectional_pay_verify_multiple_revoke_tokens(const char *ser_sender_revoke_token, const char *ser_receiver_revoke_token, const char *ser_merch_state);
char* ffishim_bidirectional_pay_verify_payment_token(const char *ser_channel_state, const char *ser_cust_state, const char *ser_pay_token);

// closing routines for both sides
char* ffishim_bidirectional_customer_close(const char *ser_channel_state, const char *ser_cust_state);
char* ffishim_bidirectional_merchant_close(const char *ser_channel_state, const char *ser_channel_token, const char *ser_address, const char *ser_cust_close, const char *ser_merch_state);

// WTP logic for on-chain validation of closing messages
char* ffishim_bidirectional_wtp_verify_cust_close_message(const char *ser_channel_token, const char *ser_wpk, const char *ser_close_msg, const char *ser_close_token);
char* ffishim_bidirectional_wtp_verify_merch_close_message(const char *ser_channel_token, const char *ser_wpk, const char *ser_merch_close);

char* ffishim_bidirectional_wtp_check_wpk(const char *wpk);

#ifdef __cplusplus

  const char* string_replace_all(const char* previous_string, char old_char, char new_char)
  {
    std::string s(previous_string);
    std::string old_c(1,old_char);
    std::string new_c(1,new_char);
    size_t index;
    while ((index = s.find(old_c)) != std::string::npos) {
        s.replace(index, 1, new_c);
    }

    printf("STRING: %s\n", s.c_str());
    return s.c_str();
  }

  int wtp_check_wpk(const char *wpk)
  {
      const char *ret = ffishim_bidirectional_wtp_check_wpk(wpk);
      printf("RESULT: %s\n", ret);
      return 0;
  }


  /* Purpose: verify cust close message
  * Arguments: take as input the channel token and wpk
  *
  * Returns: 0 (false) or 1 (true)
  */
  int wtp_verify_cust_close_message(const char *channel_token, const char *wpk, const char *cust_close, const char *close_token)
  {
    // Call rust
    const char *return_json = ffishim_bidirectional_wtp_verify_cust_close_message(channel_token, wpk, cust_close, close_token);

    Document d;
    d.Parse(return_json);
    // Make sure we arent going to get an error when indexing into the JSON
    assert(d.HasMember("result"));
    Value& s = d["result"];

    // If the return_value is true, then return 1.  Otherwise, just assume 0
    if( std::string(s.GetString()).compare(std::string("true")) == 0)
    {
      return 1;
    }
    return 0;
  }

  /* Purpose: verify merch close message
  * Arguments: take as input the master pub params for CL (pp), serialized channel closure message (rc_c),
  *
  * Returns: 0 (false) or 1 (true)
  */
  int wtp_verify_merch_close_message(const char *channel_token, const char *wpk, const char *merch_close)
  {
    // Call into Rust
    const char* return_json = string_replace_all(ffishim_bidirectional_wtp_verify_merch_close_message(channel_token, wpk, merch_close), '\'', '\"');

    Document d;
    d.Parse(return_json);
    // Make sure we arent going to get an error when indexing into the JSON
    assert(d.HasMember("result"));
    Value& s = d["result"];

    // If the return_value is true, then return 1.  Otherwise, just assume 0
    if( std::string(s.GetString()).compare(std::string("true")) == 0)
    {
      return 1;
    }
    return 0;
  }
}
#endif // end c++ check

#endif // LIBBOLT_INCLUDE_H_
