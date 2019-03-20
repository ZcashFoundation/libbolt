#ifndef LIBBOLT_INCLUDE_H_
#define LIBBOLT_INCLUDE_H_

#include <stdint.h>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

using namespace rapidjson;

extern "C" {

  char* ffishim_validate_channel_open(const char *tc_c, const char *m);

  char* ffishim_validate_channel_close(const char *pp, const char *rc_c, const char *pk_m);

  char* ffishim_resolve_channel_dispute(const char *pp, const char *rc_c, const char *tc_c, const char *rc_m, const char *pk_m);

  const char* string_replace_all(const char* previous_string, char old_char, char new_char)
  {
    std::string s(previous_string);
    std::string old_c(1,old_char);
    std::string new_c(1,new_char);
    size_t index;
    while ((index = s.find(old_c)) != std::string::npos) {
        s.replace(index, 1, new_c);
    }
    return s.c_str();
  }

  /* Purpose: open channel
  * Arguments: take as input the channel token which consists of the serialized wallet commitment,
  * commitment pub params and a second arg (serialized vector of messages m).
  * Returns: 0 (false) or 1 (true)
  */
  int validate_channel_open(const char *tc_c, const char *m)
  {
    // Call into Rust
    const char* return_json = string_replace_all(ffishim_validate_channel_open(tc_c, m), '\'', '\"');

    Document d;
    d.Parse(return_json);
    // Make sure we arent going to get an error when indexing into the JSON
    assert(d.HasMember("return_value"));
    Value& s = d["return_value"];

    // If the return_value is true, then return 1.  Otherwise, just assume 0
    if( std::string(s.GetString()).compare(std::string("true")) == 0)
    {
      return 1;
    }
    return 0;
  }

  /* Purpose: close channel
  * Arguments: take as input the master pub params for CL (pp), serialized channel closure message (rc_c),
  * and serialized public key of merchant.
  * Returns: 0 (false) or 1 (true)
  */
  int validate_channel_close(const char *pp, const char *rc_c, const char *pk_m)
  {
    // Call into Rust
    const char* return_json = string_replace_all(ffishim_validate_channel_close(pp, rc_c, pk_m), '\'', '\"');

    Document d;
    d.Parse(return_json);
    // Make sure we arent going to get an error when indexing into the JSON
    assert(d.HasMember("return_value"));
    Value& s = d["return_value"];

    // If the return_value is true, then return 1.  Otherwise, just assume 0
    if( std::string(s.GetString()).compare(std::string("true")) == 0)
    {
      return 1;
    }
    return 0;
  }

  /* Purpose: dispute channel
  * Arguments: serialized pub params, channel closure for cust/merch and channel tokens for cust/merch
  * Returns: 0 (false) or 1 (true)
  * // TODO: figure out how to return the approp balance for cust/merch instead of true or false
  */
  int resolve_channel_dispute(const char *pp, const char *rc_c, const char *tc_c, const char *rc_m, const char *pk_m);
}
#endif // LIBBOLT_INCLUDE_H_
