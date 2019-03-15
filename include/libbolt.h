#ifndef LIBBOLT_INCLUDE_H_
#define LIBBOLT_INCLUDE_H_

#include <stdint.h>

extern "C" {

   /* Purpose: open channel
    * Arguments: take as input the serialized wallet commitment, commitment pub params and
    * serialized vector of messages (m).
    * Returns: 0 (false) or 1 (true)
    */
   int validate_channel_open(const char *w_com, const char *csp, const char *m);

   /* Purpose: close channel
    * Arguments: take as input the serialized channel closure message (rc_c), the master pub params for CL (pp),
    * and serialized public key of merchant.
    * Returns: 0 (false) or 1 (true)
    */
   int validate_channel_close(const char *rc_c, const char *pp, const char *pk_m);

   /* Purpose: dispute channel
    * Arguments: serialized pub params, channel closure for cust/merch and channel tokens for cust/merch
    * Returns: 0 (false) or 1 (true)
    * // TODO: figure out how to return the approp balance for cust/merch instead of true or false
    */
   int resolve_channel_dispute(const char *pp, const char *rc_c, const char *tc_c, const char *rc_m, const char *pk_m);
}
#endif // LIBBOLT_INCLUDE_H_
