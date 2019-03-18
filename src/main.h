#ifndef _MAIN_H_
#define _MAIN_H_

using namespace std;

#ifdef __cplusplus
extern "C" {
#endif

char* ffishim_validate_channel_open(const char *tc_c, const char *m);

char* ffishim_validate_channel_close(const char *pp, const char *rc_c, const char *pk_m);

char* ffishim_resolve_channel_dispute(const char *pp, const char *rc_c, const char *tc_c, const char *rc_m, const char *pk_m);

#ifdef __cplusplus
}
#endif


#endif