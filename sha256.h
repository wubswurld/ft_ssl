#ifndef SHA256_H
#define SHA256_H

#include "ft_ssl.h"

void print_sha(t_sha256 *sp, t_whole *np);
void print_shaArg(char *str);
void print_sha256(char *str);
void update_hash(t_sha256 *sp, const char *msg, int mlen);
void dgst_msg(t_sha256 *sp);
void compress_sha(t_sha256 *sp);
uint32_t sha256ss1(uint32_t hash);
void init_ath(t_sha256 *sp);
uint64_t swap_edian(uint64_t x);

#endif