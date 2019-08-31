#include "sha256.h"

void dgst_msg(t_sha256 *sp)
{
    //entire msg will fit in 0-16 of w[16]
    uint32_t chunk = 0;
    if (!(sp->tp = (t_sha_init *)malloc(sizeof(t_sha_init))))
        exit(1);
    //if block size is 128 it will run twice in 2 blocks
    while (chunk < sp->block / 64)
    {
        expand_msg(sp, chunk * 64);
        init_ath(sp);
        compress_sha(sp);
        sp->h[0] += sp->tp->a;
        sp->h[1] += sp->tp->b;
        sp->h[2] += sp->tp->c;
        sp->h[3] += sp->tp->d;
        sp->h[4] += sp->tp->e;
        sp->h[5] += sp->tp->f;
        sp->h[6] += sp->tp->g;
        sp->h[7] += sp->tp->h;
        chunk++;
    }
}

void expand_msg(t_sha256 *sp, uint32_t chunk)
{
    int x = 0;
    uint32_t tmp;
    uint32_t tmp1;
    while (x < 64)
    {
        (x < 16) ? sp->w[x] = LitToBigEndian(*((uint64_t *)(sp->hold + chunk + (x * 4)))) : ({
            tmp = (ROTR(sp->w[x - 15], 7)) ^ (ROTR(sp->w[x - 15], 18)) ^ (SHR(sp->w[x - 15], 3));
            tmp1 = (ROTR(sp->w[x - 2], 17)) ^ (ROTR(sp->w[x - 2], 19)) ^ (SHR(sp->w[x - 2], 10));
            sp->w[x] = sp->w[x - 16] + tmp + sp->w[x - 7] + tmp1;
        });
        x++;
    }
}

void update_hash(t_sha256 *sp, const char *msg, int mlen)
{
    sp->block = mlen + 9;
    while (sp->block % 64 > 0)
        sp->block++;
    sp->hold = (char *)malloc(sizeof(char) * (sp->block));
    ft_bzero(sp->hold, sp->block);
    ft_memcpy(sp->hold, msg, mlen);
    //add '1' bit to end 2^7 aka 128 or last place in bit because a byte has 8 bits and thats the last place
    sp->hold[mlen] = 0x80;
    *(uint64_t *)(sp->hold + sp->block - 8) = (uint64_t)swap_bits64(mlen * 8);
}

void start_sha256(char *av, t_whole *sp)
{
    t_sha256 *np;
    if (!(np = (t_sha256 *)malloc(sizeof(t_sha256))))
        exit(1);
    np->h[0] = 0x6a09e667;
    np->h[1] = 0xbb67ae85;
    np->h[2] = 0x3c6ef372;
    np->h[3] = 0xa54ff53a;
    np->h[4] = 0x510e527f;
    np->h[5] = 0x9b05688c;
    np->h[6] = 0x1f83d9ab;
    np->h[7] = 0x5be0cd19;
    update_hash(np, av, ft_strlen(av));
    dgst_msg(np);
    print_sha(np, sp);
}