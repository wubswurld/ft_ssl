#include "ft_ssl.h"

// ROtate v Left by amt bits
unsigned rol(unsigned v, short amt)
{
    unsigned msk1 = (1 << amt) - 1;
    return ((v >> (32 - amt)) & msk1) | ((v << amt) & ~msk1);
}

void handle_rest(t_md5 *sp)
{
    sp->p = 0;
    while (sp->p < 4)
    {
        sp->h[sp->p] += sp->abcd[sp->p];
        sp->p++;
    }
    sp->os += 64;
}

void set_grps(t_md5 *sp)
{
    ft_memcpy(mm.b, sp->msg2 + sp->os, 64);
    sp->q = 0;
    while (sp->q < 4)
    {
        sp->abcd[sp->q] = sp->h[sp->q];
        sp->q++;
    }
}

void init_msg(t_md5 *sp, const char *msg, int mlen)
{
    sp->grps = 1 + (mlen + 8) / 64;
    sp->msg2 = malloc(64 * sp->grps);
    ft_memcpy(sp->msg2, msg, mlen);
    sp->msg2[mlen] = (unsigned char)0x80;
    sp->q = mlen + 1;
    while (sp->q < 64 * sp->grps)
    {
        sp->msg2[sp->q] = 0;
        sp->q++;
    }
    t_output u;
    u.w = 8 * mlen;
    sp->q -= 8;
    memcpy(sp->msg2 + sp->q, &u.w, 4);
    sp->grp = 0;
}

void get_h(t_md5 *sp)
{
    int q;
    //4 constants for main algorithm
    Digest h0 = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};

    q = 0;
    while (q < 4)
    {
        sp->h[q] = h0[q];
        q++;
    }
}
