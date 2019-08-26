#include "ft_ssl.h"
#include <stdio.h>

void print_md5(unsigned *d, t_whole *sp)
{
    int j;
    int k;
    t_hash u;

    j = 0;
    if (sp->fp.s && sp->fp.q == 0 && sp->fp.r == 0)
        print_s1(sp->fix[0]);
    if (sp->arg && sp->fp.q == 0 && sp->fp.r == 0)
        print_arg(sp->fix[sp->cur_dir]);
    while (j < 4)
    {
        u.hold = d[j];
        k = 0;
        while (k < 4)
        {
            sp->fin = ft_uitoa_base(u.b[k], 16);
            if (ft_strlen(sp->fin) == 1)
                ft_putchar('0');
            ft_putstr(sp->fin);
            k++;
        }
        j++;
    }
    if (sp->fp.r)
        print_string_rev(sp->fix[sp->cur_dir]);
    ft_putchar('\n');
}

typedef union uwb {
    unsigned w;
    unsigned char b[4];
} WBunion;

typedef unsigned Digest[4];

unsigned f0(unsigned abcd[])
{
    return (abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);
}

unsigned f1(unsigned abcd[])
{
    return (abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);
}

unsigned f2(unsigned abcd[])
{
    return abcd[1] ^ abcd[2] ^ abcd[3];
}

unsigned f3(unsigned abcd[])
{
    return abcd[2] ^ (abcd[1] | ~abcd[3]);
}

typedef unsigned (*DgstFctn)(unsigned a[]);

unsigned *calcKs(unsigned *k)
{
    double s, pwr;
    int i;

    pwr = pow(2, 32);
    for (i = 0; i < 64; i++)
    {
        s = fabs(sin(1 + i));
        k[i] = (unsigned)(s * pwr);
    }
    return k;
}

// ROtate v Left by amt bits
unsigned rol(unsigned v, short amt)
{
    unsigned msk1 = (1 << amt) - 1;
    return ((v >> (32 - amt)) & msk1) | ((v << amt) & ~msk1);
}

unsigned *md5(const char *msg, int mlen)
{
    static Digest h0 = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    //    static Digest h0 = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    static DgstFctn ff[] = {&f0, &f1, &f2, &f3};
    static short M[] = {1, 5, 3, 7};
    static short O[] = {0, 1, 5, 0};
    static short rot0[] = {7, 12, 17, 22};
    static short rot1[] = {5, 9, 14, 20};
    static short rot2[] = {4, 11, 16, 23};
    static short rot3[] = {6, 10, 15, 21};
    static short *rots[] = {rot0, rot1, rot2, rot3};
    static unsigned kspace[64];
    static unsigned *k;

    static Digest h;
    Digest abcd;
    DgstFctn fctn;
    short m, o, g;
    unsigned f;
    short *rotn;
    union {
        unsigned w[16];
        char b[64];
    } mm;
    int os = 0;
    int grp, grps, q, p;
    unsigned char *msg2;

    if (k == NULL)
        k = calcKs(kspace);

    for (q = 0; q < 4; q++)
        h[q] = h0[q]; // initialize

    {
        grps = 1 + (mlen + 8) / 64;
        msg2 = malloc(64 * grps);
        memcpy(msg2, msg, mlen);
        msg2[mlen] = (unsigned char)0x80;
        q = mlen + 1;
        while (q < 64 * grps)
        {
            msg2[q] = 0;
            q++;
        }
        {
            //            unsigned char t;
            WBunion u;
            u.w = 8 * mlen;
            //            t = u.b[0]; u.b[0] = u.b[3]; u.b[3] = t;
            //            t = u.b[1]; u.b[1] = u.b[2]; u.b[2] = t;
            q -= 8;
            memcpy(msg2 + q, &u.w, 4);
        }
    }

    for (grp = 0; grp < grps; grp++)
    {
        memcpy(mm.b, msg2 + os, 64);
        for (q = 0; q < 4; q++)
            abcd[q] = h[q];
        for (p = 0; p < 4; p++)
        {
            fctn = ff[p];
            rotn = rots[p];
            m = M[p];
            o = O[p];
            for (q = 0; q < 16; q++)
            {
                g = (m * q + o) % 16;
                f = abcd[1] + rol(abcd[0] + fctn(abcd) + k[q + 16 * p] + mm.w[g], rotn[q % 4]);

                abcd[0] = abcd[3];
                abcd[3] = abcd[2];
                abcd[2] = abcd[1];
                abcd[1] = f;
            }
        }
        for (p = 0; p < 4; p++)
            h[p] += abcd[p];
        os += 64;
    }

    if (msg2)
        free(msg2);

    return h;
}

void start_md5(char *av, t_whole *sp)
{
    unsigned *d;
    d = md5(av, strlen(av));
    print_md5(d, sp);
}

// int index_grp(t_md5 *sp, int mlen, const char *msg)
// {
//     static Digest h0 = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};

//     while (sp->q < 4)
//     {
//         sp->h[sp->q] = h0[sp->q];
//         sp->q++;
//     }
//     sp->grps = 1 + (mlen + 8) / 64;
//     sp->msg2 = malloc(64 * sp->grps);
//     ft_memcpy(sp->msg2, msg, mlen);
//     sp->msg2[mlen] = (unsigned char)0x80;
//     sp->q = mlen + 1;
//     while (sp->q < 64 * sp->grps)
//     {
//         sp->msg2[sp->q] = 0;
//         sp->q++;
//     }
//     sp->q -= 8;
//     return (mlen);
// }

// void handle_split(t_md5 *sp)
// {
//     t_munion mm;

//     sp->g = (sp->m * sp->q + sp->o) % 16;
//     sp->f = sp->abcd[1] + rol(sp->abcd[0] + sp->fctn(sp->abcd) + sp->k[sp->q + 16 * sp->p] + mm.w[sp->g], sp->rotn[sp->q % 4]);
//     sp->abcd[0] = sp->abcd[3];
//     sp->abcd[3] = sp->abcd[2];
//     sp->abcd[2] = sp->abcd[1];
//     sp->abcd[1] = sp->f;
//     sp->q++;
// }

// void get_hashval(t_md5 *sp)
// {
//     t_munion mm;
//     DigestFunc ff[] = {&f0, &f1, &f2, &f3};
//     short M[] = {1, 5, 3, 7};
//     short O[] = {0, 1, 5, 0};
//     short rot0[] = {7, 12, 17, 22};
//     short rot1[] = {5, 9, 14, 20};
//     short rot2[] = {4, 11, 16, 23};
//     short rot3[] = {6, 10, 15, 21};
//     short *rots[] = {rot0, rot1, rot2, rot3};

//     while (sp->grp < sp->grps)
//     {
//         sp->q = 0;
//         ft_memcpy(mm.b, sp->msg2 + sp->os, 64);
//         grp_hash(sp);
//         sp->p = 0;
//         while (sp->p < 4)
//         {
//             sp->fctn = ff[sp->p];
//             sp->rotn = rots[sp->p];
//             sp->m = M[sp->p];
//             sp->o = O[sp->p];
//             sp->q = 0;
//             // handle_split(sp);
//             while (sp->q < 16)
//             {
//                 sp->g = (sp->m * sp->q + sp->o) % 16;
//                 sp->f = sp->abcd[1] + rol(sp->abcd[0] + sp->fctn(sp->abcd) + sp->k[sp->q + 16 * sp->p] + mm.w[sp->g], sp->rotn[sp->q % 4]);
//                 sp->abcd[0] = sp->abcd[3];
//                 sp->abcd[3] = sp->abcd[2];
//                 sp->abcd[2] = sp->abcd[1];
//                 sp->abcd[1] = sp->f;
//                 sp->q++;
//             }
//             sp->p++;
//         }
//         add_hash(sp);
//         sp->os += 64;
//         sp->grp++;
//     }
// }

// unsigned *md5(const char *msg, int mlen)
// {
//     t_md5 *sp;
//     t_hash u;
//     sp = (t_md5 *)malloc(sizeof(t_md5));
//     sp->os = 0;
//     sp->q = 0;
//     sp->p = 0;

//     if (sp->k == NULL)
//         sp->k = calcKs(sp->kspace);
//     mlen = index_grp(sp, mlen, msg);
//     u.hold = 8 * mlen;
//     ft_memcpy(sp->msg2 + sp->q, &u.hold, 4);
//     sp->grp = 0;
//     get_hashval(sp);
//     if (sp->msg2)
//         free(sp->msg2);
//     free(sp);
//     return sp->h;
// }