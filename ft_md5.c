#include "ft_ssl.h"
#include <stdio.h>

// typedef unsigned Digest[4];
typedef unsigned (*DgstFctn)(unsigned a[]);

//start hashing of md5
void start_md5(char *av, t_whole *sp)
{
    unsigned *d;
    d = md5(av, strlen(av));
    print_md5(d, sp);
}

void print_md5(unsigned *d, t_whole *sp)
{
    t_hash u;

    sp->j = 0;
    if (sp->fp.s && sp->fp.q == 0 && sp->fp.r == 0 && sp->fp.p == 0)
        print_s1(sp->fix[0]);
    if (sp->arg && sp->fp.q == 0 && sp->fp.r == 0)
        print_arg(sp->fix[sp->cur_dir]);
    while (sp->j < 4)
    {
        u.hold = d[sp->j];
        sp->k = 0;
        while (sp->k < 4)
        {
            sp->fin = ft_uitoa_base(u.b[sp->k], 16);
            if (ft_strlen(sp->fin) == 1)
                ft_putchar('0');
            ft_putstr(sp->fin);
            sp->k++;
        }
        sp->j++;
    }
    if (sp->fp.r && sp->fp.p == 0)
        print_string_rev(sp->fix[sp->cur_dir]);
    ft_putchar('\n');
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

// void grp_md5(t_md5 *sp)
// {
// }

// void sort_md5(t_md5 *sp)
// {

// }

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

unsigned *md5(const char *msg, int mlen)
{
    DgstFctn ff[] = {&f0, &f1, &f2, &f3};
    short M[] = {1, 5, 3, 7};
    short O[] = {0, 1, 5, 0};
    short rot0[] = {7, 12, 17, 22};
    short rot1[] = {5, 9, 14, 20};
    short rot2[] = {4, 11, 16, 23};
    short rot3[] = {6, 10, 15, 21};
    short *rots[] = {rot0, rot1, rot2, rot3};

    t_md5 *sp;
    sp = (t_md5 *)malloc(sizeof(t_md5));
    sp->k = NULL;
    short m, o, g;
    short *rotn;
    sp->os = 0;

    if (sp->k == NULL)
        sp->k = calcKs(sp->kspace);
    get_h(sp);
    init_msg(sp, msg, mlen);
    while (sp->grp < sp->grps)
    {
        set_grps(sp);
        sp->p = 0;
        // sort_md5(sp);
        while (sp->p < 4)
        {
            sp->fctn = ff[sp->p];
            rotn = rots[sp->p];
            m = M[sp->p];
            o = O[sp->p];
            sp->q = 0;
            while (sp->q < 16)
            {
                g = (m * sp->q + o) % 16;
                sp->f = sp->abcd[1] + rol(sp->abcd[0] + sp->fctn(sp->abcd) + sp->k[sp->q + 16 * sp->p] + mm.w[g], rotn[sp->q % 4]);

                sp->abcd[0] = sp->abcd[3];
                sp->abcd[3] = sp->abcd[2];
                sp->abcd[2] = sp->abcd[1];
                sp->abcd[1] = sp->f;
                sp->q++;
            }
            sp->p++;
        }
        sp->p = 0;
        while (sp->p < 4)
        {
            sp->h[sp->p] += sp->abcd[sp->p];
            sp->p++;
        }
        sp->os += 64;
        sp->grp++;
    }
    if (sp->msg2)
        free(sp->msg2);

    return sp->h;
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