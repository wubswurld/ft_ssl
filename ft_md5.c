#include "ft_ssl.h"
#include <stdio.h>

void    print_s1(char *str)
{
    ft_putstr("MD5 (");
    ft_putstr(str);
    ft_putstr(") = ");
}

void    print_string_rev(char *str)
{
    ft_putstr(" \"");
    ft_putstr(str);
    ft_putstr("\"");
}

void    print_md5(unsigned *d,t_whole *sp)
{
    int j;
    int k;
    t_hash u;
 
    j = 0;
    if ((sp->fp.s1 || sp->arg) && sp->fp.q == 0 && sp->fp.r == 0)
        print_s1(sp->store);
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
    if ((sp->fp.s1 || sp->arg) && sp->fp.r)
        print_string_rev(sp->store);
    ft_putchar('\n');
}
// void    print_smd5(unsigned *d,t_whole *sp)
// {
//     int j;
//     int k;
//     char *str;
//     t_hash u;
 
//     j = 0;
//     sp->fin = (char *)malloc(sizeof(char));
//     ft_putstr("MD5 (\"");
//     ft_putstr(sp->store);
//     ft_putstr("\") = ");

//     while (j < 4)
//     {
//         u.hold = d[j];
//         k = 0;
//         while (k < 4) 
//         {
//             str = ft_uitoa_base(u.b[k], 16);
//                 //  ft_putchar('0');
//             // sp->fin = str;
//             // ft_strcat(sp->fin, str);
//              if (ft_strlen(str) == 1)
//                 ft_putchar('0');
//                 // ft_strcpy(sp->fin, 0);    
//             ft_putstr(str);
//             k++;
//         }
//         j++;
//     }
//     // ft_putstr(sp->fin);
//     ft_putchar('\n');
// }
void    start_md5(char *av, t_whole *sp)
{
    unsigned *d; 
    d = md5(av, strlen(av));
    print_md5(d, sp);
}

int    index_grp(t_md5 *sp, int mlen, const char *msg)
{
    static Digest h0 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    
    while (sp->q < 4)
    {
        sp->h[sp->q] = h0[sp->q]; 
        sp->q++;
    }
    sp->grps  = 1 + (mlen+8)/64;
    sp->msg2 = malloc( 64*sp->grps);
    ft_memcpy(sp->msg2, msg, mlen);
    sp->msg2[mlen] = (unsigned char)0x80;  
    sp->q = mlen + 1;
    while (sp->q < 64*sp->grps)
    {
        sp->msg2[sp->q] = 0;
        sp->q++;
    }
    sp->q -= 8;
    return (mlen);
}

void    handle_split(t_md5 *sp)
{
    t_munion mm;

    sp->g = (sp->m*sp->q + sp->o) % 16;
    sp->f = sp->abcd[1] + rol(sp->abcd[0]+ sp->fctn(sp->abcd) + sp->k[sp->q+16*sp->p] + mm.w[sp->g], sp->rotn[sp->q%4]);
    sp->abcd[0] = sp->abcd[3];
    sp->abcd[3] = sp->abcd[2];
    sp->abcd[2] = sp->abcd[1];
    sp->abcd[1] = sp->f;
    sp->q++;
}

void    get_hashval(t_md5 *sp) 
{
    t_munion mm;
    DigestFunc ff[] = { &f0, &f1, &f2, &f3 };
    short M[] = { 1, 5, 3, 7 };
    short O[] = { 0, 1, 5, 0 };
    short rot0[] = { 7,12,17,22};
    short rot1[] = { 5, 9,14,20};
    short rot2[] = { 4,11,16,23};
    short rot3[] = { 6,10,15,21};
    short *rots[] = {rot0, rot1, rot2, rot3 }; 

    while (sp->grp < sp->grps)
    {
        sp->q = 0;
        ft_memcpy(mm.b, sp->msg2+sp->os, 64);
        grp_hash(sp);
        sp->p = 0;
        while (sp->p<4) {
            sp->fctn = ff[sp->p];
            sp->rotn = rots[sp->p];
            sp->m = M[sp->p]; 
            sp->o= O[sp->p];
            sp->q = 0;
            // handle_split(sp);
            while (sp->q<16) 
            {
                sp->g = (sp->m*sp->q + sp->o) % 16;
                sp->f = sp->abcd[1] + rol(sp->abcd[0]+ sp->fctn(sp->abcd) + sp->k[sp->q+16*sp->p] + mm.w[sp->g], sp->rotn[sp->q%4]);
                sp->abcd[0] = sp->abcd[3];
                sp->abcd[3] = sp->abcd[2];
                sp->abcd[2] = sp->abcd[1];
                sp->abcd[1] = sp->f;
                sp->q++;
            }
            sp->p++;
        }
        add_hash(sp);
        sp->os += 64;
        sp->grp++;
    }
}

unsigned *md5( const char *msg, int mlen) 
{ 
    t_md5   *sp;
    t_hash  u;
    sp = (t_md5 *)malloc(sizeof(t_md5));
    sp->os = 0;
    sp->q = 0;
    sp->p = 0;
 
    if (sp->k==NULL) 
        sp->k = calcKs(sp->kspace);
    mlen = index_grp(sp, mlen, msg);
    u.hold = 8*mlen;
    ft_memcpy(sp->msg2+sp->q, &u.hold, 4);
    sp->grp = 0; 
    get_hashval(sp);
    if(sp->msg2)
        free(sp->msg2);
    return sp->h;
}   

