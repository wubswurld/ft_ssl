#include "ft_ssl.h"
#include <stdio.h>

// typedef unsigned Digest[4];
typedef unsigned (*DgstFctn)(unsigned a[]);

//start hashing of md5
void start_md5(char *av, t_whole *sp)
{
    unsigned *d;
    d = md5(av, ft_strlen(av));
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

void handle_f(t_md5 *sp)
{
    DgstFctn ff[] = {&f0, &f1, &f2, &f3};
    short M[] = {1, 5, 3, 7};
    short O[] = {0, 1, 5, 0};
    short rot0[] = {7, 12, 17, 22};
    short rot1[] = {5, 9, 14, 20};
    short rot2[] = {4, 11, 16, 23};
    short rot3[] = {6, 10, 15, 21};
    short *rots[] = {rot0, rot1, rot2, rot3};

    sp->fctn = ff[sp->p];
    sp->rotn = rots[sp->p];
    sp->m = M[sp->p];
    sp->o = O[sp->p];
    sp->q = 0;
    while (sp->q < 16)
    {
        sp->g = (sp->m * sp->q + sp->o) % 16;
        sp->f = sp->abcd[1] + rol(sp->abcd[0] + sp->fctn(sp->abcd) + sp->k[sp->q + 16 * sp->p] + mm.w[sp->g], sp->rotn[sp->q % 4]);

        sp->abcd[0] = sp->abcd[3];
        sp->abcd[3] = sp->abcd[2];
        sp->abcd[2] = sp->abcd[1];
        sp->abcd[1] = sp->f;
        sp->q++;
    }
}

unsigned *md5(const char *msg, int mlen)
{
    t_md5 *sp;
    sp = (t_md5 *)malloc(sizeof(t_md5));
    sp->k = NULL;
    sp->os = 0;

    if (sp->k == NULL)
        sp->k = calcKs(sp->kspace);
    get_h(sp);
    init_msg(sp, msg, mlen);
    while (sp->grp < sp->grps)
    {
        set_grps(sp);
        sp->p = 0;
        while (sp->p < 4)
        {
            handle_f(sp);
            sp->p++;
        }
        handle_rest(sp);
        sp->grp++;
    }
    if (sp->msg2)
        free(sp->msg2);
    return sp->h;
}