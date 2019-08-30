#include "ft_ssl.h"
#include <stdio.h>

void parse_md5(char **av, t_whole *sp, int ac)
{
    int x = 0;
    while (sp->ret < ac)
    {
        sp->fix[x++] = ft_strdup(av[sp->ret]);
        sp->ret++;
    }
}

int get_hash(char *str)
{
    int x;
    const char *arr[2] = {"md5", "sha256"};

    x = 0;
    while (arr[x])
    {
        if (ft_strcmp(arr[x], str) == 0)
            return (x);
        if (ft_strcmp(arr[x], str) > 0)
            return (-1);
        x++;
    }
    return (-1);
}

void get_flags(char **av, t_whole *sp)
{
    int y = 0;
    while (av[sp->ret])
    {
        if (av[sp->ret][0] == '-')
        {
            y = 1;
            while (av[sp->ret][y])
            {
                (av[sp->ret][y] == 's') ? sp->fp.s = 1 : 0;
                (av[sp->ret][y] == 'p') ? sp->fp.p = 1 : 0;
                (av[sp->ret][y] == 'r') ? sp->fp.r = 1 : 0;
                (av[sp->ret][y] == 'q') ? sp->fp.q = 1 : 0;
                if (sp->fp.p == 0 && sp->fp.s == 0 && sp->fp.r == 0 && sp->fp.q == 0)
                    invalid_option(av, y, sp);
                y++;
            }
        }
        else
            return;
        sp->ret++;
    }
}

void count_dir(char **av, t_whole *sp)
{
    sp->dir_ct = 0;
    int q = sp->ret;
    while (av[q])
    {
        if (av[q][0] != '-')
            sp->dir_ct++;
        q++;
    }
}

unsigned int k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

};

void init_hash(t_sha256 *sp)
{
    sp->h[0] = 0x6a09e667;
    sp->h[1] = 0xbb67ae85;
    sp->h[2] = 0x3c6ef372;
    sp->h[3] = 0xa54ff53a;
    sp->h[4] = 0x510e527f;
    sp->h[5] = 0x9b05688c;
    sp->h[6] = 0x1f83d9ab;
    sp->h[7] = 0x5be0cd19;
}

uint64_t swap_bits64(uint64_t x)
{
    x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
    x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
    return (x << 32) | (x >> 32);
}

unsigned int LitToBigEndian(unsigned int x)
{
    return (((x >> 24) & 0x000000ff) | ((x >> 8) & 0x0000ff00) | ((x << 8) & 0x00ff0000) | ((x << 24) & 0xff000000));
}

void expand_msg(t_sha256 *sp, uint32_t chunk)
{
    int x = 0;
    uint32_t tmp;
    uint32_t tmp1;
    while (x < 64)
    {
        if (x < 16)
        {
            // printf("%d\n", chunk);
            sp->w[x] = LitToBigEndian(*((uint64_t *)(sp->hold + chunk + (x * 4))));
            // ft_memcpy(&sp->w[x], sp->hold, 64);
            // sp->w[x] = LitToBigEndian(sp->w[x]);
        }
        else
        {
            tmp = (ROTR(sp->w[x - 15], 7)) ^ (ROTR(sp->w[x - 15], 18)) ^ (SHR(sp->w[x - 15], 3));
            tmp1 = (ROTR(sp->w[x - 2], 17)) ^ (ROTR(sp->w[x - 2], 19)) ^ (SHR(sp->w[x - 2], 10));
            sp->w[x] = sp->w[x - 16] + tmp + sp->w[x - 7] + tmp1;
        }
        x++;
    }
}

void init_ath(t_sha256 *sp)
{
    sp->tp->a = sp->h[0];
    sp->tp->b = sp->h[1];
    sp->tp->c = sp->h[2];
    sp->tp->d = sp->h[3];
    sp->tp->e = sp->h[4];
    sp->tp->f = sp->h[5];
    sp->tp->g = sp->h[6];
    sp->tp->h = sp->h[7];
}

uint32_t sha256ss1(uint32_t hash)
{
    return ((hash >> 6) | (hash << (32 - 6))) ^ ((hash >> 11) | (hash << (32 - 11))) ^ ((hash >> 25) | (hash << (32 - 25)));
}

uint32_t sha256ss0(uint32_t hash)
{
    // return ((ROTR(hash, 2, 32)) ^ (ROTR(hash, 13, 32)) ^ (ROTR(hash, 22, 32)));
    return ((hash >> 2) | (hash << (32 - 2))) ^ ((hash >> 13) | (hash << (32 - 13))) ^ ((hash >> 22) | (hash << (32 - 22)));
}

void compress_sha(t_sha256 *sp)
{
    int x = 0;
    uint32_t tmp;
    uint32_t tmp1;
    uint32_t hold;
    uint32_t hold1;
    uint32_t fin[2];
    while (x < 64)
    {
        // tmp = TRIP_SHFT(sp->tp->e);
        // tmp = sha256ss1(sp->tp->e);
        tmp = (((sp->tp->e >> 6) | (sp->tp->e << (32 - 6))) ^ ((sp->tp->e >> 11) | (sp->tp->e << (32 - 11))) ^ ((sp->tp->e >> 25) | (sp->tp->e << (32 - 25))));
        // printf("%x\n", tmp);
        // printf("tmp: %x\n", tmp[0]);
        hold = (sp->tp->e & sp->tp->f) ^ ((~sp->tp->e) & sp->tp->g);
        // printf("%x\n", hold);
        // hold = CH(sp->tp->e, sp->tp->f, sp->tp->g);
        fin[0] = sp->tp->h + tmp + hold + k[x] + sp->w[x];
        // tmp1 = ROTR(sp->tp->a, 2) ^ ROTR(sp->tp->a, 13) ^ ROTR(sp->tp->a, 22);
        tmp1 = sha256ss0(sp->tp->a);
        hold1 = MAJ(sp->tp->a, sp->tp->b, sp->tp->c);
        fin[1] = tmp1 + hold1;
        sp->tp->h = sp->tp->g;
        sp->tp->g = sp->tp->f;
        sp->tp->f = sp->tp->e;
        sp->tp->e = sp->tp->d + fin[0];
        sp->tp->d = sp->tp->c;
        sp->tp->c = sp->tp->b;
        sp->tp->b = sp->tp->a;
        sp->tp->a = fin[0] + fin[1];
        x++;
    }
}

void add_compress(t_sha256 *sp)
{
    sp->h[0] += sp->tp->a;
    sp->h[1] += sp->tp->b;
    sp->h[2] += sp->tp->c;
    sp->h[3] += sp->tp->d;
    sp->h[4] += sp->tp->e;
    sp->h[5] += sp->tp->f;
    sp->h[6] += sp->tp->g;
    sp->h[7] += sp->tp->h;
}

void dgst_msg(t_sha256 *sp)
{
    //entire msg will fit in 0-16 of w[16]
    uint32_t chunk = 0;
    if (!(sp->tp = (t_sha_init *)malloc(sizeof(t_sha_init))))
        exit(1);
    //if block size is 128 it will run twice in 2 blocks
    // int tmp = sp->block / 64;

    while (chunk < sp->block / 64)
    {
        expand_msg(sp, chunk * 64);
        init_ath(sp);
        // printf("%x\n", sp->w[0]);
        compress_sha(sp);
        add_compress(sp);
        chunk++;
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
    // sp->hold[sp->block - 8] = (uint64_t)LitToBigEndian(mlen * 8);
}

void print_sha256(char *str)
{
    ft_putstr("SHA256 (\"");
    ft_putstr(str);
    ft_putstr("\") = ");
}

void print_sha(t_sha256 *sp, t_whole *np)
{
    int i;
    // t_sha256 *np;
    char *tmp = NULL;
    // np = NULL;
    i = 0;
    // if (!(np = (t_sha256 *)malloc(sizeof(t_sha256))))
    //     exit(1);
    // printf("%d\n", np->fp.s);
    if (np->fp.s && np->fp.q == 0 && np->fp.r == 0 && np->fp.p == 0)
        print_sha256(np->fix[0]);
    // if (np->arg && np->fp.q == 0 && np->fp.r == 0)
    // print_arg(np->fix[np->cur_dir]);
    while (i < 8)
    {
        tmp = ft_uitoa_base(sp->h[i], 16);
        // tmp -= 1;
        // ft_putnstr(tmp, 8);
        // i++;
        ft_putstr(tmp);
        if (ft_strlen(tmp) == 1)
            ft_putchar('0');
        // ft_putstr(ft_uitoa_base(sp->h[i], 16));
        // printf("%08x", (sp->h[i]));
        i++;
    }
    ft_putchar('\n');
    // printf("%x\n", sp->h[7]);
    free(sp);
}

void sha256(const char *msg, int mlen, t_sha256 *sp)
{
    // t_sha256 *sp;
    // if (!(sp = (t_sha256 *)malloc(sizeof(t_sha256))))
    //     exit(1);
    init_hash(sp);
    update_hash(sp, msg, mlen);
    dgst_msg(sp);
    // int x = -1;
    // while (++x < 8)
    // sp->h[x] = LitToBigEndian(sp->h[x]);
}

void start_sha256(char *av, t_whole *sp)
{
    t_sha256 *np;
    if (!(np = (t_sha256 *)malloc(sizeof(t_sha256))))
        exit(1);
    sha256(av, ft_strlen(av), np);
    print_sha(np, sp);
}