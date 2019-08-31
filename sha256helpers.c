#include "sha256.h"

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

uint64_t swap_edian(uint64_t x)
{
    x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
    x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
    return (x << 32) | (x >> 32);
}

unsigned int LitToBigEndian(unsigned int x)
{
    return (((x >> 24) & 0x000000ff) | ((x >> 8) & 0x0000ff00) | ((x << 8) & 0x00ff0000) | ((x << 24) & 0xff000000));
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
        tmp = (((sp->tp->e >> 6) | (sp->tp->e << (32 - 6))) ^ ((sp->tp->e >> 11) | (sp->tp->e << (32 - 11))) ^ ((sp->tp->e >> 25) | (sp->tp->e << (32 - 25))));
        hold = (sp->tp->e & sp->tp->f) ^ ((~sp->tp->e) & sp->tp->g);
        fin[0] = sp->tp->h + tmp + hold + k[x] + sp->w[x];
        tmp1 = ((sp->tp->a >> 2) | (sp->tp->a << (32 - 2))) ^ ((sp->tp->a >> 13) | (sp->tp->a << (32 - 13))) ^ ((sp->tp->a >> 22) | (sp->tp->a << (32 - 22)));
        hold1 = (sp->tp->a & sp->tp->b) ^ (sp->tp->a & sp->tp->c) ^ (sp->tp->b & sp->tp->c);
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