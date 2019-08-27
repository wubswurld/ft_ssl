#include "ft_ssl.h"

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

unsigned *calcKs(unsigned *k)
{
    double s;
    double pwr;
    int i;

    i = 0;
    pwr = pow(2, 32);
    while (i < 64)
    {
        s = fabs(sin(1 + i));
        k[i] = (unsigned)(s * pwr);
        i++;
    }
    return k;
}

// ROtate v Left by amt bits
unsigned rol(unsigned v, short amt)
{
    unsigned msk1 = (1 << amt) - 1;
    return ((v >> (32 - amt)) & msk1) | ((v << amt) & ~msk1);
}
