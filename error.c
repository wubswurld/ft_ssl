#include "ft_ssl.h"

void put_srr()
{
    ft_putstr("md5: option requires an argument -- s\n");
    ft_putstr("usage: md5 [-pqrtx] [-s string] [files ...]\n");
    exit(1);
}

void error_one()
{
    ft_putstr("usage: ft_ssl command [command opts] [command args]");
    exit(1);
}

void invalid_hash(char *av)
{
    ft_putstr("ft_ssl: Error: \'");
    ft_putstr(av);
    ft_putstr("\' is an invalid command.");
    exit(1);
}