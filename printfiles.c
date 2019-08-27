#include "ft_ssl.h"

void print_s1(char *str)
{
    ft_putstr("MD5 (\"");
    ft_putstr(str);
    ft_putstr("\") = ");
}

void print_string_rev(char *str)
{
    ft_putchar(' ');
    ft_putstr(str);
}

void print_arg(char *str)
{
    ft_putstr("MD5 (");
    ft_putstr(str);
    ft_putstr(") = ");
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