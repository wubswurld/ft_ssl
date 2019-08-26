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