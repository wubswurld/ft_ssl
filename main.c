#include "ft_ssl.h"

void    print_error(char *str)
{
    ft_putstr("usage:");
    ft_putstr(str);
    ft_putstr("[-pqrtx] [-s string] [files ...]\n"); 
}

int     main(int ac, char **av)
{
    if (ac == 1)
        print_error(av[0]);
    return (0);  
}