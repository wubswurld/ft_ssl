#include "ft_ssl.h"
#include <stdio.h>

int     get_hash(char *str)
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

void    get_args(t_whole *sp, char *av)
{
    int y;

    y = 0;
    sp->store = (char *)malloc(sizeof(char));
    sp->arg = 1;
    ft_strcpy(sp->store, av);
    printf("store: %s\n", sp->store);
    if (sp->fp.s)
    {
        sp->fp.s = 0;
        sp->fp.s1 = 1;
    }
}

void    get_flags(char *av, t_whole *sp)
{
    int y = 0; 
    if (av[y] == '-')
    {
        y = 1;
        while (av[y])
        {
            (av[y] == 's') ? sp->fp.s = 1 : 0;
            (av[y] == 'p') ? sp->fp.p = 1 : 0; 
            (av[y] == 'r') ? sp->fp.r = 1 : 0; 
            (av[y] == 'q') ? sp->fp.q = 1 : 0; 
            y++;
        }
    }
    else
    get_args(sp, av);
}