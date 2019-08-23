#include "ft_ssl.h"
#include <stdio.h>

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

char *get_args(t_whole *sp, char *av)
{
    int y;
    int x;

    y = 0;
    x = 0;
    sp->store = (char *)malloc(sizeof(char));
    sp->fix = (char **)malloc(sizeof(char *));
    sp->arg = 1;
    ft_strcpy(sp->store, av);
    if (sp->fp.s)
    {
        sp->fp.s = 0;
        sp->fp.s1 = 1;
    }
    return (sp->store);
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
                y++;
            }
        }
        else
        {
            return;
        }
        sp->ret++;
    }
}