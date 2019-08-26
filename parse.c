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

void start_sha256(char *av, t_whole *sp)
{
    printf("%s\n", av);
    printf("%d\n", sp->fp.s1);
}