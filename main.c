#include "ft_ssl.h"
#include <stdio.h>

// int     count_flags(char *str)
// {
//     int y = 0;
//     if (str[0] == '-')
//     {
//         while (str[y + 1])
//             y++;
//     }
//     return (y);
// }


int    get_flags(char *av, t_whole *sp)
{
    int y = 0; 
    if (av[y] == '-')
    {
        y = 1;
        while (av[y])
        {
            // sp->flags[y] = av[y];
            (av[y] == 's') ? sp->fp.s = 1 : 0;
            (av[y] == 'p') ? sp->fp.p = 1 : 0; 
            (av[y] == 'r') ? sp->fp.r = 1 : 0; 
            (av[y] == 'q') ? sp->fp.q = 1 : 0; 
            y++;
        }
    }
    return (y);
}

int     get_hash(char *str)
{
    int x;
    const char *arr[2] = {"md5", "sha256"};

    x = 0;
    while (arr[x])
    {
        if (ft_strcmp(arr[x], str) == 0)
            return (x);
        x++;
    }
    return (-1);
}

// int     read_stdin()
// {
//     int x;
//     char buf[1024];
//     while (fgets(buf, 1024, stdin))
//     {
//        fputs(buf, stdout);
//     }
//     return (x);
// }

int     main(int ac, char **av)
{
    int x;
    t_whole *sp;
    int numFlags;
    
    x = 1;
    numFlags = 0;
    if (!(sp = (t_whole *)malloc(sizeof(t_whole))))
        exit(1);
    if (ac < 2)
       ft_putstr("usage: ft_ssl command [command opts] [command args]");
    sp->hash = get_hash(av[1]);
    while (av[++x]) {
        numFlags = get_flags(av[x], sp);
    }
    if (sp.fp.p == 1)
        sp.ret = read_stdin();
    return (0);  
}