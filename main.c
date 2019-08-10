#include "ft_ssl.h"
#include <stdio.h>

t_shift     *check_type[2] = {start_md5, start_sha256};

void    start_sha256(t_whole *sp, char *av)
{
    printf("SHA256\n");
    printf("%s\n", av);
    printf("%d\n", sp->hash);
}
void    start_md5(t_whole *sp, char *av)
{
    printf("MD5\n");
    printf("%s\n", av);
    printf("%d\n", sp->hash);
}

void    get_args(t_whole *sp, char *av)
{
    int y;

    y = 0;
    sp->store = (char *)malloc(sizeof(char));
    ft_strcpy(sp->store, av);
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

void     read_stdin(t_whole *sp)
{
    int x;
    char  ch[1000];
    while ((x = read(STDIN_FILENO, &ch, 1)) > 0)
    {
        ch[x] = '\0';
        ft_putstr(ch);
    }
    ft_putchar('\n');
    printf("%d\n", sp->hash);
    check_type[sp->hash](sp, ch);
}

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
    while (av[++x])
        get_flags(av[x], sp);
    if (sp->fp.p == 1)
        read_stdin(sp);
    // if (ac >= 3)

    return (0);  
}