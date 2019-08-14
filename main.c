#include "ft_ssl.h"
#include <stdio.h>

t_shift     *check_type[2] = {start_md5, start_sha256};

void    start_sha256(char *av)
{
    printf("%s\n", av);
}

void     read_stdin(t_whole *sp)
{
    int x;
    char  ch[1008];
    sp->value = (char *)malloc(sizeof(char));
    while ((x = read(STDIN_FILENO, &ch, 1008)) > 0)
    {
        ch[x] = '\0';
        ft_strcpy(sp->value, ch);
    }
    if (sp->fp.p)
        ft_putstr(ch);
    check_type[sp->hash](ch);
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
    if (sp->hash == -1)
    {
        ft_putstr("md5 or sha256");
        exit(1);
    }
    while (av[++x])
        get_flags(av[x], sp);
    if (sp->fp.p == 1 || sp->arg == 0)
        read_stdin(sp);
    // printf("%s\n", sp->store);
    // if (ac >= 3)
    return (0);  
}