#include "ft_ssl.h"
#include <stdio.h>

t_shift     *check_type[2] = {start_md5, start_sha256};

void    start_sha256(char *av, t_whole *sp)
{
    printf("%s\n", av);
    printf("%d\n", sp->fp.s1);
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
    check_type[sp->hash](sp->value, sp);
}

void    check_rest(t_whole *sp)
{
    int ret = 0;
    int fd;
    char hold[10008];
    sp->argval = (char *)malloc(sizeof(char));
    if (sp->fp.s1)
        check_type[sp->hash](sp->store, sp);
    if (sp->arg && sp->fp.s1 == 0)
    {
        if ((fd = open(sp->store, O_RDONLY)))
        {
            if ((ret = read(fd, &hold, 10008)) > 0)
            {
                 hold[ret] = '\0'; 
                check_type[sp->hash](hold, sp);
            }
            else
                putError(sp->store);
        }
    }
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
    if (ac >= 3)
        check_rest(sp);    
    return (0);  
}