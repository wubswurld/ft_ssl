#include "ft_ssl.h"
#include <stdio.h>

t_shift *check_type[2] = {start_md5, start_sha256};

void start_sha256(char *av, t_whole *sp)
{
    printf("%s\n", av);
    printf("%d\n", sp->fp.s1);
}

void read_stdin(t_whole *sp)
{
    int x;
    char ch[1008];
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

void check_rest(t_whole *sp)
{
    int x = 0;
    int i = 0;
    int fd;
    char hold[10008];
    int ret = 0;
    if (sp->fp.s)
    {
        printf("%s\n", sp->fix[1]);
        check_type[sp->hash](sp->fix[1], sp);
        sp->fp.s = 0;
        x++;
    }
    printf("%d\n", sp->dir_ct);
    while (x < sp->dir_ct)
    {
        if ((fd = open(sp->fix[x], O_RDONLY)))
        {
            if ((ret = read(fd, &hold, 10008)) > 0)
            {
                hold[ret] = '\0';
                check_type[sp->hash](hold, sp);
            }
            else
            {
                putError(sp->fix[x]);
                return;
            }
        }
        else
        {
            return;
        }
        x++;
    }
    // int x = 0;
    // int ret = 0;
    // int fd;
    // char hold[10008];
    // sp->argval = (char *)malloc(sizeof(char));
    // if (sp->fp.s1)
    //     check_type[sp->hash](sp->store, sp);
    // if (sp->arg && sp->fp.s1 == 0)
    // {
    //     if ((fd = open(sp->store, O_RDONLY)))
    //     {
    //         if ((ret = read(fd, &hold, 10008)) > 0)
    //         {
    //             hold[ret] = '\0';
    //             check_type[sp->hash](hold, sp);
    //         }
    //         else
    //             putError(sp->store);
    //     }
    // }
}

void parse_md5(char **av, t_whole *sp, int ac)
{
    int x = 0;
    while (sp->ret < ac)
    {
        sp->fix[x++] = ft_strdup(av[sp->ret]);
        sp->ret++;
    }
    // sp->fix[sp->ret] = NULL;
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

void error_one()
{
    ft_putstr("usage: ft_ssl command [command opts] [command args]");
    exit(1);
}

int main(int ac, char **av)
{
    t_whole *sp;
    if (!(sp = (t_whole *)malloc(sizeof(t_whole))))
        exit(1);
    sp->fix = (char **)malloc(sizeof(char *));
    if (ac < 2)
        error_one();
    sp->hash = get_hash(av[1]);
    sp->ret = 2;
    if (sp->hash == -1)
    {
        ft_putstr("md5 or sha256");
        exit(1);
    }
    else
    {
        get_flags(av, sp);
        count_dir(av, sp);
        parse_md5(av, sp, ac);
    }
    if (sp->fp.p == 1)
        read_stdin(sp);
    if (ac >= 3)
        check_rest(sp);
    return (0);
}