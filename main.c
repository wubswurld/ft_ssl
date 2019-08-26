#include "ft_ssl.h"
#include <stdio.h>

t_shift *check_type[2] = {start_md5, start_sha256};

void read_stdin(t_whole *sp)
{
    int x;
    char ch[10008];
    sp->value = (char *)malloc(sizeof(char));
    while ((x = read(STDIN_FILENO, &ch, 10008)) > 0)
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
    sp->cur_dir = 0;
    int fd;
    int ret = 0;
    while (sp->cur_dir < sp->dir_ct)
    {
        if (sp->fp.s)
        {
            check_type[sp->hash](sp->fix[0], sp);
            sp->fp.s = 0;
        }
        else if ((fd = open(sp->fix[sp->cur_dir], O_RDONLY)))
        {
            if ((ret = read(fd, &sp->hold, 10008)) > 0)
            {
                sp->hold[ret] = '\0';
                sp->arg = 1;
                check_type[sp->hash](sp->hold, sp);
            }
            else
            {
                putError(sp->fix[sp->cur_dir]);
            }
        }
        sp->cur_dir++;
    }
}

int main(int ac, char **av)
{
    t_whole *sp;
    if (!(sp = (t_whole *)malloc(sizeof(t_whole))))
        exit(1);
    if (ac < 2)
        error_one();
    sp->hash = get_hash(av[1]);
    sp->ret = 2;
    if (sp->hash == -1)
        invalid_hash(av[1]);
    else
    {
        get_flags(av, sp);
        count_dir(av, sp);
        sp->fix = (char **)malloc(sizeof(char *) * (sp->dir_ct));
        parse_md5(av, sp, ac);
    }
    if ((sp->fp.p == 1 || sp->dir_ct == 0) && sp->err == 0)
        read_stdin(sp);
    if (ac >= 3)
        check_rest(sp);
    return (0);
}