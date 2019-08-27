#include "ft_ssl.h"

char *ft_uitoa_base(unsigned int val, int base)
{
	// max base of 16 is = to 0123456789abcdef
	static char tmp[] = "0123456789abcdef";
	static char buf[65];
	char *ptr;

	ptr = &buf[64];
	*ptr = '\0';
	if (val == 0)
	{
		*--ptr = tmp[val % base];
		val = val / base;
	}
	while (val != 0)
	{
		*--ptr = tmp[val % base];
		val = val / base;
	}
	return (ptr);
}

void putError(char *str)
{
	ft_putstr("md5: ");
	ft_putstr(str);
	ft_putstr(": ");
	ft_putstr("No such file or directory\n");
}

void invalid_option(char **av, int y, t_whole *sp)
{
	ft_putstr("md5: illegal option -- ");
	ft_putchar(av[sp->ret][y]);
	ft_putchar('\n');
	ft_putstr("usage: md5 [-pqrtx] [-s string] [files ...]\n");
	sp->err = 1;
}