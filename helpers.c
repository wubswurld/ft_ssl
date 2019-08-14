#include "ft_ssl.h"

char	*ft_uitoa_base(unsigned int val, int base)
{
	// max base of 16 is = to 0123456789abcdef
	static char tmp[] = "0123456789abcdef";
	static char buf[65];
	char		*ptr;

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