#ifndef FT_SSL_H
# define FT_SSL_H

# include <unistd.h>
# include <stdbool.h> 
# include <stdlib.h>
# include "final-libft/libft.h"

typedef struct	s_flags
{
	bool		s;
	bool		p;
	bool		r;
	bool		q;
}				t_flags;

typedef struct s_whole
{
    t_flags     fp;
	int			hash;
	int			ret;
	char		*flags;
}               t_whole;

#endif