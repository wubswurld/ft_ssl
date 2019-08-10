#ifndef FT_SSL_H
# define FT_SSL_H

# include <unistd.h>
# include <stdbool.h> 
# include <stdlib.h>
# include "final-libft/libft.h"

typedef struct	s_flags
{
	bool		s;
	bool		s1;
	bool		p;
	bool		r;
	bool		q;
}				t_flags;

typedef struct s_whole
{
    t_flags     fp;
	char		*store;
	int			hash;
	int			ret;
}               t_whole;

void    start_md5(t_whole *sp, char *av);
void    start_sha256(t_whole *sp, char *av);

typedef void	t_shift(t_whole *sp, char *av);

#endif