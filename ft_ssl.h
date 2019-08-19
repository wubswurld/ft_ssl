#ifndef FT_SSL_H
# define FT_SSL_H

# include <unistd.h>
# include <stdbool.h> 
# include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
# include "final-libft/libft.h"

typedef struct	s_flags
{
	bool		s;
	bool		s1;
	bool		bp;
	bool		p;
	bool		r;
	bool		q;
}				t_flags;

typedef union 	s_hash {
    unsigned hold;
    unsigned char b[4];
} 				t_hash;

typedef union 	s_munion{
        unsigned w[16];
        char     b[64];
} 				t_munion;

typedef unsigned Digest[4];
typedef unsigned (*DigestFunc)(unsigned a[]);

typedef struct s_whole
{
    t_flags     fp;
	bool		arg;
	char		*argval;
	char		*store;
	char		**fix;
	char		*value;
	char		*fin;
	int			hash;
	int			ret;
}               t_whole;

typedef struct s_md5
{
	int grp;
    int grps;
	int os;
    int q;
    int p;
	short m; 
	short o; 
	short g;
	Digest abcd;
    unsigned f;
	unsigned char *msg2;
	short *rotn;
	unsigned kspace[64];
	unsigned *k;
	Digest h;  
	DigestFunc fctn;
}				t_md5;

void	putError(char *str);
void    print_s1(char *str);
void    grp_hash(t_md5 *sp);
void    add_hash(t_md5 *sp);
void    start_md5(char *av, t_whole *sp);
void    start_sha256(char *av,t_whole *sp);
void    get_args(t_whole *sp, char *av);
int     get_hash(char *str);
void    get_flags(char *av, t_whole *sp);
unsigned *md5( const char *msg, int mlen);
char	*ft_uitoa_base(unsigned int val, int base);
unsigned f0( unsigned abcd[] );
unsigned f1( unsigned abcd[] );
unsigned f2( unsigned abcd[] );
unsigned f3( unsigned abcd[] );
unsigned *calcKs( unsigned *k);
unsigned rol( unsigned v, short amt );

typedef void	t_shift(char *av, t_whole *sp);

#endif