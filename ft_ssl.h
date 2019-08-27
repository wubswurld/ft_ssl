#ifndef FT_SSL_H
#define FT_SSL_H

#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "final-libft/libft.h"

typedef unsigned Digest[4];
typedef unsigned (*DgstFctn)(unsigned a[]);

typedef struct s_flags
{
	bool s;
	bool s1;
	bool bp;
	bool p;
	bool r;
	bool q;
} t_flags;

typedef union s_hash {
	unsigned hold;
	unsigned char b[4];
} t_hash;

// typedef unsigned Digest[4];
// typedef unsigned (*DigestFunc)(unsigned a[]);
union s_union {
	unsigned w[16];
	char b[64];
} mm;

typedef union s_output {
	unsigned w;
	unsigned char b[4];
} t_output;

typedef struct s_whole
{
	t_flags fp;
	bool arg;
	bool err;
	char **fix;
	char *value;
	char *fin;
	int hash;
	int ret;
	int dir_ct;
	int cur_dir;
	int fd;
	int k;
	int j;
	char hold[10008];
} t_whole;

typedef struct s_md5
{
	int grps;
	int grp;
	int q;
	int p;
	int os;
	unsigned char *msg2;
	Digest h;
	Digest abcd;
	DgstFctn fctn;
	unsigned f;
	unsigned *k;
	unsigned kspace[64];

} t_md5;

// typedef struct s_md5
// {
// 	int grp;
// 	int grps;
// 	int os;
// 	int q;
// 	int p;
// 	short m;
// 	short o;
// 	short g;
// 	Digest abcd;
// 	unsigned f;
// 	unsigned char *msg2;
// 	short *rotn;
// 	unsigned kspace[64];
// 	unsigned *k;
// 	Digest h;
// 	DigestFunc fctn;
// } t_md5;

//printing
void putError(char *str);
void print_s1(char *str);
void print_arg(char *str);
void print_string_rev(char *str);
void error_one();
void invalid_hash(char *av);
void invalid_option(char **av, int y, t_whole *sp);
void print_md5(unsigned *d, t_whole *sp);
//parsing
void count_dir(char **av, t_whole *sp);
void parse_md5(char **av, t_whole *sp, int ac);
// void grp_hash(t_md5 *sp);
// void add_hash(t_md5 *sp);

//start
void start_md5(char *av, t_whole *sp);
void start_sha256(char *av, t_whole *sp);

int get_hash(char *str);
void get_flags(char **av, t_whole *sp);
unsigned *md5(const char *msg, int mlen);
char *ft_uitoa_base(unsigned int val, int base);
unsigned f0(unsigned abcd[]);
unsigned f1(unsigned abcd[]);
unsigned f2(unsigned abcd[]);
unsigned f3(unsigned abcd[]);
unsigned *calcKs(unsigned *k);
unsigned rol(unsigned v, short amt);

typedef void t_shift(char *av, t_whole *sp);

#endif