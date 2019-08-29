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

#define ROTR(x, n, w) (x >> n) | (x << (w - n))
#define ROTL(x, n, w) (x << n) | (x >> (w - n))
#define SHR(x, n) (x >> n)
#define CH(x, y, z) (x & y) ^ ((~x) & z)
#define MAJ(x, y, z) (x & y) ^ (x & z) ^ (y & z)

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
	short *rotn;
	short m;
	short o;
	short g;

} t_md5;

typedef struct s_sha_init
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t g;
	uint32_t h;

} t_sha_init;

typedef struct s_sha256
{
	unsigned int h[8];
	uint32_t w[64];
	uint32_t tmp[2];
	char *hold;
	char *tech;
	uint64_t block;
	t_sha_init *tp;
} t_sha256;

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

//algorithm
void get_h(t_md5 *sp);
void init_msg(t_md5 *sp, const char *msg, int mlen);
void set_grps(t_md5 *sp);
void handle_f(t_md5 *sp);
void handle_rest(t_md5 *sp);

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