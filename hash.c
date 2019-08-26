#include "ft_ssl.h"

// void    grp_hash(t_md5 *sp)
// {
//     while (sp->q<4)
//     {
//          sp->abcd[sp->q] = sp->h[sp->q];
//          sp->q++;
//     }
// }

// void    add_hash(t_md5 *sp)
// {
//       sp->p = 0;
//     while (sp->p < 4)
//     {
//         sp->h[sp->p] += sp->abcd[sp->p];
//         sp->p++;
//     }
// }