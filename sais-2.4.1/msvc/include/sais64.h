/*
 * sais64.h for sais
 * Copyright (c) 2008-2010 Yuta Mori All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _SAIS64_H
#define _SAIS64_H 1

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <inttypes.h>

#ifndef SAIS_API
# define SAIS_API 
#endif

/*- Datatypes -*/
#ifndef _SA_UINT8_T
#define _SA_UINT8_T
typedef uint8_t sa_uint8_t;
#endif
#ifndef _SA_UINT16_T
#define _SA_UINT16_T
typedef uint16_t sa_uint16_t;
#endif
#ifndef _SA_UINT32_T
#define _SA_UINT32_T
typedef uint32_t sa_uint32_t;
#endif
#ifndef _SA_INT64_T
#define _SA_INT64_T
typedef int64_t sa_int64_t;
#endif
#ifndef SA_PRIdINT64
#define SA_PRIdINT64 PRId64
#endif


/*- Prototypes -*/

/**
 * Constructs the suffix array of a given string.
 * @param T[0..n-1] The input string.
 * @param SA[0..n-1] The output array of suffixes.
 * @param n The length of the given string.
 * @param k The alphabet size.
 * @return 0 if no error occurred, -1 or -2 otherwise.
 */
SAIS_API
sa_int64_t
sais64_u8(const sa_uint8_t *T, sa_int64_t *SA, sa_int64_t n, sa_int64_t k);

SAIS_API
sa_int64_t
sais64_u16(const sa_uint16_t *T, sa_int64_t *SA, sa_int64_t n, sa_int64_t k);

SAIS_API
sa_int64_t
sais64_u32(const sa_uint32_t *T, sa_int64_t *SA, sa_int64_t n, sa_int64_t k);

SAIS_API
sa_int64_t
sais64_i64(const sa_int64_t *T, sa_int64_t *SA, sa_int64_t n, sa_int64_t k);


/**
 * Constructs the burrows-wheeler transformed string of a given string.
 * @param T[0..n-1] The input string.
 * @param U[0..n-1] The output string. (can be T)
 * @param A[0..n-1] The temporary array. (can be NULL)
 * @param n The length of the given string.
 * @return The primary index if no error occurred, -1 or -2 otherwise.
 */
SAIS_API
sa_int64_t
sais64_u8_bwt(const sa_uint8_t *T, sa_uint8_t *U, sa_int64_t *A, sa_int64_t n, sa_int64_t k);

SAIS_API
sa_int64_t
sais64_u16_bwt(const sa_uint16_t *T, sa_uint16_t *U, sa_int64_t *A, sa_int64_t n, sa_int64_t k);

SAIS_API
sa_int64_t
sais64_u32_bwt(const sa_uint32_t *T, sa_uint32_t *U, sa_int64_t *A, sa_int64_t n, sa_int64_t k);

SAIS_API
sa_int64_t
sais64_i64_bwt(const sa_int64_t *T, sa_int64_t *U, sa_int64_t *A, sa_int64_t n, sa_int64_t k);


/**
 * Returns the version of the sais64 library.
 * @return The version number string.
 */
SAIS_API
const char *
sais64_version(void);


#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* _SAIS64_H */
