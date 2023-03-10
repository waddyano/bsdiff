/*
 * sais_config.h for sais
 * Copyright (c) 2010 Yuta Mori All Rights Reserved.
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

#ifndef _SAIS_CONFIG_H
#define _SAIS_CONFIG_H 1

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*- Define to the version of this package. -*/
#define PROJECT_VERSION_FULL "2.4.1"

/*- Define to 1 if you have the header files. -*/
#define HAVE_INTTYPES_H 1
#define HAVE_STDDEF_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
/* #undef HAVE_STRINGS_H */
#define HAVE_MEMORY_H 1
#define HAVE_SYS_TYPES_H 1

/*- for WinIO -*/
#define HAVE_IO_H 1
#define HAVE_FCNTL_H 1
#define HAVE__SETMODE 1
/* #undef HAVE_SETMODE */
#define HAVE__FILENO 1
#define HAVE_FOPEN_S 1
#define HAVE__O_BINARY 1
#ifndef HAVE__SETMODE
# if defined(HAVE_SETMODE)
#  define _setmode setmode
#  define HAVE__SETMODE 1
# endif
# if defined(HAVE__SETMODE) && !defined(HAVE__O_BINARY)
#  undef _O_BINARY
#  define _O_BINARY 0
#  define HAVE__O_BINARY 1
# endif
#endif

/*- for inline -*/
#ifndef INLINE
# define INLINE inline
#endif

/*- for Integer -*/
#define SA_INT32_C(val) INT32_C(val)
#define SA_UINT32_C(val) UINT32_C(val)
#define SA_INT64_C(val) INT64_C(val)

/*- for DLL -*/
#define SAIS_DLLEXPORT 


#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* _SAIS_CONFIG_H */
