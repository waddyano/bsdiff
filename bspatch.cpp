/*-
 * Copyright 2003-2005 Colin Percival
 * Copyright 2012 Matthew Endsley
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions 
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <limits.h>
#include <stdio.h>
#include <zstd.h>
#include "bspatch.h"

static int64_t offtin(uint8_t *buf)
{
	int64_t y;

	y=buf[7]&0x7F;
	y=y*256;y+=buf[6];
	y=y*256;y+=buf[5];
	y=y*256;y+=buf[4];
	y=y*256;y+=buf[3];
	y=y*256;y+=buf[2];
	y=y*256;y+=buf[1];
	y=y*256;y+=buf[0];

	if(buf[7]&0x80) y=-y;

	return y;
}

int bspatch(const uint8_t* oldbytes, int64_t oldsize, uint8_t* newbytes, int64_t newsize, struct bspatch_stream* stream)
{
	uint8_t buf[8];
	int64_t oldpos,newpos;
	int64_t ctrl[3];
	int64_t i;

	printf("old file size %lld new file size %lld\n", oldsize, newsize);
	oldpos=0;newpos=0;
	while(newpos<newsize) {
		/* Read control data */
		for(i=0;i<=2;i++) {
			if (stream->read(stream, buf, 8))
				return -1;
			ctrl[i]=offtin(buf);
		};

		printf("ctrl %lld %lld %lld\n", ctrl[0], ctrl[1], ctrl[2]);
		/* Sanity-check */
		if (ctrl[0]<0 || ctrl[0]>INT_MAX ||
			ctrl[1]<0 || ctrl[1]>INT_MAX ||
			newpos+ctrl[0]>newsize)
			return -1;

		printf("oldpos %lld newpos %lld\n", oldpos, newpos);
		/* Read diff string */
		if (stream->read(stream, newbytes + newpos, (int)ctrl[0]))
			return -1;

		/* Add old data to diff string */
		for(i=0;i<ctrl[0];i++)
			if((oldpos+i>=0) && (oldpos+i<oldsize))
				newbytes[newpos+i]+=oldbytes[oldpos+i];

		/* Adjust pointers */
		newpos+=ctrl[0];
		oldpos+=ctrl[0];

		/* Sanity-check */
		if(newpos+ctrl[1]>newsize)
			return -1;

		/* Read extra string */
		if (stream->read(stream, newbytes + newpos, (int)ctrl[1]))
			return -1;

		/* Adjust pointers */
		newpos+=ctrl[1];
		oldpos+=ctrl[2];
	};

	return 0;
}

#if defined(BSPATCH_EXECUTABLE)

#include <bzlib.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <err.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <fcntl.h>

#ifdef _WIN32
#include <stdarg.h>
static void err(int eval, const char* fmt, ...)
{
	fprintf(stderr, "bsdiff: ");
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(errno));
	exit(eval);
}

static void errx(int eval, const char* fmt, ...)
{
	fprintf(stderr, "bsdiff: ");
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(eval);
}
#endif

struct ZSTD_stream
{
	size_t buffInSize;
	uint8_t* buffIn = nullptr;
	size_t buffOutSize;
	uint8_t* buffOut = nullptr;
	size_t outUsed;
	size_t outAvail;
	ZSTD_DCtx* dctx = nullptr;
	FILE* inputfp;
	ZSTD_inBuffer input;

	void init(FILE* fp)
	{
		inputfp = fp;
		buffInSize = ZSTD_CStreamInSize();
		buffIn = (uint8_t*)malloc(buffInSize);
		buffOutSize = ZSTD_CStreamOutSize();
		buffOut = (uint8_t*)malloc(buffOutSize);
		outUsed = 0;
		outAvail = 0;
		dctx = ZSTD_createDCtx();
		input = { nullptr, 0, 0 };

	}

	static int read(const bspatch_stream* stream, void* buffer, int size)
	{
		return ((ZSTD_stream*)stream->opaque)->read_internal(buffer, size);
	}

	int read_internal(void* buffer, int size)
	{
		size_t left = size;
		uint8_t* ptr = (uint8_t *)buffer;

		while (left > 0)
		{
			size_t chunk = left;
			if (chunk > outAvail)
			{
				chunk = outAvail;
			}

			if (chunk > 0)
			{
				memcpy(ptr, buffOut + outUsed, chunk);
				left -= chunk;
				outAvail -= chunk;
				ptr += chunk;
				outUsed += chunk;
				if (left == 0)
				{
					break;
				}
			}

			if (input.pos < input.size)
			{
				ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
				size_t const ret = ZSTD_decompressStream(dctx, &output, &input);
				if (output.pos > 0)
				{
					outUsed = 0;
					outAvail = output.pos;
					continue;
				}
			}

			size_t n = fread(buffIn, 1, buffInSize, inputfp);
			if (n == 0)
				break;
			input = { buffIn, n, 0 };
		}
		return 0;
	}

	~ZSTD_stream()
	{
		ZSTD_freeDCtx(dctx);
		free(buffIn);
		free(buffOut);
	}
};

static int bz2_read(const struct bspatch_stream* stream, void* buffer, int length)
{
	int n;
	int bz2err;
	BZFILE* bz2;

	bz2 = (BZFILE*)stream->opaque;
	n = BZ2_bzRead(&bz2err, bz2, buffer, length);
	if (n != length)
		return -1;

	return 0;
}

int main(int argc,char * argv[])
{
	FILE * f;
	int fd;
	int bz2err;
	uint8_t header[24];
	uint8_t *oldbytes, *newbytes;
	int64_t oldsize, newsize;
	BZFILE* bz2;
	struct stat sb;

	if(argc!=4) errx(1,"usage: %s oldfile newfile patchfile\n",argv[0]);

	/* Open patch file */
	if ((f = fopen(argv[3], "rb")) == NULL)
		err(1, "fopen(%s)", argv[3]);

	/* Read header */
	if (fread(header, 1, 24, f) != 24) {
		if (feof(f))
			errx(1, "Corrupt patch\n");
		err(1, "fread(%s)", argv[3]);
	}

	bool use_zstd = false;
	if (memcmp(header, "ENDSLEY/BSDIFF43", 16) == 0)
	{

	}
	else if (memcmp(header, "ENDSLEY/BSDIFF4Z", 16) == 0)
	{
		use_zstd = true;
	}
	else
	{
		errx(1, "Corrupt patch\n");
	}

	/* Read lengths from header */
	newsize=offtin(header+16);
	if(newsize<0)
		errx(1,"Corrupt patch\n");

	/* Close patch file and re-open it via libbzip2 at the right places */
	if(((fd=open(argv[1],O_RDONLY|O_BINARY,0))<0) ||
		((oldsize=lseek(fd,0,SEEK_END))==-1) ||
		((oldbytes=(uint8_t *)malloc(oldsize+1))==NULL) ||
		(lseek(fd,0,SEEK_SET)!=0) ||
		(read(fd,oldbytes,(int)oldsize)!=oldsize) ||
		(fstat(fd, &sb)) ||
		(close(fd)==-1)) err(1,"%s",argv[1]);
	if((newbytes=(uint8_t *)malloc(newsize+1))==NULL) err(1,NULL);

	if (NULL == (bz2 = BZ2_bzReadOpen(&bz2err, f, 0, 0, NULL, 0)))
		errx(1, "BZ2_bzReadOpen, bz2err=%d", bz2err);

	struct bspatch_stream stream;

	if (use_zstd)
	{
		printf("using zstd\n");
		ZSTD_stream* zstd = new ZSTD_stream;
		zstd->init(f);
		stream.read = ZSTD_stream::read;
		stream.opaque = zstd;
		if (bspatch(oldbytes, oldsize, newbytes, newsize, &stream))
			errx(1, "bspatch");
		delete zstd;
	}
	else
	{
		stream.read = bz2_read;
		stream.opaque = bz2;
		if (bspatch(oldbytes, oldsize, newbytes, newsize, &stream))
			errx(1, "bspatch");

		/* Clean up the bzip2 reads */
		BZ2_bzReadClose(&bz2err, bz2);
	}
	fclose(f);

	/* Write the new file */
	if(((fd=open(argv[2],O_CREAT|O_TRUNC|O_WRONLY|O_BINARY,sb.st_mode))<0) ||
		(write(fd,newbytes,(int)newsize)!=newsize) || (close(fd)==-1))
		err(1,"%s",argv[2]);

	free(newbytes);
	free(oldbytes);

	return 0;
}

#endif
