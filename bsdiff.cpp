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

#include "bsdiff.h"

#include <limits.h>
#include <sais64.h>
#include <string.h>

#define MIN(x,y) (((x)<(y)) ? (x) : (y))

static void split(int64_t *I,int64_t *V,int64_t start,int64_t len,int64_t h)
{
	int64_t i,j,k,x,tmp,jj,kk;

	if(len<16) {
		for(k=start;k<start+len;k+=j) {
			j=1;x=V[I[k]+h];
			for(i=1;k+i<start+len;i++) {
				if(V[I[k+i]+h]<x) {
					x=V[I[k+i]+h];
					j=0;
				};
				if(V[I[k+i]+h]==x) {
					tmp=I[k+j];I[k+j]=I[k+i];I[k+i]=tmp;
					j++;
				};
			};
			for(i=0;i<j;i++) V[I[k+i]]=k+j-1;
			if(j==1) I[k]=-1;
		};
		return;
	};

	x=V[I[start+len/2]+h];
	jj=0;kk=0;
	for(i=start;i<start+len;i++) {
		if(V[I[i]+h]<x) jj++;
		if(V[I[i]+h]==x) kk++;
	};
	jj+=start;kk+=jj;

	i=start;j=0;k=0;
	while(i<jj) {
		if(V[I[i]+h]<x) {
			i++;
		} else if(V[I[i]+h]==x) {
			tmp=I[i];I[i]=I[jj+j];I[jj+j]=tmp;
			j++;
		} else {
			tmp=I[i];I[i]=I[kk+k];I[kk+k]=tmp;
			k++;
		};
	};

	while(jj+j<kk) {
		if(V[I[jj+j]+h]==x) {
			j++;
		} else {
			tmp=I[jj+j];I[jj+j]=I[kk+k];I[kk+k]=tmp;
			k++;
		};
	};

	if(jj>start) split(I,V,start,jj-start,h);

	for(i=0;i<kk-jj;i++) V[I[jj+i]]=kk-1;
	if(jj==kk-1) I[jj]=-1;

	if(start+len>kk) split(I,V,kk,start+len-kk,h);
}

static void qsufsort(int64_t *I,int64_t *V,const uint8_t *old,int64_t oldsize)
{
	int64_t buckets[256];
	int64_t i,h,len;

	for(i=0;i<256;i++) buckets[i]=0;
	for(i=0;i<oldsize;i++) buckets[old[i]]++;
	for(i=1;i<256;i++) buckets[i]+=buckets[i-1];
	for(i=255;i>0;i--) buckets[i]=buckets[i-1];
	buckets[0]=0;

	for(i=0;i<oldsize;i++) I[++buckets[old[i]]]=i;
	I[0]=oldsize;
	for(i=0;i<oldsize;i++) V[i]=buckets[old[i]];
	V[oldsize]=0;
	for(i=1;i<256;i++) if(buckets[i]==buckets[i-1]+1) I[buckets[i]]=-1;
	I[0]=-1;

	for(h=1;I[0]!=-(oldsize+1);h+=h) {
		len=0;
		for(i=0;i<oldsize+1;) {
			if(I[i]<0) {
				len-=I[i];
				i-=I[i];
			} else {
				if(len) I[i-len]=-len;
				len=V[I[i]]+1-i;
				split(I,V,i,len,h);
				i+=len;
				len=0;
			};
		};
		if(len) I[i-len]=-len;
	};

	for(i=0;i<oldsize+1;i++) I[V[i]]=i;
}

static int64_t matchlen(const uint8_t *oldbytes,int64_t oldsize,const uint8_t *newbytes,int64_t newsize)
{
	int64_t i;

	for(i=0;(i<oldsize)&&(i<newsize);i++)
		if(oldbytes[i]!=newbytes[i]) break;

	return i;
}

static int64_t search(const int64_t *I,const uint8_t *oldbytes,int64_t oldsize,
		const uint8_t *newbytes,int64_t newsize,int64_t st,int64_t en,int64_t *pos)
{
	int64_t x,y;

	if(en-st<2) {
		x=matchlen(oldbytes+I[st],oldsize-I[st],newbytes,newsize);
		y=matchlen(oldbytes+I[en],oldsize-I[en],newbytes,newsize);

		if(x>y) {
			*pos=I[st];
			return x;
		} else {
			*pos=I[en];
			return y;
		}
	};

	x=st+(en-st)/2;
	if(memcmp(oldbytes+I[x],newbytes,MIN(oldsize-I[x],newsize))<0) {
		return search(I,oldbytes,oldsize,newbytes,newsize,x,en,pos);
	} else {
		return search(I,oldbytes,oldsize,newbytes,newsize,st,x,pos);
	};
}

static void offtout(int64_t x,uint8_t *buf)
{
	int64_t y;

	if(x<0) y=-x; else y=x;

	buf[0]=y%256;y-=buf[0];
	y=y/256;buf[1]=y%256;y-=buf[1];
	y=y/256;buf[2]=y%256;y-=buf[2];
	y=y/256;buf[3]=y%256;y-=buf[3];
	y=y/256;buf[4]=y%256;y-=buf[4];
	y=y/256;buf[5]=y%256;y-=buf[5];
	y=y/256;buf[6]=y%256;y-=buf[6];
	y=y/256;buf[7]=y%256;

	if(x<0) buf[7]|=0x80;
}

static int64_t writedata(struct bsdiff_stream* stream, const void* buffer, int64_t length)
{
	int64_t result = 0;

	while (length > 0)
	{
		const int smallsize = (int)MIN(length, INT_MAX);
		const int writeresult = stream->write(stream, buffer, smallsize);
		if (writeresult == -1)
		{
			return -1;
		}

		result += writeresult;
		length -= smallsize;
		buffer = (uint8_t*)buffer + smallsize;
	}

	return result;
}

struct bsdiff_request
{
	const uint8_t* oldbytes;
	int64_t oldsize;
	const uint8_t* newbytes;
	int64_t newsize;
	struct bsdiff_stream* stream;
	int64_t *I;
	uint8_t *buffer;
	bool use_sais;
};

static int bsdiff_internal(const struct bsdiff_request req)
{
	int64_t* I;
	int64_t scan, pos, len;
	int64_t lastscan, lastpos, lastoffset;
	int64_t oldscore, scsc;
	int64_t s, Sf, lenf, Sb, lenb;
	int64_t overlap, Ss, lens;
	int64_t i;
	uint8_t* buffer;
	uint8_t buf[8 * 3];

	I = req.I;

	if (req.use_sais)
	{
		sais64_u8(req.oldbytes, I, req.oldsize, 256);
	}
	else
	{
		int64_t* V;
		if ((V = (int64_t*)req.stream->malloc((req.oldsize + 1) * sizeof(int64_t))) == NULL) return -1;
		qsufsort(I, V, req.oldbytes, req.oldsize);
		req.stream->free(V);
	}

	buffer = req.buffer;

	/* Compute the differences, writing ctrl as we go */
	scan=0;len=0;pos=0;
	lastscan=0;lastpos=0;lastoffset=0;
	while(scan<req.newsize) {
		oldscore=0;

		for(scsc=scan+=len;scan<req.newsize;scan++) {
			len=search(I,req.oldbytes,req.oldsize,req.newbytes+scan,req.newsize-scan,
					0,req.oldsize,&pos);

			for(;scsc<scan+len;scsc++)
			if((scsc+lastoffset<req.oldsize) &&
				(req.oldbytes[scsc+lastoffset] == req.newbytes[scsc]))
				oldscore++;

			if(((len==oldscore) && (len!=0)) || 
				(len>oldscore+8)) break;

			if((scan+lastoffset<req.oldsize) &&
				(req.oldbytes[scan+lastoffset] == req.newbytes[scan]))
				oldscore--;
		};

		if((len!=oldscore) || (scan==req.newsize)) {
			s=0;Sf=0;lenf=0;
			for(i=0;(lastscan+i<scan)&&(lastpos+i<req.oldsize);) {
				if(req.oldbytes[lastpos+i]==req.newbytes[lastscan+i]) s++;
				i++;
				if(s*2-i>Sf*2-lenf) { Sf=s; lenf=i; };
			};

			lenb=0;
			if(scan<req.newsize) {
				s=0;Sb=0;
				for(i=1;(scan>=lastscan+i)&&(pos>=i);i++) {
					if(req.oldbytes[pos-i]==req.newbytes[scan-i]) s++;
					if(s*2-i>Sb*2-lenb) { Sb=s; lenb=i; };
				};
			};

			if(lastscan+lenf>scan-lenb) {
				overlap=(lastscan+lenf)-(scan-lenb);
				s=0;Ss=0;lens=0;
				for(i=0;i<overlap;i++) {
					if(req.newbytes[lastscan+lenf-overlap+i]==
					   req.oldbytes[lastpos+lenf-overlap+i]) s++;
					if(req.newbytes[scan-lenb+i]==
					   req.oldbytes[pos-lenb+i]) s--;
					if(s>Ss) { Ss=s; lens=i+1; };
				};

				lenf+=lens-overlap;
				lenb-=lens;
			};

			offtout(lenf,buf);
			offtout((scan-lenb)-(lastscan+lenf),buf+8);
			offtout((pos-lenb)-(lastpos+lenf),buf+16);

			/* Write control data */
			if (writedata(req.stream, buf, sizeof(buf)))
				return -1;

			/* Write diff data */
			int64_t nz = 0;
			for (i = 0; i < lenf; i++)
			{
				buffer[i] = req.newbytes[lastscan + i] - req.oldbytes[lastpos + i];
				if (buffer[i] == 0)
					++nz;
			}
			if (writedata(req.stream, buffer, lenf))
				return -1;

			/* Write extra data */
			for(i=0;i<(scan-lenb)-(lastscan+lenf);i++)
				buffer[i]=req.newbytes[lastscan+lenf+i];
			if (writedata(req.stream, buffer, (scan-lenb)-(lastscan+lenf)))
				return -1;

			lastscan=scan-lenb;
			lastpos=pos-lenb;
			lastoffset=pos-scan;
		};
	};

	return 0;
}

int bsdiff(const uint8_t* oldbytes, int64_t oldsize, const uint8_t* newbytes, int64_t newsize, struct bsdiff_stream* stream, bool use_sais)
{
	int result;
	struct bsdiff_request req;

	if((req.I=(int64_t *)stream->malloc((oldsize+1)*sizeof(int64_t)))==NULL)
		return -1;

	if((req.buffer=(uint8_t *)stream->malloc(newsize+1))==NULL)
	{
		stream->free(req.I);
		return -1;
	}

	req.oldbytes = oldbytes;
	req.oldsize = oldsize;
	req.newbytes = newbytes;
	req.newsize = newsize;
	req.stream = stream;
	req.use_sais = use_sais;

	result = bsdiff_internal(req);

	stream->free(req.buffer);
	stream->free(req.I);

	return result;
}

#if defined(BSDIFF_EXECUTABLE)

#include <sys/types.h>

#include <bzlib.h>
#include <zstd.h>
#ifndef _WIN32
#include <err.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

struct ZSTD_stream
{
	size_t buffInSize;
	uint8_t* buffIn = nullptr;
	size_t buffOutSize;
	uint8_t* buffOut = nullptr;
	size_t inUsed;
	ZSTD_CCtx* cctx = nullptr;
	FILE* outputfp;

	void init(FILE *fp)
	{
		outputfp = fp;
		buffInSize = ZSTD_CStreamInSize();
		buffIn = (uint8_t *)malloc(buffInSize);
		buffOutSize = ZSTD_CStreamOutSize();
		buffOut = (uint8_t*)malloc(buffOutSize);
		inUsed = 0;
		cctx = ZSTD_createCCtx();

		ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, 9);
		ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);
		ZSTD_CCtx_setParameter(cctx, ZSTD_c_nbWorkers, 1);
	}

	static int write(struct bsdiff_stream* stream, const void* buffer, int size)
	{
		return ((ZSTD_stream *)stream->opaque)->write_internal(buffer, size);
	}
	
	int write_internal(const void* buffer, int size)
	{
		size_t left = size;
		const uint8_t* ptr = (const uint8_t*)buffer;

		while (left > 0)
		{
			size_t chunk = left;
			if (chunk > buffInSize - inUsed)
			{
				chunk = buffInSize - inUsed;
			}

			memcpy(buffIn + inUsed, ptr, chunk);
			inUsed += chunk;
			left -= chunk;
			ptr += chunk;
			if (left == 0)
				return 0;

			ZSTD_inBuffer input = { buffIn, buffInSize, 0 };
			do
			{
				ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
				size_t const remaining = ZSTD_compressStream2(cctx, &output, &input, ZSTD_e_continue);
				if (fwrite(buffOut, 1, output.pos, outputfp) != output.pos)
				{
					return -1;
				}
			} while (input.pos < input.size);

			inUsed = 0;
		}

		return 0;
	}

	void flush()
	{
		ZSTD_inBuffer input = { buffIn, inUsed, 0 };
		size_t remaining;
		do
		{
			ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
			remaining = ZSTD_compressStream2(cctx, &output, &input, ZSTD_e_end);
			fwrite(buffOut, 1, output.pos, outputfp);
		} while (remaining != 0);
	}

	~ZSTD_stream()
	{
		ZSTD_freeCCtx(cctx);
		free(buffIn);
		free(buffOut);
	}
};

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

#if _WIN32
#include <time.h>
#define EPOCHFILETIME (116444736000000000LL)

struct timezone
{
	int tz_minuteswest; /* minutes W of Greenwich */
	int tz_dsttime;     /* type of dst correction */
};

int gettimeofday(struct timeval* tv, struct timezone* tz)
{
	static bool      tzflag;

	if (tv != nullptr)
	{
		FILETIME        ft;
		LARGE_INTEGER   li;
		GetSystemTimeAsFileTime(&ft);
		li.LowPart = ft.dwLowDateTime;
		li.HighPart = ft.dwHighDateTime;
		int64_t t = li.QuadPart;       /* In 100-nanosecond intervals */
		t -= EPOCHFILETIME;     /* Offset to the Epoch time */
		t /= 10;                /* In microseconds */
		tv->tv_sec = (long)(t / 1000000);
		tv->tv_usec = (long)(t % 1000000);
	}

	if (tz != nullptr)
	{
		if (!tzflag)
		{
			_tzset();
			tzflag = true;
		}

		tz->tz_minuteswest = _timezone / 60;
		tz->tz_dsttime = _daylight;
	}

	return 0;
}
#endif

static int bz2_write(struct bsdiff_stream* stream, const void* buffer, int size)
{
	int bz2err;
	BZFILE* bz2;

	bz2 = (BZFILE*)stream->opaque;
	BZ2_bzWrite(&bz2err, bz2, (void*)buffer, size);
	if (bz2err != BZ_STREAM_END && bz2err != BZ_OK)
		return -1;

	return 0;
}

int main(int argc,char *argv[])
{
	int fd;
	int bz2err;
	uint8_t *oldbytes = NULL,*newbytes = NULL;
	off_t oldsize,newsize;
	uint8_t buf[8];
	FILE * pf;

	int i = 1;
	bool use_zstd = false;
	bool use_sais = false;

	while (i < argc)
	{
		if (strcmp(argv[i], "-zstd") == 0)
		{
			use_zstd = true;
			++i;
		}
		else if (strcmp(argv[i], "-sais") == 0)
		{
			use_sais = true;
			++i;
		}
		else
		{
			break;
		}
	}

	if (i + 3 != argc) errx(1, "usage: %s [ -zstd ] [-sais] oldfile newfile patchfile\n", argv[0]);

	timeval start;
	gettimeofday(&start, nullptr);

	const char* oldfile = argv[i];
	const char* newfile = argv[i + 1];
	const char* patchfile = argv[i + 2];

	/* Allocate oldsize+1 bytes instead of oldsize bytes to ensure
		that we never try to malloc(0) and get a NULL pointer */
	if(((fd=open(oldfile,O_RDONLY|O_BINARY,0))<0) ||
		((oldsize=lseek(fd,0,SEEK_END))==-1) ||
		((oldbytes=(uint8_t *)malloc(oldsize+1))==NULL) ||
		(lseek(fd,0,SEEK_SET)!=0) ||
		(read(fd,oldbytes,oldsize)!=oldsize) ||
		(close(fd)==-1)) err(1,"loading %s",oldfile);


	/* Allocate newsize+1 bytes instead of newsize bytes to ensure
		that we never try to malloc(0) and get a NULL pointer */
	if(((fd=open(newfile,O_RDONLY|O_BINARY,0))<0) ||
		((newsize=lseek(fd,0,SEEK_END))==-1) ||
		((newbytes=(uint8_t *)malloc(newsize+1))==NULL) ||
		(lseek(fd,0,SEEK_SET)!=0) ||
		(read(fd,newbytes,newsize)!=newsize) ||
		(close(fd)==-1)) err(1,"load %s",newfile);

	/* Create the patch file */
	if ((pf = fopen(patchfile, "wb")) == NULL)
		err(1, "opening %s", patchfile);

	/* Write header (signature+newsize)*/
	offtout(newsize, buf);

	const char* head = "ENDSLEY/BSDIFF43";
	if (use_zstd)
	{
		head = "ENDSLEY/BSDIFF4Z";
	}
	if (fwrite(head, 16, 1, pf) != 1 ||
		fwrite(buf, sizeof(buf), 1, pf) != 1)
		err(1, "Failed to write header");


	struct bsdiff_stream stream;
	memset(&stream, 0, sizeof(stream));
	stream.malloc = malloc;
	stream.free = free;

	if (use_zstd)
	{
		stream.write = ZSTD_stream::write;

		ZSTD_stream* zstd = new ZSTD_stream;
		zstd->init(pf);
		stream.opaque = zstd;

		if (bsdiff(oldbytes, oldsize, newbytes, newsize, &stream, use_sais))
			err(1, "bsdiff itself");

		zstd->flush();
		delete zstd;
	}
	else
	{
		stream.write = bz2_write;

		BZFILE* bz2;
		if (NULL == (bz2 = BZ2_bzWriteOpen(&bz2err, pf, 9, 0, 0)))
			errx(1, "BZ2_bzWriteOpen, bz2err=%d", bz2err);

		stream.opaque = bz2;
		if (bsdiff(oldbytes, oldsize, newbytes, newsize, &stream, use_sais))
			err(1, "bsdiff");

		BZ2_bzWriteClose(&bz2err, bz2, 0, NULL, NULL);
		if (bz2err != BZ_OK)
			err(1, "BZ2_bzWriteClose, bz2err=%d", bz2err);
	}

	if (fclose(pf))
		err(1, "fclose");

	/* Free the memory we used */
	free(oldbytes);
	free(newbytes);

	timeval end;
	gettimeofday(&end, nullptr);

	end.tv_sec -= start.tv_sec;
	end.tv_usec -= start.tv_usec;
	if (end.tv_usec < 0)
	{
		--end.tv_sec;
		end.tv_usec += 1000000;
	}

	printf("took %d.%03d\n", end.tv_sec, end.tv_usec / 1000);

	return 0;
}

#endif
