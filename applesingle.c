/*

applesingle.c - command line utility for manipulating AppleSingle and
                AppleDouble files.

Build cmd for Mac OS 10.4:
  gcc -DHAVE_DESKTOP_MANAGER -O2 -framework Carbon -lcrypto applesingle.c -o applesingle
Build cmd for later releases (e.g. with openssl installed under /usr/local):
  cc -m32 -Wno-deprecated-declarations -O2 -framework Carbon -lcrypto applesingle.c -o applesingle
Build cmd for Linux/x86:
  cc -O2 -lcrypto applesingle.c -o applesingle

Copyright (c) 2006, 2009, 2011, 2016, 2019 Finn Thain
fthain@telegraphics.com.au

Portions of Desktop Manager support code copyright (c) 1992-2002 Apple Computer, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Notes:
* This format is too limited to represent modern HFS+ features like large
  forks and POSIX dates. Two files make up an AppleDouble: Data (foo) and
  Header (foo.ADF or ._foo in Mac OS X). It appears ._foo is subject to the
  same 4 GB resource fork size limit and doesn't encode any dates (only
  the resource fork and finder information entries).
* The traditional Finder/Desktop comment is not the same as Spotlight's
  kMDItemFinderComment attribute, so Tiger doesn't really provide a way to
  store them or access them since the Desktop Database API was deprecated.
* The POSIX file name is a custom extension to the format. It is encoded
  in UTF-8 (since HFS+ does this).
* This program is able to output a series of AppleSingle files in one
  stream, similar to archive tools like cpio(1) or pax(1). This feature is
  presently only really useful for comparing files (and for validating entire
  backups) because this program is not able to reconstruct archived files.
  However, the command line options syntax is modeled on pax(1) and may
  eventually get a "-r" option for this. Or perhaps a better approach would
  be instead to extend pax itself (like hfspax).
* The format doesn't accomodate directories, but could probably be extended.
* Apple now ships their own "applesingle" command, which means this one should
  be renamed.

2006-06-19 First cut.
2009-09-01 Clean up code style. Rewrite help text. Rework argument parsing and
           error handling. Add access time suppression. Numerous bug fixes.
2011-03-29 Improve option handling. Clean up comments and indentation.
2011-04-01 Clean up some error messages. Fix AppleDouble rsrc padding bug. Also
           improve -v option behaviour. Simplify filename seperator output.
2011-04-03 Fix data fork too big error for AppleSingle encoding.
2016-08-08 Add HAVE_DESKTOP_MANAGER macro to fix build on recent OS releases.
2019-11-23 Add support for non-Mac (e.g. Linux) hosts.
*/


#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <dirent.h>
#include <openssl/md5.h>

#ifdef __MACOSX__
#include <Carbon/Carbon.h>
#define ENABLE_ENCODING
#define EPROTO EFTYPE
#else
#include <stdlib.h>
#include <string.h>
typedef int8_t SInt8;
typedef int16_t SInt16;
typedef int32_t SInt32;
typedef int64_t SInt64;
typedef uint8_t UInt8;
typedef uint16_t UInt16;
typedef uint32_t UInt32;
typedef uint64_t UInt64;
#endif


/* AppleSingle file header and AppleDouble "header file" header. */
struct asHdr {
	UInt32 magic;
	UInt32 version;
	UInt8  filler[16];
	UInt16 entries;
} __attribute__ ((packed));

typedef struct asHdr asHdr;

/* Magic numbers. */
enum { kAppleDoubleMagic = 0x00051607, kAppleSingleMagic = 0x00051600 };

/* This program only produces version 2 files. */
#define AS_VERSION 0x00020000

/* Entry descriptor. */
struct asEntryDesc {
	UInt32 entry_id;
	UInt32 offset;
	UInt32 length;
} __attribute__ ((packed));

typedef struct asEntryDesc asEntryDesc;

/* Predefined entry IDs. */
#define AS_DATA         1
#define AS_RESOURCE     2
#define AS_NAME         3
#define AS_COMMENT      4
#define AS_FILE_DATES   8
#define AS_FILE_INFO    9
#define AS_MAC_INFO    10

/* Non-standard entry ID (beware, invented here). */
#define AS_POSIX_NAME    0x00000101 /* Always the first entry, if present */

/* File dates info entry. */
struct asDatesEntry {
	SInt32 creation;
	SInt32 modification;
	SInt32 backup;
	SInt32 access;
} __attribute__ ((packed));

typedef struct asDatesEntry asDatesEntry;

/* Mac info entry. */
typedef UInt32 asMacInfoEntry;

/* Mac info entry constants. */
enum { kASMacInfoLocked = 0x01, kASMacInfoProtected = 0x02 };


/* Some error handling routines. */

char *err_msg = NULL;
char err_msg_buf[255];

inline int posix_error3(int e, char *fmt, char *m)
{
	if (e == 0)
		return 0;
	snprintf(err_msg_buf, sizeof(err_msg_buf), fmt, m, strerror(e));
	err_msg = err_msg_buf;
	return e;
}

inline int posix_error(int e, char *m)
{
	return posix_error3(e, "%s: %s", m);
}

void report_and_reset_error(char *m)
{
	if (err_msg != NULL) {
		fprintf(stderr, "%s: %s\n", m, err_msg);
		err_msg = NULL;
	}
}

#ifdef ENABLE_ENCODING

inline OSErr carbon_error(OSErr e, char *m)
{
	if (e == 0)
		return 0;
	snprintf(err_msg_buf, sizeof(err_msg_buf), "%s: error %d", m, e);
	err_msg = err_msg_buf;
	return e;
}

/* A routine to figure out whether the HFS unsigned 48-bit seconds-since-1904
 * quantity fits in the AppleSingle/Double signed 32-bit seconds-since-2000
 * variable, and also do the conversion.
 */

int utcdatetime_to_AS(UTCDateTime *utcdt)
{
	unsigned int rounding = utcdt->fraction >> 15;
	unsigned long long t = ((unsigned long long)utcdt->highSeconds << 32) +
	                       utcdt->lowSeconds + rounding;
	if (t == 0)
		return 0; /* no need to mess it up further */
	if (t < 882006352ULL) {
		fprintf(stderr, "timestamp value is too small\n");
		return (int)0x80000000;
	}
	if (t > 5176973647ULL) {
		fprintf(stderr, "timestamp value is too large\n");
		return (int)0x7fffffff;
	}
	return (long long)t - 3029490000LL;
}


#ifdef HAVE_DESKTOP_MANAGER /* Not available in 64-bit Carbon (Leopard etc.) */

/* Routines to extract the Finder comment.
 * Adapted from Apple's MoreDesktopMgr.c sample.
 */

OSErr GetDesktopFileName(short vRefNum, Str255 desktopName)
{
	OSErr error;
	HParamBlockRec pb;
	short index;
	Boolean found;

	pb.fileParam.ioNamePtr = desktopName;
	pb.fileParam.ioVRefNum = vRefNum;
	pb.fileParam.ioFVersNum = 0;
	index = 1;
	found = false;
	do {
		pb.fileParam.ioDirID = fsRtDirID;
		pb.fileParam.ioFDirIndex = index;
		error = PBHGetFInfoSync(&pb);
		if (error == noErr)
			if ((pb.fileParam.ioFlFndrInfo.fdType == 'FNDR') &&
			    (pb.fileParam.ioFlFndrInfo.fdCreator == 'ERIK'))
				found = true;
		++index;
	} while ((error == noErr) && !found);

	return error;
}

OSErr GetVolumeInfoNoName(ConstStr255Param pathname, short vRefNum, HParmBlkPtr pb)
{
	Str255 tempPathname;
	OSErr error;

	if (pb != NULL)
	{
		pb->volumeParam.ioVRefNum = vRefNum;
		if (pathname == NULL) {
			pb->volumeParam.ioNamePtr = NULL;
			pb->volumeParam.ioVolIndex = 0;    /* use ioVRefNum only */
		} else {
			BlockMoveData(pathname, tempPathname, pathname[0] + 1);  /* make a copy of the string and */
			pb->volumeParam.ioNamePtr = (StringPtr)tempPathname;  /* use the copy so original isn't trashed */
			pb->volumeParam.ioVolIndex = -1;  /* use ioNamePtr/ioVRefNum combination */
		}
		error = PBHGetVInfoSync(pb);
		pb->volumeParam.ioNamePtr = NULL;  /* ioNamePtr may point to local tempPathname, so don't return it */
		carbon_error(error, "PBHGetVInfoSync");
	}
	else
		carbon_error(error = paramErr, "GetVolumeInfoNoName");
	return error;
}

OSErr DetermineVRefNum(ConstStr255Param pathname, short vRefNum, short *realVRefNum)
{
	HParamBlockRec pb;
	OSErr error;

	error = GetVolumeInfoNoName(pathname, vRefNum, &pb);
	if (error == noErr)
		*realVRefNum = pb.volumeParam.ioVRefNum;
	return error;
}

enum { kFCMTResType = 'FCMT' };

OSErr GetCommentFromDesktopFile(short vRefNum, ConstStr255Param name, Str255 comment, short commentID)
{
	OSErr error;
	short realVRefNum;
	Str255 desktopName;
	short savedResFile;
	short dfRefNum;
	StringHandle commentHandle;

	/* commentID == 0 means there's no comment */
	if (commentID != 0) {
		error = DetermineVRefNum(name, vRefNum, &realVRefNum);
		if (error == noErr) {
			error = GetDesktopFileName(realVRefNum, desktopName);
			if (error == noErr) {
				savedResFile = CurResFile();
				SetResLoad(false);
				dfRefNum = HOpenResFile(realVRefNum, fsRtDirID, desktopName, fsRdPerm);
				SetResLoad(true);

				if (dfRefNum != -1) {
					UseResFile(dfRefNum);
					/* Get the comment resource */
					commentHandle = (StringHandle)Get1Resource(kFCMTResType, commentID);
					if (commentHandle != NULL)
						if (GetHandleSize((Handle)commentHandle) > 0)
							BlockMoveData(*commentHandle, comment, *commentHandle[0] + 1);
						else
							error = afpItemNotFound;
					else
						error = afpItemNotFound;

					/* restore the resource chain and close the Desktop file */
					UseResFile(savedResFile);
					CloseResFile(dfRefNum);
				} else
					carbon_error(error = ResError(), "HOpenResFile");
			} else
				error = afpItemNotFound;
		}
	} else
		error = afpItemNotFound;

	return error;
}

OSErr DTGetComment(short vRefNum, long dirID, Str255 name, Str255 comment, short commentID)
{
	DTPBRec pb;
	OSErr error;

	if (comment != NULL) {
		comment[0] = 0;  /* return nothing by default */
		/* attempt to open the desktop database */
		pb.ioNamePtr = name;
		pb.ioVRefNum = vRefNum;
		error = PBDTOpenInform(&pb);
		if (error == noErr) {
			/* There was a desktop database and it's now open */
			if ((pb.ioTagInfo & 1) == 1) {
				pb.ioDirID = dirID;
				pb.ioDTBuffer = (void *)&comment[1];
				pb.ioDTReqCount = 255;
				error = PBDTGetCommentSync(&pb);
				if (error != afpItemNotFound && !carbon_error(error, "PBDTGetCommentSync"))
					comment[0] = (unsigned char)pb.ioDTActCount;
			}
		} else /* There is no desktop database - try the Desktop file */
			error = GetCommentFromDesktopFile(vRefNum, name, comment, commentID);
	} else
		carbon_error(error = paramErr, "DTGetComment");

	return error;
}

#endif /* HAVE_DESKTOP_MANAGER */


#define READ_BUFFER_SIZE (32 * 1024)

/* A routine to output a given fork. */

OSErr dump_fork(UInt64 *pos, FSRef *ref, HFSUniStr255 *forkName)
{
	SInt16 forkRefNum;
	OSErr err = FSOpenFork(ref, forkName->length, forkName->unicode,
	                       fsRdPerm, &forkRefNum);
	if (carbon_error(err, "FSOpenFork")) return err;

	char *buf = malloc(READ_BUFFER_SIZE);
	if (!buf) {
		posix_error(err = errno, "malloc");
		FSCloseFork(forkRefNum);
		return err;
	}

	OSErr read_err;
	do {
		ByteCount n = 0;
		read_err = FSReadFork(forkRefNum, fsAtMark | noCacheMask, 0,
		                      READ_BUFFER_SIZE, buf, &n);
		*pos += fwrite(buf, 1, n, stdout);
		if (posix_error(err = ferror(stdout), "fwrite"))
			break;
		if (read_err && read_err != eofErr) {
			err = carbon_error(read_err, "FSReadFork");
			break;
		}
	} while (!read_err);
	free(buf);
	FSCloseFork(forkRefNum);
	return err;
}


/* Output some nulls. */

int dump_padding(UInt64 *pos, size_t n)
{
	int err;
	char *buf = calloc(1, n);
	if (buf == NULL) {
		posix_error(err = errno, "calloc");
	} else {
		*pos += fwrite(buf, 1, n, stdout);
		posix_error(err = ferror(stdout), "fwrite");
		free(buf);
	}
	return err;
}


/* Output the POSIX name entry. */

int dump_posix_name(UInt64 *pos, char *p)
{
	*pos += fwrite(p, 1, strlen(p), stdout);
	return posix_error(ferror(stdout), "fwrite");
}


/* Output the comment entry. */

int dump_comment(UInt64 *pos, Str255 c)
{
	*pos += fwrite(&c[1], 1, (size_t)c[0], stdout);
	return posix_error(ferror(stdout), "fwrite");
}


/* Output the name entry. */

int dump_name(UInt64 *pos, FSSpec *s)
{
	*pos += fwrite(&s->name[1], 1, (size_t)s->name[0], stdout);
	return posix_error(ferror(stdout), "fwrite");
}


/* Output the Mac info entry. */

int dump_mac_info(UInt64 *pos, FSCatalogInfo *ci)
{
	asMacInfoEntry e = 0;
	e |= ci->nodeFlags & kFSNodeLockedMask ? kASMacInfoLocked : 0;
	e |= ci->nodeFlags & kFSNodeCopyProtectMask ? kASMacInfoProtected : 0;
	*pos += fwrite(&e, 1, sizeof(e), stdout);
	return posix_error(ferror(stdout), "fwrite");
}


/* Output the file dates entry. */

int dump_file_dates(UInt64 *pos, FSCatalogInfo *ci, short quash_atime)
{
	asDatesEntry e;
	e.creation = htobe32(utcdatetime_to_AS(&ci->createDate));
	e.modification = htobe32(utcdatetime_to_AS(&ci->contentModDate));
	e.backup = htobe32(utcdatetime_to_AS(&ci->backupDate));
	e.access = htobe32(utcdatetime_to_AS(quash_atime ?
	                                     &ci->contentModDate : &ci->accessDate));
	*pos += fwrite(&e, 1, sizeof(e), stdout);
	return posix_error(ferror(stdout), "fwrite");
}


/* Output the file info entry. */

int dump_file_info(UInt64 *pos, FSCatalogInfo *ci)
{
	*pos += fwrite(&ci->finderInfo, 1, sizeof(ci->finderInfo), stdout);
	int err = ferror(stdout);
	if (posix_error(err, "fwrite")) return err;
	*pos += fwrite(&ci->extFinderInfo, 1, sizeof(ci->extFinderInfo), stdout);
	return posix_error(ferror(stdout), "fwrite");
}


/* Output a descriptor. */

int dump_descriptors(UInt64 *pos, asEntryDesc *p)
{
	while (p->entry_id) {
		asEntryDesc d;
		d.entry_id = htobe32(p.entry_id);
		d.offset = htobe32(p.offset);
		d.length = htobe32(p.length);
		*pos += fwrite(&d, 1, sizeof(d), stdout);
		int err = ferror(stdout);
		if (posix_error(err, "fwrite")) return err;
		p++;
	}
	return 0;
}


/* Output the file header. */

int dump_header(UInt64 *pos, int format, short entries)
{
	asHdr h;
	h.magic = htobe32(format);
	h.version = htobe32(AS_VERSION);
	h.entries = htobe16(entries);
	bzero(&h.filler, sizeof(h.filler));
	*pos += fwrite(&h, 1, sizeof(h), stdout);
	return posix_error(ferror(stdout), "fwrite");
}


/* Output a file in its AppleSingle or AppleDouble representation,
 * with or without its comment entry.
 */

OSErr encode_file(char *filename, int format, short include_comment,
                  short include_posixname, short quash_atime)
{
	FSRef ref;
	OSErr err = FSPathMakeRef((UInt8 *)filename, &ref, false);
	if (carbon_error(err, "FSPathMakeRef")) return err;

	FSCatalogInfoBitmap theInfo = kFSCatInfoNodeFlags  | kFSCatInfoAllDates    |
	                              kFSCatInfoFinderInfo | kFSCatInfoFinderXInfo |
	                              kFSCatInfoDataSizes  | kFSCatInfoRsrcSizes;
	FSCatalogInfo catalogInfo;
	FSSpec fsSpec;
	err = FSGetCatalogInfo(&ref, theInfo, &catalogInfo, NULL, &fsSpec, NULL);
	if (carbon_error(err, "FSGetCatalogInfo"))
		return err;

	if (catalogInfo.rsrcLogicalSize > 0xffffffffULL)
		return posix_error3(EFBIG,
		"%s: Resource fork too big for AppleSingle/Double format", filename);

	if (catalogInfo.dataLogicalSize > 0xffffffffULL &&
	    format == kAppleSingleMagic)
		return posix_error3(EFBIG,
		    "%s: Data fork too big for AppleSingle format", filename);

	char *comment = NULL;
#ifdef HAVE_DESKTOP_MANAGER
	if (include_comment) {
		if ((comment = malloc(256)) == NULL)
			return posix_error(errno, "malloc");
		FXInfo *fxi = (void *)&catalogInfo.extFinderInfo;
		err = DTGetComment(fsSpec.vRefNum, fsSpec.parID, fsSpec.name,
		                   (void *)comment, fxi->fdComment);
		if (err == afpItemNotFound) {
			free(comment);
			comment = NULL;
		} else {
			free(comment);
			return err;
		}
	}
#endif

	asEntryDesc des[9];

	/* Populate each descriptor in memory before writing them out. */

	short entry = 0;
	short entries = 5 + (comment != NULL ? 1 : 0)
	                  + (format == kAppleSingleMagic ? 1 : 0 )
	                  + (include_posixname ? 1 : 0);

	des[entry].offset = sizeof(asHdr) + entries * sizeof(asEntryDesc);
	if (include_posixname) {
		des[entry].entry_id = AS_POSIX_NAME;
		des[entry].length = strlen(filename);
		entry++;
		des[entry].offset = des[entry-1].offset + des[entry-1].length;
	}

	des[entry].entry_id = AS_FILE_INFO;
	des[entry].length = sizeof(FInfo) + sizeof(FXInfo);
	entry++;

	des[entry].offset = des[entry-1].offset + des[entry-1].length;
	des[entry].entry_id = AS_FILE_DATES;
	des[entry].length = sizeof(asDatesEntry);
	entry++;

	des[entry].offset = des[entry-1].offset + des[entry-1].length;
	des[entry].entry_id = AS_MAC_INFO;
	des[entry].length = sizeof(asMacInfoEntry);
	entry++;

	des[entry].offset = des[entry-1].offset + des[entry-1].length;
	des[entry].entry_id = AS_NAME;
	des[entry].length = fsSpec.name[0];
	entry++;

	if (comment != NULL) {
		des[entry].offset = des[entry-1].offset + des[entry-1].length;
		des[entry].entry_id = AS_COMMENT;
		des[entry].length = comment[0];
		entry++;
	}

	int rsrc_padding = 0;
	des[entry].offset = des[entry-1].offset + des[entry-1].length;
	des[entry].entry_id = AS_RESOURCE;
	des[entry].length = catalogInfo.rsrcLogicalSize;
	entry++;

	if (format == kAppleSingleMagic) {
		if (catalogInfo.rsrcLogicalSize)
			rsrc_padding = (4096 - (catalogInfo.rsrcLogicalSize % 4096)) % 4096;
		des[entry].offset = des[entry-1].offset +
		                    des[entry-1].length + rsrc_padding;
		des[entry].entry_id = AS_DATA;
		des[entry].length = catalogInfo.dataLogicalSize;
		entry++;
	}

	des[entry].entry_id = 0; /* sentinel */
	
	/* Having populated the descriptors, write them out following the header,
	 * then write out their entries.
	 */

	UInt64 pos = 0;
	UInt64 final_pos = des[entry-1].offset + des[entry-1].length;

	/* dump header */
	err = dump_header(&pos, format, entries);
	if (err) goto out;

	/* dump descriptors */
	err = dump_descriptors(&pos, des);
	if (err) goto out;

	/* dump entries */
	asEntryDesc *cur_des = &des[0];
	HFSUniStr255 forkName;
	do {
		if (pos > 0xffffffffULL) {
			posix_error3(err = EFBIG,
			   "%s: Output too large for AppleSingle/Double format", filename);
			goto out;
		}

		/* sanity check */
		if (pos != (unsigned long long)cur_des->offset) {
//			fprintf(stderr, "pos %llu offset %lu\n", pos, (unsigned long)cur_des->offset); 
			fprintf(stderr, "Bad position/offset in encode_file()!\n");
			err = EIO;
			goto out;
		}

		switch(cur_des->entry_id) {
		case AS_POSIX_NAME:
			err = dump_posix_name(&pos, filename);
			if (err) goto out;
			break;
		case AS_FILE_INFO:
			err = dump_file_info(&pos, &catalogInfo);
			if (err) goto out;
			break;
		case AS_FILE_DATES:
			err = dump_file_dates(&pos, &catalogInfo, quash_atime);
			if (err) goto out;
			break;
		case AS_MAC_INFO:
			err = dump_mac_info(&pos, &catalogInfo);
			if (err) goto out;
			break;
		case AS_NAME:
			err = dump_name(&pos, &fsSpec);
			if (err) goto out;
			break;
		case AS_COMMENT:
			err = dump_comment(&pos, (void *)comment);
			if (err) goto out;
			break;
		case AS_RESOURCE:
			err = FSGetResourceForkName(&forkName);
			if (carbon_error(err, "FSGetResourceForkName")) goto out;
			err = dump_fork(&pos, &ref, &forkName);
			if (err) goto out;
			if (rsrc_padding)
				err = dump_padding(&pos, rsrc_padding);
			if (err) goto out;
			break;
		case AS_DATA:
			err = FSGetDataForkName(&forkName);
			if (carbon_error(err, "FSGetDataForkName")) goto out;
			err = dump_fork(&pos, &ref, &forkName);
			if (err) goto out;
			break;
		}
	} while ((++cur_des)->entry_id);

	/* sanity check */
	if (pos != final_pos) {
//		fprintf(stderr, "pos %llu final_pos %llu\n", pos, final_pos);
		fprintf(stderr, "Bad position/final position in encode_file()!\n");
		err = EIO;
		goto out;
	}

	err = 0;

out:
	if (comment)
		free(comment);
	return err;
}


/* Retrieve a record from a file, given a seperator character. */

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
	char *p;                    // reads stored here
	size_t const rchunk = 1;    // number of bytes to read
	size_t const mchunk = 512;  // number of extra bytes to malloc
	size_t m = rchunk + 1;      // initial buffer size

	if (*lineptr) {
		if (*n < m) {
			*lineptr = (char*)realloc(*lineptr, m);
			if (!*lineptr) return -1;
			*n = m;
		}
	} else {
		*lineptr = (char*)malloc(m);
		if (!*lineptr) return -1;
		*n = m;
	}

	m = 0; // record length including seperator

	do {
		size_t i;     // number of bytes read etc
		size_t j = 0; // number of bytes searched

		p = *lineptr + m;

		i = fread(p, 1, rchunk, stream);
		if (i < rchunk && ferror(stream))
			return -1;
		while (j < i) {
			++j;
			if (*p++ == (char)delim) {
				*p = '\0';
				if (j != i) {
					if (fseek(stream, j - i, SEEK_CUR))
						return -1;
					if (feof(stream))
						clearerr(stream);
				}
				m += j;
				return m;
			}
		}

		m += j;
		if (feof(stream)) {
			if (m) return m;
			if (!i) return -1;
		}

		// allocate space for next read plus possible null terminator
		i = ((m + (rchunk + 1 > mchunk ? rchunk + 1 : mchunk) +
		      mchunk - 1) / mchunk) * mchunk;
		if (i != *n) {
			*lineptr = (char*)realloc(*lineptr, i);
			if (!*lineptr) return -1;
			*n = i;
		}
	} while (1);
}

#endif // ENABLE_ENCODING


/* Qsort comparison routine for sorting descriptors by offset. */

int compare_desc_offset(const void * a, const void * b)
{
	UInt32 ao = be32toh(((asEntryDesc*)a)->offset);
	UInt32 bo = be32toh(((asEntryDesc*)b)->offset);

	if (ao < bo)
		return -1;
	else if (ao > bo)
		return 1;
	else return 0;
}


/* Routine to convert some input to hex on stdout.
 * One line of hex is 8 columns of 8 hex digits,
 * with each column having ' ' or '\n' seperator.
 */
#define CHARS_PER_COL    (8)
#define COLS_PER_LINE    (8)
#define HEX_LINE_CHARS   (COLS_PER_LINE * (1 + CHARS_PER_COL))
#define BIN_LINE_BYTES   (COLS_PER_LINE * (CHARS_PER_COL / 2))
#define LINES_PER_BUFFER (512)
#define HEX_BUFFER_SIZE  (LINES_PER_BUFFER * HEX_LINE_CHARS)
#define BIN_BUFFER_SIZE  (LINES_PER_BUFFER * BIN_LINE_BYTES)

int output_hex(FILE *f, size_t n)
{
	char digits[] = "0123456789abcdef";
	unsigned char *bin_buf = malloc(BIN_BUFFER_SIZE);
	if (bin_buf == NULL) {
		perror("malloc");
		return errno;
	}
	unsigned char *hex_buf = malloc(HEX_BUFFER_SIZE);
	if (hex_buf == NULL) {
		perror("malloc");
		free(bin_buf);
		return errno;
	}
	int err = 0;
	do {
		size_t bin_chunk = n > BIN_BUFFER_SIZE ? BIN_BUFFER_SIZE : n;
		size_t i = fread(bin_buf, 1, bin_chunk, f);
		if (i < bin_chunk) {
			if (feof(f)) {
				err = EPROTO;
				bin_chunk = i;
			} else {
				posix_error(err = ferror(f), "fread");
				goto out;
			}
		}
		i = 0; /* number of input bytes processed */
		unsigned char *b = bin_buf, *h = hex_buf;
		while (i < bin_chunk) {
			*h++ = digits[*b >> 4];
			*h++ = digits[*b & 0x0f];
			++b;
			++i;
			if (i % 4 == 0)
				*h++ = (i % 32 == 0) ? '\n' : ' ';
		}
		size_t hex_chunk;
		if (i < 4) {
			/* add a '\n' */
			hex_chunk = 2 * i + 1;
		} if (i % 4 == 0) {
			/* change the last seperator to a '\n' */
			hex_chunk = ((i * 2) / 8) * 9;
			h--;
		} else {
			/* add a '\n' */
			hex_chunk = ((i * 2) / 8) * 9 + (i % 4) * 2 + 1;
		}
		*h = '\n';
		if (!fwrite(hex_buf, hex_chunk, 1, stdout))
			posix_error(err = ferror(stdout), "fwrite");
		n -= i;
	} while (err == 0 && n > 0);
out:
	free(hex_buf);
	free(bin_buf);
	return err;
}


/* Copy some bytes to stdout. */

int output_raw(FILE *f, char *buf, unsigned buf_sz, size_t n)
{
	size_t chunk = n > buf_sz ? buf_sz : n;
	while (n) {
		if (n < chunk)
			chunk = n;
		size_t r = fread(buf, 1, chunk, f);
		if (!fwrite(buf, r, 1, stdout))
			return posix_error(ferror(stdout), "fwrite");
		if (r < chunk) {
			if (feof(f))
				return posix_error(EPROTO, "unexpected EOF");
			int read_error = ferror(f);
			if (posix_error(read_error, "fread"))
				return read_error;
		}
		n -= r;
	}
	return 0;
}


/* Output a message digest. */

int output_digest(FILE *f, char *buf, unsigned buf_sz, size_t n)
{
	MD5_CTX c;
	MD5_Init(&c);
	UInt64 md[2];
	size_t chunk = n > buf_sz ? buf_sz : n;
	while (n) {
		if (n < chunk) chunk = n;
		size_t r = fread(buf, 1, chunk, f);
		if (r < chunk) {
			if (feof(f))
				return posix_error(EPROTO, "unexpected EOF");
			int read_error = ferror(f);
			if (posix_error(read_error, "fread"))
				return read_error;
		}
		MD5_Update(&c, buf, r);
		n -= r;
	}
	MD5_Final((void*)md, &c);
	printf("%016llx%016llx (md5)\n", md[0], md[1]);
	return 0;
}


/* Throw away some input. */

int discard(FILE *f, char *buf, unsigned buf_sz, size_t n)
{
	size_t chunk = n > buf_sz ? buf_sz : n;
	while (n) {
		if (n < chunk) chunk = n;
		size_t r = fread(buf, 1, chunk, f);
		if (r < chunk) {
			if (feof(f))
				return posix_error(EPROTO, "unexpected EOF");
			int read_error = ferror(f);
			if (posix_error(read_error, "fread"))
				return read_error;
		}
		n -= r;
	}
	return 0;
}


/* Output the name of an entry ID. */

void output_entry_id(UInt32 id)
{
	switch(id) {
	case AS_DATA:
		printf("data\n");
		break;
	case AS_RESOURCE:
		printf("rsrc\n");
		break;
	case AS_NAME:
		printf("name\n");
		break;
	case AS_COMMENT:
		printf("comment\n");
		break;
	case AS_FILE_DATES:
		printf("file dates\n");
		break;
	case AS_FILE_INFO:
		printf("file info\n");
		break;
	case AS_MAC_INFO:
		printf("mac info\n");
		break;
	case AS_POSIX_NAME:
		printf("posix name\n");
		break;
	default:
		printf("id = %ld\n", (long)id);
	}
}


/* Output the filename seperator character. */

int output_sep(char sep)
{
	if (!fwrite(&sep, 1, 1, stdout))
		return posix_error(ferror(stdout), "fwrite");
	return 0;
}


#define WRITE_BUFFER_SIZE (32 * 1024)

/* Routine to decode an AppleDouble or AppleSingle stream. */

int decode_file(FILE *f, int list_only, UInt32 id, int verbose, char sep)
{
	int err = 0;
	asHdr h;
	UInt64 pos = fread(&h, 1, sizeof(h), f);

	if (pos != sizeof(h)) {
		if (feof(f)) {
			if (!pos)
				return 0;
			posix_error(err = EPROTO, "short read from header");
		} else
			posix_error(err = ferror(f), "failed to read header");
		return err;
	}

	UInt32 magic = be32toh(h.magic);
	UInt32 version = be32toh(h.version);
	UInt32 entries = be16toh(h.entries);

	if (magic != kAppleDoubleMagic && magic != kAppleSingleMagic)
		return posix_error(EPROTO, "bad magic number");

	if (list_only && verbose)
		printf("Headr: magic 0x%08lx, version %08lx, entries %u\n",
		       magic, version, entries);

	asEntryDesc *descriptors, *d;
	d = descriptors = malloc(entries * sizeof(asEntryDesc));
	if (descriptors == NULL)
		return posix_error(errno, "malloc");

	UInt16 n = entries;
	while (n) {
		pos += fread(d, 1, sizeof(*d), f);
		if (feof(f)) {
			posix_error(err = EPROTO, "unexpected EOF");
			goto out1;
		} else if (posix_error(err = ferror(f), "fread"))
			goto out1;
		if (list_only && verbose)
			printf("Descr: entry id %10lu, offset %10lu, length %10lu\n",
			       be32toh(d->entry_id), be32toh(d->offset),
			       be32toh(d->length));
		d++;
		n--;
	}

	/* According to the spec, entries can appear in any order. */
	qsort(descriptors, entries, sizeof(asEntryDesc), compare_desc_offset);

	char *buf = malloc(WRITE_BUFFER_SIZE);
	if (buf == NULL) {
		posix_error(err = errno, "malloc");
		goto out1;
	}

	int saw_posix_name = -1;
	n = entries;
	d = descriptors;
	while (n) {
		UInt32 offset = be32toh(d->offset);

		if (pos > (long long unsigned)offset) {
			fprintf(stderr, "Bad descriptor offset %u at %llu\n", (unsigned)offset, pos);
			d++;
			n--;
		} else if (pos == (long long unsigned)offset) {
			UInt32 entry_id = be32toh(d->entry_id);
			UInt32 length = be32toh(d->length);

			if (entry_id == AS_POSIX_NAME)
				saw_posix_name = entries - n;

			if (list_only) {
				if (verbose) {
					printf("Entry: position %llu, ", pos);
					output_entry_id(entry_id);
				}
				switch (entry_id) {
				case AS_POSIX_NAME:
					if (verbose > 1) {
						err = output_hex(f, length);
					} else {
						err = output_raw(f, buf, WRITE_BUFFER_SIZE, length);
						if (err) goto out2;
						err = output_sep(sep);
					}
					break;
				case AS_DATA:
				case AS_RESOURCE:
					if (verbose == 1) {
						err = output_digest(f, buf, WRITE_BUFFER_SIZE, length);
						break;
					}
				default:
					if (verbose)
						err = output_hex(f, length);
					else
						err = discard(f, buf, WRITE_BUFFER_SIZE, length);
				}
			} else if (entry_id == id) {
				err = output_raw(f, buf, WRITE_BUFFER_SIZE, length);
				if (err) goto out2;
			} else
				err = discard(f, buf, WRITE_BUFFER_SIZE, length);

			if (err) goto out2;
			pos += length;
			d++;
			n--;
		} else {
			UInt32 gap = offset - pos;
			if (list_only && verbose)
				printf("Misc.: %u byte gap at %llu\n", (unsigned)gap, pos);
			err = discard(f, buf, WRITE_BUFFER_SIZE, gap);
			if (err) goto out2;
			pos += gap;
		}
	}

	if (!verbose) {
		if (saw_posix_name == -1)
			fprintf(stderr, "No POSIX name entry\n");
		else if (saw_posix_name)
			fprintf(stderr, "POSIX name was not the first entry\n");
	}

out2:
	free(buf);
out1:
	free(descriptors);
	return err;
}


/* "Key=value,..." option splitting routine. */

char *parse_kv_pairs(char *p, char **k, char**v)
{
	while (*p == ',' || *p == '=')
		++p;
	if (!*p)
		return NULL;
	*k = p++;
	while (*p != '=')
		if (*p == ',') {
			*v = "1";
			*p++ = '\0';
			return p;
		} else if (!*p) {
			*v = "1";
			return p;
		} else
			++p;
	while (*p == '=')
		*p++ = '\0';
	*v = p;
	while (*p && *p != ',')
		++p;
	if (*p == ',')
		*p++ = '\0';
	return p;
}


/* Last but not least, the main program. */

int main(int argc, char * argv[])
{
	extern int optind;
	extern char *optarg;
	int rc;
	int format = kAppleSingleMagic;
	int include_comment = 0;
	int include_posixname = 0;
	int quash_atime = 0;
	int encode = 0;
	int list_only = 1;
	UInt32 id = AS_DATA;
	int verbose = 0;
	int null_sep = 0;
	int flag, usage = 0;
	char * me = argv[0];

	while ((flag = getopt(argc, argv, "0e:o:rvw")) != -1) {
		char *key, *value;
		char *my_optarg = optarg;

		switch (flag) {
		case '0':
			null_sep = 1;
			break;
		case 'o':
			while ((my_optarg = parse_kv_pairs(my_optarg, &key, &value))) {
				if (!strcmp(key, "finder_comment"))
#ifdef HAVE_DESKTOP_MANAGER
					include_comment = atoi(value);
#else
					fprintf(stderr, "finder_comment option is unavailable.\n");
#endif
				else if (!strcmp(key, "posix_name"))
					include_posixname = atoi(value);
				else if (!strcmp(key, "appledouble") && atoi(value))
					format = kAppleDoubleMagic;
				else if (!strcmp(key, "quash_atime"))
					quash_atime = atoi(value);
				else fprintf(stderr, "unknown option: %s\n", key);
			}
			break;
		case 'v':
			verbose++;
			break;
#ifdef ENABLE_ENCODING
		case 'w':
			encode = 1;
			break;
#endif
		case 'r':
			list_only = 0;
			break;
		case 'e':
			id = atoi(optarg);
			break;
		default:
			usage = 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0 && null_sep)
		usage = 1;

	if (encode && verbose)
		usage = 1;

	if (!encode && *argv)
		usage = 1;

	if (!encode && (include_comment || include_posixname ||
	                format == kAppleDoubleMagic || quash_atime))
		usage = 1;

	if (usage) {
		fprintf(stderr,
"Usage: %s -h\n"
"    Print this message.\n"
"\n"
"Usage: %s [-v] [-0]\n"
"    List the POSIX name entry (if any) from the file(s) encoded on STDIN.\n"
"    -0   Write names seperated by null characters instead of newline.\n"
"    -v   Dump the other entries as well. Add more -v options to see more\n"
"         entries in hexadecimal.\n"
"\n"
"Usage: %s -r [-e entry-id]\n"
"    Extract a given entry from the file(s) encoded on STDIN.\n"
"    -e   ID of entry: 1 for data fork (default), 2 for rsrc fork, etc.\n"
"\n"
#ifdef ENABLE_ENCODING
"Usage: %s -w [-o name[=value],...] filename...\n"
"    Dump to STDOUT the encoded representation of the given file(s).\n"
"    -o   Set options that infulence the encoding, i.e.\n"
"         finder_comment : include the Finder comment entry. Requires the\n"
"                          Desktop Manager API (Mac OS 10.4 and earlier).\n"
"         posix_name     : include POSIX filename entry.\n"
"         appledouble    : instead of AppleSingle, dump the non-data half\n"
"                          of the AppleDouble representation.\n"
"         quash_atime    : use file's modification time as access time.\n"
"\n"
"Usage: %s -w [-o name[=value],...] [-0]\n"
"    Dump to STDOUT the encoded representation of the file(s) named on STDIN.\n"
"    -0   Read names seperated by null characters instead of newline.\n"
"\n"
"Note: concatenating multiple AppleSingle files as a stream is a non-standard\n"
"extension to the format as is the POSIX filename entry. They may or may not\n"
"cause other tools to explode. For more information, refer to \"AppleSingle/\n"
"AppleDouble Formats for Foreign Files Developer's Note\", Apple 1990.\n"
#else
"Encoding of files is not supported on this platform.\n"
"\n"
#endif
, me, me, me, me, me);
		rc = 3;
	} else {
		rc = 0;
#ifdef ENABLE_ENCODING
		if (encode) {
			struct stat stats;
			if (isatty(fileno(stdout))) {
				fprintf(stderr, "%s: refusing to send output to a tty.\n", me);
				exit(2);
			}

			if (argc) {
				do {
					if (stat(*argv, &stats)) {
						perror(*argv);
						rc = 1;
						argv++;
						continue;
					}
					if (!S_ISREG(stats.st_mode)) {
						fprintf(stderr, "%s: not a (plain) file\n", *argv);
						rc = 1;
						argv++;
						continue;
					}
					rc = (0 != encode_file(*argv, format, include_comment,
					                     include_posixname, quash_atime)) || rc;
					report_and_reset_error(*argv);
					argv++;
				} while (--argc);
			} else {
				char *buf = NULL;
				size_t n;
				ssize_t len;
				while ((len = getdelim(&buf, &n, null_sep ? '\0' : '\n',
				                       stdin)) != -1) {
					buf[len - 1] = '\0';
					if (stat(buf, &stats)) {
						perror(buf);
						rc = 1;
						continue;
					}
					if (!S_ISREG(stats.st_mode)) {
						fprintf(stderr,"%s: not a (plain) file\n", buf);
						rc = 1;
						continue;
					}
					rc = (0 != encode_file(buf, format, include_comment,
					                 include_posixname, quash_atime)) || rc;
					report_and_reset_error(buf);
				}
				if (buf) free(buf);
			}
		} else
#endif // ENABLE_ENCODING
		{
			int err;
			do {
				err = decode_file(stdin, list_only, id, verbose, null_sep ? '\0' : '\n');
				report_and_reset_error("stdin");
				if (feof(stdin))
					break;
			} while (err == 0);
			rc = err != 0;
		}
	}

	exit(rc);
}
