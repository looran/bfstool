/* Christmas lift ! L&A 2017 */

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <unistd.h>
#include <err.h>
#include <time.h>
#include <dirent.h>
#include <string.h>
#include <math.h>

#define RES_SIZE_MAX 32000000
#define HDR_RECORD_LEN 32
#define HDR_RECORD_NAME_LEN_MAX 24
#define HDR_RECORD_OFFSET_POS 24
#define HDR_RECORD_LEN_POS 28
#define HDR_SIZE_MAX HDR_RECORD_LEN * 1000
#define CRC_LEN 2
#define CRC_INITIAL_REMAINDER	0x1D0F
#define CRC_FINAL_XOR_VALUE	0x0000
#define CRC_WIDTH		(8 * sizeof(unsigned short))
#define TRAILER "\x50\x12\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
#define TRAILER_LEN sizeof(TRAILER)

__attribute__ ((noreturn)) void
usageexit(char **argv)
{
	printf("usage: %s pack <dir> <res.bin> | unpack <res.bin>\n"
		"unpack will create directory <res.bin.%%Y%%m%%d_%%H%%M%%S>\n", argv[0]);
	exit(-1);
}

static const unsigned short crc_ccitt_table[]=
{
	0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
	0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
	0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
	0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
	0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
	0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
	0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
	0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
	0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
	0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
	0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
	0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
	0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
	0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
	0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
	0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0,
};

unsigned short
crc_fast(unsigned char const message[], unsigned long len, unsigned short *rem2)
{
	unsigned short remainder = CRC_INITIAL_REMAINDER;
	unsigned char  data;
	unsigned int   byte;
	unsigned short rem1 = 0;

	for (byte = 0; byte < len; ++byte)
	{
		if (rem2)
			*rem2 = rem1;
		rem1 = remainder;
		data = message[byte] ^ (remainder >> (CRC_WIDTH - 8));
		remainder = crc_ccitt_table[data] ^ (remainder << 8);
	}

	return ((unsigned short)(remainder ^ CRC_FINAL_XOR_VALUE));
}

unsigned short
crc_brute(unsigned short rem2)
{
	unsigned short data, data2;
	unsigned short r;

	printf("computing last 2bytes with rem2=%d\n", rem2);

	for (data = 0; data < 65535; data++)
	{
		r = rem2;
		data2 = (data >> 8) ^ (r >> (CRC_WIDTH - 8));
		r = crc_ccitt_table[data2] ^ (r << 8);
		data2 = (data & 0xFF) ^ (r >> (CRC_WIDTH - 8));
		r = crc_ccitt_table[data2] ^ (r << 8);
		if ((unsigned short)(r ^ CRC_FINAL_XOR_VALUE) == 0) {
			printf("found last 2bytes: %04x\n", data);
			break;
		}
	}
	return data;
}

static int
_alphacasesort(const struct dirent **d1, const struct dirent **d2)
{
	return(strcasecmp((*d1)->d_name, (*d2)->d_name));
}

unsigned int
pack_files(unsigned char *map, const char *dirname)
{
	unsigned char header[HDR_SIZE_MAX];
	struct dirent **files;
	char fpath[PATH_MAX];
	struct stat st = {0};
	int f, nfiles, n, nfilesread;
	unsigned int offset, offset_align, header_offset, header_offset2, namelen;
	unsigned short crc;

	nfiles = scandir(dirname, &files, NULL, _alphacasesort);
	if (nfiles < 0)
		err(-1, "Error listing directory %s", dirname);
	if (nfiles == 0)
		err(-1, "Directory empty %s", dirname);
	n = nfilesread = 0;
	memset(header, 0xff, sizeof(header));
	strcpy((char *)header, "BFS_Header");
	header_offset = HDR_RECORD_LEN;
	offset = 0;

	printf("offset\t\tlen\t\tname\n");
	while (n < nfiles) {
		if (!strcmp(files[n]->d_name, ".") || !strcmp(files[n]->d_name, "..")
		   		|| !strcmp(files[n]->d_name, "BFS_Header")) {
			free(files[n]);
			n++;
			continue;
		}
		namelen = strlen(files[n]->d_name);
		if (namelen > HDR_RECORD_NAME_LEN_MAX - 1)
			err(-1, "File name too long, max is %d : %d", HDR_RECORD_NAME_LEN_MAX, namelen);

		snprintf(fpath, sizeof(fpath), "%s/%s", dirname, files[n]->d_name);
		f = open(fpath, O_RDONLY);
		if (f == -1)
			err(-1, "Error opening file %s", fpath);
		if (fstat(f, &st) == -1)
			err(-1, "Error getting the file size for %s", fpath);
		if (st.st_size <= 2)
			err(-1, "Error: File is empty, nothing to do");
		if (offset + HDR_SIZE_MAX + st.st_size > RES_SIZE_MAX)
			err(-1, "Too many files to fit in res.bin. Try to increase RES_SIZE_MAX (%d)", RES_SIZE_MAX);

		printf("0x%06x\t0x%06x\t%s\n", offset, (unsigned int)st.st_size, files[n]->d_name);
		strncpy((char *)header+header_offset, files[n]->d_name, namelen+1);
		*((unsigned int *)(header+header_offset+HDR_RECORD_OFFSET_POS)) = offset;
		*((unsigned int *)(header+header_offset+HDR_RECORD_LEN_POS)) = (unsigned int)st.st_size;
		header_offset += HDR_RECORD_LEN;
		read(f, map+offset, st.st_size);
		offset = offset + st.st_size;

		offset_align = offset%0x010;
		offset_align = offset_align ? offset + (0x10 - offset_align) : offset;
		if (offset_align > offset) {
			memset(map+offset, 0xff, offset_align-offset);
			if (offset_align - offset >= 2) {
				crc = crc_fast(map+(offset-st.st_size), st.st_size, NULL);
				*(map+offset) = crc >> 8;
				*(map+offset+1) = crc & 0xFF;
			}
			offset = offset_align;
		}

		close(f);
		free(files[n]);
		n++;
		nfilesread++;
	}
	free(files);
	header_offset += HDR_RECORD_LEN;
	
	printf("%d files, size %d\n", nfilesread, header_offset+offset);
	*((unsigned int *)(header+HDR_RECORD_OFFSET_POS)) = 0x0;
	*((unsigned int *)(header+HDR_RECORD_LEN_POS)) = header_offset+offset+CRC_LEN;
	for (header_offset2 = HDR_RECORD_LEN; header_offset2 < header_offset-HDR_RECORD_LEN; header_offset2 += HDR_RECORD_LEN)
		*((unsigned int *)(header+header_offset2+HDR_RECORD_OFFSET_POS)) += header_offset;
	memmove(map+header_offset, map, offset);
	memcpy(map, header, header_offset);

	return header_offset+offset;
}

int
pack(const char *dirpath, const char *respath)
{
	unsigned char *map;
	unsigned int len;
	unsigned short crc, rem2;
	int fd;

	fd = open(respath, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (fd == -1)
		err(-1, "Error opening file %s", respath);

	map = mmap(0, RES_SIZE_MAX, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);
	if (map == MAP_FAILED)
		err(-1, "mmap error");

	printf("output file : %s\n", respath);
	len = pack_files(map, dirpath);
	len += CRC_LEN;
	crc = crc_fast(map, len, &rem2);
	printf("crc: %d\n", crc);
	if (crc != 0) {
		crc = crc_brute(rem2);
		*(map+(len-2)) = crc >> 8;
		*(map+(len-1)) = crc & 0xFF;
	}
	write(fd, map, len);
	close(fd);
	printf("written %s\n", respath);

	return 0;
}

int
unpack_files(const unsigned char *map, int map_len, const char *outdir)
{
	const unsigned char *p, *name;
	unsigned int offset, len;
	char fpath[PATH_MAX];
	int f, nfiles;

	printf("offset\t\tlen\t\tname\n");
	p = map;
	nfiles = 0;
	while (*p != 0xff) {
		name = p;
		offset = *(unsigned int *)(p + HDR_RECORD_OFFSET_POS);
		len = *(unsigned int *)(p + HDR_RECORD_LEN_POS);
		printf("0x%06x\t0x%06x\t%s\n", offset, len, name);

		snprintf(fpath, sizeof(fpath), "%s/%s", outdir, name);
		f = open(fpath, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		if (!f)
			err(-1, "Cannot create file %s", fpath);
		write(f, map+offset, len);
		close(f);

		p += HDR_RECORD_LEN;
		if (p >= map+map_len)
			err(-1, "header incomplete");
		nfiles++;
	}
	printf("%d files created in %s\n", nfiles, outdir);
	return 0;
}

int
unpack(const char *respath)
{
	struct stat st = {0};
	const unsigned char *map;
	char outdir[PATH_MAX];
	int fd;
	struct tm tm;
	time_t t;

	fd = open(respath, O_RDONLY, (mode_t)0600);
	if (fd == -1)
		err(-1, "Error opening file %s", respath);
	if (fstat(fd, &st) == -1)
		err(-1, "Error getting the file size");
	if (st.st_size <= 2)
		err(-1, "Error: File is empty, nothing to do");
	map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		err(-1, "mmap error");

	t = time(NULL);
	tm = *localtime(&t);
	snprintf(outdir, sizeof(outdir), "%s.%04d%02d%02d_%02d%02d%02d", respath,
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	if (mkdir(outdir, 0750) != 0)
		err(-1, "Could not create output directory %s", outdir);

	printf("file size  : 0x%x\n", (unsigned int)st.st_size);
	printf("output dir : %s\n", outdir);

	return unpack_files(map, st.st_size, outdir);
}

int
main(int argc, char **argv)
{
	if (argc == 4 && *argv[1] == 'p')
		return pack(argv[2], argv[3]);
	else if (argc == 3 && *argv[1] == 'u')
		return unpack(argv[2]);
	else
		usageexit(argv);

	return 0; /* UNREACHED */
}
