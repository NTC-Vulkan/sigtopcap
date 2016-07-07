/*
* Copyright (c) 2016, ntc-vulkan
* All rights reserved.
*
* Author: Igor Podvoiskiy
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
* 3. Neither the name of the University of Tsukuba nor the names of its
*    contributors may be used to endorse or promote products derived from
*    this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/

#include "os.h"

#include "pcap.h"
#include "sig.h"
#include "file.h"
#include "network_types.h"

static void generate_pcap_global_header(pcap_hdr_t *hdr, unsigned int network_type)
{
	memset(hdr, 0, sizeof(pcap_hdr_t));

	hdr->magic_number = NTOHL(PCAP_MAGIC_NUMBER);
	hdr->version_major = PCAP_VERSION_MAJOR;  
	hdr->version_minor = PCAP_VERSION_MINOR;  
	hdr->thiszone = PCAP_THISZONE;      
	hdr->sigfigs = PCAP_SIGFIGS;        
	hdr->snaplen = PCAP_SNAPLEN;        
	hdr->network = network_type;     
}

static char _ip_signature[] = {0x45};

static uint16_t ip_checksum(void* vdata, size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;
    uint16_t word=0;
    size_t i;

    // Handle complete 16-bit blocks.
    for (i=0;i+1<length;i+=2) {
        memcpy(&word,data+i,2);
        acc+=NTOHS(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        word=0;
        memcpy(&word,data+length-1,1);
        acc+=NTOHS(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return NTOHS(~acc);
}

static int find_ip_signature(char *sigfilename, int skip_count)
{
	FILE *sigf = NULL;	
	int res = -ENOENT, i;
	buf_entry_t entry;
	char iphdr[20] = {0};
	uint16_t checksum = 0, calc_checksum = 0;

	if (!sigfilename)
	{
		printf("[Error]: incorrect input filename\n");
		return -EFAULT;
	}

	sigf = fopen(sigfilename, "rb");
	if (NULL == sigf)
	{
		printf("[Error]: '%s' open failed\n", sigfilename);
		return -errno;
	}

	memset(&entry, 0, sizeof(buf_entry_t));
	for (i=0; i<skip_count; i++)
		res = read_sig_entry(sigf, &entry, 0, 0);
	fclose(sigf);

	

	if (res != ERR_SUCCESS)
	{
		if (res != -ERR_SIG_FILE_CORRUPTED)
			free(entry.data);
		res = -EFAULT;
	}
	else
	{
		res = -ENOENT;
		for (i=0; i<entry.length; i++)
			if (memcmp( (char*)entry.data + i, _ip_signature, sizeof(_ip_signature) ) == 0)
			{
				memcpy(iphdr, (char*)entry.data + i, 20);
				memcpy(&checksum, (char*)iphdr + 10, sizeof(uint16_t));

				
				iphdr[10] = 0;
				iphdr[11] = 0;
				calc_checksum = ip_checksum(iphdr, 20);			
#if DEBUG == 1
				printf("[Info]: packet estimated checksum: 0x%x\n", NTOHS(checksum));
				printf("[Info]: packet calculated checksum: 0x%x\n", NTOHS(calc_checksum));
#endif
				free(entry.data);

				if (checksum != calc_checksum)
				{
					//printf("[Error]: can`t find IP-header signature. Please, set IP-header offset manually\n");
					return -ENOENT;
				}
				else
					printf("[Info]: IP-header detected (offset == %d)\n", i);
				return i;
			}
		free(entry.data);
	}

	return res;
}

static unsigned long long get_file_size(char *filename)
{
	struct stat stbuf;
	int res = 0;
	memset(&stbuf, 0, sizeof(struct stat));
	res = stat(filename, &stbuf);

	if (res != 0)
		return 0;

	return stbuf.st_size;
}

int recognize_network_type(char *sigfilename, int *offset)
{
	int res = -ENOENT, i = 0;
	for (i = 0; i < RECOGNISE_ATTEMPS; i++)
	{
		res = find_ip_signature(sigfilename, i);
		if (res > 0)
			break;
	}
	*offset = res;

	switch (res) {
		case 0:
			printf("[Info]: LINKTYPE_NULL\n");
			return LINKTYPE_NULL;
		case 4:
			printf("[Info]: LINKTYPE_FRELAY\n");
			return LINKTYPE_FRELAY;
		case 12:
			printf("[Info]: LINKTYPE_ETHERNET\n");
			return LINKTYPE_ETHERNET;
		default:
			printf("[Warning]: Can`t recognize link type\n");
			break;
	}

	return -ENOENT; 
}

static char *part_filename(char *name, int part, char *extension)
{
	int len = 0;
	char *buf = NULL;
	char *filename = NULL;
	if (!name)
		return NULL;

	len = strlen(name) + 20;

	filename = (char*)malloc( len);
	if (!filename)
		return NULL;

	buf = (char*)malloc( len);
	if (!buf)
	{
		free(filename);
		return NULL;
	}

	memset(filename, 0, len);
	memset(buf, 0, len);

	if (strstr(name, extension) != NULL)
		memcpy(buf, name, strlen(name)-strlen(extension));
	else
		strcpy(buf, name);

	snprintf(filename, len, "%s_part%d%s", buf, part, extension);
	free(buf);
	return filename;
}

int split_sig_file(char *filename, char split_type, unsigned long long split_size)
{
	FILE *sigf = NULL, *partf = NULL;
	char *part_name = NULL; 
	buf_entry_t entry;
	unsigned int time_counter = 0;
	unsigned long long part_counter = 0;
	unsigned long long fsize = 0, read_bytes = 0, done = 0, done_prev = 0;
	int res = 0, part = 0;
	size_t cnt;

	if (!filename)
	{
		printf("[Error]: incorrect input filename\n");
		return -EINVAL;
	}

	fsize = get_file_size(filename);

	switch (split_type) {
		case PACKET_SPLIT:
			if (split_size < MIN_PACKETS_SPLIT)
			{
				printf("[Error]: Split packet count value must be greater then %d packets\n", MIN_PACKETS_SPLIT);
				return -EINVAL;
			}
			break;
		case SIZE_SPLIT:
			if (split_size < MIN_SPLIT_SIZE)
			{
				printf("[Error]: Split packet size value must be greater then %d bytes\n", MIN_SPLIT_SIZE);
				return -EINVAL;
			}
			break;

		default:
			printf("[Error]: Unknown split type\n");
			return -EINVAL;
	}

	sigf = fopen(filename, "rb");
	if (NULL == sigf)
	{
		printf("[Error]: '%s' open failed\n", filename);
		return -errno;
	}

	part_name = part_filename(filename, part, ".sig");
	partf = fopen(part_name, "wb");
	if (NULL == partf)
	{
		printf("[Error]: '%s' open failed\n", part_name);
		free(part_name);
		fclose(sigf);
		return -errno;
	}

	while (1) {
		if (feof(sigf) != 0)
			break;

		// reading sig file
		memset(&entry, 0, sizeof(buf_entry_t));
		res = read_sig_entry(sigf, &entry, time_counter++, 0);
		switch (res) {
			case ERR_SUCCESS:
				break;

			case (-ERR_SIG_FILE_CORRUPTED):
				res = 0;
				free(entry.data);
				goto _close;

			case (-ERR_SIZE_IS_NOT_EQUAL):
				res = 0;
				break;

			default:
				free(entry.data);
				goto _close;
		}

		// calculating percents
		read_bytes += entry.length;
		done_prev = done;
		done = (unsigned long long)((double)read_bytes * 100.00 / (double)fsize);

		if (done_prev - done > 0)
			if (done % 10 == 0)
				printf("[Info]: %llu%% - %d\tpackets  processed\n", done, time_counter);

		// writing sig part file
		cnt = fwrite(&entry.length, sizeof(uint16_t), 1, partf);
		if (cnt != 1)
		{
			printf("[Error]: failed to write sig record length(%d)\n", (int)cnt);
			res = -EFAULT;
			free(entry.data);
			goto _close;
		}

		cnt = fwrite(entry.data, 1, entry.length, partf);
		if (cnt != entry.length)
		{
			printf("[Error]: actual and write packet size is not equal\n");
			res = -EFAULT;
			free(entry.data);
			goto _close;
		}

		free(entry.data);

		switch (split_type) {
			case PACKET_SPLIT:
				part_counter++;
				break;
			case SIZE_SPLIT:
				part_counter += entry.length;
				break;

			default:
				break;
		}

		if (part_counter >= split_size)
		{
			printf("[Info]: %llu %s saved to '%s'\n\n", 
				part_counter, 
				split_type == PACKET_SPLIT ? "packets":"bytes", 
				part_name);

			part_counter = 0;
			fclose(partf);
			free(part_name);
			part++;

			part_name = part_filename(filename, part, ".sig");
			partf = fopen(part_name, "wb");
			if (NULL == partf)
			{
				printf("[Error]: '%s' open failed\n", part_name);
				free(part_name);
				fclose(sigf);
				fclose(partf);
				return -errno;
			}
		}
	}

	

_close:
	printf("[Info]: Splitting done! %d packets total.\n", time_counter);
	if (part_name)
		free(part_name);
	fclose(sigf);
	fclose(partf);

	return res;
}

int split_pcap_file(char *filename, char split_type, unsigned long long split_size)
{
	FILE *pcapf = NULL, *partf = NULL;
	char *part_name = NULL; 
	buf_entry_t entry;
	unsigned int time_counter = 0;
	unsigned long long part_counter = 0;
	unsigned long long fsize = 0, read_bytes = 0, done = 0, done_prev = 0;
	pcap_hdr_t global_header;
	int res = 0, part = 0;
	size_t cnt;

	if (!filename)
	{
		printf("[Error]: incorrect input filename\n");
		return -EINVAL;
	}

	fsize = get_file_size(filename);

	switch (split_type) {
		case PACKET_SPLIT:
			if (split_size < MIN_PACKETS_SPLIT)
			{
				printf("[Error]: Split packet count value must be greater then %d packets\n", MIN_PACKETS_SPLIT);
				return -EINVAL;
			}
			break;
		case SIZE_SPLIT:
			if (split_size < MIN_SPLIT_SIZE)
			{
				printf("[Error]: Split packet size value must be greater then %d bytes\n", MIN_SPLIT_SIZE);
				return -EINVAL;
			}
			break;

		default:
			printf("[Error]: Unknown split type\n");
			return -EINVAL;
	}

	pcapf = fopen(filename, "rb");
	if (NULL == pcapf)
	{
		printf("[Error]: '%s' open failed\n", filename);
		return -errno;
	}

	// reading pcap global header
	memset(&global_header, 0 ,sizeof(pcap_hdr_t));
	cnt = fread(&global_header, sizeof(pcap_hdr_t), 1, pcapf);
	if (cnt != 1)
	{
		printf("[ERROR]: can`t read pcap global header\n");
		fclose(pcapf);
		return -EFAULT;
	}


	part_name = part_filename(filename, part, ".pcap");
	partf = fopen(part_name, "wb");
	if (NULL == partf)
	{
		printf("[Error]: '%s' open failed\n", part_name);
		free(part_name);
		fclose(pcapf);
		return -errno;
	}

	// writting pcap global header
	cnt = fwrite(&global_header, sizeof(pcap_hdr_t), 1, partf);
	if (cnt != 1)
	{
		printf("[Error]: can`t write pcap global header to %s\n", part_name);
		free(part_name);
		fclose(pcapf);
		fclose(partf);
		return -EFAULT;
	}

	while (1) {
		if (feof(pcapf) != 0)
			break;

		// reading pcap file
		memset(&entry, 0, sizeof(buf_entry_t));
		res = read_pcap_entry(pcapf, &entry, ++time_counter);
		switch (res) {
			case ERR_SUCCESS:
				break;

			case (-ERR_SIG_FILE_CORRUPTED):
				res = 0;
				free(entry.data);
				goto _close;

			case (-ERR_SIZE_IS_NOT_EQUAL):
				res = 0;
				break;

			default:
				free(entry.data);
				goto _close;
		}

		// calculating percents
		read_bytes += entry.length;
		done_prev = done;
		done = (unsigned long long)((double)read_bytes * 100.00 / (double)fsize);

		if (done_prev - done > 0)
			if (done % 10 == 0)
				printf("[Info]: %llu%% - %d\tpackets  processed\n", done, time_counter);

		// writing pcap part file
		cnt = fwrite(entry.data, 1, entry.length, partf);
		if (cnt != entry.length)
		{
			printf("[Error]: actual and write packet size is not equal\n");
			res = -EFAULT;
			free(entry.data);
			goto _close;
		}

		free(entry.data);

		switch (split_type) {
			case PACKET_SPLIT:
				part_counter++;
				break;
			case SIZE_SPLIT:
				part_counter += entry.length;
				break;

			default:
				break;
		}

		if (part_counter >= split_size)
		{
			printf("[Info]: %llu %s saved to '%s'\n\n", 
				part_counter, 
				split_type == PACKET_SPLIT ? "packets":"bytes", 
				part_name);

			part_counter = 0;
			fclose(partf);
			free(part_name);
			part++;

			part_name = part_filename(filename, part, ".pcap");
			partf = fopen(part_name, "wb");
			if (NULL == partf)
			{
				printf("[Error]: '%s' open failed\n", part_name);
				free(part_name);
				fclose(pcapf);
				fclose(partf);
				return -errno;
			}

			// writting pcap global header
			cnt = fwrite(&global_header, sizeof(pcap_hdr_t), 1, partf);
			if (cnt != 1)
			{
				printf("[Error]: can`t write pcap global header to %s\n", part_name);
				free(part_name);
				fclose(pcapf);
				fclose(partf);
				return -EFAULT;
			}
		}
	}

	

_close:
	printf("[Info]: Splitting done! %d packets total.\n", --time_counter);
	if (part_name)
		free(part_name);
	fclose(pcapf);
	fclose(partf);

	return res;
}

int convert_sig_to_pcap(char *sigfilename, char *pcapfilename, unsigned int network_type, int offset)
{
	FILE *sigf = NULL, *pcapf = NULL;
	buf_entry_t entry;
	pcap_hdr_t pcap_global_header;
	unsigned long long fsize = 0, read_bytes = 0, done = 0, done_prev = 0;
	unsigned int time_counter = 0;
	int res = 0;

	if (!sigfilename || !pcapfilename)
	{
		printf("[Error]: incorrect input filename\n");
		return -EFAULT;
	}

	fsize = get_file_size(sigfilename);

	sigf = fopen(sigfilename, "rb");
	if (NULL == sigf)
	{
		printf("[Error]: '%s' open failed\n", sigfilename);
		return -errno;
	}

	pcapf = fopen(pcapfilename, "wb");
	if (NULL == pcapf)
	{
		printf("[Error]: '%s' open failed\n", pcapfilename);
		res = -errno;
		goto _close;
	}

	// writing pcap global header
	generate_pcap_global_header(&pcap_global_header, network_type);
	fwrite(&pcap_global_header, sizeof(pcap_hdr_t), 1, pcapf);

	while (1) {
		if (feof(sigf) != 0)
			break;

		// reading sig file
		memset(&entry, 0, sizeof(buf_entry_t));
		res = read_sig_entry(sigf, &entry, time_counter, offset);
		switch (res) {
			case ERR_SUCCESS:
				break;

			case (-ERR_SIG_FILE_CORRUPTED):
				res = 0;
				free(entry.data);
				goto _closeall;

			case (-ERR_SIZE_IS_NOT_EQUAL):
				break;

			default:
				free(entry.data);
				goto _closeall;
		}

		// calculating percents
		read_bytes += entry.length;
		done_prev = done;
		done = (unsigned long long)((double)read_bytes * 100.00 / (double)fsize);

		if (done_prev - done > 0)
			if (done % 10 == 0)
				printf("[Info]: %llu%% - %d\tpackets  processed\n", done, time_counter);

		// writing pcap file
		res = write_pcap_entry(pcapf, &entry, time_counter++);
		free(entry.data);
		if (res != ERR_SUCCESS)
		{
			res = -EFAULT;
			goto _closeall;
		}
	}

	printf("[Info]: Converting done! %d packets total.\n", time_counter);

_closeall:
	fclose(pcapf);
_close:
	fclose(sigf);

	return res;
}