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
#include "const.h"
#include "converter.h"
#include "network_types.h"

static char help[] = "usage:\tsigtopcap -c <filename> [network_type]\n"
"\tsigtopcap -o <filename> <offset>\n"
"\tsigtopcap -s <filename> <split_type> <split_size>\n"
"\tsigtopcap -f <filename>\n"
"\tsigtopcap -h\n\n"
"\t -c converting *.sig file to *.pcap file\n"
"\t -o converting *.sig file to *.pcap file with manual setting IP-header offset value\n"
"\t -s splitting *.sig or *.pcap file\n"
"\t -f showing IP-header offset and link type\n"
"\t -h showing help\n\n"
"\t<network_type> = link-layer header type value according http://www.tcpdump.org/linktypes.html (Default: LINKTYPE_ETHERNET(1))\n"
"\t<offset> = IP-header offset\n"
"\t<split_type> = 0 - split by packet count, 1 - split by filesize\n"
"\t<split_size> = packets count in each splitted files for split_type=0, result splitted file size for split_type=1\n";

static char *pcap_filename(char *name)
{
	int len = 0;
	char *filename = NULL;
	if (!name)
		return NULL;

	if (strstr(name, ".sig") == NULL)
		return NULL;

	len = strlen(name) + 1;

	filename = (char*)malloc( len);
	if (!filename)
		return NULL;
	memset(filename, 0, len);
	memcpy(filename, name, len -4 -1);;
	strcat(filename, ".pcap");
	return filename;
}

int main(int argc, char **argv)
{
	int res = 0, offset = 0;
	char *filename = NULL;
	unsigned int network_type = LINKTYPE_ETHERNET;
	
	if (argc < 2)
	{
		printf("%s\nbuild: %s(%s)\n", help, __DATE__, __TIME__);
		return -EFAULT;
	}

	switch (argv[1][1]) {
		case 'c':
			switch (argc) {
				case 3:
					// sigtopcap -c <filename>
					res = recognize_network_type(argv[2], &offset);
					if (res < 0)
						printf("[Warning]: Can`t recognize link type. Setting default to ETHERNET\n");
					else
					{
						network_type = (unsigned)res;
						offset = 0;
					}
					break;
				case 4:
					// sigtopcap -c <filename> [network_type] 
					network_type = (unsigned)atoi(argv[3]);
					break;
				default:
					printf("%s\n", help);
					return -EFAULT;
			}

			filename = pcap_filename(argv[2]);
			if (!filename)
			{
				printf("[Error]: Incorrect *.sig filename\n");
				return -EINVAL;
			}

			printf("[Info]: Converting '%s' to '%s' [Network type = %u, offset = %d]\n", argv[2], filename, network_type, offset);
			res = convert_sig_to_pcap(argv[2], filename, network_type, offset);
			printf("[Info]: Result:%d\n", res);

			free(filename);
			break;

		case 'o':
			// sigtopcap -o <filename> <offset>
			if (argc != 4)
			{
				printf("%s\n", help);
				return -EINVAL;
			}

			filename = pcap_filename(argv[2]);
			if (!filename)
			{
				printf("[Error]: Input file must have *.sig extension\n");
				return -EINVAL;
			}

			offset = atoi(argv[3]);

			printf("[Info]: Converting '%s' to '%s' using offset [Network type = %u, offset = %d]\n", argv[2], filename, network_type, offset);
			res = convert_sig_to_pcap(argv[2], filename, network_type, offset);
			printf("[Info]: Result:%d\n", res);

			free(filename);
			break;

		case 'f':
			res = recognize_network_type(argv[2], &offset);
			printf("[Info]: ip header offset=%d; link type=%d\n", offset, res);
			break;

		case 's':
			if (argc != 5)
			{
				printf("%s\n", help);
				return -EINVAL;
			}
			if (strstr(argv[2], ".sig") != NULL)
				res = split_sig_file(argv[2], (unsigned)atoi(argv[3]), (unsigned long long)atoll(argv[4]));
			else if (strstr(argv[2], ".pcap") != NULL)
				res = split_pcap_file(argv[2], (unsigned)atoi(argv[3]), (unsigned long long)atoll (argv[4]));
			else
			{
				printf("[ERROR]: File must have *.sig or *.pcap extension\n");
				return -EINVAL;
			}
			printf("[Info]: Result: %d\n", res);
			break;

		case 'h':
		default:
			printf("%s\n", help);
			break;
	}

	return res;
}