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

#if DEBUG==1
void mem_dump(void *buf, unsigned cnt)
{
	unsigned l = cnt % 8;
	unsigned i;
	char *p, *start_addr;
	
	if ((cnt < 1) || (!buf))
		return;
		
	p = (char *)buf;
	printf ("Начальный адрес: [0x%p]\n", p);
	start_addr = p;
	
	for (i=0; i < cnt/8; i++, p += 8)
		printf ("[+0x%llx] %02x %02x %02x %02x | %02x %02x %02x %02x : %c%c%c%c %c%c%c%c\n",
			p-start_addr, 
			(( unsigned char *)p)[0] & 0xFF, (( unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			(( unsigned char *)p)[4] & 0xFF, (( unsigned char *)p)[5] & 0xFF, ((unsigned char *)p)[6] & 0xFF, ((unsigned char *)p)[7] & 0xFF,
			(( unsigned char *)p)[0] & 0xFF, (( unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			(( unsigned char *)p)[4] & 0xFF, (( unsigned char *)p)[5] & 0xFF, ((unsigned char *)p)[6] & 0xFF, ((unsigned char *)p)[7] & 0xFF
			);
			
	switch (l) {
		case 0:
			break;
		case 1:
			printf ("[0x%llx] %02x                |                     : %c\n", p-start_addr, 
			((unsigned char *)p)[0] & 0xFF,
			((unsigned char *)p)[0] & 0xFF
			); break;
		case 2:
			printf ("[0x%llx] %02x %02x           |                     : %c%c\n", p-start_addr, 
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF,
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF
			); break;
		case 3:
			printf ("[0x%llx] %02x %02x %02x      |                     : %c%c%c\n", p-start_addr, 
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF,
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF
			); break;
		case 4:
			printf ("[0x%llx] %02x %02x %02x %02x |                     : %c%c%c%c\n", p-start_addr, 
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF
			); break;
		case 5:
			printf ("[0x%llx] %02x %02x %02x %02x | %02x                : %c%c%c%c %c\n", p-start_addr, 
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			((unsigned char *)p)[4] & 0xFF,
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			((unsigned char *)p)[4] & 0xFF
			); break;
		case 6:
			printf ("[0x%llx] %02x %02x %02x %02x | %02x %02x           : %c%c%c%c %c%c\n", p-start_addr, 
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			((unsigned char *)p)[4] & 0xFF, ((unsigned char *)p)[5] & 0xFF,
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			((unsigned char *)p)[4] & 0xFF, ((unsigned char *)p)[5] & 0xFF
			); break;
		case 7:
			printf ("[0x%llx] %02x %02x %02x %02x | %02x %02x %02x      : %c%c%c%c %c%c%c\n", p-start_addr, 
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			((unsigned char *)p)[4] & 0xFF, ((unsigned char *)p)[5] & 0xFF, ((unsigned char *)p)[6] & 0xFF,
			((unsigned char *)p)[0] & 0xFF, ((unsigned char *)p)[1] & 0xFF, ((unsigned char *)p)[2] & 0xFF, ((unsigned char *)p)[3] & 0xFF,
			((unsigned char *)p)[4] & 0xFF, ((unsigned char *)p)[5] & 0xFF, ((unsigned char *)p)[6] & 0xFF
			); break;
		default:
			break;
	}
	
	return;	
}
#endif // DEBUG

int read_sig_entry(FILE *f, buf_entry_t *e, unsigned int time_counter, int offset)
{
	sig_hdr_t sighdr;
	int off = 0;
	size_t cnt;

	// reading sig header
	memset(&sighdr, 0, sizeof(sig_hdr_t));
	cnt = fread(&sighdr, sizeof(sig_hdr_t), 1, f);
	if (cnt != 1)
	{
		if (cnt != 0)
			printf("[Warning]: sig file is corrupted\n");
		return -ERR_SIG_FILE_CORRUPTED;
	}

	e->length = sighdr.length;

	if (offset > 0)
		e->length += (uint16_t)ETH_HDR_SIZE - (uint16_t)offset;

	// reading sig packet
	e->data = malloc(e->length);
	if (!e->data)
	{
		printf("[Error]: memory allocation failed\n");
		return -ERR_NO_MEM;
	}

	if (offset > 0)
	{
		fread((char*)e->data, 1, (uint16_t)offset, f);
		memset(e->data, 0, offset);
		off = ETH_HDR_SIZE;
	}
	cnt = fread( (char*)e->data + off, 1, sighdr.length - offset, f);

	if (offset > 0)
	{
		// fixing ethernet frame type
		((char*)e->data)[12] = 0x08;
		((char*)e->data)[13] = 0x0;
	}

	if (cnt != (sighdr.length - offset))
	{
		printf("[Warning]: actual and read packet size is not equal. Packet #%u maybe truncated\n", ++time_counter);
		/*
		free(e->data);
		return -EFAULT;
		*/
		return -ERR_SIZE_IS_NOT_EQUAL;
	}

	return ERR_SUCCESS;
}

int read_pcap_entry(FILE *f, buf_entry_t *e, unsigned int time_counter)
{
	pcaprec_hdr_t pcaprechdr;
	size_t cnt;

	// reading sig header
	memset(&pcaprechdr, 0, sizeof(pcaprec_hdr_t));
	cnt = fread(&pcaprechdr, sizeof(pcaprec_hdr_t), 1, f);
	if (cnt != 1)
	{
		if (cnt != 0)
			printf("[Warning]: pcap file is corrupted\n");
		return -ERR_SIG_FILE_CORRUPTED;
	}

	e->length = pcaprechdr.orig_len+sizeof(pcaprec_hdr_t);

	// reading sig packet
	e->data = malloc(e->length);
	if (!e->data)
	{
		printf("[Error]: memory allocation failed\n");
		return -ERR_NO_MEM;
	}

	memset(e->data, 0, e->length);
	memcpy(e->data, &pcaprechdr, sizeof(pcaprec_hdr_t));

	cnt = fread( (char*)e->data + sizeof(pcaprec_hdr_t), 1, e->length - sizeof(pcaprec_hdr_t), f);
	if (cnt != (e->length-sizeof(pcaprec_hdr_t)))
	{
		printf("[Warning]: actual and read packet size is not equal. Packet #%u maybe truncated\n", ++time_counter);
		return -ERR_SIZE_IS_NOT_EQUAL;
	}

	return ERR_SUCCESS;
}

int write_pcap_entry(FILE *f, buf_entry_t *e, unsigned int time_counter)
{
	pcaprec_hdr_t pcaprec_hdr;
	size_t cnt;

	//mem_dump(e->data, e->length);

	// writting pcap record header
	memset(&pcaprec_hdr, 0, sizeof(pcaprec_hdr_t));

	pcaprec_hdr.ts_sec = time_counter;        
	pcaprec_hdr.ts_usec = 0;       
	pcaprec_hdr.incl_len = e->length;       
	pcaprec_hdr.orig_len = e->length;      

	cnt = fwrite(&pcaprec_hdr, sizeof(pcaprec_hdr_t), 1, f);
	if (cnt != 1)
	{
		printf("[Error]: failed to write pcap record header\n");
		return -ERR_WRITE_PCAP_REC_HDR;
	}

	// writting pcap packet payload
	cnt = fwrite(e->data, 1, e->length, f);
	if (cnt != e->length)
	{
		printf("[Error]: actual and write packet size is not equal\n");
		return -ERR_SIZE_IS_NOT_EQUAL;
	}

	return ERR_SUCCESS;
}