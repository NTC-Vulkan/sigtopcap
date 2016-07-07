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

#ifndef _CONSTH
#define _CONSTH

#include "os.h"
#include "network_types.h"

#define PCAP_MAGIC_NUMBER 0xD4C3B2A1
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_THISZONE 0
#define PCAP_SIGFIGS 0
#define PCAP_SNAPLEN 0xFFFF
#define PCAP_NETWORK LINKTYPE_ETHERNET

#define DEBUG 0

enum ERR_CODES {
	ERR_SUCCESS = 0,
	ERR_NO_MEM = ENOMEM,
	ERR_SIG_FILE_CORRUPTED = 500,
	ERR_WRITE_PCAP_REC_HDR,
	ERR_SIZE_IS_NOT_EQUAL
};

enum SPLIT_TYPE {
	PACKET_SPLIT = 0,
	SIZE_SPLIT
};

#define ETH_HDR_SIZE 14

#define MIN_PACKETS_SPLIT 1
// 10 Mb
#define MIN_SPLIT_SIZE 10*1024*1024

#define RECOGNISE_ATTEMPS 200

#endif // _CONSTH