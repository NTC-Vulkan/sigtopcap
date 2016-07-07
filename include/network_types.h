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

#ifndef _NETWORK_TYPES_H
#define _NETWORK_TYPES_H

// BSD loopback encapsulation - 4 bytes
#define LINKTYPE_NULL	0	

// IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up) -12 bytes
#define LINKTYPE_ETHERNET	1		

// AX.25 packet, with nothing preceding it
#define LINKTYPE_AX25	3	

// IEEE 802.5 Token Ring	
#define LINKTYPE_IEEE802_5	6		

// ARCNET
#define LINKTYPE_ARCNET_BSD	7	

// SLIP, encapsulated with a LINKTYPE_SLIP header	
#define LINKTYPE_SLIP	8		

// PPP
#define LINKTYPE_PPP	9	

// FDDI	
#define LINKTYPE_FDDI	10		

// PPP in HDLC-like framing
#define LINKTYPE_PPP_HDLC	50		

// PPPoE
#define LINKTYPE_PPP_ETHER	51

// RFC 1483 LLC/SNAP-encapsulated ATM
#define LINKTYPE_ATM_RFC1483	100

// Raw IP; 
#define LINKTYPE_RAW	101

// Cisco PPP with HDLC framing
#define LINKTYPE_C_HDLC	104

// IEEE 802.11 wireless LAN.
#define LINKTYPE_IEEE802_11	105		

// Frame Relay
#define LINKTYPE_FRELAY	107		

// OpenBSD loopback encapsulation
#define LINKTYPE_LOOP	108		

// Linux "cooked" capture encapsulation.
#define LINKTYPE_LINUX_SLL	113		

// Apple LocalTalk
#define LINKTYPE_LTALK	114

// OpenBSD pflog
#define LINKTYPE_PFLOG	117	

// Prism monitor mode information followed by an 802.11 header
#define LINKTYPE_IEEE802_11_PRISM	119		

// RFC 2625 IP-over-Fibre Channel, with the link-layer header being the Network_Header as described in that RFC
#define LINKTYPE_IP_OVER_FC	122		

// ATM traffic, encapsulated as per the scheme used by SunATM devices
#define LINKTYPE_SUNATM	123		

// Radiotap link-layer information followed by an 802.11 header
#define LINKTYPE_IEEE802_11_RADIOTAP	127		

// ARCNET Data Packets
#define LINKTYPE_ARCNET_LINUX	129		

// Apple IP-over-IEEE 1394 cooked header
#define LINKTYPE_APPLE_IP_OVER_IEEE1394	138		

// Signaling System 7 Message Transfer Part Level 2, as specified by ITU-T Recommendation Q.703, preceded by a pseudo-header
#define LINKTYPE_MTP2_WITH_PHDR	139		

// Signaling System 7 Message Transfer Part Level 2, as specified by ITU-T Recommendation Q.703
#define LINKTYPE_MTP2	140		

// Signaling System 7 Message Transfer Part Level 3, as specified by ITU-T Recommendation Q.704, with no MTP2 header preceding the MTP3 packet
#define LINKTYPE_MTP3	141		

// Signaling System 7 Signalling Connection Control Part
#define LINKTYPE_SCCP	142		

// DOCSIS MAC frames
#define LINKTYPE_DOCSIS	143

// Linux-IrDA packets
#define LINKTYPE_LINUX_IRDA	144

// Reserved for private use
#define LINKTYPE_USER0	147
#define LINKTYPE_USER1	148
#define LINKTYPE_USER2	149	
#define LINKTYPE_USER3	150
#define LINKTYPE_USER4	151	
#define LINKTYPE_USER5	152
#define LINKTYPE_USER6	153	
#define LINKTYPE_USER7	154
#define LINKTYPE_USER8	155	
#define LINKTYPE_USER9	156
#define LINKTYPE_USER10	157	
#define LINKTYPE_USER11	158
#define LINKTYPE_USER12	159	
#define LINKTYPE_USER13	160
#define LINKTYPE_USER14	161	
#define LINKTYPE_USER15	162	

// AVS monitor mode information followed by an 802.11 header
#define LINKTYPE_IEEE802_11_AVS	163	

// BACnet MS/TP frames
#define LINKTYPE_BACNET_MS_TP	165

// PPP in HDLC-like encapsulation
#define LINKTYPE_PPP_PPPD	166

// General Packet Radio Service Logical Link Control
#define LINKTYPE_GPRS_LLC	169

// Transparent-mapped generic framing procedure
#define LINKTYPE_GPF_T	170

// Frame-mapped generic framing procedure
#define LINKTYPE_GPF_F	171

// Link Access Procedures on the D Channel (LAPD) frames
#define LINKTYPE_LINUX_LAPD	177	

// Bluetooth HCI UART transport layer
#define LINKTYPE_BLUETOOTH_HCI_H4	187

// USB packets
#define LINKTYPE_USB_LINUX	189

// Per-Packet Information
#define LINKTYPE_PPI	192

// IEEE 802.15.4 wireless Personal Area Network
#define LINKTYPE_IEEE802_15_4	195

// Various link-layer types, with a pseudo-header, for SITA.
#define LINKTYPE_SITA	196		

// Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF records.
#define LINKTYPE_ERF	197		

// Bluetooth HCI UART transport layer
#define LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR	201

// AX.25 packet, with a 1-byte KISS header containing a type indicator.
#define LINKTYPE_AX25_KISS	202		

// Link Access Procedures on the D Channel (LAPD) frames
#define LINKTYPE_LAPD	203

// PPP
#define LINKTYPE_PPP_WITH_DIR	204		

// Cisco PPP with HDLC framing
#define LINKTYPE_C_HDLC_WITH_DIR	205

// Frame Relay, preceded with a one-byte pseudo-header
#define LINKTYPE_FRELAY_WITH_DIR	206

// IPMB over an I2C circuit, with a Linux-specific pseudo-header.
#define LINKTYPE_IPMB_LINUX	209		

// IEEE 802.15.4 wireless Personal Area Network
#define LINKTYPE_IEEE802_15_4_NONASK_PHY	215

// USB packets, beginning with a Linux USB header
#define LINKTYPE_USB_LINUX_MMAPPED	220

// Fibre Channel FC-2 frames
#define LINKTYPE_FC_2	224

// Fibre Channel FC-2 frames, beginning an encoding of the SOF
#define LINKTYPE_FC_2_WITH_FRAME_DELIMS	225

// Solaris ipnet pseudo-header
#define LINKTYPE_IPNET	226

// CAN (Controller Area Network) frames
#define LINKTYPE_CAN_SOCKETCAN	227

// Raw IPv4
#define LINKTYPE_IPV4	228

// Raw IPv6
#define LINKTYPE_IPV6	229	

// IEEE 802.15.4 wireless Personal Area Network
#define LINKTYPE_IEEE802_15_4_NOFCS	230

// Raw D-Bus messages
#define LINKTYPE_DBUS	231	

// DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver)
#define LINKTYPE_DVB_CI	235		

// Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the same as, 27.010)
#define LINKTYPE_MUX27010	236		

// D_PDUs as described by NATO standard STANAG 5066
#define LINKTYPE_STANAG_5066_D_PDU	237		

// Linux netlink NETLINK NFLOG socket log messages.
#define LINKTYPE_NFLOG	239		

// Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices
#define LINKTYPE_NETANALYZER	240	

// Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices
#define LINKTYPE_NETANALYZER_TRANSPARENT	241	

// IP-over-InfiniBand
#define LINKTYPE_IPOIB	242

// MPEG-2 Transport Stream transport packets
#define LINKTYPE_MPEG_2_TS	243	

// Pseudo-header for ng4T GmbH
#define LINKTYPE_NG40	244		

// Pseudo-header for NFC LLCP packet captures
#define LINKTYPE_NFC_LLCP	245

// Raw InfiniBand frames
#define LINKTYPE_INFINIBAND	247

// SCTP packets
#define LINKTYPE_SCTP	248	

// USB packets, beginning with a USBPcap header.
#define LINKTYPE_USBPCAP	249		

// Serial-line packet header for the Schweitzer Engineering Laboratories "RTAC" product
#define LINKTYPE_RTAC_SERIAL	250	

// Bluetooth Low Energy air interface Link Layer packets
#define LINKTYPE_BLUETOOTH_LE_LL	251

// Linux Netlink capture encapsulation.
#define LINKTYPE_NETLINK	253		

// Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack
#define LINKTYPE_BLUETOOTH_LINUX_MONITOR	254		

// Bluetooth Basic Rate and Enhanced Data Rate baseband packets
#define LINKTYPE_BLUETOOTH_BREDR_BB	255		

// Bluetooth Low Energy link-layer packets
#define LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR	256		

// PROFIBUS data link layer packets
#define LINKTYPE_PROFIBUS_DL	257		

// Apple PKTAP capture encapsulation.
#define LINKTYPE_PKTAP	258		

// Ethernet-over-passive-optical-network packets
#define LINKTYPE_EPON	259	

// IPMI trace packets
#define LINKTYPE_IPMI_HPM_2	260	

// Per Joshua Wright <jwright@hasborg.com>, formats for Z-Wave RF profiles R1 and R2 captures.
#define LINKTYPE_ZWAVE_R1_R2	261		

// Per Joshua Wright <jwright@hasborg.com>, formats for Z-Wave RF profile R3 captures.
#define LINKTYPE_ZWAVE_R3	262		

// Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet structure captures.
#define LINKTYPE_WATTSTOPPER_DLM	263

// Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD)
#define LINKTYPE_ISO_14443	264

#endif // _NETWORK_TYPES_H