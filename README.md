# sigtopcap
INTRODUCTION
------------

The 'sigtopcap' utility converts input '*.sig' files into '*.pcap' format.
Additional option is to separate input file ('*.sig' or '*.pcap') into multiple parts.

REQUIREMENTS
------------

This utility supports the following operation systems (x64):
	* Windows 8.1 Professional
	* Linux Mint 17.3 Amd64

INSTALLATION
------------

	* In Linux just type: make install.
	* In Windows: copy sigtopcap to the system folder and add environment varible.
	* You may use this utility without installation from its './bin/' folder.

CONFIGURATION
-------------

	There is no configuration.

USAGE
-----

	sigtopcap -c <filename> [network_type]
	sigtopcap -o <filename> <offset>
	sigtopcap -s <filename> <split_type> <split_size>
	sigtopcap -f <filename>
	sigtopcap -h

	 -c converting *.sig file to *.pcap file
	 -o converting *.sig file to *.pcap file with manual setting IP-header offset value
	 -s splitting *.sig or *.pcap file
	 -f showing IP-header offset and link type
	 -h showing help

	<network_type> = link-layer header type value according http://www.tcpdump.org/linktypes.html (Default: LINKTYPE_ETHERNET(1))
	<offset> = IP-header offset
	<split_type> = 0 - split by packet count, 1 - split by filesize
	<split_size> = packets count in each splitted files for split_type=0, result splitted file size for split_type=1

TROUBLESHOOTING
---------------

support email: techsupport@ntc-vulkan.ru

If utility can`t detect link type and IP-header offset, please do the following steps:
1. Open input '*.sig' file in a hex editor.
2. Find IP-header by start signature 0x45.
3. Calculate bytes before start signature (<offset>)
4. Execute 'sigtopcap -o <filename> <offset>'

If visual studio can`t find include files, please do tho following steps:
1. Open sigtopcap project properties.
2. Open `configuration properties->VC++ Directories`
3. Add `Include Directories` value: path of sigtopcap\include folder.

AUTHOR
------

Igor Podvoiskiy
email: i.podvoiskiy@ntc-vulkan.ru

COMPANY
-------

NTC-VULKAN
