#audits

for the new FACA 4.1 formata

#Field	Name 			Max Bytes 	Type 		Value			Comments 
#01 	EventType 		2 		Uint8 		11			FIXED value 11 - DHCP event CDR	
02 	StartTimeKey 		14 		String 		AAAAMMDDhhmmss		start date and time
03 	EndTimeKey 		14 		String  	AAAAMMDDhhmmss		end date and time
04 	Cell 			507 		String 		--			NA
05 	FromNumber		130 		String 		aa:bb:cc:dd:ee:ff	CM MAC : if HFC(ipv4)
06 	ToNumber 		130 		String 		--			NA
07 	PortId 			50 		String 		aa:bb:cc:dd:ee:ff	CM MAC : if HFC(ipv4)
08 	Duration 		12 		Uint32 		ItoA(seconds)		Duration in seconds	
09 	CallType 		1 		Uint8 		0			FIXED value 0
10 	IMEI 			50 		String 		--			NA
11 	IMSI 			50 		String 		--			NA
12 	Cnumber 		24 		String 		--			NA
13 	NetworkCallReference 	64 		String 		--			NA
14 	NetworkElement		12 		String 		DHCP			DHCP: ipv4,  DHCP.AI/DHCP.PD if ipv6
15 	DataVolume 		25 		Uint64 		--			NA
16 	PrivateIPAddress 	78 		String 		--			NA (CM IP Private Address)
17 	MACAddress 		17 		String 		aa:bb:cc:dd:ee:ff	CPE MAC Addr (Home Gateway 
18 	Parameters 		3 		Uint8 		2			FIXED value 2= HFC record
19 	PublicIPAddress 	78 		String 		aaaBBBcccDDD		Public IPv4 Address
20 	PortRangeStart 		5 		Uint32 		--			NA	
21 	PortRangeEnd 		5		Uint32 		--			NA
22 	IPv6_first 		40 		String 		--			NA for IPv4, First address of IPv6 range 
23 	IPv6_last 		40 		String 		--			NA for IPv4, Last address of IPv6 range

Documemntação (FOCA_DTS_SIAJ_v4.1.pdf)
-----------------------------------------------------------------------------------------------------------------------------------
