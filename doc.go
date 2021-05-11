package main

// FOCA 4.1 DHCP
// for IPv4 Only

/*
for the new FACA 4.1 formata

# Field  		Name     	Value                   Comments
01  11		EventType	"11" FIXED value
02 20210228083015     StartTimeKey	AAAAMMDDhhmmss          start date and time
03 20210228084015     EndTimeKey      AAAAMMDDhhmmss          end date and time
04 IGNORE
05 MAC CM		FromNumber      aa:bb:cc:dd:ee:ff       CM MAC : if HFC(ipv4)
06 IGNORE
07 MAC CM	    	PortId          aa:bb:cc:dd:ee:ff       CM MAC : if HFC(ipv4)
08 600     		Duration        ItoA(seconds)           Duration in seconds
09 0    		CallType        "0" FIXED value
10-13 IGNORE
14 DHCP    		NetworkElement   "DHCP"  FIXED value
15 IGNORE
16 ip???????    	PrivateIPAddress aaaBBBcccDDD           CM IP Private Address, [WTF-1]
17 MAC HGW		MACAddress       aa:bb:cc:dd:ee:ff       Home Gateway MAC Addr  [WTF-2]
18 2    		Parameters       "2" FIXED value 	2= HFC record
19 IP???????    	PublicIPAddress  aaaaBBBcccDDD		DHCP: Not Aplicable !! REALLY ??[?? WTF-3]
20-23 IGNORE

*/

/*
$echo "11,20210511083028,20210511093030,,00:05:ca:69:db:30,,00:05:ca:69:db:30,3602,0,,,,,DHCP,,081020244002,00:05:ca:69:db:34,2,081020244002,,,," | tr , "\n" | cat -n
----------------------------------------------------
     1	11
     2	20210511083028
     3	20210511093030
     4
     5	00:05:ca:69:db:30
     6
     7	00:05:ca:69:db:30
     8	3602
     9	0
     10
     11
     12
     13
     14	DHCP
     15
     16	081020244002
     17	00:05:ca:69:db:34
     18	2
     19	081020244002
     20
     21
     22
     23
------------------------------------------------------
*/
