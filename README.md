# bcc ipaudits parser
## A parser for  Incognito BCC 6.3 dhcpd audit files
Each file holds several (~500.000), dhcpd transations. one record per line.
The Line/Record have 17 fields:
*  "Start Time",
*  "End Time",
*  "IP Address",
*  "Gateway",
*  "HW Address",
*  "Client ID",
*  "Action",
*  "Host Sent",
*  "Host Received",
*  "A DNS Update",
*  "Protocol",
*  "Circuit ID",
*  "Remote ID,                                                                                ",
*  "Vendor Class ID",
*  "DOCSIS DeviceClass",
*  "Vendor-Specific Data",
*  "Interface ID"
