package main

/*
===========================================================
#### Stats

action: 10
	"Offered" = 575734
	"Released" = 13793
	"Active" = 49625
	"Lease Expired" = 47181
	"NAK:No Record of the lease" = 99
	"Forced" = 4357
	"Renewal" = 295084
	"Offer expired" = 4760
	"NAK:Not Renewable" = 23146
	"Failover conflict" = 852
aDNSUpdate: 1
	"Successful" = 1014631
protocol: 2
	"DHCPV4" = 1013268
	"BOOTP" = 1363
vendorClassId: 37
	"docsis3.0" = 29302
	"dhcpcd-5.2.10" = 2
	"docsis2.0" = 97423
	"'nosstb'" = 485
	"nosstb" = 18
	"udhcp 1.12.1" = 12
	"Vigor2820 series" = 3
	"MSFT 98" = 8
	"50" = 39
	"RV082" = 6
	"huawei AR1220" = 21
	"OpenTV" = 9891
	"MSFT 5.0" = 1314
	"dslforum.org" = 38
	"Vigor2925" = 10
	"nds" = 44227
	"" = 1129922
	"udhcp 0.9.8" = 107
	"dhcpcd-5.5.6" = 100
	"fon_test" = 104193
	"BR32L" = 22
	"pktc1.5" = 611676
	"Vigor2820" = 5
	"udhcp 1.20.2" = 4
	"dhcpcd-6.10.0" = 3
	"udhcp 1.24.2" = 2
	"udhcp 0.9.9-pre" = 283
	"udhcp 1.11.2" = 8
	"udhcp 1.11.1" = 5
	"ciscopnp" = 3
	"4d" = 41
	"udhcp 0.9.7" = 5
	"AirStation Series BUFFALO INC." = 8
	"Vigor2110n" = 6
	"udhcp 1.15.2" = 2
	"Vigor2820n" = 3
	"udhcp 1.17.4" = 65
InterfaceID: 0
ip classifier: 11
	"10.213" = 39558
	"10.98" = 601000
	"128.65" = 30028
	"10.156" = 52
	"172.16" = 54308
	"100.82" = 28550
	"78.29" = 78110
	"81.20" = 14843
	"0.0" = 23245
	"192.168" = 57822
	"10.212" = 87115

*/

// doc doc doc
/*




base ≃ ipaddr and 255.255.252.0
index = ipaddr and 0.0.3.255     (1K)


type _IP [4]bytes	// 0 MSB, 3 LSB

struct dhcpLine {
	macCPE	mac
	macCM	mac
	datetime time.UnixDate
	operation int // dhcp operation
	result  int
	next*	struct dhcpLine
}

struct ipItem {
	ipAddress
	first*, last* struct dhcpLine	// linked list of dhcpLines
	cargo [256]bytes
}

struct block1K [1024]ipItem


// use a MAP(IP & 0xffc0)->Block1K ???


struct IPPUB = [30]blok1K  //-- IPPUB[base]blo1k[1ndex] ????


// use a MAP(IP & 0xffc0)->Block1K ???
or



// função linear em vez de um MAP.... profiling/benchmark....
func index(ip _IP) (base, index int) { // uint16 ???
	index = ip[3] + 256 * ( ip[2] & 0x03 )
	switch ip[0] {
	case 78:	// 78.29.128.0/18		// 0011.1100
		base = ip[2] & 0x3c
	case 81:	// 81.20.240.0/20
		base = 16 + ip[2] & 0x0C		// 0000.1100
	case 128:
		base = 20 + ip[2] & 0x1c
	case 185:
		base =28 + 1

	}

}

exemplo de como pode ser explicado partes do projeto/processo...

So that’s what I did. Instead of running an entire MapReduce cluster, I decided to run one massive but cheap machine using Go for parallelism.

Design
==========
The application was simple:

List all the files in S3 for a particular date – Cloudfront has around 20K individual log files generated per day.
Download each file.
Process the lines in each file discarding all the static file accesses and other lines we didn’t care about.
Lookup the creatorid of each model and collection referenced from our API.
Lookup the GeoIP data for the IP address using a Maxmind database.
Transform the output into a zipped CSV we could import into Redshift.
Run on an AWS machine to give close network proximity to S3 and to get plenty of processors.
Parallelizing

I used a goroutine pool for each of the separate parts of the problem:

File Listing
File Downloading
Line Processing
Aggregating the CSV.
Essentially, the file lister would list all the S3 objects and pass them via channel to the file downloader. One of the file downloader routines would fetch the file, split the file lines into groups of 5,000 and pass them along to the line processors. These would process all the lines, do all required lookups, and pass the values along to the csv aggregator.

I kept the csv lines in slices and outputted them to separate CSV files in groups of 50,000 which I then uploaded to S3.

Result
Eventually I got it working, and I was able to process 1 day of data in 10-20 minutes, depending on if I was using a 32 core or a 64 core machine.

Debugging, for the most part was dramatically easier than Spark. If something went wrong, I only had to ssh to a single machine to look at the logs.

I didn’t use anything complex to run the job, a simple screen session was good enough.

Of course, using Go had its own set of issues.


*/
