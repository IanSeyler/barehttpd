/* hello_http */
/* Based off minIP - https://github.com/IanSeyler/minIP */

/* Global Includes */
#include "libBareMetal.h"

/* Global defines */
#define swap16(x) __builtin_bswap16(x)
#define swap32(x) __builtin_bswap32(x)
#define NULL ((void *)0)
#undef ETH_FRAME_LEN
#define ETH_FRAME_LEN 1518
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define PROTOCOL_IP_ICMP 1
#define PROTOCOL_IP_TCP 6
#define PROTOCOL_IP_UDP 11
#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define TCP_CWR 128
#define TCP_ECN 64
#define TCP_URG 32
#define TCP_ACK 16
#define TCP_PSH 8
#define TCP_RST 4
#define TCP_SYN 2
#define TCP_FIN 1
#define INTERFACE 0

/* Global variables */
u8 src_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
u8 dst_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
u8 src_IP[4] = {192, 168, 4, 250};
u8 src_SN[4] = {255, 255, 255, 0};
u8 src_GW[4] = {192, 168, 4, 1};
#ifndef NO_DHCP
u8 dhcpdst[4] = {255, 255, 255, 255};
u8 dhcpsrc[4] = {0, 0, 0, 0};
#endif
unsigned char *buffer;
unsigned char tosend[ETH_FRAME_LEN];
int running = 1, recv_packet_len;
u16 EtherType = 0;
u8 hitcount = 0;
char tempstring[] = "   ";

/* Global structs */
#pragma pack(1)
typedef struct eth_header {
	u8 dest_mac[6];
	u8 src_mac[6];
	u16 type;
} eth_header; // 14 bytes
typedef struct arp_packet {
	eth_header ethernet;
	u16 hardware_type;
	u16 protocol;
	u8 hardware_size;
	u8 protocol_size;
	u16 opcode;
	u8 sender_mac[6];
	u8 sender_ip[4];
	u8 target_mac[6];
	u8 target_ip[4];
} arp_packet; // 28 bytes
typedef struct ipv4_packet {
	eth_header ethernet;
	u8 version;
	u8 dsf;
	u16 total_length;
	u16 id;
	u16 flags;
	u8 ttl;
	u8 protocol;
	u16 checksum;
	u8 src_ip[4];
	u8 dest_ip[4];
} ipv4_packet; // 20 bytes since we don't support options
typedef struct icmp_packet {
	ipv4_packet ipv4;
	u8 type;
	u8 code;
	u16 checksum;
	u16 id;
	u16 sequence;
	u64 timestamp;
	u8 data[2]; // Set to 2 so can be used as pointer
} icmp_packet;
typedef struct udp_packet {
	ipv4_packet ipv4;
	u16 src_port;
	u16 dest_port;
	u16 length;
	u16 checksum;
	u8 data[2]; // Set to 2 so can be used as pointer
} udp_packet;
typedef struct tcp_packet {
	ipv4_packet ipv4;
	u16 src_port;
	u16 dest_port;
	u32 seqnum;
	u32 acknum;
	u8 data_offset;
	u8 flags;
	u16 window;
	u16 checksum;
	u16 urg_pointer;
	// Options and data
	u8 data[2]; // Set to 2 so can be used as pointer
} tcp_packet;

/* Default HTTP page with HTTP headers */
char webpage[] =
"HTTP/1.0 200 OK\n"
"Server: BareMetal\n"
"Content-type: text/html\n"
"\n"
"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>BareMetal OS Demo</title><style> body { background: #000; color: #fff; font-family: monospace; display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center; padding: 20px;} h1 { font-size: 10vw; margin: 0; text-shadow: 0 0 20px var(--c); } p { font-size: 1.2rem; max-width: 600px; line-height: 1.5; color: #888;} span { color: var(--c);}</style></head><body><h1 id=\"h\">You are                 and I am                </h1><p>This is a demonstration of the <span>headless multi-agent system orchestration</span> using the <a href=\"https://returninfinity.com\" target=null> BareMetal kernel</a>.</p><small>Hit count:    </small><script>const h = Date.now()%360;document.body.style.setProperty('--c', `hsl(${h}, 100%, 50%)`);</script></body></html>\n";
u32 WEBPAGE_LEN = sizeof(webpage) - 1;
const char webpage404[] =
"HTTP/1.0 404 Not Found\n"
"Server: BareMetal\n"
"Content-type: text/html\n"
"\n"
"<!DOCTYPE html>\n"
"<html>\n"
"\t<head>\n"
"\t\t<title>404</title>\n"
"\t</head>\n"
"\t<body>\n"
"\t\t<p>404 - Not found</p>\n"
"\t</body>\n"
"</html>\n";
u32 WEBPAGE404_LEN = sizeof(webpage404) - 1;
const char version_string[] = "barehttpd v0.9.5 (2026 06 05)\n";

/* Global functions */
u16 checksum(u8* data, u16 bytes);
u16 checksum_tcp(u8* data, u16 bytes, u16 protocol, u16 length);
int net_init();
void* memset(void* s, int c, int n);
void* memcpy(void* d, const void* s, int n);
int strlen(const char* s);
int strcat(char* dest, const char* src);
char* b_to_s(char* buffer, unsigned char byte);
char* b_to_hex(char* buffer, unsigned char byte);
void display_ip(u8* ip);
void halt();
void helper_ethernet(eth_header* tx, eth_header* rx, u16 ethertype);
void helper_ipv4(ipv4_packet* tx, ipv4_packet* rx);

/* Main code */
int main()
{
	b_output(version_string, (unsigned long)strlen(version_string));
	net_init();

	while(running == 1)
	{
		recv_packet_len = b_net_rx((void**)&buffer, INTERFACE);

		// If there was no data then halt until an interrupt occurs
		if (recv_packet_len == 0)
		{
			halt();
			continue;
		}

//		#ifdef DEBUG
//		if (recv_packet_len > 0)
//			b_system(DUMP_MEM, (u64)buffer, recv_packet_len);
//		#endif

		if (buffer == NULL || recv_packet_len < sizeof(eth_header)) // Check for valid buffer address and packet length
		{
			continue; // Restart to the beginning of the while loop
		}

		eth_header* rx = (eth_header*)buffer;
		EtherType = swap16(rx->type);

		#ifdef DEBUG
		b_output(" ", 1);
//		#else
//		b_output(".", 1);
		#endif

		memset(tosend, 0, ETH_FRAME_LEN); // clear the send buffer
		if (EtherType == ETHERTYPE_ARP && recv_packet_len >= sizeof(arp_packet))
		{
			#ifdef DEBUG
			b_output("arp", 3);
			#endif
			arp_packet* rx_arp = (arp_packet*)buffer;
			if (swap16(rx_arp->opcode) == ARP_REQUEST)
			{
				if (*(u32*)rx_arp->target_ip == *(u32*)src_IP) // Verify the request is for our IP
				{
					arp_packet* tx_arp = (arp_packet*)tosend;
					// Ethernet
					helper_ethernet(&tx_arp->ethernet, &rx_arp->ethernet, ETHERTYPE_ARP);
					// ARP
					tx_arp->hardware_type = swap16(1); // Ethernet
					tx_arp->protocol = swap16(ETHERTYPE_IPV4);
					tx_arp->hardware_size = 6;
					tx_arp->protocol_size = 4;
					tx_arp->opcode = swap16(ARP_REPLY);
					memcpy(tx_arp->sender_mac, src_MAC, 6);
					memcpy(tx_arp->sender_ip, rx_arp->target_ip, 4);
					memcpy(tx_arp->target_mac, rx_arp->sender_mac, 6);
					memcpy(tx_arp->target_ip, rx_arp->sender_ip, 4);
					// Send the reply
					b_net_tx(tosend, 42, INTERFACE);
					#ifdef DEBUG
					b_output("!", 1); // Request was responded to
					#endif
				}
			}
			else if (buffer[21] == ARP_REPLY)
			{
				// TODO - Responses to our requests
			}
		}
		else if (EtherType == ETHERTYPE_IPV4 && recv_packet_len >= sizeof(ipv4_packet))
		{
			#ifdef DEBUG
			b_output("ipv4_", 5);
			#endif
			ipv4_packet* rx_ipv4 = (ipv4_packet*)buffer;
			if(rx_ipv4->protocol == PROTOCOL_IP_ICMP)
			{
				#ifdef DEBUG
				b_output("icmp", 4);
				#endif
				icmp_packet* rx_icmp = (icmp_packet*)buffer;
				if(rx_icmp->type == ICMP_ECHO_REQUEST)
				{
					if (*(u32*)rx_icmp->ipv4.dest_ip == *(u32*)src_IP)
					{
						// Reply to the ping request
						icmp_packet* tx_icmp = (icmp_packet*)tosend;
						// Ethernet
						helper_ethernet(&tx_icmp->ipv4.ethernet, &rx_icmp->ipv4.ethernet, ETHERTYPE_IPV4);
						// IPv4
						// Todo - a better way to check the minimum.. breaks the memcpy below but that math may be off.
						if (swap16(rx_icmp->ipv4.total_length) > 1400 || swap16(rx_icmp->ipv4.total_length) < 36) // Ignore ICMP larger and smaller than this
							continue;
						helper_ipv4(&tx_icmp->ipv4, &rx_icmp->ipv4);
						tx_icmp->ipv4.checksum = rx_icmp->ipv4.checksum; // Use the received checksum
						// ICMP
						tx_icmp->type = ICMP_ECHO_REPLY;
						tx_icmp->code = rx_icmp->code;
						tx_icmp->checksum = 0;
						tx_icmp->id = rx_icmp->id;
						tx_icmp->sequence = rx_icmp->sequence;
						tx_icmp->timestamp = rx_icmp->timestamp;
						memcpy (tx_icmp->data, rx_icmp->data, (swap16(rx_icmp->ipv4.total_length)-20-16)); // IP length - IPv4 header - ICMP header
						tx_icmp->checksum = checksum(&tosend[34], recv_packet_len-14-20); // Frame length - MAC header - IPv4 header
						// Send the reply
						b_net_tx(tosend, recv_packet_len, INTERFACE);
						#ifdef DEBUG
						b_output("!", 1); // Request was responded to
						#endif
					}
				}
				else if (rx_icmp->type == ICMP_ECHO_REPLY)
				{
					// Ignore these for now.
				}
				else
				{
					// Do nothing
				}
			}
			else if(rx_ipv4->protocol == PROTOCOL_IP_TCP)
			{
				#ifdef DEBUG
				b_output("tcp_", 4);
				#endif
				tcp_packet* rx_tcp = (tcp_packet*)buffer;
				if (rx_tcp->flags & TCP_SYN && *(u32*)rx_tcp->ipv4.dest_ip == *(u32*)src_IP) // && rx_tcp->dest_port == swap16(80))
				{
					#ifdef DEBUG
					b_output("syn", 3);
					#endif
					if (rx_tcp->dest_port != swap16(80))
					{
						tcp_packet* tx_tcp = (tcp_packet*)tosend;
						memcpy((void*)tosend, (void*)buffer, ETH_FRAME_LEN); // make a copy of the original frame
						// Ethernet
						helper_ethernet(&tx_tcp->ipv4.ethernet, &rx_tcp->ipv4.ethernet, ETHERTYPE_IPV4);
						// IPv4
						helper_ipv4(&tx_tcp->ipv4, &rx_tcp->ipv4);
						tx_tcp->ipv4.checksum = checksum(&tosend[14], 20);
						// TCP
						tx_tcp->src_port = rx_tcp->dest_port;
						tx_tcp->dest_port = rx_tcp->src_port;
						tx_tcp->seqnum = rx_tcp->seqnum;
						tx_tcp->acknum = swap32(swap32(rx_tcp->seqnum)+1);
						tx_tcp->data_offset = rx_tcp->data_offset;
						tx_tcp->flags = TCP_RST|TCP_ACK;
						tx_tcp->window = rx_tcp->window;
						tx_tcp->checksum = 0;
						tx_tcp->urg_pointer = rx_tcp->urg_pointer;
						tx_tcp->checksum = checksum_tcp(&tosend[34], recv_packet_len-34, PROTOCOL_IP_TCP, recv_packet_len-34);
						// Send the reply
						b_net_tx(tosend, recv_packet_len, INTERFACE);
						#ifdef DEBUG
						b_output("!", 1); // Request was responded to
						#endif
					}
					else
					{
						tcp_packet* tx_tcp = (tcp_packet*)tosend;
						memcpy((void*)tosend, (void*)buffer, ETH_FRAME_LEN); // make a copy of the original frame
						// Ethernet
						helper_ethernet(&tx_tcp->ipv4.ethernet, &rx_tcp->ipv4.ethernet, ETHERTYPE_IPV4);
						// IPv4
						helper_ipv4(&tx_tcp->ipv4, &rx_tcp->ipv4);
						tx_tcp->ipv4.checksum = checksum(&tosend[14], 20);
						// TCP
						tx_tcp->src_port = rx_tcp->dest_port;
						tx_tcp->dest_port = rx_tcp->src_port;
						tx_tcp->seqnum = rx_tcp->seqnum;
						tx_tcp->acknum = swap32(swap32(rx_tcp->seqnum)+1);
						tx_tcp->data_offset = rx_tcp->data_offset;
						tx_tcp->flags = TCP_SYN|TCP_ACK;
						tx_tcp->window = rx_tcp->window;
						tx_tcp->checksum = 0;
						tx_tcp->urg_pointer = rx_tcp->urg_pointer;
						tx_tcp->checksum = checksum_tcp(&tosend[34], recv_packet_len-34, PROTOCOL_IP_TCP, recv_packet_len-34);
						// Send the reply
						b_net_tx(tosend, recv_packet_len, INTERFACE);
						#ifdef DEBUG
						b_output("!", 1); // Request was responded to
						#endif
					}
				}
				else if (rx_tcp->flags == TCP_ACK)
				{
					// Ignore these for now.
					#ifdef DEBUG
					b_output("ack", 3);
					#endif
				}
				else if (rx_tcp->flags == (TCP_PSH|TCP_ACK) && *(u32*)rx_tcp->ipv4.dest_ip == *(u32*)src_IP && rx_tcp->dest_port == swap16(80))
				{
					#ifdef DEBUG
					b_output("psh", 3);
					#endif
					tcp_packet* tx_tcp = (tcp_packet*)tosend;
					memcpy((void*)tosend, (void*)buffer, ETH_FRAME_LEN); // make a copy of the original frame
					// Ethernet
					helper_ethernet(&tx_tcp->ipv4.ethernet, &rx_tcp->ipv4.ethernet, ETHERTYPE_IPV4);
					// IPv4
					helper_ipv4(&tx_tcp->ipv4, &rx_tcp->ipv4);
					tx_tcp->ipv4.total_length = swap16(52);
					tx_tcp->ipv4.checksum = checksum(&tosend[14], 20);
					// TCP
					tx_tcp->src_port = rx_tcp->dest_port;
					tx_tcp->dest_port = rx_tcp->src_port;
					tx_tcp->seqnum = rx_tcp->seqnum;
					tx_tcp->acknum = swap32(swap32(rx_tcp->seqnum)+(recv_packet_len-14-20-32)); // Add the bytes received
					tx_tcp->data_offset = rx_tcp->data_offset;
					tx_tcp->flags = TCP_ACK;
					tx_tcp->window = rx_tcp->window;
					tx_tcp->checksum = 0;
					tx_tcp->urg_pointer = rx_tcp->urg_pointer;
					tx_tcp->checksum = checksum_tcp(&tosend[34], 32, PROTOCOL_IP_TCP, 32);
					// Send the reply
					b_net_tx(tosend, 66, INTERFACE);
					// Check for what was requested
					char* http_request = (char*)buffer + 66;
					u32 request_len = recv_packet_len - 66;
					u32 send404 = 1; // Default to 404
					// Check if the request starts with "GET / " or "GET /INDEX"
					if (request_len >= 6) {
						if (http_request[0] == 'G' && http_request[1] == 'E' && http_request[2] == 'T' && http_request[3] == ' ')
						{
							// Check for "GET / " (6 chars including space after slash)
							if (http_request[4] == '/' && (http_request[5] == ' ' || http_request[5] == 'H'))
							{
								send404 = 0;
							}
							// Check for "GET /INDEX" (case insensitive)
							else if (request_len >= 10 && http_request[4] == '/')
							{
								if ((http_request[5] == 'I' || http_request[5] == 'i') &&
								    (http_request[6] == 'N' || http_request[6] == 'n') &&
								    (http_request[7] == 'D' || http_request[7] == 'd') &&
								    (http_request[8] == 'E' || http_request[8] == 'e') &&
								    (http_request[9] == 'X' || http_request[9] == 'x'))
									{
										send404 = 0;
									}
								}
							}
						}
					// If so, send the page, otherwise 404
					if (send404 == 0)
					{
						char tstring[] = "               ";
						char ipstring[16];
						u8 ipval;

						// Clear out old strings on page
						memcpy((char*)webpage+641, tstring, strlen(tstring));
						memcpy((char*)webpage+641+25, tstring, strlen(tstring));
						memcpy((char*)webpage+851+27, tstring, 3);

						// Get the client's IP address and update the webpage
						memset(ipstring, 0, 16);
						ipval = rx_tcp->ipv4.src_ip[0];
						b_to_s(tempstring, ipval);
						strcat(ipstring, tempstring);
						strcat(ipstring, ".");
						ipval = rx_tcp->ipv4.src_ip[1];
						b_to_s(tempstring, ipval);
						strcat(ipstring, tempstring);
						strcat(ipstring, ".");
						ipval = rx_tcp->ipv4.src_ip[2];
						b_to_s(tempstring, ipval);
						strcat(ipstring, tempstring);
						strcat(ipstring, ".");
						ipval = rx_tcp->ipv4.src_ip[3];
						b_to_s(tempstring, ipval);
						strcat(ipstring, tempstring);
						memcpy((char*)webpage+641, ipstring, strlen(ipstring));

						// Get the server's IP address and update the webpage
						memset(ipstring, 0, 16);
						ipval = rx_tcp->ipv4.dest_ip[0];
						b_to_s(tempstring, ipval);
						strcat(ipstring, tempstring);
						strcat(ipstring, ".");
						ipval = rx_tcp->ipv4.dest_ip[1];
						b_to_s(tempstring, ipval);
						strcat(ipstring, tempstring);
						strcat(ipstring, ".");
						ipval = rx_tcp->ipv4.dest_ip[2];
						b_to_s(tempstring, ipval);
						strcat(ipstring, tempstring);
						strcat(ipstring, ".");
						ipval = rx_tcp->ipv4.dest_ip[3];
						b_to_s(tempstring, ipval);
						strcat(ipstring, tempstring);
						memcpy((char*)webpage+641+25, ipstring, strlen(ipstring));

						// Add hitcount to webpage
						hitcount++;
						b_to_s(tempstring, hitcount);
						memcpy((char*)webpage+851+27, tempstring, strlen(tempstring));

						// Send the page
						tx_tcp->ipv4.total_length = swap16(52+WEBPAGE_LEN);
						tx_tcp->ipv4.checksum = 0;
						tx_tcp->ipv4.checksum = checksum(&tosend[14], 20);
						tx_tcp->flags = TCP_PSH|TCP_ACK;
						tx_tcp->checksum = 0;
						memcpy((char*)tosend+66, (char*)webpage, WEBPAGE_LEN);
						tx_tcp->checksum = checksum_tcp(&tosend[34], 32+WEBPAGE_LEN, PROTOCOL_IP_TCP, 32+WEBPAGE_LEN);
						b_net_tx(tosend, 66+WEBPAGE_LEN, INTERFACE);
						// Disconnect the client
						tx_tcp->ipv4.total_length = swap16(52);
						tx_tcp->ipv4.checksum = 0;
						tx_tcp->ipv4.checksum = checksum(&tosend[14], 20);
						tx_tcp->seqnum = swap32(swap32(tx_tcp->seqnum)+WEBPAGE_LEN);
					}
					else
					{
						tx_tcp->ipv4.total_length = swap16(52+WEBPAGE404_LEN);
						tx_tcp->ipv4.checksum = 0;
						tx_tcp->ipv4.checksum = checksum(&tosend[14], 20);
						tx_tcp->flags = TCP_PSH|TCP_ACK;
						tx_tcp->checksum = 0;
						memcpy((char*)tosend+66, (char*)webpage404, WEBPAGE404_LEN);
						tx_tcp->checksum = checksum_tcp(&tosend[34], 32+WEBPAGE404_LEN, PROTOCOL_IP_TCP, 32+WEBPAGE404_LEN);
						b_net_tx(tosend, 66+WEBPAGE404_LEN, INTERFACE);
						// Disconnect the client
						tx_tcp->ipv4.total_length = swap16(52);
						tx_tcp->ipv4.checksum = 0;
						tx_tcp->ipv4.checksum = checksum(&tosend[14], 20);
						tx_tcp->seqnum = swap32(swap32(tx_tcp->seqnum)+WEBPAGE404_LEN);
					}
					tx_tcp->flags = TCP_FIN|TCP_ACK;
					tx_tcp->checksum = 0;
					tx_tcp->checksum = checksum_tcp(&tosend[34], 32, PROTOCOL_IP_TCP, 32);
					b_net_tx(tosend, 66, INTERFACE);
					#ifdef DEBUG
					b_output("!", 1); // Request was responded to
					#endif
				}
				else if (rx_tcp->flags == (TCP_FIN|TCP_ACK))
				{
					#ifdef DEBUG
					b_output("fin", 3);
					#endif
					tcp_packet* tx_tcp = (tcp_packet*)tosend;
					memcpy((void*)tosend, (void*)buffer, ETH_FRAME_LEN); // make a copy of the original frame
					// Ethernet
					helper_ethernet(&tx_tcp->ipv4.ethernet, &rx_tcp->ipv4.ethernet, ETHERTYPE_IPV4);
					// IPv4
					helper_ipv4(&tx_tcp->ipv4, &rx_tcp->ipv4);
					tx_tcp->ipv4.total_length = swap16(52);
					tx_tcp->ipv4.checksum = checksum(&tosend[14], 20);
					// TCP
					tx_tcp->src_port = rx_tcp->dest_port;
					tx_tcp->dest_port = rx_tcp->src_port;
					tx_tcp->seqnum = rx_tcp->acknum;
					tx_tcp->acknum = swap32(swap32(rx_tcp->seqnum)+1);
					tx_tcp->data_offset = rx_tcp->data_offset;
					tx_tcp->flags = TCP_ACK;
					tx_tcp->window = rx_tcp->window;
					tx_tcp->checksum = 0;
					tx_tcp->urg_pointer = rx_tcp->urg_pointer;
					tx_tcp->checksum = checksum_tcp(&tosend[34], 32, PROTOCOL_IP_TCP, 32);
					// Send the reply
					b_net_tx(tosend, 66, INTERFACE);
					#ifdef DEBUG
					b_output("!", 1); // Request was responded to
					#endif
				}
				else {
					#ifdef DEBUG
					b_output("?", 1);
					#endif
				}
			}
			else if (rx_ipv4->protocol == PROTOCOL_IP_UDP)
			{
				// TODO - UDP
				#ifdef DEBUG
				b_output("udp", 3);
				#endif
			}
			else
			{
				// Do nothing (some other protocol)
				#ifdef DEBUG
				b_output("?", 1);
				#endif
			}
		}
		else if (EtherType == ETHERTYPE_IPV6)
		{
			// TODO - IPv6
			#ifdef DEBUG
			b_output("ipv6", 4);
			#endif
		}
		else
		{
			#ifdef DEBUG
			b_output("?", 1);
			#endif
		}
	}

	b_output("\n", 1);
	return 0;
}


/* checksum - Calculate a checksum value */
// Returns 16-bit checksum
u16 checksum(u8* data, u16 bytes)
{
	u32 sum = 0;
	u16 i;

	for (i=0; i<bytes-1; i+=2) // Add up the words
		sum += *(u16 *) &data[i];

	if (bytes & 1) // Add the left-over byte if there is one
		sum += (u8) data[i];

	while (sum >> 16) // Fold total to 16-bits
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum; // Return 1's complement
}


/* checksum_tcp - Calculate a TCP checksum value */
// Returns 16-bit checksum
u16 checksum_tcp(u8* data, u16 bytes, u16 protocol, u16 length)
{
	u32 sum = 0;
	u16 i;
	data -= 8; // Start at the source and dest IPs
	bytes += 8;

	for (i=0; i<bytes-1; i+=2) // Add up the words
		sum += *(u16 *) &data[i];

	if (bytes & 1) // Add the left-over byte if there is one
		sum += (u8) data[i];

	sum += swap16(protocol);
	sum += swap16(length);

	while (sum >> 16) // Fold total to 16-bits
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum; // Return 1's complement
}


/* net_init */
int net_init()
{
    char tstring[] = "xxx";
	/* Populate the MAC Address */
	/* Pulls the MAC from the OS sys var table... so gross */
	char * os_MAC = (void*)0x11A008; // Address of the MAC for interface 0
	os_MAC += INTERFACE * 128;
	memcpy(src_MAC, os_MAC, 6); // Copy MAC address

	#ifndef NO_DHCP
	// Send a DHCP Discover packet
	udp_packet* tx_udp = (udp_packet*)tosend;
	memset(tosend, 0, 1500);
	// Ethernet
	memcpy(tx_udp->ipv4.ethernet.dest_mac, dst_broadcast, 6);
	memcpy(tx_udp->ipv4.ethernet.src_mac, src_MAC, 6);
	tx_udp->ipv4.ethernet.type = swap16(ETHERTYPE_IPV4);
	// IPv4
	tx_udp->ipv4.version = 0x45;
	tx_udp->ipv4.dsf = 0;
	tx_udp->ipv4.total_length = swap16(312);
	tx_udp->ipv4.id = 0;
	tx_udp->ipv4.flags = swap16(0x4000);
	tx_udp->ipv4.ttl = 0x40;
	tx_udp->ipv4.protocol = 0x11;
	tx_udp->ipv4.checksum = 0;
	memcpy(tx_udp->ipv4.src_ip, dhcpsrc, 4);
	memcpy(tx_udp->ipv4.dest_ip, dhcpdst, 4);
	tx_udp->ipv4.checksum = checksum(&tosend[14], 20);
	// UDP
	tx_udp->src_port = swap16(68);
	tx_udp->dest_port = swap16(67);
	tx_udp->length = swap16(292);
	tx_udp->checksum = 0;
//	tx_udp->checksum = checksum_tcp(&tosend[34], 32, PROTOCOL_IP_TCP, 32);
	// DHCP
	tosend[42] = 0x01;
	tosend[43] = 0x01;
	tosend[44] = 0x06;
	tosend[45] = 0x00;
	// 4-byte transaction ID
	tosend[46] = src_MAC[2];
	tosend[47] = src_MAC[3];
	tosend[48] = src_MAC[4];
	tosend[49] = src_MAC[5];
	memcpy(&tosend[70], src_MAC, 6);
	// DHCP magic value
	tosend[278] = 0x63;
	tosend[279] = 0x82;
	tosend[280] = 0x53;
	tosend[281] = 0x63;

	tosend[282] = 0x35; // message type
	tosend[283] = 0x01; // length
	tosend[284] = 0x01; // discover

	tosend[285] = 0x3d; // client id
	tosend[286] = 0x07; // length
	tosend[287] = 0x01;
	memcpy(&tosend[288], src_MAC, 6);
	tosend[294] = 0x37; // Parameter Request List
	tosend[295] = 0x11; // Length
	tosend[296] = 0x01; // Subnet Mask
	tosend[297] = 0x02; // Time Offset
	tosend[298] = 0x06; // Domain Name Server
	tosend[299] = 0x0c; // Host Name
	tosend[300] = 0x0f; // Domain Name
	tosend[301] = 0x1a; // Interface MTU
	tosend[302] = 0x1c; // Broadcast Address
	tosend[303] = 0x79; // Classless Static Route
	tosend[304] = 0x03; // Router
	tosend[305] = 0x21; // Static Route
	tosend[306] = 0x28; // Network Information Service Domain
	tosend[307] = 0x29; // Network Information Service Servers
	tosend[308] = 0x2a; // Network Time Protocol Servers
	tosend[309] = 0x77; // Domain Search
	tosend[310] = 0xf9; // Private/Classless Static Route
	tosend[311] = 0xfc; // Private/Proxy Autodiscovery
	tosend[312] = 0x11; // Root Path
	tosend[313] = 0x39; // Maximum DHCP Message Size
	tosend[314] = 0x02; // Length
	tosend[315] = 0x02; // Size (0x240 - 576 bytes)
	tosend[316] = 0x40;
	tosend[317] = 0x0c; // Host Name
	tosend[318] = 0x06; // Length
	tosend[319] = 'b';
	tosend[320] = 'm';
	b_to_hex(tstring, src_MAC[4]);
	tosend[321] = tstring[0];
	tosend[322] = tstring[1];
	b_to_hex(tstring, src_MAC[5]);
	tosend[323] = tstring[0];
	tosend[324] = tstring[1];
	tosend[325] = 0xFF; // End

	// Send the reply
	b_net_tx(tosend, 326, INTERFACE);

	// Wait for a DHCP Offer Packet
	int dhcp = 0;
	while (dhcp == 0)
	{
		recv_packet_len = b_net_rx((void**)&buffer, INTERFACE);
		eth_header* rx = (eth_header*)buffer;

		// If there was no data then halt until an interrupt occurs
		if (recv_packet_len == 0)
		{
			halt();
			continue;
		}

//		#ifdef DEBUG
//		if (recv_packet_len > 0)
//		{
//			b_system(DUMP_MEM, (u64)buffer, recv_packet_len);
//		}
//		#endif
		if (swap16(rx->type) == ETHERTYPE_IPV4)
		{
			udp_packet* rx_udp = (udp_packet*)buffer;
			if (swap16(rx_udp->dest_port) == 68)
			{
				unsigned int index = 282;
				u8 tval = 0, tlen = 0;
				memcpy(src_IP, buffer + 58, 4);
				dhcp = 1;
				b_output("DHCP - IP: ", 11);
				display_ip(src_IP);

				// Parse options
				while (1)
				{
					tval = buffer[index];
					if (tval == 0xFF)
						break;
					tlen = buffer[index+1];
					if (tval == 0x01) // Subnet
					{
						memcpy(src_SN, buffer + index + 2, 4);
						b_output(", SN: ", 6);
						display_ip(src_SN);
					}
					else if (tval == 0x03) // Router
					{
						memcpy(src_GW, buffer + index + 2, 4);
						b_output(", GW: ", 6);
						display_ip(src_GW);
					}
					index = index + tlen + 2;
				}
			}
		}
	}

	if (dhcp == 1)
	{
		// Send a DHCP Request packet
		tx_udp->ipv4.total_length = swap16(324);
		tx_udp->ipv4.checksum = 0;
		tx_udp->ipv4.checksum = checksum(&tosend[14], 20);
		tx_udp->length = swap16(304);
		tx_udp->checksum = 0;
		tosend[282] = 0x35; // message type
		tosend[283] = 0x01; // length
		tosend[284] = 0x03; // request

		tosend[317] = 0x32; // requested IP Address
		tosend[318] = 0x04; // length
		memcpy(tosend + 319, buffer + 58, 4); // requested IP Address value

		tosend[323] = 0x36; // dhcp server identifier
		tosend[324] = 0x04; // length
		memcpy(tosend + 325, buffer + 26, 4); // dhcp server identifier value

		tosend[329] = 0x0c; // Host Name
		tosend[330] = 0x06; // Length
		tosend[331] = 'b';
		tosend[332] = 'm';
		b_to_hex(tstring, src_MAC[4]);
		tosend[333] = tstring[0];
		tosend[334] = tstring[1];
		b_to_hex(tstring, src_MAC[5]);
		tosend[335] = tstring[0];
		tosend[336] = tstring[1];
		tosend[337] = 0xFF; // End

		// Send the reply
		b_net_tx(tosend, 338, INTERFACE);
	}

	// Wait for a DHCP ACK Packet
	dhcp = 0;
	while (dhcp == 0)
	{
		recv_packet_len = b_net_rx((void**)&buffer, INTERFACE);
		eth_header* rx = (eth_header*)buffer;

		// If there was no data then halt until an interrupt occurs
		if (recv_packet_len == 0)
		{
			halt();
			continue;
		}

		if (swap16(rx->type) == ETHERTYPE_IPV4)
		{
			udp_packet* rx_udp = (udp_packet*)buffer;
			if (swap16(rx_udp->dest_port) == 68)
			{
				unsigned int index = 282;
				u8 tval = 0, tlen = 0;

				// Parse options
				while (1)
				{
					tval = buffer[index];
					if (tval == 0xFF)
						break;
					tlen = buffer[index+1];
					if (tval == 0x35) // DHCP Message
					{
						tval = buffer[index+2];
						if (tval == 0x05) // ACK
						{
							dhcp = 1;
							b_output(" - ACK'd\n", 9);
						}
					}
					index = index + tlen + 2;
				}
			}
		}
	}
	#endif

	return 0;
}


void* memset(void* s, int c, int n)
{
	char* _src;

	_src = (char*)s;

	while (n--)
	{
		*_src++ = c;
	}

	return s;
}


void* memcpy(void* d, const void* s, int n)
{
	char* dest;
	char* src;

	dest = (char*)d;
	src = (char*)s;

	while (n--)
	{
		*dest++ = *src++;
	}

	return d;
}


int strlen(const char* s)
{
	int r = 0;

	for(; *s++ != 0; r++) { }

	return r;
}


int strcat(char* dest, const char* src)
{
	int len = strlen(dest);
	int i;

	for (i = 0; src[i] != 0; i++)
	{
		dest[len + i] = src[i];
	}

	dest[len + i] = 0;

	return len + i;
}

// Convert a byte value to a string
char* b_to_s(char* buffer, unsigned char byte)
{
	int i = 0;
	int temp = byte;
	char digits[4];
	int digit_count = 0;

	// Check if the byte was 0 and set the string if so
	if (byte == 0)
	{
		buffer[0] = '0';
		buffer[1] = '\0';
		return buffer;
	}

	// Extract the individual digits
	while (temp > 0)
	{
		digits[digit_count] = (temp % 10) + '0';
		temp /= 10;
		digit_count++;
	}

	// Put digits in the correct order
	for (i=0; i < digit_count; i++)
	{
		buffer[i] = digits[digit_count - 1 - i];
	}

	// Null terminate the string
	buffer[digit_count] = '\0';

	return buffer;
}


// Convert a byte value to a two-character uppercase hex string
char* b_to_hex(char* buffer, unsigned char byte)
{
	const char hex[] = "0123456789ABCDEF";
	buffer[0] = hex[(byte >> 4) & 0xF];
	buffer[1] = hex[byte & 0xF];
	buffer[2] = '\0';
	return buffer;
}


void display_ip(u8* ip)
{
	char tstring[] = "xxx";
	b_to_s(tstring, ip[0]);
	b_output(tstring, (unsigned long)strlen(tstring));
	b_output(".", 1);
	b_to_s(tstring, ip[1]);
	b_output(tstring, (unsigned long)strlen(tstring));
	b_output(".", 1);
	b_to_s(tstring, ip[2]);
	b_output(tstring, (unsigned long)strlen(tstring));
	b_output(".", 1);
	b_to_s(tstring, ip[3]);
	b_output(tstring, (unsigned long)strlen(tstring));
}

void halt()
{
	asm volatile ("hlt" : : );
}

void helper_ethernet(eth_header* tx, eth_header* rx, u16 ethertype) {
	memcpy(tx->dest_mac, rx->src_mac, 6);
	memcpy(tx->src_mac, src_MAC, 6);
	tx->type = swap16(ethertype);
}

void helper_ipv4(ipv4_packet* tx, ipv4_packet* rx)
{
	tx->version = rx->version;
	tx->dsf = rx->dsf;
	tx->total_length = rx->total_length;
	tx->id = rx->id;
	tx->flags = rx->flags;
	tx->ttl = rx->ttl;
	tx->protocol = rx->protocol;
	tx->checksum = 0;
	memcpy(tx->src_ip, rx->dest_ip, 4);
	memcpy(tx->dest_ip, rx->src_ip, 4);
}

/* EOF */
