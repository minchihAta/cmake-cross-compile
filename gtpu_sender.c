/*
	Raw UDP sockets
*/
#include<stdio.h>	//for printf
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <netinet/ip_icmp.h>

/* 
	96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

struct gtpuhdr
{
    uint8_t flags;
    uint8_t ms_type;
    uint16_t length;
    uint32_t teid;
};

/*
	Generic checksum calculation function
*/
unsigned short checksum(unsigned short *buf, int bufsz){
    unsigned long sum = 0xffff;

    while(bufsz > 1){
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if(bufsz == 1)
        sum += *(unsigned char*)buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int main (void)
{
	//Create a raw socket of type IPPROTO
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
		exit(1);
	}
	
	//Datagram to represent the packet
	char datagram[4096] , source_ip[32] , *data , *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, 4096);

    // Outer IP header
    struct iphdr *outer_iph = (struct iphdr *) datagram;
    // Outer UDP header
    struct udphdr *outer_udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
    // Gtpu header
    struct gtpuhdr *gtpuh = (struct gtpuhdr *) (datagram + sizeof (struct iphdr) + sizeof (struct udphdr));
	
	//IP header
	struct iphdr *iph = (struct iphdr *) (datagram + 
                                          sizeof (struct iphdr) + 
                                          sizeof (struct udphdr) + 
                                          sizeof (struct gtpuhdr));
	
	//ICMP header
	struct icmphdr *icmph = (struct icmphdr *) (datagram + 
                                sizeof (struct iphdr) + 
                                sizeof (struct udphdr) + 
                                sizeof (struct gtpuhdr) +
                                sizeof (struct iphdr));
	
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	//Inner Data part
	data = datagram + 
            sizeof (struct iphdr) + 
            sizeof (struct udphdr) + 
            sizeof (struct gtpuhdr) +
            sizeof (struct iphdr) + sizeof(struct icmphdr);
	strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	
	//some address resolution
	strcpy(source_ip , "60.60.60.2");
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr ("60.60.60.1");
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data));
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_ICMP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
	
	//Ip checksum
	// iph->check = csum ((unsigned short *) datagram, iph->tot_len);
    printf("1\n");
    iph->check = 0;
	
	//icmp header
	icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->checksum = 0x060b;
    icmph->un.echo.id = 0;
    icmph->un.echo.sequence = 0;

    //Outer IP header
	outer_iph->ihl = 5;
	outer_iph->version = 4;
	outer_iph->tos = 0;
	outer_iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct gtpuhdr) +
        sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
	outer_iph->id = htonl (54321);	//Id of this packet
	outer_iph->frag_off = 0;
	outer_iph->ttl = 255;
	outer_iph->protocol = IPPROTO_UDP;
	outer_iph->check = 0;		//Set to 0 before calculating checksum
	outer_iph->saddr = inet_addr ("10.10.10.1");	//Spoof the source ip address
	outer_iph->daddr = inet_addr ("10.10.10.10");
    //Outer UDP header
	outer_udph->source = htons (2152);
	outer_udph->dest = htons (2152);
	outer_udph->len = htons(8+8+20+ sizeof(struct icmphdr) + strlen(data));	//tcp header size
	outer_udph->check = 0;	//leave checksum 0 now, filled later by pseudo header

    gtpuh->flags = 0x30;
    gtpuh->ms_type = 0xff;
    gtpuh->length = htons(sizeof (struct gtpuhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(data));
    gtpuh->teid = 0x01020304;
	
	//loop if you want to flood :)
	//while (1)
	{
		//Send the packet
		if (sendto (s, datagram, outer_iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
		{
			perror("sendto failed");
		}
		//Data send successfully
		else
		{
			printf ("Packet Send. Length : %d \n" , (outer_iph->tot_len));
		}
	}
	
	return 0;
}

//Complete