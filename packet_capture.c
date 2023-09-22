#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<linux/if_ether.h>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>

#define IPSTR "%d.%d.%d.%d"
#define IP2STR(ip) ((ip>>24)&0xFF), ((ip>>16)&0xFF), \
                   ((ip>>8)&0xFF), (ip&0xFF)


void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main()
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle;
	char errbuf[100] , *devname , devs[10][16];
	int count = 1 , n;
	
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s - %d \n" , count , device->name , device->description, device->flags);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);  //get interface name 
		}
		count++;
	}

	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : \n");
	scanf("%d", &n);
    devname = devs[n];
    printf("start sniff packets on devsname: %s\n", devname);
    //Open the device for sniffing
	handle = pcap_open_live(devname, 256, 1, 0, errbuf);
    if (handle == NULL) {
        printf("Error open devices : %s" , errbuf);
        exit(1);
    }
    //Create filter expression
	struct bpf_program fcode;
    const char *filter = "icmp";
    //Compile filter expression
    pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN);
    //Set filter
    pcap_setfilter(handle, &fcode);
    //Start packet sniffer
	pcap_loop(handle, -1, process_packet, NULL);
	return 0;	
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
    //print byte value
	printf("\nICMP\n");
	struct ether_header *eth = NULL;
	struct iphdr *iph = NULL;
	eth = (struct ether_header *)buffer;
	iph = (struct iphdr *)(eth+1);
	printf("Src Ipv4: "IPSTR", Dst Ipv4: " IPSTR "\n", 
          IP2STR(ntohl(iph->saddr)), IP2STR(ntohl(iph->daddr)));
	printf("\nPacket End\n");
}