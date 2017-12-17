#include <stdio.h>                //For Standard I/O 
#include <stdlib.h>               //Standard Libraries like exit etc..
#include <sys/socket.h>		  //For Socket APIs
#include <errno.h>		  //For errno
#include <net/if.h>		  //For Promiscous mode i.e, monitoring mode
#include <sys/ioctl.h>		  //For IOCTLs
#include <linux/if_ether.h>       //For ETH_P_ALL and for other
#include <string.h>		  //For string functions like strncpy etc.
#include <unistd.h>  		  //For close() 
#include <netinet/ip.h>		  //For IP Header
#include <arpa/inet.h>		  //For inet_ntoa and some others functions...
#include <netinet/ip_icmp.h>	  //For ICMP Header
#include <netinet/tcp.h>	  //For TCP Header
#include <netinet/udp.h>	  //For UDP Header
#include <signal.h>


//global variables to track number of TCP/UDP/ICMP/IGMP/Others
int tcp=0,icmp=0,igmp,udp=0,others=0,total=0;
struct sockaddr_in source,dest;
FILE *logsniff; //redirecting output to a file to parse any packet or ip info using grep 
//Pass RAW BUFFER into Ethhdr structure and print Ethernet header information.


void  INThandler(int sig)
{
	char  c;

	signal(sig, SIG_IGN);
	printf("OUCH, did you hit Ctrl-C?\n"
		"Do you really want to quit? [y/n] ");
	c = getchar();
	if (c == 'y' || c == 'Y')
	{
	
		printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);
		exit(0);
	}
	else
          signal(SIGINT, INThandler);
	getchar(); // Get new line character
}


void ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	fprintf(logsniff , "\n");
	fprintf(logsniff , "Ethernet Header\n");
	fprintf(logsniff , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logsniff , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logsniff , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}


//Pass RAW BUFFER into iphdr structure and then print IP Header details.
void ip_header(unsigned char* Buffer, int Size)
{
	ethernet_header(Buffer , Size);

	unsigned short iphdrlen;
	 
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logsniff , "\n");
	fprintf(logsniff , "IP Header\n");
	fprintf(logsniff , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logsniff , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logsniff , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logsniff , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logsniff , "   |-Identification    : %d\n",ntohs(iph->id));
	fprintf(logsniff , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logsniff , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logsniff , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logsniff , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logsniff , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
	}


//Pass RAW BUFFER into icmphdr structure and then print ICMP Header details.
void icmp_packet(unsigned char* Buffer , int Size)
{
	

	fprintf(logsniff,"\n***********************ICMP PACKET***********************\n");
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	ip_header(Buffer,Size);	     
	fprintf(logsniff , "\n");
	 
	fprintf(logsniff , "ICMP Header\n");
	fprintf(logsniff , "   |-Type : %d",(unsigned int)(icmph->type));
	     
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logsniff , "  (TTL Expired)\n");
	}	
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logsniff , "  (ICMP Echo Reply)\n");
	}
     
	fprintf(logsniff , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logsniff , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    
}


//Pass same sniffed RAW BUFFER into tcphdr structure and print TCP Header/Packet details.
void tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	     
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	fprintf(logsniff , "\n\n***********************TCP Packet*************************\n");  
	 
	ip_header(Buffer,Size);
	 
	fprintf(logsniff , "\n");
	fprintf(logsniff , "TCP Header\n");
	fprintf(logsniff , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logsniff , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logsniff , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logsniff , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logsniff , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(logsniff , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logsniff , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(logsniff , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logsniff , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logsniff , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logsniff , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logsniff , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logsniff , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logsniff , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logsniff , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logsniff , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logsniff , "\n");

}


//Pass same sniffed RAW BUFFER into udphdr structure and print UDP Packet/Header details.
void udp_packet(unsigned char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logsniff , "\n\n***********************UDP Packet*************************\n");
	
	ip_header(Buffer,Size);			
	
	fprintf(logsniff , "\nUDP Header\n");
	fprintf(logsniff , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logsniff , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logsniff , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logsniff , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
}

//process packet according to protocol number and also counts number of TCP/ICMP/UDP/IGMP/Others(ARP etc.) Packets
void packetCounter(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	int proto = iph->protocol;
	if (proto == 1)
	{
		++icmp;
		icmp_packet(buffer,size);
	}
	else if (proto == 2)
	{
		++igmp;
	}
	else if(proto == 6)
	{
		++tcp;
		tcp_packet(buffer,size);
	}
	else if(proto == 17)
	{
		++udp;
		udp_packet(buffer,size);
	}
	else
	{
		++others; //like ARP etc..
	}

	
	//printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);
}



int main(int argc, char **argv)
{

	printf("Writing packets info in sniff_logger.txt\n");	
	signal(SIGINT, INThandler);
	struct sockaddr saddr;
	int sock, saddr_size,n;
	unsigned char *buff = (unsigned char *) malloc(65536);
	//unsigned char *iphead, *ethhead;
	struct ifreq ethreq;
	int count = 1;
	logsniff=fopen("sniff_logger.txt","w");
	if(logsniff==NULL) 
	{
		 printf("Unable to create sniff_logger.txt file.");
	}

	if ( (sock=socket(AF_PACKET, SOCK_RAW,htons(ETH_P_ALL)))<0) 
	{
		perror("socket");
		exit(1);
	}

	/* Set the network card in promiscuos mode */
	strncpy(ethreq.ifr_name,argv[1],IFNAMSIZ);
	if (ioctl(sock,SIOCGIFFLAGS,&ethreq)==-1) 
	{
		perror("ioctl");
		close(sock);
		exit(1);
	}
	ethreq.ifr_flags|=IFF_PROMISC;
	if (ioctl(sock,SIOCSIFFLAGS,&ethreq)==-1) 
	{
		perror("ioctl");
		close(sock);
		exit(1);
	}

	while (count) 
	{
		n = recvfrom(sock,buff,65536,0,NULL,NULL); //UDP based , but I think there will be loss of  some packets , but faster then TCP .
		if(n <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		packetCounter(buff,n);
	}
	
	ethreq.ifr_flags ^= IFF_PROMISC; // mask it off (remove)
	ioctl(sock, SIOCSIFFLAGS, &ethreq); // update
	close(sock);
	return 0;
	

}
