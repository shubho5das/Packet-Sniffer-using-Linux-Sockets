/*
    Packet Sniffer using Linux Sockets      
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>   // provides declaration for icmp headers
#include <netinet/udp.h>       // provides declaration for udp headers
#include <netinet/tcp.h>       // provides declaration for tcp headers
#include <netinet/ip.h>        // provides declaration for ip headers
#include <sys/socket.h>
#include <arpa/inet.h>
#include<unistd.h>

/* ------------ Globals ------------*/
int sock_raw;
int cnt_tcp=0, cnt_udp=0, cnt_icmp=0, cnt_igmp=0, cnt_other=0, total=0;

FILE *logfile;

/* ------------ Utility Functions ------------*/

// Function Declarations
void process_packet(unsigned char*, int);
void print_ip_header(unsigned char*, int);
void print_tcp_packet(unsigned char*, int);
void print_udp_packet(unsigned char*, int);

// Function Definitions
void process_packet(unsigned char* buffer, int size){
    /*
     Note: 
      - The parameters - buffer and size are obtained from recvfrom() 
      - buffer contains the msg-data; size contains the msg-size
    */ 

    // Obtaining the IP-Header of the packet
    struct iphdr *ip_header = (struct iphdr*)buffer;


    // Checking the L4-Protocol from the IP-Header, and accordingly display corresponding info
    switch(ip_header->protocol){
        case 1: 
            // ICMP Protocol
            cnt_icmp++;
            break;

        case 2:
            // IGMP Protocol
            cnt_igmp++;
            break;

        case 6:
            // TCP Protocol
            cnt_tcp++;
            print_tcp_packet(buffer, size);
            break;

        case 17:
            // UDP Protocol
            cnt_udp++;
            print_udp_packet(buffer, size);
            break;
        
        default:
            // Some other protocol 
            cnt_other++;
            break;
    }

    total++;

    printf(
        "TCP: %d    UDP: %d    ICMP: %d    IGMP: %d    Other: %d    Total: %d\r",  
        cnt_tcp, cnt_udp, cnt_icmp, cnt_igmp, cnt_other, total);
    
        /*  
            [Note] \r (carriage return):
            Moves the active position to the initial position of the current line */
}

void print_ip_header(unsigned char* buffer, int size){

    struct iphdr *ip_header = (struct iphdr *)buffer;
    unsigned short ip_header_length = (ip_header->ihl * 4);       // scale-of-4

    struct sockaddr_in source_addr;
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin_addr.s_addr = ip_header->saddr;

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)ip_header->version);
    fprintf(logfile,"   |-IP Header Length  : %d Bytes\n", ((unsigned int)(ip_header->ihl))*4);
    fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)ip_header->tos);
    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(ip_header->tot_len));
    fprintf(logfile,"   |-Identification    : %d\n",ntohs(ip_header->id));
    fprintf(logfile,"   |-TTL               : %d\n",(unsigned int)ip_header->ttl);
    fprintf(logfile,"   |-Protocol          : %d\n",(unsigned int)ip_header->protocol);
    fprintf(logfile,"   |-Checksum          : %d\n",ntohs(ip_header->check));
    // fprintf(logfile,"   |-Raw Source IP     : %d\n",source_addr.sin_addr.s_addr);
    fprintf(logfile,"   |-Source IP         : %s\n",inet_ntoa(source_addr.sin_addr));
    fprintf(logfile,"   |-Destination IP    : %s\n",inet_ntoa(dest_addr.sin_addr));    

}

void print_tcp_packet(unsigned char*buffer, int size){
    struct iphdr *ip_header = (struct iphdr *)buffer;
    unsigned short ip_header_length = (ip_header->ihl * 4); 

    struct tcphdr *tcp_header = (struct tcphdr*)(buffer + ip_header_length);


    fprintf(logfile,"\n\n***********************TCP Packet*************************\n");   

    // Printing the L3 Header (IP)
    print_ip_header(buffer, size);

    // Printing the L4 Header (TCP)
    fprintf(logfile, "\n");
    fprintf(logfile, "TCP Header\n");
    fprintf(logfile, "   |-Source Port           : %u\n",ntohs(tcp_header->source));
    fprintf(logfile, "   |-Destination Port      : %u\n",ntohs(tcp_header->dest));

    fprintf(logfile, "   |-Sequence Number       : %u\n",ntohl(tcp_header->seq));
    fprintf(logfile, "   |-Acknowledge Number    : %u\n",ntohl(tcp_header->ack_seq));

    fprintf(logfile, "   |-Header Length         : %d BYTES\n" ,(unsigned int)tcp_header->doff*4);
    fprintf(logfile, "   |-Urgent Flag           : %d\n",(unsigned int)tcp_header->urg);
    fprintf(logfile, "   |-Acknowledgement Flag  : %d\n",(unsigned int)tcp_header->ack);
    fprintf(logfile, "   |-Push Flag             : %d\n",(unsigned int)tcp_header->psh);
    fprintf(logfile, "   |-Reset Flag            : %d\n",(unsigned int)tcp_header->rst);
    fprintf(logfile, "   |-Synchronise Flag      : %d\n",(unsigned int)tcp_header->syn);
    fprintf(logfile, "   |-Finish Flag           : %d\n",(unsigned int)tcp_header->fin);
    fprintf(logfile, "   |-Window                : %d\n",ntohs(tcp_header->window));
    fprintf(logfile, "   |-Checksum              : %d\n",ntohs(tcp_header->check));
    fprintf(logfile, "   |-Urgent Pointer        : %d\n",tcp_header->urg_ptr);
    fprintf(logfile,"\n");

}

void print_udp_packet(unsigned char*buffer, int size){
    struct iphdr *ip_header = (struct iphdr *)buffer;
    unsigned short ip_header_length = (ip_header->ihl * 4); 

    struct udphdr *udp_header = (struct udphdr*)(buffer + ip_header_length);


    fprintf(logfile,"\n\n***********************UDP Packet*************************\n");

    // Printing the L3 Header (IP)
    print_ip_header(buffer, size);

    // Printing the L4 Header (UDP)
    fprintf(logfile, "\n");
    fprintf(logfile, "UDP Header\n");   
    fprintf(logfile, "   |-Source Port      : %d\n" , ntohs(udp_header->source));
    fprintf(logfile, "   |-Destination Port : %d\n" , ntohs(udp_header->dest));
    fprintf(logfile, "   |-UDP Length       : %d\n" , ntohs(udp_header->len));
    fprintf(logfile, "   |-UDP Checksum     : %d\n" , ntohs(udp_header->check));    
    fprintf(logfile, "\n");

}

/* ------------ Main  ------------*/

int main(){
    int addr_size, data_size;
    struct sockaddr addr;

    unsigned char buffer[1024];

    logfile = fopen("log.txt", "w");
    if(logfile == NULL){
        printf("Unable to create file...");
    }

    printf("Starting...\n");

    // Step 1: Creating the Raw Socket 
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0){
        perror("Socket error\n");
        exit(1);
    }

    // Step 2
    while(1){
        // 2.1 Receiving a packet
        addr_size = sizeof(addr);
        data_size = recvfrom(sock_raw, buffer, 1024, 0, &addr, (socklen_t*)&addr_size);
        if(data_size < 0){
            printf("Recvfrom() error - failed to receive packets\n");
            exit(1);
        }

        // 2.2 Processing the received packet
        process_packet(buffer, data_size);
    }

    close(sock_raw);
    printf("Finised");

    return 0;
}
