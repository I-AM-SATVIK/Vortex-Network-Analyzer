#include <iostream>
#include <pcap.h>
// Note: pcap.h automatically includes winsock2.h on Windows, which provides the ntohs() function.

using namespace std;

// Define the 14-byte Ethernet header
struct ethernet_header {
    u_char  dest_mac[6];    // Destination MAC address
    u_char  src_mac[6];     // Source MAC address
    u_short ethertype;      // Protocol type (IPv4, ARP, IPv6, etc.)
};

// Define a 4-byte struct to hold an IP address
struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

// Define a struct that maps exactly to an IPv4 header (20 bytes total)
struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    struct  ip_address saddr; // Source IP address
    struct  ip_address daddr; // Destination IP address
};

// The callback function that runs every time a packet is captured
void packethandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    
    // 1. Map the ethernet_header struct to the very beginning of the raw byte stream
    const ethernet_header *eh = (ethernet_header *)pkt_data;

    // 2. Check the EtherType. 0x0800 indicates IPv4. 
    // We use ntohs() to convert from network byte order to host byte order.
    if (ntohs(eh->ethertype) == 0x0800) {
        
        // Skip the 14 bytes of the Ethernet header
        int ethernet_header_length = 14;

        // Map the ip_header struct to where the IP data begins
        const ip_header *ih = (ip_header *)(pkt_data + ethernet_header_length);

        // Print the parsed IPv4 data
        cout << "IPv4 Packet | Length: " << header->len << " bytes | ";
        cout << "Source IP: " << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4 << " -> ";
        cout << "Dest IP: " << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 << "\n";
    } else {
        // Print a log for non-IPv4 packets to prove the filter is working
        // We use hex formatting to output the exact EtherType code caught
        cout << "Non-IPv4 Packet Filtered (EtherType: 0x" << hex << ntohs(eh->ethertype) << dec << ")\n";
    }
}

int main(){
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;
    int i=0, inum;
    
    if(pcap_findalldevs(&alldevs, error)==-1){
        cerr<<"Error finding devices : "<<error<<"\n";
        return 1;
    }
    
    for(device = alldevs; device!=NULL; device = device->next){
        cout<<++i<<") "<<device->name;
        if(device->description) cout<<"("<<device->description<<")";
        cout<<"\n";
    }
    
    if(i==0){
        cout<<"No Interface Found"<<"\n";
        return 1;
    }
    
    cout<<"Enter the interface number (1-"<<i<<"): ";
    cin>>inum;
    
    if(inum<1 || inum>i){
        cout<<"Interface number out of range."<<"\n";
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    device = alldevs;
    for(int j=0; j<inum-1; j++){
        device = device->next;
    }
    
    cout<<"\nOpening "<<device->description<<"..."<<"\n";
    pcap_t *adhandle;
    
    // Set to 0 for Non-Promiscuous Mode to ensure stability on the physical interface
    adhandle = pcap_open_live(device->name, 65536, 0, 1000, error);
    
    if(adhandle == NULL){
        cerr<<"Unable to open adapter : "<<error<<"\n";
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    pcap_freealldevs(alldevs);
    
    cout<<"Listening for Packets..."<<"\n";
    
    // Capture 10 packets
    pcap_loop(adhandle, 10, packethandler, NULL);
    
    cout<<"Capture Complete"<<"\n";
    
    pcap_close(adhandle);
    return 0;
}