#include <iostream>
#include <pcap.h>

using namespace std;

struct ethernet_header {
    u_char  dest_mac[6];
    u_char  src_mac[6];
    u_short ethertype;
};

struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

struct ip_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    struct  ip_address saddr;
    struct  ip_address daddr;
};

struct tcp_header {
    u_short sport;
    u_short dport;
};

struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
};

void packethandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    
    // Retrieve the datalink type passed from main()
    int link_type = *(int*)param;
    int link_offset = 0;
    bool is_ipv4 = false;

    // Standard Ethernet / Wi-Fi (14-byte header)
    if (link_type == DLT_EN10MB) { 
        const ethernet_header *eh = (ethernet_header *)pkt_data;
        if (ntohs(eh->ethertype) == 0x0800) {
            link_offset = 14;
            is_ipv4 = true;
        }
    } 
    // Local Loopback Adapter (4-byte header)
    else if (link_type == DLT_NULL) { 
        // A loopback header is 4 bytes. The value '2' represents AF_INET (IPv4).
        if (pkt_data[0] == 2 || pkt_data[3] == 2) {
            link_offset = 4;
            is_ipv4 = true;
        }
    }

    // Process if it is an IPv4 packet, dynamically skipping the link offset
    if (is_ipv4) {
        const ip_header *ih = (ip_header *)(pkt_data + link_offset);
        int ip_header_length = (ih->ver_ihl & 0x0F) * 4;

        cout << "IPv4 | " << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4 << " -> ";
        cout << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 << " | ";

        if (ih->proto == 6) { 
            const tcp_header *th = (tcp_header *)(pkt_data + link_offset + ip_header_length);
            cout << "TCP Ports: " << ntohs(th->sport) << " -> " << ntohs(th->dport) << "\n";
        } else if (ih->proto == 17) { 
            const udp_header *uh = (udp_header *)(pkt_data + link_offset + ip_header_length);
            cout << "UDP Ports: " << ntohs(uh->sport) << " -> " << ntohs(uh->dport) << "\n";
        } else {
            cout << "Other Protocol: " << (int)ih->proto << "\n";
        }
    }
}

int main(){
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;
    int i=0, inum;
    
    if(pcap_findalldevs(&alldevs, error)==-1) return 1;
    for(device = alldevs; device!=NULL; device = device->next) { 
        cout<<++i<<") "<<device->name<<"::"<<device->description<<"\n"; 
    }
    
    cout<<"Enter the interface number (1-"<<i<<"): ";
    cin>>inum;
    
    device = alldevs;
    for(int j=0; j<inum-1; j++) device = device->next;
    
    pcap_t *adhandle = pcap_open_live(device->name, 65536, 0, 1000, error);
    if(adhandle == NULL) return 1;
    
    // Identify the hardware link type before capturing
    int link_type = pcap_datalink(adhandle);
    
    pcap_freealldevs(alldevs);
    cout<<"Listening for Packets...\n";
    
    // Pass the link_type integer to the callback function via the param argument
    pcap_loop(adhandle, -1, packethandler, (u_char*)&link_type);
    
    cout<<"Capture Complete\n";
    pcap_close(adhandle);
    return 0;
}