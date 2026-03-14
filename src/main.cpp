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

// Layer 4: TCP Header (Expanded to reach the Data Offset field)
struct tcp_header {
    u_short sport;          // 2 bytes
    u_short dport;          // 2 bytes
    u_int   seq;            // 4 bytes
    u_int   ack;            // 4 bytes
    u_char  data_offset;    // 1 byte (Top 4 bits contain the header length)
    u_char  flags;          // 1 byte
    u_short win;            // 2 bytes
    u_short crc;            // 2 bytes
    u_short urp;            // 2 bytes
};

// Layer 4: UDP Header (Fixed at 8 bytes)
struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
};

void packethandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    
    int link_type = *(int*)param;
    int link_offset = 0;
    bool is_ipv4 = false;

    if (link_type == DLT_EN10MB) { 
        const ethernet_header *eh = (ethernet_header *)pkt_data;
        if (ntohs(eh->ethertype) == 0x0800) { link_offset = 14; is_ipv4 = true; }
    } else if (link_type == DLT_NULL) { 
        if (pkt_data[0] == 2 || pkt_data[3] == 2) { link_offset = 4; is_ipv4 = true; }
    }

    if (is_ipv4) {
        const ip_header *ih = (ip_header *)(pkt_data + link_offset);
        int ip_header_length = (ih->ver_ihl & 0x0F) * 4;
        int transport_header_length = 0;
        
        cout << "\n-------------------------------------------------\n";
        cout << "IPv4 | " << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4 << " -> ";
        cout << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 << "\n";

        if (ih->proto == 6) { 
            const tcp_header *th = (tcp_header *)(pkt_data + link_offset + ip_header_length);
            transport_header_length = ((th->data_offset & 0xF0) >> 4) * 4;
            cout << "TCP  | Ports: " << ntohs(th->sport) << " -> " << ntohs(th->dport) << "\n";
        } else if (ih->proto == 17) { 
            const udp_header *uh = (udp_header *)(pkt_data + link_offset + ip_header_length);
            transport_header_length = 8; 
            cout << "UDP  | Ports: " << ntohs(uh->sport) << " -> " << ntohs(uh->dport) << "\n";
        } else {
            return; 
        }

        int total_headers_size = link_offset + ip_header_length + transport_header_length;
        int payload_size = header->len - total_headers_size;

        if (payload_size > 0) {
            cout << "DATA | Payload Size: " << payload_size << " bytes\n\n";
            const u_char *payload = pkt_data + total_headers_size;
            
            // Limit the dump to the first 64 bytes to prevent terminal flooding
            int dump_size = (payload_size < 64) ? payload_size : 64;

            // Generate the Hex Dump
            for (int i = 0; i < dump_size; i += 16) {
                
                // 1. Print the memory offset (e.g., 0000, 0010)
                printf("  %04X  ", i);

                // 2. Print the Hexadecimal view
                for (int j = 0; j < 16; j++) {
                    if (i + j < dump_size) {
                        printf("%02X ", payload[i + j]);
                    } else {
                        printf("   "); // Print blank spaces if the row is incomplete
                    }
                    if (j == 7) printf(" "); // Add a divider space in the middle of the hex grid
                }

                printf("  ");

                // 3. Print the ASCII view
                for (int j = 0; j < 16; j++) {
                    if (i + j < dump_size) {
                        u_char c = payload[i + j];
                        if (c >= 32 && c <= 126) {
                            printf("%c", c);
                        } else {
                            printf(".");
                        }
                    }
                }
                printf("\n");
            }
            cout << "\n";
        } else {
            cout << "DATA | No Payload (0 bytes)\n";
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