#include <iostream>
#include <pcap.h>
#include <winsock2.h>
#include <sstream>
#include <iomanip>

using namespace std;

struct ethernet_header {
    u_char  dest_mac[6];
    u_char  src_mac[6];
    u_short ethertype;
};

struct ip_address {
    u_char byte1; u_char byte2; u_char byte3; u_char byte4;
};

struct ip_header {
    u_char  ver_ihl; u_char  tos; u_short tlen; u_short identification;
    u_short flags_fo; u_char  ttl; u_char  proto; u_short crc;
    struct  ip_address saddr; struct  ip_address daddr;
};

struct tcp_header {
    u_short sport; u_short dport; u_int seq; u_int ack;
    u_char data_offset; u_char flags; u_short win; u_short crc; u_short urp;
};

struct udp_header {
    u_short sport; u_short dport; u_short len; u_short crc;
};

// New struct to pass the socket and link type to the callback
struct engine_context {
    int link_type;
    SOCKET udp_socket;
    sockaddr_in dest_addr;
};

void packethandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    
    engine_context *ctx = (engine_context *)param;
    int link_offset = 0;
    bool is_ipv4 = false;

    if (ctx->link_type == DLT_EN10MB) { 
        const ethernet_header *eh = (ethernet_header *)pkt_data;
        if (ntohs(eh->ethertype) == 0x0800) { link_offset = 14; is_ipv4 = true; }
    } else if (ctx->link_type == DLT_NULL) { 
        if (pkt_data[0] == 2 || pkt_data[3] == 2) { link_offset = 4; is_ipv4 = true; }
    }

    if (is_ipv4) {
        const ip_header *ih = (ip_header *)(pkt_data + link_offset);
        int ip_header_length = (ih->ver_ihl & 0x0F) * 4;
        int transport_header_length = 0;
        string protocol_name = "OTHER";
        u_short src_port = 0, dest_port = 0;

        if (ih->proto == 6) { 
            const tcp_header *th = (tcp_header *)(pkt_data + link_offset + ip_header_length);
            transport_header_length = ((th->data_offset & 0xF0) >> 4) * 4;
            src_port = ntohs(th->sport); dest_port = ntohs(th->dport);
            protocol_name = "TCP";
        } else if (ih->proto == 17) { 
            const udp_header *uh = (udp_header *)(pkt_data + link_offset + ip_header_length);
            transport_header_length = 8; 
            src_port = ntohs(uh->sport); dest_port = ntohs(uh->dport);
            protocol_name = "UDP";
        } else {
            return; 
        }

        int total_headers_size = link_offset + ip_header_length + transport_header_length;
        int payload_size = header->len - total_headers_size;
        
        // Data Serialization: Build the pipe-delimited string
        stringstream ss;
        ss << protocol_name << "|"
           << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4 << "|"
           << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 << "|"
           << src_port << "|" << dest_port << "|" << payload_size << "|";

        if (payload_size > 0) {
            const u_char *payload = pkt_data + total_headers_size;
            int dump_size = (payload_size < 64) ? payload_size : 64;
            // Append hex payload without spaces for dense transmission
            for (int i = 0; i < dump_size; i++) {
                ss << hex << uppercase << setw(2) << setfill('0') << (int)payload[i];
            }
        } else {
            ss << "NONE";
        }

        string packet_data = ss.str();

        // Transmit the serialized string over the local UDP socket
        sendto(ctx->udp_socket, packet_data.c_str(), packet_data.length(), 0, 
              (struct sockaddr *)&ctx->dest_addr, sizeof(ctx->dest_addr));
    }
}

int main(){
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    int i=0, inum;
    
    // 1. Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed.\n"; return 1;
    }

    if(pcap_findalldevs(&alldevs, error)==-1) return 1;
    for(device = alldevs; device!=NULL; device = device->next) { 
        cout<<++i<<") "<<device->name<<"::"<<device->description<<"\n"; 
    }
    
    cout<<"Enter interface number (1-"<<i<<"): "; cin>>inum;
    device = alldevs; for(int j=0; j<inum-1; j++) device = device->next;
    
    pcap_t *adhandle = pcap_open_live(device->name, 65536, 0, 1000, error);
    if(adhandle == NULL) return 1;
    
    // 2. Setup the UDP Socket Context for IPC
    engine_context ctx;
    ctx.link_type = pcap_datalink(adhandle);
    ctx.udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    ctx.dest_addr.sin_family = AF_INET;
    ctx.dest_addr.sin_port = htons(5555); // Target port for the Python GUI
    ctx.dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Localhost

    pcap_freealldevs(alldevs);
    cout<<"Engine running. Transmitting data to 127.0.0.1:5555...\n";
    
    pcap_loop(adhandle, -1, packethandler, (u_char*)&ctx);
    
    closesocket(ctx.udp_socket);
    WSACleanup();
    pcap_close(adhandle);
    return 0;
}