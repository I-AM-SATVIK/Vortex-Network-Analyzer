
#include <iostream>
#include <pcap.h>

using namespace std;
struct ethernet_header{
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short ethertype; //will store protocol type
};

struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

struct ip_header{
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    struct ip_address saddr;
    struct ip_address daddr;
};

void packethandler(u_char *paramater, const struct pcap_pkthdr *header, const u_char *pkt_data){
    const ethernet_header *eh = (ethernet_header*)pkt_data;
    if(ntohs(eh->ethertype)==0x0800){
        int ethernet_header_length = 14;
        const ip_header *ih = (ip_header*)(pkt_data + ethernet_header_length);
        cout << "IPv4 Packet | Length: " << header->len << " bytes | ";
        cout << "Source IP: " << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4 << " -> ";
        cout << "Dest IP: " << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 << "\n"; 
    }else{
        cout<<"Non-IPv4 Packet Filtered (EtherType: 0x"<<hex<<ntohs(eh->ethertype)<<dec<<")\n";
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