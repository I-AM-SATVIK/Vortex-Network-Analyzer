#include <iostream>
#include <pcap.h>
using namespace std;
void packethandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    cout<<"Packet Captured ! Length : "<<header->len<<" bytes."<<"\n";
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
    adhandle = pcap_open_live(device->name, 65536,1, 1000,error);
    if(adhandle == NULL){
        cerr<<"Unable to open adapter : "<<error<<"\n";
        pcap_freealldevs(alldevs);
        return 1;
    }
    pcap_freealldevs(alldevs);
    cout<<"Listening for Packets..."<<"\n";
    pcap_loop(adhandle, 10, packethandler, NULL);
    cout<<"Capture Complete"<<"\n";
    pcap_close(adhandle);
    return 0;
}