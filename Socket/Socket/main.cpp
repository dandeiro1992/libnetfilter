#include <memory>
#include <functional>
#include <array>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <iostream>
#include <net/if.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <vector>
#include <iterator>
#include <map>
#define BUFFER_SIZE 1600
int create_socket(int number_of_socket, char * interface)
{
    int sock_raw=socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    struct sockaddr_ll saddr, daddr;
    memset(&saddr, 0, sizeof(struct sockaddr_ll));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = if_nametoindex(interface);

    if (bind(sock_raw, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
        perror("bind failed\n");
        close(sock_raw);
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);
    if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("bind to problem ");
        }
    return sock_raw;
}
void thread_function(std::string interface,std::map<std::string, int> sockets,std::map<int,std::string> addresses)
{
    int input_socket=sockets.find(interface)->second;
    int saddr_size , data_size, daddr_size, bytes_sent;
    struct sockaddr_ll saddr;
    unsigned char *buffer=(unsigned char *)malloc(BUFFER_SIZE);
    saddr_size = sizeof (struct sockaddr);
    daddr_size = sizeof (struct sockaddr);

    std::map<std::string, std::vector<unsigned char *> > packets_map;
    for (auto it=sockets.begin();it!=sockets.end();it++)
    {
        packets_map.insert(std::make_pair(it->first,std::vector<unsigned char *>()));
    }
    while (true)
    {
        data_size = recvfrom(input_socket , buffer , BUFFER_SIZE , 0 ,(struct sockaddr *) &saddr , (socklen_t*)&saddr_size);
        if(addresses.count(buffer[30])>0)
        {
            bytes_sent=write(sockets.find(addresses.find(buffer[30])->second)->second,buffer,data_size);
            packets_map[(addresses.find(buffer[30])->second)].emplace_back(buffer);
        }

    }
}
void deal_with_old_frames(std::map<std::string, std::vector<unsigned char *> > packets_map,std::map<std::string, int> sockets,std::map<int,std::string> addresses)
{
    for(auto it=packets_map.begin();it!=packets_map.end;it++)
    {
        if (it->second.size()>30)
        {
            it->first
        }
    }
}
int main()
{
    std::map<std::string,int> sockets;
    sockets["enp1s0f0"]=create_socket(1,"enp1s0f0");
    sockets["enp1s0f1"]=create_socket(1,"enp1s0f1");
    sockets["enp1s0f2"]=create_socket(1,"enp1s0f2");

    std::map<int,std::string> addresses;
    addresses[182]="enp1s0f0";
    addresses[183]="enp1s0f1";
    addresses[184]="enp1s0f2";


    return 0;
}
