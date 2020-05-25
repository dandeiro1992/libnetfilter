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
#include <thread>
#include <random>
#define BUFFER_SIZE 1600
#define FRAME_BYTE 33
#define NUMBER_OF_OLD_FRAMES 1000
#define FRAME_TO_DELETE 100
#define PERCENTAGE 2
class Tmp{
public:
    unsigned char data[BUFFER_SIZE];

    Tmp(unsigned char other[])
    {
        for (int i=0;i<BUFFER_SIZE;i++)
            this->data[i]=other[i];
    }
    void print()
    {
        for (int i=0;i<6;i++)
            std::cout<<(data[i]);
    }
    ~Tmp()=default;
};

int create_socket(char * interface)
{
    int sock_raw=socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    struct sockaddr_ll saddr;
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

void deal_with_old_frames(std::map<std::string, std::vector<Tmp> > packets_map,std::map<std::string, int> sockets,int random_number)
{
    for(auto it=packets_map.begin();it!=packets_map.end();it++)
    {
        if (it->second.size()>random_number)
        {
            for (auto iterator=it->second.begin();iterator!=it->second.end();iterator++)
            {
                write(sockets.find(it->first)->second,iterator->data,BUFFER_SIZE);
            }
            it->second.clear();
        }
    }
}

void thread_function(std::string interface,std::map<std::string, int> sockets,std::map<int,std::string> addresses)
{
    std::uniform_int_distribution<int> d(0, NUMBER_OF_OLD_FRAMES);
    std::uniform_int_distribution<int> d1(0, FRAME_TO_DELETE);
    std::random_device rd1;
    int input_socket=sockets.find(interface)->second;
    int saddr_size , data_size, bytes_sent;
    struct sockaddr_ll saddr;
    unsigned char buffer[1600];//=(unsigned char *)malloc(BUFFER_SIZE);
    saddr_size = sizeof (struct sockaddr);
    std::map<std::string, std::vector<Tmp> > packets_map;
    for (auto it=sockets.begin();it!=sockets.end();it++)
    {
        packets_map.insert(std::make_pair(it->first,std::vector<Tmp>()));
    }
    while (true)
    {
        data_size = recvfrom(input_socket , &buffer , BUFFER_SIZE , 0 ,(struct sockaddr *) &saddr , (socklen_t*)&saddr_size);
        if(d1(rd1)>PERCENTAGE)
        {
            if(addresses.count(buffer[FRAME_BYTE])>0)
            {
                bytes_sent=write(sockets.find(addresses.find(buffer[FRAME_BYTE])->second)->second,&buffer,data_size);
                packets_map[(addresses.find(buffer[FRAME_BYTE])->second)].push_back(Tmp(buffer));
                deal_with_old_frames(packets_map,sockets,NUMBER_OF_OLD_FRAMES);
            }

        }
    }
}

int main()
{
    std::map<std::string,int> sockets;
    sockets["enp2s0f0"]=create_socket("enp2s0f0");
    sockets["enp2s0f1"]=create_socket("enp2s0f1");
    sockets["enp2s0f2"]=create_socket("enp2s0f2");

    std::map<int,std::string> addresses;
    addresses[182]="enp2s0f0";
    addresses[183]="enp2s0f1";
    addresses[184]="enp2s0f2";

    std::thread first_thread(thread_function,"enp2s0f0",sockets,addresses);
    std::thread second_thread(thread_function,"enp2s0f1",sockets,addresses);
    std::thread third_thread(thread_function,"enp2s0f2",sockets,addresses);

    first_thread.join();
    second_thread.join();
    third_thread.join();


    return 0;
}
