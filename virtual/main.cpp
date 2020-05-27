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
#define NUMBER_OF_OLD_FRAMES 10
#define FRAME_TO_DELETE 100
#define PERCENTAGE 0
#define VIRTUAL_INTERFACE "ifb0"
using FRAME=std::array<unsigned char,BUFFER_SIZE>;
//class Tmp{
//public:


//    Tmp(unsigned char &other[BUFFER_SIZE]): data(other)
//    {
//        //for (int i=0;i<BUFFER_SIZE;i++)
//          //  this->data[i]=other[i];
//    }
//    void print()
//    {
//        for (int i=0;i<6;i++)
//            std::cout<<(data[i]);
//    }

//    unsigned char data[BUFFER_SIZE];
//};

int create_socket(const char* interface)
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

//void deal_with_old_frames(std::map<std::string, std::vector<FRAME>> &packets_map,std::map<std::string, int> &sockets,int random_number)
//{
//    for(auto it=packets_map.begin();it!=packets_map.end();it++)
//    {
//        if (it->second.size()>random_number)
//        {
//            for (auto iterator=it->second.begin();iterator!=it->second.end();iterator++)
//            {
//                write(sockets.find(it->first)->second,iterator->data(),BUFFER_SIZE);
//            }
//            it->second.clear();
//        }
//    }
//}

void thread_function( std::map<std::string, int> sockets, int main_socket, std::map<int,std::string> addresses)
{
    std::uniform_int_distribution<int> d(0, NUMBER_OF_OLD_FRAMES);
    std::uniform_int_distribution<int> d1(0, FRAME_TO_DELETE);
    std::random_device rd1;
    int saddr_size , data_size;
    struct sockaddr_ll saddr;
    FRAME buffer;//=(unsigned char *)malloc(BUFFER_SIZE);
    saddr_size = sizeof (struct sockaddr);
    std::map<std::string, std::vector< FRAME >> packets_map;
    for (auto it=sockets.begin();it!=sockets.end();it++)
    {
        packets_map.insert(std::make_pair(it->first,std::vector< FRAME >()));
    }
    while (true)
    {
        data_size = recvfrom(main_socket , &buffer , BUFFER_SIZE , 0 ,(struct sockaddr *) &saddr , (socklen_t*)&saddr_size);
        if(1)//d1(rd1)>PERCENTAGE)
        {
            if(addresses.count(buffer[FRAME_BYTE-4])>0)
            {
                // MAC
                buffer[0]=0xe0;
                buffer[1]=0x1a;
                buffer[2]=0xea;
                buffer[3]=0x37;
                buffer[4]=0x3b;
                buffer[5]=0x6c;
                buffer[6]=0xe0;
                buffer[7]=0x1a;
                buffer[8]=0xea;
                buffer[9]=0x37;
                buffer[10]=0x3b;
                buffer[0]=0x62;
                // IP
                buffer[29]=0x02;
                buffer[33]=0x01;

                write(sockets.find(addresses.find(buffer[FRAME_BYTE])->second)->second,&buffer,data_size);
                //write(sockets.find("enp1s0f1")->second,&buffer,data_size);
                //packets_map[(addresses.find(buffer[FRAME_BYTE])->second)].push_back(buffer);
                //deal_with_old_frames(packets_map,sockets,NUMBER_OF_OLD_FRAMES);
            }

        }
    }
}

int main()
{
    int main_socket=create_socket(VIRTUAL_INTERFACE);
    std::map<std::string,int> sockets;
    //sockets[VIRTUAL_INTERFACE]=create_socket(VIRTUAL_INTERFACE);
    sockets["enp1s0f1"]=create_socket("enp1s0f1");
    //sockets["enp2s0f2"]=create_socket("enp2s0f2");

    std::map<int,std::string> addresses;
    //addresses[182]="enp2s0f0";
    //addresses[183]="enp2s0f1";
    addresses[1]="enp1s0f1";

    std::thread first_thread(thread_function,sockets,main_socket,addresses);
    //std::thread second_thread(thread_function,"enp2s0f1",sockets,addresses);
    //std::thread third_thread(thread_function,"enp2s0f2",sockets,addresses);

    first_thread.join();
    //second_thread.join();
    //third_thread.join();


    return 0;
}
