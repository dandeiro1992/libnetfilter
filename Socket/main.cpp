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
//extern "C"
//{
//#include <libnetfilter_queue/libnetfilter_queue.h>
//#include <libnetfilter_queue/pktbuff.h>
//#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
//#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
//#include <libnetfilter_queue/libnetfilter_queue_udp.h>
//}

//#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m); }} while(false)

//#define CONCAT_0(pre, post) pre ## post
//#define CONCAT_1(pre, post) CONCAT_0(pre, post)
//#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

//using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
//#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
//#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)




//static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
//{
//    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
//    THROW_IF_TRUE(ph == nullptr, "Issue while packet header");

//    unsigned char *rawData = nullptr;
//    int len = nfq_get_payload(nfad, &rawData);
//    THROW_IF_TRUE(len < 0, "Can\'t get payload data");

//    struct pkt_buff * pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);

//    THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate");
//    SCOPED_GUARD( pktb_free(pkBuff); ); // Don't forget to clean up

//    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
//    THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header parse.");

//    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");
//    if(ip->protocol == IPPROTO_TCP)
//    {
//        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
//        THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");

//        void *payload = nfq_tcp_get_payload(tcp, pkBuff);
//        unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
//        payloadLen -= 4 * tcp->th_off;
//        THROW_IF_TRUE(payload == nullptr, "Issue while payload.");

//        for (unsigned int i = 0; i < payloadLen / 2; ++i) {
//            char tmp = (static_cast<char *>(payload))[i];
//            (static_cast<char *>(payload))[i] = (static_cast<char *>(payload))[payloadLen - 1 - i];
//            (static_cast<char *>(payload))[payloadLen - 1 - i] = tmp;
//        }

//        nfq_tcp_compute_checksum_ipv4(tcp, ip);
//        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
//    }
//    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
//}


//int main()
//{
//    // socket //
//    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
//    if (sd < 0)
//    {
//      // Error
//    }
//    const char *opt;
//    opt = "enp1s0f1";
//    const int len = strnlen(opt, IFNAMSIZ);
//    if (len == IFNAMSIZ) {
//        fprintf(stderr, "Too long iface name");
//        return 1;
//    }
//    setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, opt, len);

//    struct sockaddr_in sin;
//    memset(&sin, 0, sizeof(sin));
//    sin.sin_family = AF_INET;
//    sin.sin_addr.s_addr = INADDR_ANY;


//    struct nfq_handle * handler = nfq_open();
//    THROW_IF_TRUE(handler == nullptr, "Can\'t open hfqueue handler.");
//    SCOPED_GUARD( nfq_close(handler); ); // Don’t forget to clean up

//    struct nfq_q_handle *queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
//    THROW_IF_TRUE(queue == nullptr, "Can\'t create queue handler.");
//    SCOPED_GUARD( nfq_destroy_queue(queue); ); // Do not forget to clean up

//    THROW_IF_TRUE(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

//    int fd = nfq_fd(handler);
//    std::array<char, 0x10000> buffer;
//    const unsigned char *frame=reinterpret_cast<unsigned char*>(0xe0,0x1a,0xea,0x37,0x3b,0x6c,0xe0,0x1a,0xea,0x37,0x3b,0x62,0x08,0x00,0x45,0x00,0x00,0x54,0x40,0x9e,0x40,0x00,0x40,0x01,0x78,0xb7,0xc0,0xa8,0x00,0x01,0xc0,0xa8,0x00,0x02,0x08,0x00,0x5a,0x77,0x47,0xc7,0x0e,0x20,0xcb,0xf9,0xc8,0x5e,0x00,0x00,0x00,0x00,0xea,0x75,0x0a,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37);

//    for(;;)
//    {
//        int len = read(fd, buffer.data(), buffer.size());
//        std::cout<<"otrzymalem tyle bajtow\n"<<len<<"\n";
//        std::cout<<"otrzymalem ramke: "<<std::endl;
//        for (int i=0;i<len;i++)
//        {
//            std::printf("%.02x ", uint8_t(buffer[i]));
//        }

//        THROW_IF_TRUE(len < 0, "Issue while read");
//        nfq_handle_packet(handler, buffer.data(), len);
//        send(sd,frame,len-48,0);

//    }
//    return 0;
// }

int main()
{
    int saddr_size , data_size, daddr_size, bytes_sent;
    struct sockaddr_ll saddr, daddr;
    unsigned char *buffer=(unsigned char *)malloc(65535);
    unsigned char *new_buffer=(unsigned char *)malloc(65535);

    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ; //For receiving
    int sock = socket( PF_PACKET , SOCK_RAW , IPPROTO_RAW) ;            //For sending

    memset(&saddr, 0, sizeof(struct sockaddr_ll));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = if_nametoindex("enp1s0f1");
    if (bind(sock_raw, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
        perror("bind failed\n");
        close(sock_raw);
    }

    memset(&daddr, 0, sizeof(struct sockaddr_ll));
    daddr.sll_family = AF_PACKET;
    daddr.sll_protocol = htons(ETH_P_ALL);
    daddr.sll_ifindex = if_nametoindex("enp1s0f1");
    if (bind(sock, (struct sockaddr*) &daddr, sizeof(daddr)) < 0) {
      perror("bind failed\n");
      close(sock);
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "enp1s0f1");
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("bind to eth1");
        }

    while(1)
    {
        saddr_size = sizeof (struct sockaddr);
        daddr_size = sizeof (struct sockaddr);
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 ,(struct sockaddr *) &saddr , (socklen_t*)&saddr_size);

//        for (int i=0;i<data_size;i++)
//        {
//            printf("%.02x ",buffer[i]);
//        }
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        else
        {
        //printf("Received %d bytes\n",data_size);

        //Huge code to process the packet (optional)

            if (buffer[33]==0x02)
            {
                //Send the same packet out
                //making new frame
                for (int i=0;i<6;i++)
                {
                    new_buffer[i]=buffer[i+6];
                    new_buffer[i+6]=buffer[i];
                }
                for(int i=0;i<data_size-12;i++)
                {
                    new_buffer[i+12]=buffer[i+12];
                }
                new_buffer[29]=0x02;
                new_buffer[33]=0x01;
                bytes_sent=write(sock,new_buffer,data_size);
                //printf("Sent %d bytes\n",bytes_sent);
                 if (bytes_sent < 0) {
                    perror("sendto");
                    exit(1);
                 }
            }
        }
    }
    close(sock_raw);
    return 0;
}
