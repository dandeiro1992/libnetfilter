#include <memory>
#include <functional>
#include <array>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <thread>
extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

}
#include <vector>
std::vector<std::array<char, 0x10000>> packets_vector;
#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m); }} while(false)

#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    THROW_IF_TRUE(ph == nullptr, "Issue while packet header");

    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    THROW_IF_TRUE(len < 0, "Can\'t get payload data");

    struct pkt_buff * pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate");
    SCOPED_GUARD( pktb_free(pkBuff); ); // Don't forget to clean up

    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header parse.");
    //std::cout<<"adres:  "<<ip->daddr<<std::endl;
    //ip->daddr=16777343;
    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");
    nfq_ip_set_checksum(ip);
    if(ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");
        void *payload = nfq_tcp_get_payload(tcp, pkBuff);
        unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
        payloadLen -= 4 * tcp->th_off;
        THROW_IF_TRUE(payload == nullptr, "Issue while payload.");

        for (unsigned int i = 0; i < payloadLen / 2; ++i) {
            char tmp = (static_cast<char *>(payload))[i];
            (static_cast<char *>(payload))[i] = (static_cast<char *>(payload))[payloadLen - 1 - i];
            (static_cast<char *>(payload))[payloadLen - 1 - i] = tmp;
        }

        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    }
    else if (ip->protocol==IPPROTO_UDP)
    {
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    }
    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}

static int netfilterCallback_2(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    THROW_IF_TRUE(ph == nullptr, "Issue while packet header");

    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    THROW_IF_TRUE(len < 0, "Can\'t get payload data");

    struct pkt_buff * pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate");
    SCOPED_GUARD( pktb_free(pkBuff); ); // Don't forget to clean up

    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header parse.");

    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");

    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}

void receiving_queue()
{
    struct nfq_handle * handler = nfq_open();
    THROW_IF_TRUE(handler == nullptr, "Can\'t open hfqueue handler.");
    SCOPED_GUARD( nfq_close(handler); ); // Don’t forget to clean up

    struct nfq_q_handle *queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
    THROW_IF_TRUE(queue == nullptr, "Can\'t create queue handler.");
    SCOPED_GUARD( nfq_destroy_queue(queue); ); // Do not forget to clean up

    THROW_IF_TRUE(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

    int fd = nfq_fd(handler);
    std::array<char, 0x10000> buffer;
    for (auto it=array.begin();it!=array.end();it++)
        std::cout<<*it;
    for(;;)
    {
        int len = read(fd, buffer.data(), buffer.size());
        packets_vector.push_back(buffer);
        THROW_IF_TRUE(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
    }
}

void sending_queue()
{
    struct nfq_handle * handler_2 = nfq_open();
    THROW_IF_TRUE(handler_2 == nullptr, "Can\'t open hfqueue handler.");
    SCOPED_GUARD( nfq_close(handler_2); ); // Don’t forget to clean up

    struct nfq_q_handle *queue_2 = nfq_create_queue(handler_2, 1, netfilterCallback_2, nullptr);
    THROW_IF_TRUE(queue_2 == nullptr, "Can\'t create queue handler.");
    SCOPED_GUARD( nfq_destroy_queue(queue_2); ); // Do not forget to clean up

    THROW_IF_TRUE(nfq_set_mode(queue_2, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");


    int fd_2=nfq_fd(handler_2);
    for (auto it=packets_vector.begin();it!=packets_vector.end();it++)
    {
       send(fd_2,it->data(),it->size(),0) ;
    }

}

int main()
{
    std:: thread first_thread(receiving_queue);
    std:: thread second_thread(sending_queue);

    return 0;
 }
