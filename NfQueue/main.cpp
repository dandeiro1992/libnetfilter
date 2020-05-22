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
extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
}
#define SERWER_PORT 8888
#define SERWER_IP "192.168.0.1"

#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m); }} while(false)

#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

//unsigned int inet_addr(char *str)
//{
//    int a, b, c, d;
//    char arr[4];
//    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
//    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
//    return *(unsigned int *)arr;
//}

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

    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");

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

int main()
{
    struct nfq_handle * handler = nfq_open();
    THROW_IF_TRUE(handler == nullptr, "Can\'t open hfqueue handler.");
    SCOPED_GUARD( nfq_close(handler); ); // Don’t forget to clean up

    struct nfq_q_handle *queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
    THROW_IF_TRUE(queue == nullptr, "Can\'t create queue handler.");
    SCOPED_GUARD( nfq_destroy_queue(queue); ); // Do not forget to clean up

    THROW_IF_TRUE(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

    // robimy nasz handler do wysylania danych z powrotem
    struct nfq_handle * handler_2 = nfq_open();
    THROW_IF_TRUE(handler_2 == nullptr, "Can\'t open hfqueue handler.");
    SCOPED_GUARD( nfq_close(handler_2); ); // Don’t forget to clean up

    struct nfq_q_handle *queue_2 = nfq_create_queue(handler, 1, netfilterCallback_2, nullptr);
    THROW_IF_TRUE(queue_2 == nullptr, "Can\'t create queue handler.");
    SCOPED_GUARD( nfq_destroy_queue(queue_2); ); // Do not forget to clean up

    THROW_IF_TRUE(nfq_set_mode(queue_2, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

    ////////////////////////////////////
       // SOCKET //
    int sockfd;
    struct sockaddr_in     servaddr;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERWER_PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    int n, len;
        // socket //
    char * napis="damian";
    int fd = nfq_fd(handler);
    int fd_2=nfq_fd(handler_2);
    std::array<char, 0x10000> buffer;
    for(;;)
    {
        int len = read(fd, buffer.data(), buffer.size());
        THROW_IF_TRUE(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
        sendto(sockfd, (const char *)buffer.data(), strlen(buffer.data()),
                MSG_CONFIRM, (const struct sockaddr *) &servaddr,
                    sizeof(servaddr));
    }
    return 0;
 }
