#ifndef ROUTER_H
#define ROUTER_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <map>
#include <queue>
#include <string>
#include <mutex>
#include <thread>
#include "tinyxml2.h"
#define IPV6_HDRLEN 40
// #define TCP_HDRLEN 20
// #define RTP_HDRLEN 12
// fe80::2ecf:67ff:fe29:d2f8
#define MTU 1500
#define SOCKET_ERROR -1
#define LISTEN_PORT 0
typedef int SOCKET;
std::string trim(const std::string &str);
bool operator<(const struct in6_addr& lhs, const struct in6_addr& rhs);
bool operator==(const struct in6_addr& lhs, const struct in6_addr& rhs);
// 0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|Traffic Class|   Flow Label (20 bits)                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Payload Length| Next Header|  Hop Limit                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                     Source Address (128 bits)                 |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                  Destination Address (128 bits)               |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Extension Headers (if any)                    |
// |                                                               |
// |                             Payload                             |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 手动构建IPv6头部结构体、40字节定长

struct ipv6_header
{
    unsigned int ver_tc_fl;     // 版本（4bit）、流量类型（8bit）、流标签（20bit）、共32bit
    unsigned short payload_len; // 有效载荷长度（16bit），给出了数据包中跟在定长的40字节数据报首部后面的字节数量,数据+扩展头部
    unsigned char next_header;  // 下一个首部，标识数据报中的数据字段需要交付给哪个协议（如TCP或UDP）
    unsigned char hop_limit;    // 跳限制，每过一台路由器减1
    struct in6_addr src_addr;   // 源地址（128bit）
    struct in6_addr dest_addr;  // 目的地址（128bit）
};

class IPv6Router
{
public:
    IPv6Router(const char *listen_ip);
    ~IPv6Router();
    bool initialize_socket();
    void close_socket();

    bool listen_for_receive();
    void receive_ipv6_segment();
    void send_ipv6_segment(const struct in6_addr dest_addr, const char *data, size_t data_len);
    bool listen_for_send();
    bool init_routing_table(const char* xmlFile);
    struct in6_addr next_hop(const struct in6_addr dest_addr);
private:
    SOCKET sockfd;
    const char *listen_ip;

    std::queue<std::string> ipv6BufferQue;
    std::mutex bufferQueLock;
    std::mutex printLock;
    std::map<in6_addr, in6_addr> routing_table; // +-+-+-+-+-+-+-+-+-+
                                                      // |目的地址|下一跳地址|
};

#endif // ROUTER_H