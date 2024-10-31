#include "Router.h"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <net/if.h>
#include <cstdio>
#include <functional> // 包含std::less
IPv6Router::IPv6Router(const char *listen_ip)
    : listen_ip(listen_ip)
{
} // 构造函数实现

IPv6Router::~IPv6Router()
{
    close_socket();
}

bool IPv6Router::initialize_socket()
{
    // 创建IPv6 socket
    sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);

    if (sockfd < 0)
    {
        std::cerr << "Failed to create socket" << sockfd << std::endl;
        return false;
    }
    else
    {
        std::cout << "Success to create socket" << std::endl;
    }

    int optval = 0; // 表示加上头部
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_HDRINCL, &optval, sizeof(optval)) < 0)
    {
        std::cerr << "Failed to set socket option" << std::endl;
        // close_socket();
        return false;
    }
    else
    {
        std::cout << "Success to set socket option" << std::endl;
    }

    // 绑定socket到地址和端口
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;

    // 设置以太网eth0接口时需要专门指明
    unsigned int index = if_nametoindex("eth0"); // 假设我们使用的是eth0接口
    if (index == 0)
    {
        perror("if_nametoindex failed");
    }
    else
    {
        std::cout << "The eth0 index is " << index << std::endl;
        addr.sin6_scope_id = index;
    }

    if (inet_pton(AF_INET6, listen_ip, &addr.sin6_addr) <= 0)
    {
        std::cerr << "Invalid address/Address not supported:" << listen_ip << std::endl;
        // close_socket();
        return false;
    }
    else
    {
        std::cout << "success address IPv6: " << listen_ip << std::endl;
    }

    // 绑定ip端口号
    if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        std::cerr << "Bind failed:" << strerror(errno) << std::endl;
        // close_socket();
        return false;
    }

    return true;
}

void IPv6Router::close_socket()
{
    if (sockfd > 0)
    {
        close(sockfd);
        sockfd = -1;
    }
}

bool IPv6Router::listen_for_receive()
{
    std::cout << "listen for receive..." << std::endl;
    while (true)
    {
        char buffer[MTU];
        struct sockaddr_in6 src_addr;
        unsigned int src_addr_len = sizeof(src_addr);
        memset(buffer, 0, sizeof(buffer));

        if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &src_addr_len) == SOCKET_ERROR)
        {
            std::cerr << "Failed to receive data " << strerror(errno) << std::endl;
            continue;
        }
        receive_ipv6_segment();

        std::this_thread::sleep_for(std::chrono::milliseconds(2));

        struct ipv6_header *ipv6_hdr = (struct ipv6_header *)buffer;
        char *data = buffer + IPV6_HDRLEN;
        size_t data_len = ntohs(ipv6_hdr->payload_len); // 為ipv6的長度

        std::cout << "Received data length: " << data_len << std::endl;

        ipv6_hdr->hop_limit--; // TTL要减一

        if (!ipv6_hdr->hop_limit) // 0
        {
            std::cout << "Hop limit is 0, segment discarded." << std::endl;
            continue; // 0 直接丢弃
        }

        bufferQueLock.lock();
        ipv6BufferQue.push(std::string(buffer, data_len + IPV6_HDRLEN));
        bufferQueLock.unlock();
    }

    return true;
}

void IPv6Router::receive_ipv6_segment()
{
    std::cout << "Router received data." << std::endl;
}

bool IPv6Router::listen_for_send()
{
    std::cout << "listen for send:" << std::endl;
    while (true)
    {
        if (ipv6BufferQue.empty())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        // std::cout << "ipv6BufferQue: " << ipv6BufferQue.size() << std::endl;
        bufferQueLock.lock();
        std::string frontBuffer = std::move(ipv6BufferQue.front());
        ipv6BufferQue.pop();
        bufferQueLock.unlock();

        const char *buffer = frontBuffer.c_str();
        const char *ipv6_hdr = buffer;
        const char *pdata = ipv6_hdr + IPV6_HDRLEN;
        unsigned short payload_length = ntohs(((ipv6_header *)ipv6_hdr)->payload_len);
        unsigned char hop_limit = ((ipv6_header *)ipv6_hdr)->hop_limit;

        struct in6_addr dest_addr = ((ipv6_header *)ipv6_hdr)->dest_addr;
        // 在此处就查好表来，然后在下面加上就

        send_ipv6_segment(dest_addr, buffer, frontBuffer.length()); // 暂时这样
        std::this_thread::sleep_for(std::chrono::milliseconds(2));  // 模拟
    }
}

void IPv6Router::send_ipv6_segment(const struct in6_addr dest_addr, const char *data, size_t data_len)
{
    struct sockaddr_in6 next_sockaddr;
    memset(&next_sockaddr, 0, sizeof(next_sockaddr));
    next_sockaddr.sin6_family = AF_INET6;

    // 查询路由表，交给下一跳的地址

    next_sockaddr.sin6_addr = next_hop(dest_addr);
    in6_addr next_addr = next_hop(dest_addr);
    const char *ch = (char *)&next_addr;
    printf("next addr:\n ");
    for (int i = 0; i < 16; i++)
    {
        if (i % 4 == 0)
        {
            printf("\n");
        }
        printf("%x ", *(ch + i));
    }
    printf("\n");
    next_sockaddr.sin6_scope_id = 2; // 后续完善
    // 指定以太网eth0
    // unsigned int index = if_nametoindex("eth0"); // 假设我们使用的是eth0接口
    // if (!index)
    // {
    //     perror("if_nametoindex failed");
    // }
    // else
    // {
    //     std::cout << "The eth0 index is " << index << std::endl;
    //     next_sockaddr.sin6_scope_id = index;
    // }
    // 更改scope_id

    ssize_t sent = sendto(sockfd, data, data_len, 0, (struct sockaddr *)&next_sockaddr, sizeof(next_sockaddr));
    if (sent < 0)
    {
        std::cerr << "Failed to send data: " << strerror(errno) << std::endl;
    }
    else
    {
        std::cout << "Router send data: " << sent << "Bytes" << std::endl;
    }
    // std::cout << "Router send data." << std::endl;
}

bool IPv6Router::init_routing_table(const char *xmlFile)
{

    tinyxml2::XMLDocument doc;
    std::cout << "LoadFile:" << xmlFile << std::endl;
    tinyxml2::XMLError eResult = doc.LoadFile(xmlFile);
    if (eResult != tinyxml2::XML_SUCCESS)
    {
        std::cerr << "Error loading XML file. Error code: " << eResult << std::endl;
        return false;
    }

    tinyxml2::XMLElement *root = doc.RootElement();
    if (strcmp(root->Name(), "routing_table") != 0)
    {
        std::cerr << "Invalid XML format" << std::endl;
        return false;
    }

    for (tinyxml2::XMLElement *route = root->FirstChildElement("route"); route != nullptr; route = route->NextSiblingElement("route"))
    {
        std::string tempDestStr = trim(route->FirstChildElement("dest_ip")->GetText());
        std::string tempNextStr = trim(route->FirstChildElement("next_ip")->GetText());

        const char *dest_ip = tempDestStr.c_str();
        const char *next_ip = tempNextStr.c_str();

        in6_addr destAddr, nextHopAddr;
        
        if (inet_pton(AF_INET6, dest_ip, &destAddr) <= 0)
        {
            std::cerr << "Invalid destination address" << std::endl;
            return false;
        }
        if (inet_pton(AF_INET6, next_ip, &nextHopAddr) <= 0)
        {
            std::cerr << "Invalid next hop address" << std::endl;
            return false;
        }

        routing_table[destAddr]=nextHopAddr;
    }
    std::cout << "routing_table imported success" << std::endl;
    return true;
}

struct in6_addr IPv6Router::next_hop(const struct in6_addr dest_addr)
{

    auto it = routing_table.find(dest_addr);
    if (it != routing_table.end())
    {
        struct in6_addr next_addr = it->second;
        return next_addr;
    }
    else
    {
        return IN6ADDR_ANY_INIT;
    }
}

std::string trim(const std::string &str)
{
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos)
        return "";
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, last - first + 1);
}

// 重载in6_addr的运算符<
bool operator<(const struct in6_addr &lhs, const struct in6_addr &rhs)
{
    return std::lexicographical_compare(lhs.s6_addr, lhs.s6_addr + 16, rhs.s6_addr, rhs.s6_addr + 16);
}

// 重载in6_addr的运算符==
bool operator==(const struct in6_addr &lhs, const struct in6_addr &rhs)
{
    return std::equal(lhs.s6_addr, lhs.s6_addr + 16, rhs.s6_addr);
}

int main(int argc, char const *argv[])
{
    const char *listen_ip = "fe80::2ecf:67ff:fe29:d2f8"; // 本机IPv6
    IPv6Router router(listen_ip);

    if (!router.init_routing_table("/home/pi05/Desktop/RpRouter/src/routing_table.xml"))
    {
        return 0;
    }

    if (router.initialize_socket())
    {
        std::thread receive_thread(&IPv6Router::listen_for_receive, &router);
        std::thread send_thread(&IPv6Router::listen_for_send, &router);
        // router.listen_for_receive();
        receive_thread.join();
        send_thread.join();
        std::cout << "------Terminte routing------" << std::endl;
    }

    return 0;
}
