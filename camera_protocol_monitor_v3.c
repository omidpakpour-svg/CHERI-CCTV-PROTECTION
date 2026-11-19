/*
 * camera_protocol_monitor_v3.c
 *
 * SAMA5D3 live camera traffic monitor
 *
 * Camera:    192.168.1.10
 * Interface: eth0
 *
 * Shows:
 *   TCP / UDP / ICMP
 *   Source IP
 *   Source port
 *   Destination IP
 *   Destination port
 *   Packets per second
 *   HTTP / HTTPS / RTSP candidates
 *   Basic RTP candidates
 *
 * Compile:
 *
 * arm-linux-gnueabihf-gcc -static -Wall -Wextra -O2 \
 * camera_protocol_monitor_v3.c -o camera_protocol_monitor_v3
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* --------------------------------------------------------- */
/* Configuration                                             */
/* --------------------------------------------------------- */

#define INTERFACE_NAME "eth0"
#define CAMERA_IP_TEXT "192.168.1.10"

#define BUFFER_SIZE 65536
#define MAX_FLOWS 128
#define MAX_DISPLAY_FLOWS 10

/* --------------------------------------------------------- */
/* Global program state                                      */
/* --------------------------------------------------------- */

static volatile sig_atomic_t running = 1;

/* --------------------------------------------------------- */
/* Statistics                                                */
/* --------------------------------------------------------- */

typedef struct
{
    unsigned long long tcp_total;
    unsigned long long udp_total;
    unsigned long long icmp_total;

    unsigned long long tcp_second;
    unsigned long long udp_second;
    unsigned long long icmp_second;

    unsigned long long from_camera_bytes;
    unsigned long long to_camera_bytes;

} Statistics;

static Statistics stats;

/* --------------------------------------------------------- */
/* Flow table                                                */
/* --------------------------------------------------------- */

typedef struct
{
    uint8_t protocol;

    uint32_t src_ip;
    uint32_t dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    unsigned long long packets_second;
    unsigned long long packets_total;

    int rtp_candidate;

} Flow;

static Flow flows[MAX_FLOWS];
static int flow_count = 0;

/* --------------------------------------------------------- */
/* Ctrl+C                                                    */
/* --------------------------------------------------------- */

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* --------------------------------------------------------- */
/* Current time                                              */
/* --------------------------------------------------------- */

static double get_time_seconds(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (double)tv.tv_sec +
           ((double)tv.tv_usec / 1000000.0);
}

/* --------------------------------------------------------- */
/* Convert IP to text                                        */
/* --------------------------------------------------------- */

static void ip_string(uint32_t ip,
                      char *buf,
                      size_t len)
{
    struct in_addr address;

    address.s_addr = ip;

    if (inet_ntop(AF_INET,
                  &address,
                  buf,
                  len) == NULL)
    {
        snprintf(buf, len, "?");
    }
}

/* --------------------------------------------------------- */
/* Protocol name                                             */
/* --------------------------------------------------------- */

static const char *protocol_string(uint8_t protocol)
{
    if (protocol == IPPROTO_TCP)
        return "TCP";

    if (protocol == IPPROTO_UDP)
        return "UDP";

    if (protocol == IPPROTO_ICMP)
        return "ICMP";

    return "OTHER";
}

/* --------------------------------------------------------- */
/* Basic RTP candidate check                                 */
/* --------------------------------------------------------- */

static int looks_like_rtp(const unsigned char *payload,
                          size_t length)
{
    unsigned int version;

    if (payload == NULL)
        return 0;

    /*
     * RTP base header requires at least 12 bytes.
     */
    if (length < 12)
        return 0;

    /*
     * First two bits should be binary 10 for RTP version 2.
     */
    version = payload[0] >> 6;

    if (version != 2)
        return 0;

    return 1;
}

/* --------------------------------------------------------- */
/* Find existing flow or create new one                      */
/* --------------------------------------------------------- */

static Flow *get_flow(uint8_t protocol,
                      uint32_t src_ip,
                      uint16_t src_port,
                      uint32_t dst_ip,
                      uint16_t dst_port)
{
    int i;

    for (i = 0; i < flow_count; i++)
    {
        if ((flows[i].protocol == protocol) &&
            (flows[i].src_ip == src_ip) &&
            (flows[i].dst_ip == dst_ip) &&
            (flows[i].src_port == src_port) &&
            (flows[i].dst_port == dst_port))
        {
            return &flows[i];
        }
    }

    if (flow_count >= MAX_FLOWS)
        return NULL;

    memset(&flows[flow_count],
           0,
           sizeof(Flow));

    flows[flow_count].protocol = protocol;
    flows[flow_count].src_ip = src_ip;
    flows[flow_count].dst_ip = dst_ip;
    flows[flow_count].src_port = src_port;
    flows[flow_count].dst_port = dst_port;

    flow_count++;

    return &flows[flow_count - 1];
}

/* --------------------------------------------------------- */
/* Record packet in flow table                               */
/* --------------------------------------------------------- */

static void record_flow(uint8_t protocol,
                        uint32_t src_ip,
                        uint16_t src_port,
                        uint32_t dst_ip,
                        uint16_t dst_port,
                        int rtp)
{
    Flow *flow;

    flow = get_flow(protocol,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port);

    if (flow == NULL)
        return;

    flow->packets_second++;
    flow->packets_total++;

    if (rtp)
        flow->rtp_candidate = 1;
}

/* --------------------------------------------------------- */
/* Classify a flow                                           */
/* --------------------------------------------------------- */

static const char *classify_flow(const Flow *flow)
{
    if (flow->protocol == IPPROTO_TCP)
    {
        if ((flow->src_port == 554) ||
            (flow->dst_port == 554))
        {
            return "RTSP";
        }

        if ((flow->src_port == 80) ||
            (flow->dst_port == 80))
        {
            return "HTTP";
        }

        if ((flow->src_port == 443) ||
            (flow->dst_port == 443))
        {
            return "HTTPS";
        }

        return "TCP";
    }

    if (flow->protocol == IPPROTO_UDP)
    {
        if (flow->rtp_candidate)
            return "RTP?";

        return "UDP";
    }

    if (flow->protocol == IPPROTO_ICMP)
        return "ICMP";

    return "OTHER";
}

/* --------------------------------------------------------- */
/* TCP processing                                            */
/* --------------------------------------------------------- */

static void process_tcp(const unsigned char *buffer,
                        size_t packet_length,
                        size_t ip_offset,
                        const struct iphdr *ip)
{
    size_t ip_header_length;
    size_t tcp_offset;

    const struct tcphdr *tcp;

    uint16_t src_port;
    uint16_t dst_port;

    ip_header_length = ip->ihl * 4U;

    tcp_offset =
        ip_offset +
        ip_header_length;

    if (packet_length <
        tcp_offset + sizeof(struct tcphdr))
    {
        return;
    }

    tcp =
        (const struct tcphdr *)
        (buffer + tcp_offset);

    src_port = ntohs(tcp->source);
    dst_port = ntohs(tcp->dest);

    stats.tcp_total++;
    stats.tcp_second++;

    record_flow(IPPROTO_TCP,
                ip->saddr,
                src_port,
                ip->daddr,
                dst_port,
                0);
}

/* --------------------------------------------------------- */
/* UDP processing                                            */
/* --------------------------------------------------------- */

static void process_udp(const unsigned char *buffer,
                        size_t packet_length,
                        size_t ip_offset,
                        const struct iphdr *ip)
{
    size_t ip_header_length;
    size_t udp_offset;
    size_t payload_offset;
    size_t payload_length;

    const struct udphdr *udp;

    const unsigned char *payload = NULL;

    uint16_t src_port;
    uint16_t dst_port;
    uint16_t udp_length;

    int rtp = 0;

    ip_header_length = ip->ihl * 4U;

    udp_offset =
        ip_offset +
        ip_header_length;

    if (packet_length <
        udp_offset + sizeof(struct udphdr))
    {
        return;
    }

    udp =
        (const struct udphdr *)
        (buffer + udp_offset);

    src_port = ntohs(udp->source);
    dst_port = ntohs(udp->dest);
    udp_length = ntohs(udp->len);

    payload_offset =
        udp_offset +
        sizeof(struct udphdr);

    if ((udp_length > sizeof(struct udphdr)) &&
        (packet_length > payload_offset))
    {
        payload_length =
            udp_length -
            sizeof(struct udphdr);

        if (payload_offset +
            payload_length >
            packet_length)
        {
            payload_length =
                packet_length -
                payload_offset;
        }

        payload =
            buffer + payload_offset;

        rtp =
            looks_like_rtp(payload,
                           payload_length);
    }

    stats.udp_total++;
    stats.udp_second++;

    record_flow(IPPROTO_UDP,
                ip->saddr,
                src_port,
                ip->daddr,
                dst_port,
                rtp);
}

/* --------------------------------------------------------- */
/* ICMP processing                                           */
/* --------------------------------------------------------- */

static void process_icmp(const struct iphdr *ip)
{
    stats.icmp_total++;
    stats.icmp_second++;

    /*
     * ICMP has no TCP or UDP ports.
     * Use zero for both.
     */

    record_flow(IPPROTO_ICMP,
                ip->saddr,
                0,
                ip->daddr,
                0,
                0);
}

/* --------------------------------------------------------- */
/* Flow sort                                                 */
/* --------------------------------------------------------- */

static int compare_flows(const void *a,
                         const void *b)
{
    const Flow *flow_a =
        *(const Flow * const *)a;

    const Flow *flow_b =
        *(const Flow * const *)b;

    if (flow_a->packets_second <
        flow_b->packets_second)
        return 1;

    if (flow_a->packets_second >
        flow_b->packets_second)
        return -1;

    return 0;
}

/* --------------------------------------------------------- */
/* Dashboard                                                 */
/* --------------------------------------------------------- */

static void display_dashboard(double seconds)
{
    Flow *active[MAX_FLOWS];

    int active_count = 0;
    int display_count;

    int i;

    double from_mbps;
    double to_mbps;

    if (seconds <= 0.0)
        seconds = 1.0;

    from_mbps =
        ((double)stats.from_camera_bytes * 8.0) /
        seconds /
        1000000.0;

    to_mbps =
        ((double)stats.to_camera_bytes * 8.0) /
        seconds /
        1000000.0;

    /*
     * Build list of flows active during current second.
     */

    for (i = 0;
         i < flow_count;
         i++)
    {
        if (flows[i].packets_second > 0)
        {
            active[active_count] =
                &flows[i];

            active_count++;
        }
    }

    qsort(active,
          active_count,
          sizeof(active[0]),
          compare_flows);

    display_count = active_count;

    if (display_count >
        MAX_DISPLAY_FLOWS)
    {
        display_count =
            MAX_DISPLAY_FLOWS;
    }

    /*
     * Move cursor back to top.
     */
    printf("\033[H");

    printf(
        "+-----------------------------------------------------------------------------------+\n");

    printf(
        "|                    SAMA5D3 CAMERA TRAFFIC MONITOR                                |\n");

    printf(
        "+-----------------------------------------------------------------------------------+\n");

    printf(
        "| Camera: %-15s       Interface: %-8s                                  |\n",
        CAMERA_IP_TEXT,
        INTERFACE_NAME);

    printf(
        "+-----------------------------------------------------------------------------------+\n");

    printf(
        "| CURRENT PACKETS / SECOND                                                         |\n");

    printf(
        "| TCP: %-10llu       UDP: %-10llu       ICMP: %-10llu                     |\n",
        stats.tcp_second,
        stats.udp_second,
        stats.icmp_second);

    printf(
        "+-----------------------------------------------------------------------------------+\n");

    printf(
        "| From camera: %8.3f Mbps          To camera: %8.3f Mbps                         |\n",
        from_mbps,
        to_mbps);

    printf(
        "+-----------------------------------------------------------------------------------+\n");

    printf(
        "| ACTIVE TCP / UDP PORTS                                                            |\n");

    printf(
        "+------+-----------------+-------+-----------------+-------+--------+----------------+\n");

    printf(
        "| Prot | Source IP       | SPort | Destination IP  | DPort | Pkt/s  | Classification |\n");

    printf(
        "+------+-----------------+-------+-----------------+-------+--------+----------------+\n");

    for (i = 0;
         i < MAX_DISPLAY_FLOWS;
         i++)
    {
        if (i < display_count)
        {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            Flow *flow =
                active[i];

            const char *classification =
                classify_flow(flow);

            ip_string(
                flow->src_ip,
                src_ip,
                sizeof(src_ip));

            ip_string(
                flow->dst_ip,
                dst_ip,
                sizeof(dst_ip));

            if (flow->protocol ==
                IPPROTO_ICMP)
            {
                printf(
                    "| %-4s | %-15s |   -   | %-15s |   -   | %-6llu | %-14s |\n",
                    protocol_string(flow->protocol),
                    src_ip,
                    dst_ip,
                    flow->packets_second,
                    classification);
            }
            else
            {
                printf(
                    "| %-4s | %-15s | %-5u | %-15s | %-5u | %-6llu | %-14s |\n",
                    protocol_string(flow->protocol),
                    src_ip,
                    flow->src_port,
                    dst_ip,
                    flow->dst_port,
                    flow->packets_second,
                    classification);
            }
        }
        else
        {
            /*
             * Blank row overwrites old data from previous refresh.
             */
            printf(
                "|      |                 |       |                 |       |        |                |\n");
        }
    }

    printf(
        "+------+-----------------+-------+-----------------+-------+--------+----------------+\n");

    printf(
        "| TOTAL: TCP=%-10llu UDP=%-10llu ICMP=%-10llu                              |\n",
        stats.tcp_total,
        stats.udp_total,
        stats.icmp_total);

    printf(
        "+-----------------------------------------------------------------------------------+\n");

    printf(
        "| Ctrl+C to stop                                                                    |\n");

    printf(
        "+-----------------------------------------------------------------------------------+\n");

    printf("\033[J");

    fflush(stdout);
}

/* --------------------------------------------------------- */
/* Reset one-second counters                                 */
/* --------------------------------------------------------- */

static void reset_second(void)
{
    int i;

    stats.tcp_second = 0;
    stats.udp_second = 0;
    stats.icmp_second = 0;

    stats.from_camera_bytes = 0;
    stats.to_camera_bytes = 0;

    for (i = 0;
         i < flow_count;
         i++)
    {
        flows[i].packets_second = 0;
    }
}

/* --------------------------------------------------------- */
/* Main                                                      */
/* --------------------------------------------------------- */

int main(void)
{
    int socket_fd;

    unsigned char buffer[BUFFER_SIZE];

    struct ifreq ifr;
    struct sockaddr_ll bind_address;

    uint32_t camera_ip;

    double last_update;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    memset(&stats, 0, sizeof(stats));
    memset(flows, 0, sizeof(flows));

    camera_ip =
        inet_addr(CAMERA_IP_TEXT);

    if (camera_ip == INADDR_NONE)
    {
        fprintf(stderr,
                "Bad camera IP\n");

        return EXIT_FAILURE;
    }

    /*
     * Raw Ethernet capture.
     */
    socket_fd =
        socket(AF_PACKET,
               SOCK_RAW,
               htons(ETH_P_ALL));

    if (socket_fd < 0)
    {
        perror("socket");
        return EXIT_FAILURE;
    }

    /*
     * 1-second timeout allows dashboard updates
     * even when no packets arrive.
     */
    {
        struct timeval timeout;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            sizeof(timeout));
    }

    /*
     * Get eth0 interface number.
     */
    memset(&ifr, 0, sizeof(ifr));

    strncpy(
        ifr.ifr_name,
        INTERFACE_NAME,
        IFNAMSIZ - 1);

    if (ioctl(
            socket_fd,
            SIOCGIFINDEX,
            &ifr) < 0)
    {
        perror("SIOCGIFINDEX");

        close(socket_fd);

        return EXIT_FAILURE;
    }

    /*
     * Bind to eth0.
     */
    memset(
        &bind_address,
        0,
        sizeof(bind_address));

    bind_address.sll_family =
        AF_PACKET;

    bind_address.sll_protocol =
        htons(ETH_P_ALL);

    bind_address.sll_ifindex =
        ifr.ifr_ifindex;

    if (bind(
            socket_fd,
            (struct sockaddr *)&bind_address,
            sizeof(bind_address)) < 0)
    {
        perror("bind");

        close(socket_fd);

        return EXIT_FAILURE;
    }

    /*
     * Clear screen and hide cursor.
     */
    printf("\033[2J");
    printf("\033[H");
    printf("\033[?25l");

    fflush(stdout);

    last_update =
        get_time_seconds();

    while (running)
    {
        ssize_t received;

        size_t packet_length;

        struct ethhdr *ethernet;
        struct iphdr *ip;

        unsigned short ethernet_type;

        size_t ip_offset;
        size_t ip_header_length;

        double now;
        double elapsed;

        received =
            recvfrom(
                socket_fd,
                buffer,
                sizeof(buffer),
                0,
                NULL,
                NULL);

        if (received > 0)
        {
            packet_length =
                (size_t)received;

            if (packet_length >=
                sizeof(struct ethhdr))
            {
                ethernet =
                    (struct ethhdr *)buffer;

                ethernet_type =
                    ntohs(ethernet->h_proto);

                /*
                 * This version handles normal Ethernet IPv4.
                 */
                if (ethernet_type ==
                    ETH_P_IP)
                {
                    ip_offset =
                        sizeof(struct ethhdr);

                    if (packet_length >=
                        ip_offset +
                        sizeof(struct iphdr))
                    {
                        ip =
                            (struct iphdr *)
                            (buffer + ip_offset);

                        ip_header_length =
                            ip->ihl * 4U;

                        if ((ip_header_length >=
                             sizeof(struct iphdr)) &&
                            (packet_length >=
                             ip_offset +
                             ip_header_length))
                        {
                            /*
                             * Only traffic involving camera.
                             */
                            if ((ip->saddr ==
                                 camera_ip) ||
                                (ip->daddr ==
                                 camera_ip))
                            {
                                /*
                                 * Traffic direction.
                                 */
                                if (ip->saddr ==
                                    camera_ip)
                                {
                                    stats.from_camera_bytes +=
                                        packet_length;
                                }

                                if (ip->daddr ==
                                    camera_ip)
                                {
                                    stats.to_camera_bytes +=
                                        packet_length;
                                }

                                /*
                                 * Transport protocol.
                                 */
                                switch (ip->protocol)
                                {
                                    case IPPROTO_TCP:

                                        process_tcp(
                                            buffer,
                                            packet_length,
                                            ip_offset,
                                            ip);

                                        break;

                                    case IPPROTO_UDP:

                                        process_udp(
                                            buffer,
                                            packet_length,
                                            ip_offset,
                                            ip);

                                        break;

                                    case IPPROTO_ICMP:

                                        process_icmp(ip);

                                        break;

                                    default:
                                        break;
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            if ((errno != EAGAIN) &&
                (errno != EWOULDBLOCK) &&
                (errno != EINTR))
            {
                perror("recvfrom");
                break;
            }
        }

        /*
         * Dashboard refresh.
         */
        now =
            get_time_seconds();

        elapsed =
            now - last_update;

        if (elapsed >= 1.0)
        {
            display_dashboard(elapsed);

            reset_second();

            last_update = now;
        }
    }

    close(socket_fd);

    /*
     * Restore terminal.
     */
    printf("\033[?25h");
    printf("\033[2J");
    printf("\033[H");

    printf(
        "Camera traffic monitor stopped.\n");

    return EXIT_SUCCESS;
}