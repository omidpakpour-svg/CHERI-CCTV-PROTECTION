/*
 * camera_protocol_monitor_v4.c
 *
 * SAMA5D3 live camera-flow monitor.
 *
 * Camera:    192.168.1.10
 * Interface: eth0
 *
 * Features:
 *   - Filters IPv4 traffic involving the camera
 *   - Shows TCP, UDP and ICMP
 *   - Shows source and destination IP addresses
 *   - Shows source and destination TCP/UDP ports
 *   - Shows live packets/sec and kbit/sec per flow
 *   - Shows total packets and total transferred MB per flow
 *   - Retains discovered flow rows when traffic stops
 *   - Labels HTTP, HTTPS and RTSP candidates
 *   - Performs a basic RTP-header candidate check
 *   - Continuously refreshes one terminal dashboard
 *
 * Compile on Ubuntu:
 *
 * arm-linux-gnueabihf-gcc -static -Wall -Wextra -O2 \
 * camera_protocol_monitor_v4.c \
 * -o camera_protocol_monitor_v4
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

#define INTERFACE_NAME        "eth0"
#define CAMERA_IP_TEXT        "192.168.1.10"

#define BUFFER_SIZE           65536
#define MAX_FLOWS             128
#define DISPLAY_FLOWS         20
#define DISPLAY_INTERVAL_SEC  1.0

/* --------------------------------------------------------- */
/* Global control                                            */
/* --------------------------------------------------------- */

static volatile sig_atomic_t running = 1;

/* --------------------------------------------------------- */
/* Global packet statistics                                  */
/* --------------------------------------------------------- */

typedef struct
{
    unsigned long long tcp_total;
    unsigned long long udp_total;
    unsigned long long icmp_total;

    unsigned long long tcp_current;
    unsigned long long udp_current;
    unsigned long long icmp_current;

    unsigned long long from_camera_bytes;
    unsigned long long to_camera_bytes;

} Statistics;

static Statistics statistics;

/* --------------------------------------------------------- */
/* Flow record                                               */
/* --------------------------------------------------------- */

typedef struct
{
    uint8_t protocol;

    uint32_t source_ip;
    uint32_t destination_ip;

    uint16_t source_port;
    uint16_t destination_port;

    unsigned long long current_packets;
    unsigned long long total_packets;

    unsigned long long current_bytes;
    unsigned long long total_bytes;

    int rtp_candidate;

} Flow;

static Flow flows[MAX_FLOWS];
static int flow_count = 0;

/* --------------------------------------------------------- */
/* Signal handling                                           */
/* --------------------------------------------------------- */

static void signal_handler(int signal_number)
{
    (void)signal_number;
    running = 0;
}

/* --------------------------------------------------------- */
/* Time helper                                               */
/* --------------------------------------------------------- */

static double current_time_seconds(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return 0.0;

    return (double)tv.tv_sec +
           ((double)tv.tv_usec / 1000000.0);
}

/* --------------------------------------------------------- */
/* IP-address conversion                                     */
/* --------------------------------------------------------- */

static void ip_to_text(uint32_t address,
                       char *output,
                       size_t output_length)
{
    struct in_addr ip_address;

    ip_address.s_addr = address;

    if (inet_ntop(AF_INET,
                  &ip_address,
                  output,
                  output_length) == NULL)
    {
        snprintf(output,
                 output_length,
                 "?");
    }
}

/* --------------------------------------------------------- */
/* Protocol name                                             */
/* --------------------------------------------------------- */

static const char *protocol_name(uint8_t protocol)
{
    switch (protocol)
    {
        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_UDP:
            return "UDP";

        case IPPROTO_ICMP:
            return "ICMP";

        default:
            return "OTHER";
    }
}

/* --------------------------------------------------------- */
/* Basic RTP-header detection                                */
/* --------------------------------------------------------- */

/*
 * This identifies only an RTP candidate.
 *
 * RTP version 2 uses binary 10 in the first two bits of the
 * first RTP-header byte. A UDP packet can coincidentally match,
 * so this is not definitive RTP identification.
 */
static int looks_like_rtp(const unsigned char *payload,
                          size_t payload_length)
{
    unsigned int version;
    unsigned int payload_type;

    if (payload == NULL)
        return 0;

    if (payload_length < 12)
        return 0;

    version = payload[0] >> 6;

    if (version != 2)
        return 0;

    payload_type = payload[1] & 0x7F;

    /*
     * Exclude the small payload-type range commonly reserved
     * to avoid conflicts with RTCP packet types.
     */
    if ((payload_type >= 72) &&
        (payload_type <= 76))
    {
        return 0;
    }

    return 1;
}

/* --------------------------------------------------------- */
/* Locate or create a flow                                   */
/* --------------------------------------------------------- */

static Flow *get_flow(uint8_t protocol,
                      uint32_t source_ip,
                      uint16_t source_port,
                      uint32_t destination_ip,
                      uint16_t destination_port)
{
    int index;

    for (index = 0;
         index < flow_count;
         index++)
    {
        if ((flows[index].protocol == protocol) &&
            (flows[index].source_ip == source_ip) &&
            (flows[index].source_port == source_port) &&
            (flows[index].destination_ip == destination_ip) &&
            (flows[index].destination_port ==
             destination_port))
        {
            return &flows[index];
        }
    }

    if (flow_count >= MAX_FLOWS)
        return NULL;

    memset(&flows[flow_count],
           0,
           sizeof(flows[flow_count]));

    flows[flow_count].protocol = protocol;
    flows[flow_count].source_ip = source_ip;
    flows[flow_count].source_port = source_port;

    flows[flow_count].destination_ip =
        destination_ip;

    flows[flow_count].destination_port =
        destination_port;

    flow_count++;

    return &flows[flow_count - 1];
}

/* --------------------------------------------------------- */
/* Record flow packet and volume                             */
/* --------------------------------------------------------- */

static void record_flow(uint8_t protocol,
                        uint32_t source_ip,
                        uint16_t source_port,
                        uint32_t destination_ip,
                        uint16_t destination_port,
                        size_t packet_length,
                        int rtp_candidate)
{
    Flow *flow;

    flow = get_flow(protocol,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port);

    if (flow == NULL)
        return;

    flow->current_packets++;
    flow->total_packets++;

    flow->current_bytes += packet_length;
    flow->total_bytes += packet_length;

    if (rtp_candidate)
        flow->rtp_candidate = 1;
}

/* --------------------------------------------------------- */
/* Flow classification                                      */
/* --------------------------------------------------------- */

static const char *classify_flow(const Flow *flow)
{
    if (flow->protocol == IPPROTO_TCP)
    {
        if ((flow->source_port == 554) ||
            (flow->destination_port == 554))
        {
            return "RTSP";
        }

        if ((flow->source_port == 80) ||
            (flow->destination_port == 80))
        {
            return "HTTP";
        }

        if ((flow->source_port == 443) ||
            (flow->destination_port == 443))
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
/* Process TCP                                               */
/* --------------------------------------------------------- */

static void process_tcp(const unsigned char *buffer,
                        size_t packet_length,
                        size_t ip_offset,
                        const struct iphdr *ip_header)
{
    size_t ip_header_length;
    size_t tcp_offset;
    size_t tcp_header_length;

    const struct tcphdr *tcp_header;

    uint16_t source_port;
    uint16_t destination_port;

    ip_header_length =
        (size_t)ip_header->ihl * 4U;

    tcp_offset =
        ip_offset + ip_header_length;

    if (packet_length <
        tcp_offset + sizeof(struct tcphdr))
    {
        return;
    }

    tcp_header =
        (const struct tcphdr *)
        (buffer + tcp_offset);

    tcp_header_length =
        (size_t)tcp_header->doff * 4U;

    if (tcp_header_length <
        sizeof(struct tcphdr))
    {
        return;
    }

    if (packet_length <
        tcp_offset + tcp_header_length)
    {
        return;
    }

    source_port =
        ntohs(tcp_header->source);

    destination_port =
        ntohs(tcp_header->dest);

    statistics.tcp_total++;
    statistics.tcp_current++;

    record_flow(IPPROTO_TCP,
                ip_header->saddr,
                source_port,
                ip_header->daddr,
                destination_port,
                packet_length,
                0);
}

/* --------------------------------------------------------- */
/* Process UDP                                               */
/* --------------------------------------------------------- */

static void process_udp(const unsigned char *buffer,
                        size_t packet_length,
                        size_t ip_offset,
                        const struct iphdr *ip_header)
{
    size_t ip_header_length;
    size_t udp_offset;
    size_t payload_offset;
    size_t payload_length;

    const struct udphdr *udp_header;
    const unsigned char *payload = NULL;

    uint16_t source_port;
    uint16_t destination_port;
    uint16_t udp_length;

    int rtp_candidate = 0;

    ip_header_length =
        (size_t)ip_header->ihl * 4U;

    udp_offset =
        ip_offset + ip_header_length;

    if (packet_length <
        udp_offset + sizeof(struct udphdr))
    {
        return;
    }

    udp_header =
        (const struct udphdr *)
        (buffer + udp_offset);

    source_port =
        ntohs(udp_header->source);

    destination_port =
        ntohs(udp_header->dest);

    udp_length =
        ntohs(udp_header->len);

    payload_offset =
        udp_offset + sizeof(struct udphdr);

    payload_length = 0;

    if ((udp_length > sizeof(struct udphdr)) &&
        (packet_length > payload_offset))
    {
        payload_length =
            (size_t)udp_length -
            sizeof(struct udphdr);

        if (payload_offset + payload_length >
            packet_length)
        {
            payload_length =
                packet_length - payload_offset;
        }

        payload =
            buffer + payload_offset;

        rtp_candidate =
            looks_like_rtp(payload,
                           payload_length);
    }

    statistics.udp_total++;
    statistics.udp_current++;

    record_flow(IPPROTO_UDP,
                ip_header->saddr,
                source_port,
                ip_header->daddr,
                destination_port,
                packet_length,
                rtp_candidate);
}

/* --------------------------------------------------------- */
/* Process ICMP                                              */
/* --------------------------------------------------------- */

static void process_icmp(size_t packet_length,
                         const struct iphdr *ip_header)
{
    statistics.icmp_total++;
    statistics.icmp_current++;

    /*
     * ICMP does not have TCP/UDP port numbers.
     */
    record_flow(IPPROTO_ICMP,
                ip_header->saddr,
                0,
                ip_header->daddr,
                0,
                packet_length,
                0);
}

/* --------------------------------------------------------- */
/* Sort flows                                                */
/* --------------------------------------------------------- */

/*
 * Active high-volume flows appear first.
 *
 * When two flows have equal current volume, the flow with the
 * larger historic volume appears first.
 */
static int compare_flows(const void *left,
                         const void *right)
{
    const Flow *flow_a =
        *(const Flow * const *)left;

    const Flow *flow_b =
        *(const Flow * const *)right;

    if (flow_a->current_bytes <
        flow_b->current_bytes)
    {
        return 1;
    }

    if (flow_a->current_bytes >
        flow_b->current_bytes)
    {
        return -1;
    }

    if (flow_a->total_bytes <
        flow_b->total_bytes)
    {
        return 1;
    }

    if (flow_a->total_bytes >
        flow_b->total_bytes)
    {
        return -1;
    }

    return 0;
}

/* --------------------------------------------------------- */
/* Reset interval statistics                                 */
/* --------------------------------------------------------- */

static void reset_current_interval(void)
{
    int index;

    statistics.tcp_current = 0;
    statistics.udp_current = 0;
    statistics.icmp_current = 0;

    statistics.from_camera_bytes = 0;
    statistics.to_camera_bytes = 0;

    for (index = 0;
         index < flow_count;
         index++)
    {
        flows[index].current_packets = 0;
        flows[index].current_bytes = 0;
    }
}

/* --------------------------------------------------------- */
/* Display dashboard                                         */
/* --------------------------------------------------------- */

static void display_dashboard(double elapsed_seconds)
{
    Flow *ordered_flows[MAX_FLOWS];

    int ordered_count;
    int displayed_count;
    int index;

    double from_camera_mbps;
    double to_camera_mbps;

    if (elapsed_seconds <= 0.0)
        elapsed_seconds = 1.0;

    from_camera_mbps =
        ((double)statistics.from_camera_bytes * 8.0) /
        elapsed_seconds /
        1000000.0;

    to_camera_mbps =
        ((double)statistics.to_camera_bytes * 8.0) /
        elapsed_seconds /
        1000000.0;

    /*
     * Retain every discovered flow, even when the current rate
     * is zero.
     */
    ordered_count = flow_count;

    for (index = 0;
         index < ordered_count;
         index++)
    {
        ordered_flows[index] = &flows[index];
    }

    qsort(ordered_flows,
          (size_t)ordered_count,
          sizeof(ordered_flows[0]),
          compare_flows);

    displayed_count = ordered_count;

    if (displayed_count > DISPLAY_FLOWS)
        displayed_count = DISPLAY_FLOWS;

    /*
     * Move the cursor to the top-left without clearing the full
     * terminal.
     */
    printf("\033[H");

    printf(
        "+----------------------------------------------------------------------------------------------------------------+\n");

    printf(
        "|                                  SAMA5D3 CAMERA FLOW MONITOR                                                   |\n");

    printf(
        "+----------------------------------------------------------------------------------------------------------------+\n");

    printf(
        "| Camera: %-15s    Interface: %-7s    Discovered flows: %-3d                                         |\n",
        CAMERA_IP_TEXT,
        INTERFACE_NAME,
        flow_count);

    printf(
        "+----------------------------------------------------------------------------------------------------------------+\n");

    printf(
        "| CURRENT: TCP=%-8llu UDP=%-8llu ICMP=%-8llu   Camera RX=%7.3f Mbps   Camera TX=%7.3f Mbps       |\n",
        statistics.tcp_current,
        statistics.udp_current,
        statistics.icmp_current,
        from_camera_mbps,
        to_camera_mbps);

    printf(
        "+------+-----------------+-------+-----------------+-------+--------+-----------+----------+----------+------------+\n");

    printf(
        "| Prot | Source IP       | SPort | Destination IP  | DPort | Pkt/s  | kbit/s    | TotalPkt | Total MB | Type       |\n");

    printf(
        "+------+-----------------+-------+-----------------+-------+--------+-----------+----------+----------+------------+\n");

    for (index = 0;
         index < DISPLAY_FLOWS;
         index++)
    {
        if (index < displayed_count)
        {
            Flow *flow = ordered_flows[index];

            char source_ip[INET_ADDRSTRLEN];
            char destination_ip[INET_ADDRSTRLEN];

            const char *classification;

            double current_kbit_per_second;
            double total_megabytes;

            ip_to_text(flow->source_ip,
                       source_ip,
                       sizeof(source_ip));

            ip_to_text(flow->destination_ip,
                       destination_ip,
                       sizeof(destination_ip));

            classification =
                classify_flow(flow);

            current_kbit_per_second =
                ((double)flow->current_bytes * 8.0) /
                elapsed_seconds /
                1000.0;

            total_megabytes =
                (double)flow->total_bytes /
                1000000.0;

            if (flow->protocol == IPPROTO_ICMP)
            {
                printf(
                    "| %-4s | %-15s |   -   | %-15s |   -   | %-6llu | %-9.2f | %-8llu | %-8.3f | %-10s |\n",
                    protocol_name(flow->protocol),
                    source_ip,
                    destination_ip,
                    flow->current_packets,
                    current_kbit_per_second,
                    flow->total_packets,
                    total_megabytes,
                    classification);
            }
            else
            {
                printf(
                    "| %-4s | %-15s | %-5u | %-15s | %-5u | %-6llu | %-9.2f | %-8llu | %-8.3f | %-10s |\n",
                    protocol_name(flow->protocol),
                    source_ip,
                    flow->source_port,
                    destination_ip,
                    flow->destination_port,
                    flow->current_packets,
                    current_kbit_per_second,
                    flow->total_packets,
                    total_megabytes,
                    classification);
            }
        }
        else
        {
            /*
             * Blank rows overwrite rows from an earlier refresh.
             */
            printf(
                "|      |                 |       |                 |       |        |           |          |          |            |\n");
        }
    }

    printf(
        "+------+-----------------+-------+-----------------+-------+--------+-----------+----------+----------+------------+\n");

    printf(
        "| TOTALS: TCP=%-12llu UDP=%-12llu ICMP=%-12llu                                      |\n",
        statistics.tcp_total,
        statistics.udp_total,
        statistics.icmp_total);

    printf(
        "+----------------------------------------------------------------------------------------------------------------+\n");

    printf(
        "| Rows remain visible after traffic stops. Press Ctrl+C to stop.                                                  |\n");

    printf(
        "+----------------------------------------------------------------------------------------------------------------+\n");

    /*
     * Remove any old content below the dashboard.
     */
    printf("\033[J");

    fflush(stdout);
}

/* --------------------------------------------------------- */
/* Main                                                      */
/* --------------------------------------------------------- */

int main(void)
{
    int socket_fd;

    unsigned char buffer[BUFFER_SIZE];

    struct ifreq interface_request;
    struct sockaddr_ll bind_address;

    uint32_t camera_ip;

    double previous_display_time;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    memset(&statistics,
           0,
           sizeof(statistics));

    memset(flows,
           0,
           sizeof(flows));

    camera_ip =
        inet_addr(CAMERA_IP_TEXT);

    if (camera_ip == INADDR_NONE)
    {
        fprintf(stderr,
                "Invalid camera IP address: %s\n",
                CAMERA_IP_TEXT);

        return EXIT_FAILURE;
    }

    /*
     * Open raw Ethernet capture socket.
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
     * Use a one-second timeout so the screen is refreshed when
     * no packets are received.
     */
    {
        struct timeval timeout;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        if (setsockopt(socket_fd,
                       SOL_SOCKET,
                       SO_RCVTIMEO,
                       &timeout,
                       sizeof(timeout)) < 0)
        {
            perror("setsockopt");

            close(socket_fd);

            return EXIT_FAILURE;
        }
    }

    /*
     * Get the SAMA5D3 eth0 interface number.
     */
    memset(&interface_request,
           0,
           sizeof(interface_request));

    strncpy(interface_request.ifr_name,
            INTERFACE_NAME,
            IFNAMSIZ - 1);

    if (ioctl(socket_fd,
              SIOCGIFINDEX,
              &interface_request) < 0)
    {
        perror("SIOCGIFINDEX");

        close(socket_fd);

        return EXIT_FAILURE;
    }

    /*
     * Bind packet capture to eth0.
     */
    memset(&bind_address,
           0,
           sizeof(bind_address));

    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);

    bind_address.sll_ifindex =
        interface_request.ifr_ifindex;

    if (bind(socket_fd,
             (struct sockaddr *)&bind_address,
             sizeof(bind_address)) < 0)
    {
        perror("bind");

        close(socket_fd);

        return EXIT_FAILURE;
    }

    /*
     * Clear the terminal once and hide the cursor.
     */
    printf("\033[2J");
    printf("\033[H");
    printf("\033[?25l");

    fflush(stdout);

    previous_display_time =
        current_time_seconds();

    while (running)
    {
        ssize_t received_length;
        size_t packet_length;

        struct ethhdr *ethernet_header;
        struct iphdr *ip_header;

        unsigned short ethernet_type;

        size_t ip_offset;
        size_t ip_header_length;

        double now;
        double elapsed;

        received_length =
            recvfrom(socket_fd,
                     buffer,
                     sizeof(buffer),
                     0,
                     NULL,
                     NULL);

        if (received_length > 0)
        {
            packet_length =
                (size_t)received_length;

            if (packet_length >=
                sizeof(struct ethhdr))
            {
                ethernet_header =
                    (struct ethhdr *)buffer;

                ethernet_type =
                    ntohs(ethernet_header->h_proto);

                /*
                 * This version processes normal, untagged IPv4
                 * Ethernet frames.
                 */
                if (ethernet_type == ETH_P_IP)
                {
                    ip_offset =
                        sizeof(struct ethhdr);

                    if (packet_length >=
                        ip_offset +
                        sizeof(struct iphdr))
                    {
                        ip_header =
                            (struct iphdr *)
                            (buffer + ip_offset);

                        ip_header_length =
                            (size_t)ip_header->ihl * 4U;

                        if ((ip_header_length >=
                             sizeof(struct iphdr)) &&
                            (packet_length >=
                             ip_offset +
                             ip_header_length))
                        {
                            /*
                             * Keep only camera-related traffic.
                             */
                            if ((ip_header->saddr ==
                                 camera_ip) ||
                                (ip_header->daddr ==
                                 camera_ip))
                            {
                                if (ip_header->saddr ==
                                    camera_ip)
                                {
                                    statistics
                                        .from_camera_bytes +=
                                        packet_length;
                                }

                                if (ip_header->daddr ==
                                    camera_ip)
                                {
                                    statistics
                                        .to_camera_bytes +=
                                        packet_length;
                                }

                                switch (ip_header->protocol)
                                {
                                    case IPPROTO_TCP:

                                        process_tcp(
                                            buffer,
                                            packet_length,
                                            ip_offset,
                                            ip_header);

                                        break;

                                    case IPPROTO_UDP:

                                        process_udp(
                                            buffer,
                                            packet_length,
                                            ip_offset,
                                            ip_header);

                                        break;

                                    case IPPROTO_ICMP:

                                        process_icmp(
                                            packet_length,
                                            ip_header);

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
        else if ((errno != EAGAIN) &&
                 (errno != EWOULDBLOCK) &&
                 (errno != EINTR))
        {
            perror("recvfrom");
            break;
        }

        now =
            current_time_seconds();

        elapsed =
            now - previous_display_time;

        if (elapsed >= DISPLAY_INTERVAL_SEC)
        {
            display_dashboard(elapsed);

            reset_current_interval();

            previous_display_time = now;
        }
    }

    close(socket_fd);

    /*
     * Restore terminal cursor and clear the dashboard.
     */
    printf("\033[?25h");
    printf("\033[2J");
    printf("\033[H");

    printf("Camera flow monitor stopped.\n");

    return EXIT_SUCCESS;
}