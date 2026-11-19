/*
 * camera_protocol_monitor_v2.c
 *
 * SAMA5D3 camera protocol and port monitor
 *
 * Monitors Ethernet frames visible on eth0 and classifies traffic
 * involving camera 192.168.1.10.
 *
 * Detects:
 *   - ARP
 *   - ICMP
 *   - TCP
 *   - UDP
 *   - TCP/80 as HTTP candidate
 *   - TCP/443 as HTTPS candidate
 *   - TCP/554 as RTSP candidate
 *   - UDP/55555 as controlled abnormal-test traffic
 *   - Basic RTP candidates using the RTP header format
 *
 * Build:
 *   arm-linux-gnueabihf-gcc -static -Wall -Wextra -O2 \
 *       camera_protocol_monitor_v2.c \
 *       -o camera_protocol_monitor_v2
 *
 * Run as root:
 *   ./camera_protocol_monitor_v2
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

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
#include <linux/icmp.h>

/* ---------------------------------------------------------- */
/* Configuration                                              */
/* ---------------------------------------------------------- */

#define INTERFACE_NAME             "eth0"
#define CAMERA_IP_TEXT             "192.168.1.10"

/*
 * Controlled test port.
 *
 * Configure your Python test program to send UDP traffic to
 * camera port 55555.
 */
#define ABNORMAL_TEST_PORT         55555

/*
 * Display a summary every second.
 */
#define DISPLAY_INTERVAL_SECONDS   1

/*
 * Generate a warning if unexpected traffic exceeds this
 * packet rate.
 */
#define UNEXPECTED_RATE_WARNING    100

/*
 * Require several consecutive warning samples before declaring
 * an anomaly.
 */
#define ANOMALY_CONFIRM_SAMPLES    3

/*
 * Maximum frame size captured.
 */
#define CAPTURE_BUFFER_SIZE        65536

/*
 * Maximum number of UDP ports retained in the small runtime
 * port table.
 */
#define MAX_PORT_RECORDS           64

/* ---------------------------------------------------------- */
/* Global control                                             */
/* ---------------------------------------------------------- */

static volatile sig_atomic_t running = 1;

/* ---------------------------------------------------------- */
/* Statistics structures                                      */
/* ---------------------------------------------------------- */

typedef struct
{
    unsigned long long total_frames;

    unsigned long long arp_packets;
    unsigned long long ipv4_packets;
    unsigned long long tcp_packets;
    unsigned long long udp_packets;
    unsigned long long icmp_packets;
    unsigned long long other_ipv4_packets;

    unsigned long long from_camera_packets;
    unsigned long long to_camera_packets;

    unsigned long long http_packets;
    unsigned long long https_packets;
    unsigned long long rtsp_packets;
    unsigned long long rtp_candidate_packets;

    unsigned long long abnormal_test_packets;
    unsigned long long unexpected_packets;

    unsigned long long from_camera_bytes;
    unsigned long long to_camera_bytes;

} TrafficStats;

typedef struct
{
    uint16_t port;
    unsigned long long packets;
} PortRecord;

/* ---------------------------------------------------------- */
/* Global statistics                                          */
/* ---------------------------------------------------------- */

static TrafficStats total_stats;
static TrafficStats interval_stats;

static PortRecord udp_ports[MAX_PORT_RECORDS];
static int udp_port_count = 0;

static int consecutive_anomaly_samples = 0;

/* ---------------------------------------------------------- */
/* Signal handling                                            */
/* ---------------------------------------------------------- */

static void signal_handler(int signal_number)
{
    (void)signal_number;
    running = 0;
}

/* ---------------------------------------------------------- */
/* Time helper                                                */
/* ---------------------------------------------------------- */

static double current_time_seconds(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return 0.0;

    return (double)tv.tv_sec +
           ((double)tv.tv_usec / 1000000.0);
}

/* ---------------------------------------------------------- */
/* IP address helper                                          */
/* ---------------------------------------------------------- */

static void ip_to_text(uint32_t address,
                       char *output,
                       size_t output_size)
{
    struct in_addr addr;

    addr.s_addr = address;

    if (inet_ntop(AF_INET,
                  &addr,
                  output,
                  output_size) == NULL)
    {
        snprintf(output,
                 output_size,
                 "unknown");
    }
}

/* ---------------------------------------------------------- */
/* UDP port table                                             */
/* ---------------------------------------------------------- */

static void count_udp_port(uint16_t port)
{
    int i;

    for (i = 0; i < udp_port_count; i++)
    {
        if (udp_ports[i].port == port)
        {
            udp_ports[i].packets++;
            return;
        }
    }

    if (udp_port_count < MAX_PORT_RECORDS)
    {
        udp_ports[udp_port_count].port = port;
        udp_ports[udp_port_count].packets = 1;
        udp_port_count++;
    }
}

/* ---------------------------------------------------------- */
/* Basic RTP detection                                        */
/* ---------------------------------------------------------- */

/*
 * RTP normally has at least a 12-byte header.
 *
 * The first two bits of the first byte contain the RTP version.
 * RTP version 2 gives:
 *
 *     payload[0] >> 6 == 2
 *
 * This is only a candidate check. Random UDP payloads can
 * accidentally match this format.
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

    /*
     * Ignore the marker bit and read the 7-bit payload type.
     */
    payload_type = payload[1] & 0x7F;

    /*
     * Payload types 72-76 are normally reserved for RTCP
     * conflict avoidance, so exclude this small range from
     * the simple RTP candidate check.
     */
    if ((payload_type >= 72) && (payload_type <= 76))
        return 0;

    return 1;
}

/* ---------------------------------------------------------- */
/* Print one interesting packet                               */
/* ---------------------------------------------------------- */

static void print_flow(const char *protocol,
                       const char *src_ip,
                       uint16_t src_port,
                       const char *dst_ip,
                       uint16_t dst_port,
                       const char *classification)
{
    printf("%-5s %-15s:%-5u -> %-15s:%-5u",
           protocol,
           src_ip,
           src_port,
           dst_ip,
           dst_port);

    if ((classification != NULL) &&
        (classification[0] != '\0'))
    {
        printf("  [%s]", classification);
    }

    printf("\n");
}

/* ---------------------------------------------------------- */
/* Classify TCP traffic                                       */
/* ---------------------------------------------------------- */

static void process_tcp(const unsigned char *buffer,
                        ssize_t packet_length,
                        size_t ip_offset,
                        const struct iphdr *ip,
                        const char *src_ip,
                        const char *dst_ip)
{
    size_t ip_header_length;
    size_t tcp_offset;
    size_t tcp_header_length;

    const struct tcphdr *tcp;

    uint16_t src_port;
    uint16_t dst_port;

    const char *classification = "TCP";

    ip_header_length = (size_t)ip->ihl * 4U;
    tcp_offset = ip_offset + ip_header_length;

    if ((size_t)packet_length <
        tcp_offset + sizeof(struct tcphdr))
    {
        return;
    }

    tcp = (const struct tcphdr *)(buffer + tcp_offset);

    tcp_header_length = (size_t)tcp->doff * 4U;

    if (tcp_header_length < sizeof(struct tcphdr))
        return;

    if ((size_t)packet_length <
        tcp_offset + tcp_header_length)
    {
        return;
    }

    src_port = ntohs(tcp->source);
    dst_port = ntohs(tcp->dest);

    total_stats.tcp_packets++;
    interval_stats.tcp_packets++;

    if ((src_port == 80) || (dst_port == 80))
    {
        classification = "HTTP candidate";

        total_stats.http_packets++;
        interval_stats.http_packets++;
    }
    else if ((src_port == 443) || (dst_port == 443))
    {
        classification = "HTTPS candidate";

        total_stats.https_packets++;
        interval_stats.https_packets++;
    }
    else if ((src_port == 554) || (dst_port == 554))
    {
        classification = "RTSP candidate";

        total_stats.rtsp_packets++;
        interval_stats.rtsp_packets++;
    }
    else
    {
        /*
         * At this stage, unknown TCP traffic involving the camera
         * is counted as unexpected.
         *
         * Later, add known camera TCP ports to an allowlist.
         */
        total_stats.unexpected_packets++;
        interval_stats.unexpected_packets++;

        classification = "UNEXPECTED TCP";
    }

    print_flow("TCP",
               src_ip,
               src_port,
               dst_ip,
               dst_port,
               classification);
}

/* ---------------------------------------------------------- */
/* Classify UDP traffic                                       */
/* ---------------------------------------------------------- */

static void process_udp(const unsigned char *buffer,
                        ssize_t packet_length,
                        size_t ip_offset,
                        const struct iphdr *ip,
                        const char *src_ip,
                        const char *dst_ip)
{
    size_t ip_header_length;
    size_t udp_offset;
    size_t payload_offset;
    size_t payload_length;

    const struct udphdr *udp;
    const unsigned char *payload;

    uint16_t src_port;
    uint16_t dst_port;
    uint16_t udp_length;

    const char *classification = "UDP";

    ip_header_length = (size_t)ip->ihl * 4U;
    udp_offset = ip_offset + ip_header_length;

    if ((size_t)packet_length <
        udp_offset + sizeof(struct udphdr))
    {
        return;
    }

    udp = (const struct udphdr *)(buffer + udp_offset);

    src_port = ntohs(udp->source);
    dst_port = ntohs(udp->dest);
    udp_length = ntohs(udp->len);

    total_stats.udp_packets++;
    interval_stats.udp_packets++;

    count_udp_port(src_port);
    count_udp_port(dst_port);

    payload_offset = udp_offset + sizeof(struct udphdr);

    if ((udp_length >= sizeof(struct udphdr)) &&
        ((size_t)packet_length > payload_offset))
    {
        payload_length =
            (size_t)udp_length -
            sizeof(struct udphdr);

        if (payload_offset + payload_length >
            (size_t)packet_length)
        {
            payload_length =
                (size_t)packet_length -
                payload_offset;
        }

        payload = buffer + payload_offset;
    }
    else
    {
        payload = NULL;
        payload_length = 0;
    }

    /*
     * Controlled abnormal-test traffic.
     */
    if ((src_port == ABNORMAL_TEST_PORT) ||
        (dst_port == ABNORMAL_TEST_PORT))
    {
        classification = "ABNORMAL TEST UDP";

        total_stats.abnormal_test_packets++;
        interval_stats.abnormal_test_packets++;

        total_stats.unexpected_packets++;
        interval_stats.unexpected_packets++;
    }

    /*
     * Simple RTP candidate detection.
     *
     * Do not call every UDP packet RTP. Inspect the RTP
     * version/header pattern first.
     */
    else if (looks_like_rtp(payload, payload_length))
    {
        classification = "RTP candidate";

        total_stats.rtp_candidate_packets++;
        interval_stats.rtp_candidate_packets++;
    }

    /*
     * Other UDP traffic is currently unexpected unless it
     * matches RTP formatting.
     *
     * Later, add learned ONVIF, RTCP and camera-service ports.
     */
    else
    {
        classification = "UNEXPECTED UDP";

        total_stats.unexpected_packets++;
        interval_stats.unexpected_packets++;
    }

    print_flow("UDP",
               src_ip,
               src_port,
               dst_ip,
               dst_port,
               classification);
}

/* ---------------------------------------------------------- */
/* Display summary                                            */
/* ---------------------------------------------------------- */

static void display_summary(double interval_seconds)
{
    double from_camera_mbps;
    double to_camera_mbps;

    unsigned long long unexpected_rate;

    if (interval_seconds <= 0.0)
        interval_seconds = 1.0;

    from_camera_mbps =
        ((double)interval_stats.from_camera_bytes * 8.0) /
        interval_seconds /
        1000000.0;

    to_camera_mbps =
        ((double)interval_stats.to_camera_bytes * 8.0) /
        interval_seconds /
        1000000.0;

    unexpected_rate =
        (unsigned long long)
        ((double)interval_stats.unexpected_packets /
         interval_seconds);

    printf("\n");
    printf("============================================================\n");
    printf(" SAMA5D3 CAMERA PROTOCOL MONITOR\n");
    printf("============================================================\n");

    printf("Interface : %s\n", INTERFACE_NAME);
    printf("Camera    : %s\n", CAMERA_IP_TEXT);

    printf("\nCURRENT SAMPLE\n");
    printf("------------------------------------------------------------\n");

    printf("ARP                 : %llu\n",
           interval_stats.arp_packets);

    printf("ICMP                : %llu\n",
           interval_stats.icmp_packets);

    printf("TCP                 : %llu\n",
           interval_stats.tcp_packets);

    printf("UDP                 : %llu\n",
           interval_stats.udp_packets);

    printf("HTTP candidates     : %llu\n",
           interval_stats.http_packets);

    printf("HTTPS candidates    : %llu\n",
           interval_stats.https_packets);

    printf("RTSP candidates     : %llu\n",
           interval_stats.rtsp_packets);

    printf("RTP candidates      : %llu\n",
           interval_stats.rtp_candidate_packets);

    printf("UDP/%d test packets : %llu\n",
           ABNORMAL_TEST_PORT,
           interval_stats.abnormal_test_packets);

    printf("Unexpected packets  : %llu\n",
           interval_stats.unexpected_packets);

    printf("\nCAMERA DIRECTION\n");
    printf("------------------------------------------------------------\n");

    printf("From camera packets : %llu\n",
           interval_stats.from_camera_packets);

    printf("To camera packets   : %llu\n",
           interval_stats.to_camera_packets);

    printf("From camera rate    : %.3f Mbps\n",
           from_camera_mbps);

    printf("To camera rate      : %.3f Mbps\n",
           to_camera_mbps);

    printf("\nANOMALY CHECK\n");
    printf("------------------------------------------------------------\n");

    printf("Unexpected rate     : %llu packets/sec\n",
           unexpected_rate);

    if (unexpected_rate >= UNEXPECTED_RATE_WARNING)
    {
        consecutive_anomaly_samples++;

        printf("Sample result       : WARNING %d/%d\n",
               consecutive_anomaly_samples,
               ANOMALY_CONFIRM_SAMPLES);
    }
    else
    {
        consecutive_anomaly_samples = 0;

        printf("Sample result       : NORMAL\n");
    }

    if (consecutive_anomaly_samples >=
        ANOMALY_CONFIRM_SAMPLES)
    {
        printf("\n");
        printf("************************************************************\n");
        printf(" ABNORMAL TRAFFIC CONFIRMED\n");
        printf(" Unexpected traffic exceeded %d packets/sec for %d samples.\n",
               UNEXPECTED_RATE_WARNING,
               ANOMALY_CONFIRM_SAMPLES);
        printf("************************************************************\n");
    }

    printf("\nTOTALS\n");
    printf("------------------------------------------------------------\n");

    printf("Total frames        : %llu\n",
           total_stats.total_frames);

    printf("TCP total           : %llu\n",
           total_stats.tcp_packets);

    printf("UDP total           : %llu\n",
           total_stats.udp_packets);

    printf("ICMP total          : %llu\n",
           total_stats.icmp_packets);

    printf("Unexpected total    : %llu\n",
           total_stats.unexpected_packets);

    printf("\nPress Ctrl+C to stop.\n\n");
}

/* ---------------------------------------------------------- */
/* Main                                                       */
/* ---------------------------------------------------------- */

int main(void)
{
    int socket_fd;

    unsigned char buffer[CAPTURE_BUFFER_SIZE];

    struct ifreq ifr;
    struct sockaddr_ll bind_address;

    uint32_t camera_ip;

    double previous_display_time;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    camera_ip = inet_addr(CAMERA_IP_TEXT);

    if (camera_ip == INADDR_NONE)
    {
        fprintf(stderr,
                "Invalid camera IP: %s\n",
                CAMERA_IP_TEXT);

        return EXIT_FAILURE;
    }

    memset(&total_stats, 0, sizeof(total_stats));
    memset(&interval_stats, 0, sizeof(interval_stats));
    memset(udp_ports, 0, sizeof(udp_ports));

    /*
     * Open raw Ethernet socket.
     *
     * This requires root privileges.
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
     * Obtain interface index.
     */
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name,
            INTERFACE_NAME,
            IFNAMSIZ - 1);

    if (ioctl(socket_fd,
              SIOCGIFINDEX,
              &ifr) < 0)
    {
        perror("SIOCGIFINDEX");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    /*
     * Bind packet capture to SAMA5D3 eth0.
     */
    memset(&bind_address, 0, sizeof(bind_address));

    bind_address.sll_family =
        AF_PACKET;

    bind_address.sll_protocol =
        htons(ETH_P_ALL);

    bind_address.sll_ifindex =
        ifr.ifr_ifindex;

    if (bind(socket_fd,
             (struct sockaddr *)&bind_address,
             sizeof(bind_address)) < 0)
    {
        perror("bind");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("Monitoring camera %s on %s\n",
           CAMERA_IP_TEXT,
           INTERFACE_NAME);

    printf("Controlled abnormal-test UDP port: %d\n",
           ABNORMAL_TEST_PORT);

    printf("Press Ctrl+C to stop.\n\n");

    previous_display_time = current_time_seconds();

    while (running)
    {
        ssize_t packet_length;

        struct ethhdr *ethernet;
        struct iphdr *ip;

        unsigned short ethernet_type;

        size_t ip_offset;
        size_t ip_header_length;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        double now;
        double elapsed;

        packet_length =
            recvfrom(socket_fd,
                     buffer,
                     sizeof(buffer),
                     0,
                     NULL,
                     NULL);

        if (packet_length <= 0)
        {
            if (errno == EINTR)
                continue;

            perror("recvfrom");
            break;
        }

        total_stats.total_frames++;
        interval_stats.total_frames++;

        if ((size_t)packet_length <
            sizeof(struct ethhdr))
        {
            continue;
        }

        ethernet =
            (struct ethhdr *)buffer;

        ethernet_type =
            ntohs(ethernet->h_proto);

        /*
         * Count ARP frames.
         *
         * This first version counts all ARP visible on eth0,
         * because additional ARP-header parsing would be needed
         * to filter by camera IP.
         */
        if (ethernet_type == ETH_P_ARP)
        {
            total_stats.arp_packets++;
            interval_stats.arp_packets++;
        }

        else if (ethernet_type == ETH_P_IP)
        {
            ip_offset = sizeof(struct ethhdr);

            if ((size_t)packet_length <
                ip_offset + sizeof(struct iphdr))
            {
                continue;
            }

            ip =
                (struct iphdr *)(buffer + ip_offset);

            ip_header_length =
                (size_t)ip->ihl * 4U;

            if (ip_header_length <
                sizeof(struct iphdr))
            {
                continue;
            }

            if ((size_t)packet_length <
                ip_offset + ip_header_length)
            {
                continue;
            }

            /*
             * Ignore IPv4 traffic that does not involve the
             * camera.
             */
            if ((ip->saddr != camera_ip) &&
                (ip->daddr != camera_ip))
            {
                continue;
            }

            total_stats.ipv4_packets++;
            interval_stats.ipv4_packets++;

            ip_to_text(ip->saddr,
                       src_ip,
                       sizeof(src_ip));

            ip_to_text(ip->daddr,
                       dst_ip,
                       sizeof(dst_ip));

            /*
             * Direction relative to camera.
             */
            if (ip->saddr == camera_ip)
            {
                total_stats.from_camera_packets++;
                interval_stats.from_camera_packets++;

                total_stats.from_camera_bytes +=
                    (unsigned long long)packet_length;

                interval_stats.from_camera_bytes +=
                    (unsigned long long)packet_length;
            }

            if (ip->daddr == camera_ip)
            {
                total_stats.to_camera_packets++;
                interval_stats.to_camera_packets++;

                total_stats.to_camera_bytes +=
                    (unsigned long long)packet_length;

                interval_stats.to_camera_bytes +=
                    (unsigned long long)packet_length;
            }

            switch (ip->protocol)
            {
                case IPPROTO_ICMP:
                    total_stats.icmp_packets++;
                    interval_stats.icmp_packets++;

                    printf("ICMP  %-15s -> %-15s\n",
                           src_ip,
                           dst_ip);
                    break;

                case IPPROTO_TCP:
                    process_tcp(buffer,
                                packet_length,
                                ip_offset,
                                ip,
                                src_ip,
                                dst_ip);
                    break;

                case IPPROTO_UDP:
                    process_udp(buffer,
                                packet_length,
                                ip_offset,
                                ip,
                                src_ip,
                                dst_ip);
                    break;

                default:
                    total_stats.other_ipv4_packets++;
                    interval_stats.other_ipv4_packets++;

                    printf("IP%-3u %-15s -> %-15s\n",
                           ip->protocol,
                           src_ip,
                           dst_ip);
                    break;
            }
        }

        now = current_time_seconds();
        elapsed = now - previous_display_time;

        if (elapsed >= DISPLAY_INTERVAL_SECONDS)
        {
            display_summary(elapsed);

            memset(&interval_stats,
                   0,
                   sizeof(interval_stats));

            previous_display_time = now;
        }
    }

    close(socket_fd);

    printf("\nMonitor stopped.\n");

    return EXIT_SUCCESS;
}