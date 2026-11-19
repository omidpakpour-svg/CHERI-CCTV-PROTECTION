#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MIB_FILE "/sys/bus/spi/devices/spi0.0/sw1/1_mib"

typedef struct
{
    unsigned long long rx_total;
    unsigned long long tx_total;
    unsigned long long rx_discards;
    unsigned long long tx_discards;
    unsigned long long rx_crc_err;
} Stats;

int read_stats(Stats *s)
{
    FILE *fp = fopen(MIB_FILE, "r");

    if (fp == NULL)
    {
        perror("Cannot open KSZ9893 MIB");
        return -1;
    }

    char line[256];

    while (fgets(line, sizeof(line), fp))
    {
        sscanf(line, "rx_total = %llu", &s->rx_total);
        sscanf(line, "tx_total = %llu", &s->tx_total);
        sscanf(line, "rx_discards = %llu", &s->rx_discards);
        sscanf(line, "tx_discards = %llu", &s->tx_discards);
        sscanf(line, "rx_crc_err = %llu", &s->rx_crc_err);
    }

    fclose(fp);
    return 0;
}

int main(void)
{
    Stats previous = {0};
    Stats current = {0};

    if (read_stats(&previous) != 0)
        return 1;

    printf("\nKSZ9893 Camera Monitor\n");
    printf("==============================\n");
    printf("Monitoring switch port sw1\n");
    printf("Press Ctrl+C to stop\n\n");

    printf(" RX change     TX change     RX drop   TX drop   CRC\n");
    printf("------------------------------------------------------\n");

    while (1)
    {
        sleep(1);

        current = (Stats){0};

        if (read_stats(&current) != 0)
            return 1;

        printf("%10llu   %10llu   %7llu   %7llu   %5llu\n",
               current.rx_total - previous.rx_total,
               current.tx_total - previous.tx_total,
               current.rx_discards,
               current.tx_discards,
               current.rx_crc_err);

        previous = current;
    }

    return 0;
}