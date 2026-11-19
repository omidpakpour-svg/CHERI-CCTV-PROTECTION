#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/input.h>
#include <errno.h>
#include <string.h>

#define SW4_DEVICE "/dev/input/event0"
#define SW4_KEY_CODE 260

#define PORT1_RX "/sys/bus/spi/devices/spi0.0/sw1/1_rx"
#define PORT1_TX "/sys/bus/spi/devices/spi0.0/sw1/1_tx"

static int write_value(const char *path, int value)
{
    int fd;
    char data[2];

    fd = open(path, O_WRONLY);

    if (fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    data[0] = value ? '1' : '0';
    data[1] = '\n';

    if (write(fd, data, 2) != 2) {
        fprintf(stderr, "Cannot write %s\n", path);
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int set_port(int enable)
{
    printf("\n");

    if (enable)
        printf("RESTORING KSZ9893 PORT 1...\n");
    else
        printf("BLOCKING KSZ9893 PORT 1...\n");

    if (write_value(PORT1_RX, enable) != 0)
        return -1;

    if (write_value(PORT1_TX, enable) != 0)
        return -1;

    printf("1_rx = %d\n", enable);
    printf("1_tx = %d\n", enable);

    if (enable)
        printf("PORT 1 RESTORED\n");
    else
        printf("PORT 1 BLOCKED\n");

    return 0;
}

int main(void)
{
    int fd;
    int blocked = 0;
    struct input_event ev;

    printf("\nKSZ9893 SW4 controller\n");
    printf("------------------------\n");
    printf("SW4: %s\n", SW4_DEVICE);
    printf("RX : %s\n", PORT1_RX);
    printf("TX : %s\n\n", PORT1_TX);

    fd = open(SW4_DEVICE, O_RDONLY);

    if (fd < 0) {
        perror("Cannot open SW4");
        return 1;
    }

    printf("Waiting for SW4...\n");

    while (1) {

        if (read(fd, &ev, sizeof(ev)) != sizeof(ev))
            continue;

        if (ev.type == EV_KEY &&
            ev.code == SW4_KEY_CODE &&
            ev.value == 1) {

            printf("\nSW4 PRESSED\n");

            if (!blocked) {

                if (set_port(0) == 0)
                    blocked = 1;

            } else {

                if (set_port(1) == 0)
                    blocked = 0;
            }

            usleep(200000);

            printf("\nWaiting for SW4...\n");
        }
    }

    close(fd);
    return 0;
}
