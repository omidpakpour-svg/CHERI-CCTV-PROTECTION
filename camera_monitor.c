#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/input.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

/* ============================================================
   CONFIGURATION
   ============================================================ */

/* Built-in SAMA5D3 SW4 */
#define SW4_DEVICE   "/dev/input/event0"

/* Confirmed from your hexdump */
#define SW4_KEY_CODE 260

/* KSZ9893 Port 1 sysfs controls */
#define PORT1_RX "/sys/bus/spi/devices/spi0.0/sw1/1_rx"
#define PORT1_TX "/sys/bus/spi/devices/spi0.0/sw1/1_tx"

/* ============================================================
   GLOBAL
   ============================================================ */

static volatile sig_atomic_t running = 1;


/* ============================================================
   SIGNAL HANDLER
   ============================================================ */

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}


/* ============================================================
   WRITE VALUE TO SYSFS
   ============================================================ */

static int write_sysfs(const char *path, int value)
{
    int fd;
    char buffer[4];
    int length;

    fd = open(path, O_WRONLY);

    if (fd < 0)
    {
        fprintf(stderr,
                "ERROR opening %s: %s\n",
                path,
                strerror(errno));

        return -1;
    }

    length = snprintf(buffer,
                      sizeof(buffer),
                      "%d\n",
                      value);

    if (write(fd, buffer, length) != length)
    {
        fprintf(stderr,
                "ERROR writing %s: %s\n",
                path,
                strerror(errno));

        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}

