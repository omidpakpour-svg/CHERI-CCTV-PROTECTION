# CHERI-CCTV-PROTECTION
ATC WORK

## Testing camera traffic mirroring on the SAM board

Build [the monitor](camera_protocol_monitor_v4.c) on Ubuntu:

```sh
arm-linux-gnueabihf-gcc -static -Wall -Wextra -O2 \
  camera_protocol_monitor_v4.c -o camera_protocol_monitor_v4
```

Copy the rebuilt executable to the SAM board and run it with raw packet
capture permissions. It listens in promiscuous mode on `eth0` and reports
untagged and VLAN-tagged IPv4 traffic to or from the camera (`192.168.1.10`).

Run [the test sender](traffic_test.py) on Ubuntu with `192.168.1.25` assigned.
If the switch is mirroring traffic toward the camera to the SAM CPU port,
the monitor should show a UDP flow from `192.168.1.25` to
`192.168.1.10:55559`, with the packet count increasing.
