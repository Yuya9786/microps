#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test/test.h"

static volatile sig_atomic_t terminate;

struct ping {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
    struct timeval timestamp;
};

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

static void
ping_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *iphdr;
    uint8_t v;
    uint16_t iphlen, total, offset;
    struct ip_iface *iface;
    struct icmp_hdr *icmphdr;
    struct ping *ping;
    int id;
    char addr1[IP_ADDR_STR_LEN];
    struct timeval now, diff;
    double rtt;

    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }
    iphdr = (struct ip_hdr *)data;
    v = iphdr->vhl >> 4;
    if (v != IP_VERSION_IPV4) {
        errorf("ip version error: v=%u", v);
        return;
    }
    iphlen = (iphdr->vhl & 0x0f) << 2;
    if (len < iphlen) {
        errorf("header length error: len=%zu < hlen=%u", len, iphlen);
        return;
    }
    total = ntoh16(iphdr->total);
    if (len < total) {
        errorf("total length error: len=%zu < total=%u", len, total);
        return;
    }
    if (cksum16((uint16_t *)iphdr, iphlen, 0) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(iphdr->sum), ntoh16(cksum16((uint16_t *)iphdr, iphlen, -iphdr->sum)));
        return;
    }
    offset = ntoh16(iphdr->offset);
    if (offset & 0x2000 || offset & 0x1fff) {
        errorf("fragments does not support");
        return;
    }
    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (!iface) {
        /* iface is not registered to the device */
        return;
    }
    if (iphdr->dst != iface->unicast) {
        if (iphdr->dst != iface->broadcast && iphdr->dst != IP_ADDR_BROADCAST) {
            /* for other host */
            return;
        }
    }
    icmphdr = (struct icmp_hdr *)(data + iphlen);
    switch (icmphdr->type) {
    case ICMP_TYPE_ECHOREPLY:
        ping = (struct ping *)icmphdr;
        id = getpid() % UINT16_MAX;
        if (ntoh16(ping->id) != id) {
            return;
        }
        if (len < sizeof(*ping)) {
            return;
        }
        gettimeofday(&now, NULL);
        timersub(&now, &ping->timestamp, &diff);
        rtt = diff.tv_sec * 1000.0 + diff.tv_usec / 1000.0;
        debugf("%zu bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms", len, ip_addr_ntop(iphdr->src, addr1, sizeof(addr1)), ping->seq, iphdr->ttl, rtt);
        break;
    default:
        /* ignore */
        break;
    }
}

int
ping_init(void)
{
    if (arp_init() == -1) {
        errorf("arp_init() failure");
        return -1;
    }
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ping_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    if (ping_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

static void
cleanup(void)
{
    net_shutdown();
}

int
main(int argc, char *argv[])
{
    ip_addr_t src, dst;
    uint16_t id, seq = 0;
    struct timeval now;

    signal(SIGINT, on_signal);
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    ip_addr_pton("192.0.2.2", &src);
    ip_addr_pton("8.8.8.8", &dst);
    id = getpid() % UINT16_MAX;
    while (!terminate) {
        gettimeofday(&now, NULL);
        if (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | ++seq), (const uint8_t *)&now, sizeof(now), src, dst) == -1) {
            errorf("icmp_output() failure");
            break;
        }
        sleep(1);
    }
    cleanup();
    return 0;
}
