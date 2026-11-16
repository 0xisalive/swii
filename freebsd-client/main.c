/*
 * ukvm - minimal low-latency UDP software KVM
 *
 * freebsd-client/main.c - FreeBSD injection side (client).
 *
 * Listens for UDP datagrams from the macOS host, validates and decrypts
 * them, and replays the input onto a virtual HID device created through
 * /dev/uinput. Tracks every pressed key and button so a lost "release"
 * packet, a heartbeat saying the host went inactive, or a stall can be
 * recovered from without leaving keys stuck down.
 *
 * Build:
 *   cc -Wall -Wextra -O2 -std=c11 freebsd-client/main.c -o ukvm-client
 *
 * evdev headers live under <dev/evdev/> on FreeBSD, not <linux/>.
 */

/*
 * On FreeBSD the POSIX interfaces below are visible by default. When this
 * file is cross-checked against glibc (Linux), request the POSIX surface
 * so clock_gettime(), CLOCK_MONOTONIC and sigaction are declared.
 */
#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/protocol.h"
#include "../common/crypto.h"
#include "../common/hid_keymap.h"

#if defined(__FreeBSD__)
#include <dev/evdev/input.h>
#include <dev/evdev/uinput.h>
#define UKVM_HAVE_UINPUT 1
#elif defined(__linux__) && defined(UKVM_USE_LINUX_UINPUT)
#include <linux/input.h>
#include <linux/uinput.h>
#define UKVM_HAVE_UINPUT 1
#endif

/*
 * KEY_MAX / BTN_* arrive from the evdev header on the target. When building
 * off-target for a syntax check, hid_keymap.h supplies the numeric fallback
 * constants and we define the few extra bits uinput needs here.
 */
#ifndef KEY_MAX
#define KEY_MAX 0x2ff
#endif
#ifndef KEY_CNT
#define KEY_CNT (KEY_MAX + 1)
#endif

/* ----------------------------------------------------------------------- */
/* Global state (touched by the signal handler, hence file scope)          */
/* ----------------------------------------------------------------------- */

struct client_state {
    int      uinput_fd;
    int      sock;
    uint32_t magic;
    struct ukvm_chacha_ctx crypto;

    bool     active;                 /* client currently "grabbed" */
    uint16_t last_mouse_seq;         /* for mouse-move ordering */
    bool     have_mouse_seq;

    /* Which evdev codes are currently held down. Indexed by evdev code so a
     * single pass can release everything. Covers keys and mouse buttons. */
    uint8_t  down[KEY_CNT];
};

static struct client_state g_state;
static volatile sig_atomic_t g_stop = 0;

/* ----------------------------------------------------------------------- */
/* Time helper                                                             */
/* ----------------------------------------------------------------------- */

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ----------------------------------------------------------------------- */
/* uinput event emission                                                   */
/* ----------------------------------------------------------------------- */

#if defined(UKVM_HAVE_UINPUT)

static void emit(int fd, uint16_t type, uint16_t code, int32_t value) {
    struct input_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type  = type;
    ev.code  = code;
    ev.value = value;
    /* time is filled by the kernel for uinput; leaving it zero is fine. */
    ssize_t n = write(fd, &ev, sizeof(ev));
    if (n != (ssize_t)sizeof(ev) && errno != EAGAIN)
        fprintf(stderr, "ukvm-client: write(uinput): %s\n", strerror(errno));
}

static void syn(int fd) {
    emit(fd, EV_SYN, SYN_REPORT, 0);
}

/*
 * Track a key/button transition in the down[] table so the watchdog can
 * release it later. `code` is an evdev code; `value` is 1 (down), 0 (up),
 * or 2 (autorepeat).
 */
static void track(uint16_t code, int32_t value) {
    if (code >= KEY_CNT)
        return;
    g_state.down[code] = (value != 0) ? 1 : 0;
}

/* Release every key and button currently marked down, then clear active. */
static void release_all(void) {
    for (int code = 0; code < KEY_CNT; code++) {
        if (g_state.down[code]) {
            emit(g_state.uinput_fd, EV_KEY, (uint16_t)code, 0);
            g_state.down[code] = 0;
        }
    }
    syn(g_state.uinput_fd);
    g_state.active = false;
}

/* ----------------------------------------------------------------------- */
/* Virtual device setup                                                    */
/* ----------------------------------------------------------------------- */

static int uinput_setup(void) {
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr,
            "ukvm-client: cannot open /dev/uinput: %s\n"
            "  Ensure the module is loaded:   kldload uinput\n"
            "  and that you have permission (run as root, or set a\n"
            "  devfs rule granting rw on uinput, e.g. in /etc/devfs.rules:\n"
            "    add path 'uinput' mode 0660 group wheel\n"
            "  then: service devfs restart).\n",
            strerror(errno));
        return -1;
    }

    /* Event classes. */
    if (ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0 ||
        ioctl(fd, UI_SET_EVBIT, EV_REL) < 0 ||
        ioctl(fd, UI_SET_EVBIT, EV_SYN) < 0) {
        perror("ukvm-client: UI_SET_EVBIT");
        close(fd);
        return -1;
    }

    /* Relative axes. */
    ioctl(fd, UI_SET_RELBIT, REL_X);
    ioctl(fd, UI_SET_RELBIT, REL_Y);
    ioctl(fd, UI_SET_RELBIT, REL_WHEEL);
    ioctl(fd, UI_SET_RELBIT, REL_HWHEEL);

    /* All keyboard keys. */
    for (int k = 1; k < KEY_MAX; k++)
        ioctl(fd, UI_SET_KEYBIT, k);

    /* Mouse buttons. */
    ioctl(fd, UI_SET_KEYBIT, BTN_LEFT);
    ioctl(fd, UI_SET_KEYBIT, BTN_RIGHT);
    ioctl(fd, UI_SET_KEYBIT, BTN_MIDDLE);
    ioctl(fd, UI_SET_KEYBIT, BTN_SIDE);
    ioctl(fd, UI_SET_KEYBIT, BTN_EXTRA);

    struct uinput_user_dev uidev;
    memset(&uidev, 0, sizeof(uidev));
    snprintf(uidev.name, sizeof(uidev.name), "ukvm-virtual-hid");
    uidev.id.bustype = BUS_USB;
    uidev.id.vendor  = 0x554B; /* "UK" */
    uidev.id.product = 0x564D; /* "VM" */
    uidev.id.version = 1;

    if (write(fd, &uidev, sizeof(uidev)) != (ssize_t)sizeof(uidev)) {
        perror("ukvm-client: write(uinput_user_dev)");
        close(fd);
        return -1;
    }
    if (ioctl(fd, UI_DEV_CREATE) < 0) {
        perror("ukvm-client: UI_DEV_CREATE");
        close(fd);
        return -1;
    }
    return fd;
}

/* ----------------------------------------------------------------------- */
/* Button mapping                                                          */
/* ----------------------------------------------------------------------- */

static uint16_t button_to_evdev(uint8_t b) {
    switch (b) {
    case UKVM_BTN_LEFT:   return BTN_LEFT;
    case UKVM_BTN_RIGHT:  return BTN_RIGHT;
    case UKVM_BTN_MIDDLE: return BTN_MIDDLE;
    case UKVM_BTN_SIDE1:  return BTN_SIDE;
    case UKVM_BTN_SIDE2:  return BTN_EXTRA;
    default:              return 0;
    }
}

/* ----------------------------------------------------------------------- */
/* Packet dispatch                                                         */
/* ----------------------------------------------------------------------- */

static void handle_packet(uint8_t *buf, size_t len) {
    struct ukvm_header hdr;

    if (len < sizeof(hdr))
        return;
    memcpy(&hdr, buf, sizeof(hdr));
    ukvm_header_ntoh(&hdr);

    if (hdr.magic != g_state.magic || hdr.version != UKVM_VERSION)
        return; /* drop invalid silently */

    uint8_t *payload = buf + sizeof(hdr);
    size_t   plen    = len - sizeof(hdr);

    /* Decrypt payload in place using the plaintext seq/type as the nonce
     * seed, mirroring the host. */
    if (g_state.crypto.enabled && plen > 0) {
        uint32_t seed = ukvm_nonce_seed(hdr.seq, hdr.type);
        ukvm_chacha_xor(&g_state.crypto, seed, payload, plen);
    }

    switch (hdr.type) {
    case MSG_HEARTBEAT: {
        if (plen < sizeof(struct ukvm_heartbeat))
            return;
        struct ukvm_heartbeat hb;
        memcpy(&hb, payload, sizeof(hb));
        if (hb.active) {
            g_state.active = true;
        } else {
            release_all(); /* clears active */
        }
        break;
    }
    case MSG_MOUSE_MOVE: {
        if (plen < sizeof(struct ukvm_mouse_move))
            return;
        struct ukvm_mouse_move m;
        memcpy(&m, payload, sizeof(m));
        ukvm_mouse_move_ntoh(&m);

        /* Reject out-of-order / duplicate mouse deltas. Signed wrap-aware. */
        if (g_state.have_mouse_seq) {
            int16_t diff = (int16_t)(hdr.seq - g_state.last_mouse_seq);
            if (diff <= 0)
                return;
        }
        g_state.last_mouse_seq = hdr.seq;
        g_state.have_mouse_seq = true;
        g_state.active = true;

        if (m.dx) emit(g_state.uinput_fd, EV_REL, REL_X, m.dx);
        if (m.dy) emit(g_state.uinput_fd, EV_REL, REL_Y, m.dy);
        syn(g_state.uinput_fd);
        break;
    }
    case MSG_MOUSE_BTN: {
        if (plen < sizeof(struct ukvm_mouse_btn))
            return;
        struct ukvm_mouse_btn b;
        memcpy(&b, payload, sizeof(b));
        uint16_t code = button_to_evdev(b.button);
        if (code == 0)
            return;
        g_state.active = true;
        emit(g_state.uinput_fd, EV_KEY, code, b.state ? 1 : 0);
        track(code, b.state ? 1 : 0);
        syn(g_state.uinput_fd);
        break;
    }
    case MSG_MOUSE_SCROLL: {
        if (plen < sizeof(struct ukvm_mouse_scroll))
            return;
        struct ukvm_mouse_scroll s;
        memcpy(&s, payload, sizeof(s));
        ukvm_mouse_scroll_ntoh(&s);
        g_state.active = true;
        if (s.dy) emit(g_state.uinput_fd, EV_REL, REL_WHEEL, s.dy);
        if (s.dx) emit(g_state.uinput_fd, EV_REL, REL_HWHEEL, s.dx);
        syn(g_state.uinput_fd);
        break;
    }
    case MSG_KEY: {
        if (plen < sizeof(struct ukvm_key))
            return;
        struct ukvm_key k;
        memcpy(&k, payload, sizeof(k));
        ukvm_key_ntoh(&k);
        uint16_t code = (k.hid_usage < UKVM_HID_MAX)
                      ? hid_to_evdev[k.hid_usage] : 0;
        if (code == 0)
            return;
        g_state.active = true;
        /* state: 0 up, 1 down, 2 repeat. evdev uses value 2 for autorepeat. */
        int32_t value = (k.state == UKVM_STATE_UP) ? 0
                      : (k.state == UKVM_STATE_REPEAT) ? 2 : 1;
        emit(g_state.uinput_fd, EV_KEY, code, value);
        track(code, value);
        syn(g_state.uinput_fd);
        break;
    }
    default:
        break;
    }
}

#endif /* UKVM_HAVE_UINPUT */

/* ----------------------------------------------------------------------- */
/* Signals                                                                 */
/* ----------------------------------------------------------------------- */

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

/* ----------------------------------------------------------------------- */
/* CLI and main loop                                                       */
/* ----------------------------------------------------------------------- */

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [--port %u] [--key 0xXXXXXXXX] [--secret <pass>]\n"
        "\n"
        "  --port    UDP port to listen on (default %u)\n"
        "  --key     32-bit hex magic shared by both ends (default 0x%08X)\n"
        "  --secret  passphrase enabling ChaCha20 payload decryption\n"
        "            (must match the host's --secret)\n",
        argv0, UKVM_PORT_DEFAULT, UKVM_PORT_DEFAULT, UKVM_MAGIC_DEFAULT);
}

int main(int argc, char **argv) {
    uint16_t port = UKVM_PORT_DEFAULT;
    uint32_t magic = UKVM_MAGIC_DEFAULT;
    const char *secret = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            port = (uint16_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            magic = (uint32_t)strtoul(argv[++i], NULL, 16);
        } else if (!strcmp(argv[i], "--secret") && i + 1 < argc) {
            secret = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "ukvm-client: unknown argument '%s'\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    memset(&g_state, 0, sizeof(g_state));
    g_state.magic = magic;
    ukvm_derive_key(secret, &g_state.crypto);
    if (!g_state.crypto.enabled)
        fprintf(stderr, "ukvm-client: WARNING encryption disabled "
                        "(no --secret); expecting cleartext\n");
    else
        fprintf(stderr, "ukvm-client: ChaCha20 payload decryption enabled\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* UDP socket. */
    g_state.sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_state.sock < 0) {
        perror("ukvm-client: socket");
        return 1;
    }
    int one = 1;
    setsockopt(g_state.sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);
    if (bind(g_state.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("ukvm-client: bind");
        return 1;
    }

#if defined(UKVM_HAVE_UINPUT)
    g_state.uinput_fd = uinput_setup();
    if (g_state.uinput_fd < 0)
        return 1;

    fprintf(stderr, "ukvm-client: listening on 0.0.0.0:%u, "
                    "virtual device 'ukvm-virtual-hid' created.\n", port);

    struct pollfd pfd = { .fd = g_state.sock, .events = POLLIN };
    int64_t last_rx = now_ms();

    while (!g_stop) {
        int pr = poll(&pfd, 1, UKVM_POLL_TIMEOUT_MS);
        int64_t t = now_ms();

        if (pr < 0) {
            if (errno == EINTR)
                continue;
            perror("ukvm-client: poll");
            break;
        }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            for (;;) {
                uint8_t buf[UKVM_MAX_PACKET];
                ssize_t n = recvfrom(g_state.sock, buf, sizeof(buf), 0,
                                     NULL, NULL);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    if (errno == EINTR)
                        break;
                    perror("ukvm-client: recvfrom");
                    break;
                }
                last_rx = t;
                handle_packet(buf, (size_t)n);
            }
        }

        /* Anti-stuck-key watchdog: if active and quiet too long, release. */
        if (g_state.active &&
            (t - last_rx) >= UKVM_WATCHDOG_TIMEOUT_MS) {
            fprintf(stderr, "ukvm-client: watchdog timeout, releasing all "
                            "held input\n");
            release_all();
        }
    }

    fprintf(stderr, "ukvm-client: shutting down, releasing input\n");
    release_all();
    ioctl(g_state.uinput_fd, UI_DEV_DESTROY);
    close(g_state.uinput_fd);
    close(g_state.sock);
    return 0;
#else
    fprintf(stderr, "ukvm-client: this binary targets FreeBSD; the injection "
                    "path requires <dev/evdev/uinput.h>.\n"
                    "Configuration parsed successfully (port=%u).\n", port);
    close(g_state.sock);
    return 0;
#endif
}
