/*
 * ukvm - minimal low-latency UDP software KVM
 *
 * macos-host/main.c - macOS capture side (server).
 *
 * Captures mouse and keyboard with a CGEventTap, detects when the cursor
 * reaches a configured screen edge, then locks the local cursor and streams
 * raw input deltas to a FreeBSD client over UDP. A failsafe hotkey and the
 * reverse edge crossing both return control to the local machine.
 *
 * Build:
 *   clang -Wall -Wextra -O2 -std=c11 \
 *       -framework ApplicationServices -framework CoreFoundation \
 *       macos-host/main.c -o ukvm-host
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/protocol.h"
#include "../common/crypto.h"
#include "../common/hid_keymap.h"

#if defined(__APPLE__)
#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
#endif

/* ----------------------------------------------------------------------- */
/* Configuration and shared state                                          */
/* ----------------------------------------------------------------------- */

enum edge { EDGE_LEFT, EDGE_RIGHT, EDGE_TOP, EDGE_BOTTOM };

struct host_state {
    int                   sock;
    struct sockaddr_in    dst;
    uint32_t              magic;
    enum edge             edge;
    struct ukvm_chacha_ctx crypto;

    volatile bool         remote;    /* true while control is on the client */
    uint16_t              seq;       /* rolling sequence counter */
    uint8_t               modifiers; /* current modifier bitmask */

    double                screen_w;
    double                screen_h;

    pthread_mutex_t       send_lock;
};

static struct host_state g_state;

#if defined(__APPLE__)

/* Modifier-key tracking for kCGEventFlagsChanged. We remember whether each
 * physical modifier was down to synthesise discrete up/down transitions. */
static bool g_mod_down[8]; /* indexed by a small enum below */
enum { MI_LSHIFT, MI_RSHIFT, MI_LCTRL, MI_RCTRL,
       MI_LALT, MI_RALT, MI_LMETA, MI_RMETA };

/* ----------------------------------------------------------------------- */
/* UDP send path                                                           */
/* ----------------------------------------------------------------------- */

/*
 * Serialize and transmit one packet. `payload` is the already host-order
 * payload struct; the caller passes its length. Header fields are filled
 * here. Multi-byte fields are converted to network order and the payload
 * is encrypted in place on a local copy.
 */
static void ukvm_send(uint8_t type, const void *payload, size_t payload_len) {
    uint8_t buf[UKVM_MAX_PACKET];
    struct ukvm_header hdr;
    uint16_t seq_host;

    pthread_mutex_lock(&g_state.send_lock);
    seq_host = g_state.seq++;
    pthread_mutex_unlock(&g_state.send_lock);

    hdr.magic   = g_state.magic;
    hdr.version = UKVM_VERSION;
    hdr.type    = type;
    hdr.seq     = seq_host;

    /* Copy payload into the buffer after the header, then encrypt just the
     * payload region using a nonce derived from the plaintext seq/type. */
    memcpy(buf + sizeof(hdr), payload, payload_len);
    if (g_state.crypto.enabled) {
        uint32_t seed = ukvm_nonce_seed(seq_host, type);
        ukvm_chacha_xor(&g_state.crypto, seed, buf + sizeof(hdr), payload_len);
    }

    ukvm_header_hton(&hdr);
    memcpy(buf, &hdr, sizeof(hdr));

    ssize_t n = sendto(g_state.sock, buf, sizeof(hdr) + payload_len, 0,
                       (struct sockaddr *)&g_state.dst, sizeof(g_state.dst));
    if (n < 0 && errno != EINTR)
        fprintf(stderr, "ukvm-host: sendto: %s\n", strerror(errno));
}

static void send_heartbeat(uint8_t active) {
    struct ukvm_heartbeat hb = { .active = active };
    ukvm_send(MSG_HEARTBEAT, &hb, sizeof(hb));
}

static void send_mouse_move(int16_t dx, int16_t dy) {
    struct ukvm_mouse_move m = { .dx = dx, .dy = dy };
    ukvm_mouse_move_hton(&m);
    ukvm_send(MSG_MOUSE_MOVE, &m, sizeof(m));
}

static void send_mouse_btn(uint8_t button, uint8_t state) {
    struct ukvm_mouse_btn b = { .button = button, .state = state };
    ukvm_send(MSG_MOUSE_BTN, &b, sizeof(b));
}

static void send_mouse_scroll(int16_t dx, int16_t dy) {
    struct ukvm_mouse_scroll s = { .dx = dx, .dy = dy };
    ukvm_mouse_scroll_hton(&s);
    ukvm_send(MSG_MOUSE_SCROLL, &s, sizeof(s));
}

static void send_key(uint16_t hid, uint8_t state, uint8_t modifiers) {
    struct ukvm_key k = { .hid_usage = hid, .state = state,
                          .modifiers = modifiers };
    ukvm_key_hton(&k);
    ukvm_send(MSG_KEY, &k, sizeof(k));
}

/* ----------------------------------------------------------------------- */
/* State transitions                                                       */
/* ----------------------------------------------------------------------- */

static void enter_remote(void) {
    if (g_state.remote)
        return;
    g_state.remote = true;
    send_heartbeat(1);
    CGDisplayHideCursor(kCGNullDirectDisplay);
    CGAssociateMouseAndMouseCursorPosition(false);
    fprintf(stderr, "ukvm-host: -> REMOTE (client has control)\n");
}

static void enter_local(void) {
    if (!g_state.remote)
        return;
    g_state.remote = false;
    CGAssociateMouseAndMouseCursorPosition(true);
    CGDisplayShowCursor(kCGNullDirectDisplay);
    send_heartbeat(0);
    fprintf(stderr, "ukvm-host: -> LOCAL (host has control)\n");
}

/* ----------------------------------------------------------------------- */
/* Modifier flag tracking                                                  */
/* ----------------------------------------------------------------------- */

static void update_modifier_bit(bool down, uint8_t mod_mask) {
    if (down)
        g_state.modifiers |= mod_mask;
    else
        g_state.modifiers &= (uint8_t)~mod_mask;
}

/*
 * Compare the previous per-modifier down state with the flags present on a
 * FlagsChanged event and emit discrete key up/down packets for each change.
 */
static void handle_flags_changed(CGEventFlags flags) {
    struct { int idx; CGEventFlags bit; uint16_t hid; uint8_t mod; } mods[] = {
        { MI_LSHIFT, 0, HID_LSHIFT, UKVM_MOD_SHIFT },
        { MI_RSHIFT, 0, HID_RSHIFT, UKVM_MOD_SHIFT },
        { MI_LCTRL,  0, HID_LCTRL,  UKVM_MOD_CTRL  },
        { MI_RCTRL,  0, HID_RCTRL,  UKVM_MOD_CTRL  },
        { MI_LALT,   0, HID_LALT,   UKVM_MOD_ALT   },
        { MI_RALT,   0, HID_RALT,   UKVM_MOD_ALT   },
        { MI_LMETA,  0, HID_LMETA,  UKVM_MOD_SUPER },
        { MI_RMETA,  0, HID_RMETA,  UKVM_MOD_SUPER },
    };
    /* macOS exposes per-side device-dependent bits via these masks. */
    mods[0].bit = NX_DEVICELSHIFTKEYMASK;
    mods[1].bit = NX_DEVICERSHIFTKEYMASK;
    mods[2].bit = NX_DEVICELCTLKEYMASK;
    mods[3].bit = NX_DEVICERCTLKEYMASK;
    mods[4].bit = NX_DEVICELALTKEYMASK;
    mods[5].bit = NX_DEVICERALTKEYMASK;
    mods[6].bit = NX_DEVICELCMDKEYMASK;
    mods[7].bit = NX_DEVICERCMDKEYMASK;

    for (size_t i = 0; i < sizeof(mods) / sizeof(mods[0]); i++) {
        bool now = (flags & mods[i].bit) != 0;
        bool was = g_mod_down[mods[i].idx];
        if (now == was)
            continue;
        g_mod_down[mods[i].idx] = now;
        update_modifier_bit(now, mods[i].mod);
        if (g_state.remote)
            send_key(mods[i].hid, now ? UKVM_STATE_DOWN : UKVM_STATE_UP,
                     g_state.modifiers);
    }
}

/* ----------------------------------------------------------------------- */
/* Failsafe hotkey: Ctrl + Option + Escape                                 */
/* ----------------------------------------------------------------------- */

static bool is_failsafe(CGEventType type, CGEventRef event) {
    if (type != kCGEventKeyDown)
        return false;
    CGKeyCode kc = (CGKeyCode)CGEventGetIntegerValueField(event,
                                                          kCGKeyboardEventKeycode);
    CGEventFlags f = CGEventGetFlags(event);
    return kc == kVKX_Escape &&
           (f & kCGEventFlagMaskControl) &&
           (f & kCGEventFlagMaskAlternate);
}

/* ----------------------------------------------------------------------- */
/* Edge detection                                                          */
/* ----------------------------------------------------------------------- */

static bool at_edge(CGPoint p) {
    switch (g_state.edge) {
    case EDGE_LEFT:   return p.x <= 0.0;
    case EDGE_RIGHT:  return p.x >= g_state.screen_w - 1.0;
    case EDGE_TOP:    return p.y <= 0.0;
    case EDGE_BOTTOM: return p.y >= g_state.screen_h - 1.0;
    }
    return false;
}

/* ----------------------------------------------------------------------- */
/* Event tap callback                                                      */
/* ----------------------------------------------------------------------- */

static CGEventRef tap_callback(CGEventTapProxy proxy, CGEventType type,
                               CGEventRef event, void *ctx) {
    (void)proxy;
    (void)ctx;

    /* The tap can be disabled by the system under load or on timeout. */
    if (type == kCGEventTapDisabledByTimeout ||
        type == kCGEventTapDisabledByUserInput) {
        return event;
    }

    /* Failsafe always returns control to the host, from any state. */
    if (is_failsafe(type, event)) {
        enter_local();
        return NULL;
    }

    if (type == kCGEventFlagsChanged) {
        handle_flags_changed(CGEventGetFlags(event));
        /* Suppress locally only while remote. */
        return g_state.remote ? NULL : event;
    }

    if (!g_state.remote) {
        /* LOCAL: pass everything through, but watch for the edge. */
        if (type == kCGEventMouseMoved ||
            type == kCGEventLeftMouseDragged ||
            type == kCGEventRightMouseDragged ||
            type == kCGEventOtherMouseDragged) {
            CGPoint p = CGEventGetLocation(event);
            if (at_edge(p))
                enter_remote();
        }
        return event;
    }

    /* REMOTE: translate and forward, suppress locally (return NULL). */
    switch (type) {
    case kCGEventMouseMoved:
    case kCGEventLeftMouseDragged:
    case kCGEventRightMouseDragged:
    case kCGEventOtherMouseDragged: {
        int64_t dx = CGEventGetIntegerValueField(event, kCGMouseEventDeltaX);
        int64_t dy = CGEventGetIntegerValueField(event, kCGMouseEventDeltaY);
        send_mouse_move((int16_t)dx, (int16_t)dy);
        return NULL;
    }
    case kCGEventLeftMouseDown:  send_mouse_btn(UKVM_BTN_LEFT, 1);  return NULL;
    case kCGEventLeftMouseUp:    send_mouse_btn(UKVM_BTN_LEFT, 0);  return NULL;
    case kCGEventRightMouseDown: send_mouse_btn(UKVM_BTN_RIGHT, 1); return NULL;
    case kCGEventRightMouseUp:   send_mouse_btn(UKVM_BTN_RIGHT, 0); return NULL;
    case kCGEventOtherMouseDown:
    case kCGEventOtherMouseUp: {
        int64_t which = CGEventGetIntegerValueField(event,
                                                   kCGMouseEventButtonNumber);
        uint8_t btn;
        switch (which) {
        case 2:  btn = UKVM_BTN_MIDDLE; break;
        case 3:  btn = UKVM_BTN_SIDE1;  break;
        case 4:  btn = UKVM_BTN_SIDE2;  break;
        default: btn = UKVM_BTN_MIDDLE; break;
        }
        send_mouse_btn(btn, type == kCGEventOtherMouseDown ? 1 : 0);
        return NULL;
    }
    case kCGEventScrollWheel: {
        int64_t a1 = CGEventGetIntegerValueField(event,
                                                kCGScrollWheelEventDeltaAxis1);
        int64_t a2 = CGEventGetIntegerValueField(event,
                                                kCGScrollWheelEventDeltaAxis2);
        send_mouse_scroll((int16_t)a2, (int16_t)a1); /* dx=horiz, dy=vert */
        return NULL;
    }
    case kCGEventKeyDown:
    case kCGEventKeyUp: {
        CGKeyCode kc = (CGKeyCode)CGEventGetIntegerValueField(event,
                                                   kCGKeyboardEventKeycode);
        bool repeat = CGEventGetIntegerValueField(event,
                                                 kCGKeyboardEventAutorepeat) != 0;
        uint16_t hid = (kc < 256) ? mac_to_hid[kc] : 0;
        if (hid != 0) {
            uint8_t st = (type == kCGEventKeyUp) ? UKVM_STATE_UP
                       : (repeat ? UKVM_STATE_REPEAT : UKVM_STATE_DOWN);
            send_key(hid, st, g_state.modifiers);
        }
        return NULL;
    }
    default:
        return NULL;
    }
}

/* ----------------------------------------------------------------------- */
/* Heartbeat thread                                                        */
/* ----------------------------------------------------------------------- */

static void *heartbeat_thread(void *arg) {
    (void)arg;
    for (;;) {
        usleep(UKVM_HEARTBEAT_INTERVAL_MS * 1000);
        if (g_state.remote)
            send_heartbeat(1);
    }
    return NULL;
}

#endif /* __APPLE__ */

/* ----------------------------------------------------------------------- */
/* CLI and setup                                                           */
/* ----------------------------------------------------------------------- */

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s --target <FREEBSD_IP> [--port %u] "
        "[--edge left|right|top|bottom] [--key 0xXXXXXXXX] [--secret <pass>]\n"
        "\n"
        "  --target   IPv4 address of the FreeBSD client (required)\n"
        "  --port     UDP port (default %u)\n"
        "  --edge     screen edge that transfers control (default right)\n"
        "  --key      32-bit hex magic shared by both ends (default 0x%08X)\n"
        "  --secret   passphrase enabling ChaCha20 payload encryption\n"
        "\n"
        "  Failsafe: Ctrl+Option+Escape always returns control to the host.\n",
        argv0, UKVM_PORT_DEFAULT, UKVM_PORT_DEFAULT, UKVM_MAGIC_DEFAULT);
}

static bool parse_edge(const char *s, enum edge *out) {
    if (!strcmp(s, "left"))   { *out = EDGE_LEFT;   return true; }
    if (!strcmp(s, "right"))  { *out = EDGE_RIGHT;  return true; }
    if (!strcmp(s, "top"))    { *out = EDGE_TOP;    return true; }
    if (!strcmp(s, "bottom")) { *out = EDGE_BOTTOM; return true; }
    return false;
}

int main(int argc, char **argv) {
    const char *target = NULL;
    const char *secret = NULL;
    uint16_t port = UKVM_PORT_DEFAULT;
    uint32_t magic = UKVM_MAGIC_DEFAULT;
    enum edge edge = EDGE_RIGHT;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--target") && i + 1 < argc) {
            target = argv[++i];
        } else if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            port = (uint16_t)strtoul(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--edge") && i + 1 < argc) {
            if (!parse_edge(argv[++i], &edge)) {
                fprintf(stderr, "ukvm-host: invalid --edge\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            magic = (uint32_t)strtoul(argv[++i], NULL, 16);
        } else if (!strcmp(argv[i], "--secret") && i + 1 < argc) {
            secret = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "ukvm-host: unknown argument '%s'\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (target == NULL) {
        usage(argv[0]);
        return 2;
    }

    memset(&g_state, 0, sizeof(g_state));
    g_state.magic = magic;
    g_state.edge  = edge;
    pthread_mutex_init(&g_state.send_lock, NULL);

    ukvm_derive_key(secret, &g_state.crypto);
    if (!g_state.crypto.enabled)
        fprintf(stderr, "ukvm-host: WARNING encryption disabled "
                        "(no --secret); traffic is sent in clear\n");
    else
        fprintf(stderr, "ukvm-host: ChaCha20 payload encryption enabled\n");

    /* UDP socket. */
    g_state.sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_state.sock < 0) {
        perror("ukvm-host: socket");
        return 1;
    }
    memset(&g_state.dst, 0, sizeof(g_state.dst));
    g_state.dst.sin_family = AF_INET;
    g_state.dst.sin_port   = htons(port);
    if (inet_pton(AF_INET, target, &g_state.dst.sin_addr) != 1) {
        fprintf(stderr, "ukvm-host: invalid --target address '%s'\n", target);
        return 2;
    }

#if defined(__APPLE__)
    /*
     * Ask for accessibility access with the system prompt. Unlike the bare
     * AXIsProcessTrusted() check, passing kAXTrustedCheckOptionPrompt makes
     * macOS surface the "open System Settings" dialog and register this
     * binary in the Accessibility list, so a grant can attach to this exact
     * executable. TCC keys the grant to the binary's identity, and the
     * running process only observes a change on a fresh launch, so the
     * first run after granting will still report untrusted and exit; the
     * message below tells the user to re-run.
     */
    CFStringRef prompt_key = kAXTrustedCheckOptionPrompt;
    CFDictionaryRef opts = CFDictionaryCreate(
        kCFAllocatorDefault,
        (const void **)&prompt_key,
        (const void **)&kCFBooleanTrue,
        1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    Boolean trusted = AXIsProcessTrustedWithOptions(opts);
    CFRelease(opts);

    if (!trusted) {
        fprintf(stderr,
            "ukvm-host: accessibility permission is required.\n"
            "  A system dialog may have opened; if not, open:\n"
            "    System Settings > Privacy & Security > Accessibility\n"
            "    System Settings > Privacy & Security > Input Monitoring\n"
            "  Enable the entry for THIS binary (or the terminal you launch\n"
            "  it from). macOS binds the grant to the executable's identity,\n"
            "  so after rebuilding ukvm-host you must re-grant it. If an old\n"
            "  'ukvm-host' entry is present, remove it and re-add the current\n"
            "  one. The permission only takes effect on a fresh launch, so\n"
            "  quit and relaunch your terminal, then re-run ukvm-host.\n");
        return 1;
    }

    CGDirectDisplayID disp = CGMainDisplayID();
    g_state.screen_w = (double)CGDisplayPixelsWide(disp);
    g_state.screen_h = (double)CGDisplayPixelsHigh(disp);

    CGEventMask mask =
        CGEventMaskBit(kCGEventMouseMoved)        |
        CGEventMaskBit(kCGEventLeftMouseDown)     |
        CGEventMaskBit(kCGEventLeftMouseUp)       |
        CGEventMaskBit(kCGEventRightMouseDown)    |
        CGEventMaskBit(kCGEventRightMouseUp)      |
        CGEventMaskBit(kCGEventOtherMouseDown)    |
        CGEventMaskBit(kCGEventOtherMouseUp)      |
        CGEventMaskBit(kCGEventLeftMouseDragged)  |
        CGEventMaskBit(kCGEventRightMouseDragged) |
        CGEventMaskBit(kCGEventOtherMouseDragged) |
        CGEventMaskBit(kCGEventScrollWheel)       |
        CGEventMaskBit(kCGEventKeyDown)           |
        CGEventMaskBit(kCGEventKeyUp)             |
        CGEventMaskBit(kCGEventFlagsChanged);

    CFMachPortRef tap = CGEventTapCreate(kCGSessionEventTap,
                                         kCGHeadInsertEventTap,
                                         kCGEventTapOptionDefault,
                                         mask, tap_callback, NULL);
    if (tap == NULL) {
        fprintf(stderr, "ukvm-host: failed to create event tap "
                        "(check permissions)\n");
        return 1;
    }

    CFRunLoopSourceRef src = CFMachPortCreateRunLoopSource(kCFAllocatorDefault,
                                                           tap, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), src, kCFRunLoopCommonModes);
    CGEventTapEnable(tap, true);

    pthread_t hb;
    pthread_create(&hb, NULL, heartbeat_thread, NULL);

    fprintf(stderr, "ukvm-host: capturing; edge=%d target=%s:%u. "
                    "Move cursor to the edge to switch.\n",
            (int)edge, target, port);

    CFRunLoopRun();

    CFRelease(src);
    CFRelease(tap);
    return 0;
#else
    fprintf(stderr, "ukvm-host: this binary targets macOS; the capture path "
                    "requires ApplicationServices/CoreFoundation.\n"
                    "Configuration parsed successfully (target=%s port=%u).\n",
            target, port);
    return 0;
#endif
}
