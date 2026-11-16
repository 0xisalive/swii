/*
 * ukvm - minimal low-latency UDP software KVM
 *
 * common/protocol.h - wire protocol definitions.
 *
 * All multi-byte integers on the wire are in network byte order
 * (big-endian). Every packet begins with a fixed 8-byte header followed
 * by a type-specific payload. Structs are packed so that the on-wire
 * layout matches the in-memory layout byte for byte.
 */

#ifndef UKVM_PROTOCOL_H
#define UKVM_PROTOCOL_H

#include <stdint.h>

#if defined(__APPLE__)
#include <machine/endian.h>
#include <arpa/inet.h>
#else
#include <arpa/inet.h>
#endif

/* Default magic: ASCII "UKVM". May be overridden with a CLI-supplied key. */
#define UKVM_MAGIC_DEFAULT 0x554B564Du

/* Protocol version carried in every header. */
#define UKVM_VERSION 0x01u

/* Default UDP port. */
#define UKVM_PORT_DEFAULT 24800u

/* Timing constants (milliseconds). */
#define UKVM_HEARTBEAT_INTERVAL_MS 1000
#define UKVM_POLL_TIMEOUT_MS       500
#define UKVM_WATCHDOG_TIMEOUT_MS   2500

/* Message types carried in ukvm_header.type. */
enum ukvm_msg_type {
    MSG_HEARTBEAT    = 0x01,
    MSG_MOUSE_MOVE   = 0x02,
    MSG_MOUSE_BTN    = 0x03,
    MSG_MOUSE_SCROLL = 0x04,
    MSG_KEY          = 0x05
};

/* Mouse button identifiers used by MSG_MOUSE_BTN. */
enum ukvm_mouse_button {
    UKVM_BTN_LEFT   = 1,
    UKVM_BTN_RIGHT  = 2,
    UKVM_BTN_MIDDLE = 3,
    UKVM_BTN_SIDE1  = 4,
    UKVM_BTN_SIDE2  = 5
};

/* Key / button transition states. */
enum ukvm_key_state {
    UKVM_STATE_UP     = 0,
    UKVM_STATE_DOWN   = 1,
    UKVM_STATE_REPEAT = 2
};

/* Modifier bitmask carried in MSG_KEY.modifiers. */
enum ukvm_modifier {
    UKVM_MOD_SHIFT = 0x01,
    UKVM_MOD_CTRL  = 0x02,
    UKVM_MOD_ALT   = 0x04, /* Alt / Option */
    UKVM_MOD_SUPER = 0x08  /* Super / Command */
};

/* 8-byte fixed header prefixing every datagram. */
struct __attribute__((packed)) ukvm_header {
    uint32_t magic;   /* UKVM_MAGIC_DEFAULT or CLI-supplied key */
    uint8_t  version; /* UKVM_VERSION */
    uint8_t  type;    /* enum ukvm_msg_type */
    uint16_t seq;     /* rolling sequence number */
};

/* MSG_HEARTBEAT payload. */
struct __attribute__((packed)) ukvm_heartbeat {
    uint8_t active; /* 1 = client grabbed/active, 0 = released/inactive */
};

/* MSG_MOUSE_MOVE payload: relative delta. */
struct __attribute__((packed)) ukvm_mouse_move {
    int16_t dx;
    int16_t dy;
};

/* MSG_MOUSE_BTN payload. */
struct __attribute__((packed)) ukvm_mouse_btn {
    uint8_t button; /* enum ukvm_mouse_button */
    uint8_t state;  /* 1 = down, 0 = up */
};

/* MSG_MOUSE_SCROLL payload: wheel deltas. */
struct __attribute__((packed)) ukvm_mouse_scroll {
    int16_t dx;
    int16_t dy;
};

/* MSG_KEY payload. */
struct __attribute__((packed)) ukvm_key {
    uint16_t hid_usage; /* USB HID Usage Table, Keyboard/Keypad page 0x07 */
    uint8_t  state;     /* enum ukvm_key_state */
    uint8_t  modifiers; /* enum ukvm_modifier bitmask */
};

/*
 * Largest datagram the protocol can emit: header plus the biggest payload.
 * Used to size receive buffers.
 */
#define UKVM_MAX_PACKET (sizeof(struct ukvm_header) + 8)

/*
 * 64-bit byte order helpers are not needed; the protocol only carries
 * 16-bit and 32-bit fields. Serialization helpers below operate on the
 * packed structs in place. A sender fills host-order values, calls the
 * matching hton helper, then writes the struct; a receiver reads the
 * struct, then calls the matching ntoh helper before use.
 */

static inline void ukvm_header_hton(struct ukvm_header *h) {
    h->magic = htonl(h->magic);
    h->seq   = htons(h->seq);
}

static inline void ukvm_header_ntoh(struct ukvm_header *h) {
    h->magic = ntohl(h->magic);
    h->seq   = ntohs(h->seq);
}

static inline void ukvm_mouse_move_hton(struct ukvm_mouse_move *m) {
    m->dx = (int16_t)htons((uint16_t)m->dx);
    m->dy = (int16_t)htons((uint16_t)m->dy);
}

static inline void ukvm_mouse_move_ntoh(struct ukvm_mouse_move *m) {
    m->dx = (int16_t)ntohs((uint16_t)m->dx);
    m->dy = (int16_t)ntohs((uint16_t)m->dy);
}

static inline void ukvm_mouse_scroll_hton(struct ukvm_mouse_scroll *s) {
    s->dx = (int16_t)htons((uint16_t)s->dx);
    s->dy = (int16_t)htons((uint16_t)s->dy);
}

static inline void ukvm_mouse_scroll_ntoh(struct ukvm_mouse_scroll *s) {
    s->dx = (int16_t)ntohs((uint16_t)s->dx);
    s->dy = (int16_t)ntohs((uint16_t)s->dy);
}

static inline void ukvm_key_hton(struct ukvm_key *k) {
    k->hid_usage = htons(k->hid_usage);
}

static inline void ukvm_key_ntoh(struct ukvm_key *k) {
    k->hid_usage = ntohs(k->hid_usage);
}

#endif /* UKVM_PROTOCOL_H */
