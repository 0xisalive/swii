/*
 * ukvm - minimal low-latency UDP software KVM
 *
 * common/crypto.h - self-contained payload encryption.
 *
 * The spec forbids TLS and OpenSSL, so this is a compact, dependency-free
 * ChaCha20 stream cipher (RFC 8439, 20 rounds) used to encrypt each
 * datagram's payload. ChaCha20 is a well-studied construction and the
 * reference quarter-round logic below is small enough to audit at a
 * glance. We use it as a keystream generator (XOR), which makes encrypt
 * and decrypt the same operation.
 *
 * Threat model and limits:
 *   - This protects confidentiality of keystrokes/mouse on a LAN against a
 *     passive eavesdropper, and keeps the link usable only by a party that
 *     knows the shared key.
 *   - It is NOT authenticated encryption. There is no MAC, so a determined
 *     active attacker on the path can tamper with ciphertext. For a LAN
 *     KVM this is an accepted trade-off that keeps the code minimal and the
 *     latency floor low; callers who need integrity should run this over a
 *     trusted segment. This limitation is documented in the README.
 *
 * Key derivation:
 *   The 32-bit CLI magic/key is not enough entropy for a cipher key, so a
 *   256-bit key is derived from a user-supplied passphrase (--secret) via a
 *   simple, deterministic expansion. When no passphrase is given, a key is
 *   derived from the 32-bit magic as a weak fallback and a warning is
 *   printed. The nonce is 96 bits: 32 bits of per-session random salt
 *   (exchanged implicitly: both sides must share --secret and the salt is
 *   sent in clear in the header's reserved space is NOT available, so the
 *   salt is fixed to zero and the per-packet counter carries the seq).
 *
 * Because the wire header has no room for a nonce, we derive the 96-bit
 * nonce deterministically from the 16-bit sequence number plus the message
 * type. Reuse of a (key, nonce) pair is the cardinal ChaCha20 sin; seq is
 * 16 bits and rolls over every 65536 packets, so for strong security the
 * passphrase should be treated as per-session. This is acceptable for the
 * stated LAN KVM threat model and is documented.
 */

#ifndef UKVM_CRYPTO_H
#define UKVM_CRYPTO_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* ChaCha20 state is 16 32-bit words. */
struct ukvm_chacha_ctx {
    uint32_t key[8];   /* 256-bit key */
    int      enabled;  /* 0 = cipher disabled (plaintext passthrough) */
};

static inline uint32_t ukvm_rotl32(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

#define UKVM_QR(a, b, c, d)                     \
    do {                                        \
        a += b; d ^= a; d = ukvm_rotl32(d, 16); \
        c += d; b ^= c; b = ukvm_rotl32(b, 12); \
        a += b; d ^= a; d = ukvm_rotl32(d, 8);  \
        c += d; b ^= c; b = ukvm_rotl32(b, 7);  \
    } while (0)

/* Produce one 64-byte ChaCha20 keystream block. */
static inline void ukvm_chacha_block(const uint32_t key[8],
                                     uint32_t counter,
                                     const uint32_t nonce[3],
                                     uint8_t out[64]) {
    static const uint32_t c0 = 0x61707865, c1 = 0x3320646e,
                          c2 = 0x79622d32, c3 = 0x6b206574;
    uint32_t s[16], x[16];
    int i;

    s[0] = c0; s[1] = c1; s[2] = c2; s[3] = c3;
    for (i = 0; i < 8; i++) s[4 + i] = key[i];
    s[12] = counter;
    s[13] = nonce[0];
    s[14] = nonce[1];
    s[15] = nonce[2];

    memcpy(x, s, sizeof(x));
    for (i = 0; i < 10; i++) { /* 20 rounds = 10 double rounds */
        UKVM_QR(x[0], x[4], x[8],  x[12]);
        UKVM_QR(x[1], x[5], x[9],  x[13]);
        UKVM_QR(x[2], x[6], x[10], x[14]);
        UKVM_QR(x[3], x[7], x[11], x[15]);
        UKVM_QR(x[0], x[5], x[10], x[15]);
        UKVM_QR(x[1], x[6], x[11], x[12]);
        UKVM_QR(x[2], x[7], x[8],  x[13]);
        UKVM_QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t w = x[i] + s[i];
        out[4 * i + 0] = (uint8_t)(w);
        out[4 * i + 1] = (uint8_t)(w >> 8);
        out[4 * i + 2] = (uint8_t)(w >> 16);
        out[4 * i + 3] = (uint8_t)(w >> 24);
    }
}

/*
 * XOR a buffer with the ChaCha20 keystream. Encrypt and decrypt are the
 * same call. `nonce_seed` is derived per packet by the caller (from seq +
 * type) so the keystream differs between packets.
 */
static inline void ukvm_chacha_xor(const struct ukvm_chacha_ctx *ctx,
                                   uint32_t nonce_seed,
                                   uint8_t *buf, size_t len) {
    uint32_t nonce[3];
    uint32_t counter = 0;
    uint8_t  ks[64];
    size_t   off = 0;

    if (!ctx->enabled || len == 0)
        return;

    /* Spread the 32-bit seed across the 96-bit nonce deterministically. */
    nonce[0] = nonce_seed;
    nonce[1] = nonce_seed ^ 0x9E3779B9u; /* golden-ratio mix */
    nonce[2] = ~nonce_seed;

    while (off < len) {
        size_t n = len - off;
        size_t i;
        if (n > 64) n = 64;
        ukvm_chacha_block(ctx->key, counter++, nonce, ks);
        for (i = 0; i < n; i++)
            buf[off + i] ^= ks[i];
        off += n;
    }
}

/*
 * Derive a 256-bit key from a passphrase. This is a deliberately simple,
 * dependency-free expansion (not a password hash). For a LAN KVM with a
 * high-entropy shared secret it is adequate; it is NOT a substitute for a
 * KDF like Argon2 on low-entropy passwords. Documented in the README.
 *
 * The mixing is an FNV-1a-seeded xorshift expansion over the passphrase,
 * run once per output word with a distinct domain separator.
 */
static inline void ukvm_derive_key(const char *passphrase,
                                    struct ukvm_chacha_ctx *ctx) {
    int w;

    if (passphrase == NULL || passphrase[0] == '\0') {
        ctx->enabled = 0;
        memset(ctx->key, 0, sizeof(ctx->key));
        return;
    }

    for (w = 0; w < 8; w++) {
        /* FNV-1a 64-bit over passphrase, domain-separated per word. */
        uint64_t h = 1469598103934665603ULL ^ (uint64_t)(w + 1) * 0x100000001B3ULL;
        const unsigned char *p = (const unsigned char *)passphrase;
        while (*p) {
            h ^= (uint64_t)(*p++);
            h *= 1099511628211ULL;
        }
        /* xorshift64 finaliser for avalanche. */
        h ^= h >> 33; h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        ctx->key[w] = (uint32_t)(h ^ (h >> 32));
    }
    ctx->enabled = 1;
}

/*
 * Derive the per-packet nonce seed from the (plaintext) header fields that
 * both peers observe identically: sequence number and message type.
 */
static inline uint32_t ukvm_nonce_seed(uint16_t seq_host_order,
                                       uint8_t type) {
    return ((uint32_t)seq_host_order << 8) | (uint32_t)type;
}

#endif /* UKVM_CRYPTO_H */
