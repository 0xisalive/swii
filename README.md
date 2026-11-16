# ukvm

A minimal, zero-dependency software KVM. It shares one mouse and keyboard
from a **macOS host** to a **FreeBSD client** over a LAN using raw UDP.

No TLS, no OpenSSL, no cross-platform GUI toolkit. Just POSIX sockets, the
platform-native input APIs (CoreGraphics event taps on macOS, `/dev/uinput`
on FreeBSD), and a small self-contained ChaCha20 for payload encryption.

## Layout

```
ukvm/
├── Makefile                 OS-detecting build (Darwin -> host, FreeBSD -> client)
├── common/
│   ├── protocol.h           Wire structs, byte-order helpers, constants
│   ├── crypto.h             Self-contained ChaCha20 payload cipher
│   └── hid_keymap.h         macOS vkey -> USB HID -> FreeBSD evdev tables
├── macos-host/
│   └── main.c               CGEventTap capture, edge detection, UDP sender
└── freebsd-client/
    └── main.c               UDP listener, state tracker, /dev/uinput injector
```

## Protocol

Every datagram is an 8-byte big-endian header followed by a typed payload.

| Field   | Size | Notes                                             |
|---------|------|---------------------------------------------------|
| magic   | 4    | `0x554B564D` ("UKVM") or a CLI-supplied hex key   |
| version | 1    | `0x01`                                            |
| type    | 1    | message type (below)                              |
| seq     | 2    | rolling sequence number                           |

Message types: `MSG_HEARTBEAT` (0x01), `MSG_MOUSE_MOVE` (0x02),
`MSG_MOUSE_BTN` (0x03), `MSG_MOUSE_SCROLL` (0x04), `MSG_KEY` (0x05).
All multi-byte integers use network byte order; structs are packed.

Keycodes travel as **USB HID Usage IDs (page 0x07)**. The host maps Carbon
virtual keycodes to HID; the client maps HID to evdev `KEY_*`.

### Reliability

UDP drops and reorders. The design tolerates both:

- **Mouse moves** carry the sequence number; the client drops any delta
  whose `(int16_t)(seq - last_mouse_seq) <= 0`, so a late duplicate never
  jerks the cursor backwards.
- **Keys and buttons** are applied immediately and tracked in a
  `down[]` table.
- **Anti-stuck-key watchdog.** The client releases every held key/button
  when it receives `MSG_HEARTBEAT(active=0)`, or after 2500 ms of silence
  while active, or on `SIGINT`/`SIGTERM`. A lost "key up" cannot wedge the
  remote keyboard.

## Encryption

Pass a shared passphrase with `--secret <pass>` on both ends to enable
ChaCha20 (RFC 8439, 20 rounds) over each datagram's payload. The header
stays in clear so the receiver can demux; the per-packet nonce is derived
from the plaintext `seq` and `type`.

This is a deliberate, minimal design for a LAN threat model:

- It protects confidentiality against a passive eavesdropper and keeps the
  link usable only by a peer that knows the secret.
- It is **not** authenticated encryption — there is no MAC, so an active
  on-path attacker could tamper with ciphertext. Run it on a trusted
  segment if you need integrity.
- The 256-bit key is derived from the passphrase by a simple deterministic
  expansion, not a password hash. Use a high-entropy secret.
- `seq` is 16 bits, so the `(key, nonce)` space repeats every 65536
  packets of a given type; treat the secret as per-session.

Without `--secret`, traffic is sent in clear and both binaries print a
warning.

## Building

The Makefile detects the OS and builds the native binary:

```sh
make           # host on macOS, client on FreeBSD
make host      # force the macOS host
make client    # force the FreeBSD client
make install   # install the native binary into $(PREFIX)/bin
```

The host links `-framework ApplicationServices -framework CoreFoundation`
and compiles with `clang -Wall -Wextra -O2`. The client compiles with
`cc -Wall -Wextra -O2` and uses the FreeBSD evdev headers under
`<dev/evdev/>`.

## Running

### macOS host

Grant **Accessibility** and **Input Monitoring** to your terminal (or the
binary) under System Settings > Privacy & Security. The host refuses to
start otherwise and prints where to click.

```sh
./ukvm-host --target 192.168.1.50 --edge right --secret 'correct horse battery staple'
```

| Flag       | Default       | Meaning                                        |
|------------|---------------|------------------------------------------------|
| `--target` | (required)    | FreeBSD client IPv4 address                    |
| `--port`   | `24800`       | UDP port                                       |
| `--edge`   | `right`       | screen edge that hands control to the client   |
| `--key`    | `0x554B564D`  | 32-bit magic shared by both ends               |
| `--secret` | (none)        | passphrase enabling encryption                 |

Push the cursor to the configured edge to hand control to the client; the
local cursor hides and freezes while raw deltas stream out. Cross back over
the entry edge, or press the **Ctrl + Option + Escape** failsafe, to take
control back.

### FreeBSD client

Load the module and make sure `/dev/uinput` is writable:

```sh
kldload uinput
# grant access without running as root, e.g. /etc/devfs.rules:
#   [localrules=10]
#   add path 'uinput' mode 0660 group wheel
# then: service devfs restart

./ukvm-client --secret 'correct horse battery staple'
```

| Flag       | Default       | Meaning                                  |
|------------|---------------|------------------------------------------|
| `--port`   | `24800`       | UDP port to listen on                    |
| `--key`    | `0x554B564D`  | 32-bit magic, must match the host        |
| `--secret` | (none)        | passphrase, must match the host          |

The client creates a virtual HID named `ukvm-virtual-hid` and injects the
received input. On exit it releases all held keys and destroys the device.
