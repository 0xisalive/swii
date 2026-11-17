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
`MSG_MOUSE_BTN` (0x03), `MSG_MOUSE_SCROLL` (0x04), `MSG_KEY` (0x05),
`MSG_RELEASE` (0x06). All multi-byte integers use network byte order;
structs are packed.

`MSG_HEARTBEAT` carries `active` (byte 0) and, when active, the host's exit
`edge` (byte 1), so a client doing its own edge detection knows which
border returns control. `MSG_RELEASE` travels client->host and is
header-only; it asks the host to take control back (see below).

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
| `--return` | `client-edge` | return method: `client-edge` or `host-virtual` |
| `--client-size` | host display | client resolution `WxH`, host-virtual only |

Push the cursor to the configured edge to hand control to the client; the
local cursor hides and freezes while raw deltas stream out.

To take control back, move the pointer **back out through the entry edge**
of the client. For the default `--edge right`, control enters at the
client's left side, so moving left until you reach it hands control back.
The **Command + G** failsafe returns control instantly from anywhere.

### Return methods

The host cannot observe the client's real cursor, so there are two ways to
decide when the pointer has left the client:

- **`client-edge` (default).** The client tracks its own absolute cursor
  from the deltas it receives and sends a `MSG_RELEASE` back to the host
  when the pointer reaches the entry edge. Accurate, because the client
  knows its own resolution and applies the same motion the user sees. It
  requires the client to be started with `--screen-size WxH`; if the
  client is not given a screen size it will not signal, and you should use
  `host-virtual` instead.
- **`host-virtual`.** The host integrates the deltas it sends over a
  virtual canvas (sized from `--client-size`, or its own display by
  default) and returns control when that estimate recrosses the entry
  edge. Needs no cooperation from the client, but it is only an estimate
  and can drift from the client's real cursor over a long session.

Both ends should agree: run the host with `--return client-edge` (default)
and the client with `--screen-size`, or run the host with
`--return host-virtual` and omit the client's `--screen-size`.

In both methods the return edge is armed only after the pointer has moved
about a quarter of the screen away from where it entered. This dead-zone
keeps the entry position, which sits right next to the return edge, from
handing control straight back; you must move into the client first, then
return to the edge to come back.

The reverse `MSG_RELEASE` travels on the same UDP port as the forward
stream: the host binds the local side to `--port` so the client can always
reach it, rather than replying to an unpredictable ephemeral port. Open
that one UDP port both directions on any firewall between the machines.

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
| `--screen-size` | (none)   | this client's resolution `WxH`; enables the `client-edge` return method |

Pass `--screen-size 1920x1080` (your FreeBSD display's resolution) to use
the default `client-edge` return method, where the client detects its own
edge and signals the host. Omit it only when the host is run with
`--return host-virtual`.

The client creates a virtual HID named `ukvm-virtual-hid` and injects the
received input. On exit it releases all held keys and destroys the device.
