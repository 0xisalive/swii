/*
 * ukvm - minimal low-latency UDP software KVM
 *
 * common/hid_keymap.h - keycode translation tables.
 *
 * The wire protocol standardizes on USB HID Usage Tables, Keyboard/Keypad
 * page 0x07. Two static lookup tables bridge the platform-native codes to
 * and from that common currency:
 *
 *   mac_to_hid[256]    macOS virtual keycode (Carbon kVK_*) -> HID usage
 *   hid_to_evdev[256]  HID usage               -> FreeBSD evdev KEY_*
 *
 * Unmapped slots are left zero. On the macOS side a zero HID usage means
 * "do not transmit"; on the FreeBSD side a zero evdev code means "drop".
 *
 * The macOS half is only compiled where Carbon is available; the FreeBSD
 * half only where the evdev headers exist. Both are guarded so the header
 * can be included on either platform without dragging in the other's
 * system headers.
 */

#ifndef UKVM_HID_KEYMAP_H
#define UKVM_HID_KEYMAP_H

#include <stdint.h>

/*
 * USB HID Keyboard/Keypad usage IDs (page 0x07) referenced below. We spell
 * out the handful we need rather than depend on any system header so the
 * table is self-contained and readable on both platforms.
 */
enum {
    HID_A = 0x04, HID_B = 0x05, HID_C = 0x06, HID_D = 0x07,
    HID_E = 0x08, HID_F = 0x09, HID_G = 0x0A, HID_H = 0x0B,
    HID_I = 0x0C, HID_J = 0x0D, HID_K = 0x0E, HID_L = 0x0F,
    HID_M = 0x10, HID_N = 0x11, HID_O = 0x12, HID_P = 0x13,
    HID_Q = 0x14, HID_R = 0x15, HID_S = 0x16, HID_T = 0x17,
    HID_U = 0x18, HID_V = 0x19, HID_W = 0x1A, HID_X = 0x1B,
    HID_Y = 0x1C, HID_Z = 0x1D,

    HID_1 = 0x1E, HID_2 = 0x1F, HID_3 = 0x20, HID_4 = 0x21,
    HID_5 = 0x22, HID_6 = 0x23, HID_7 = 0x24, HID_8 = 0x25,
    HID_9 = 0x26, HID_0 = 0x27,

    HID_ENTER      = 0x28,
    HID_ESCAPE     = 0x29,
    HID_BACKSPACE  = 0x2A,
    HID_TAB        = 0x2B,
    HID_SPACE      = 0x2C,
    HID_MINUS      = 0x2D, /* - _ */
    HID_EQUAL      = 0x2E, /* = + */
    HID_LBRACKET   = 0x2F, /* [ { */
    HID_RBRACKET   = 0x30, /* ] } */
    HID_BACKSLASH  = 0x31, /* \ | */
    HID_SEMICOLON  = 0x33, /* ; : */
    HID_QUOTE      = 0x34, /* ' " */
    HID_GRAVE      = 0x35, /* ` ~ */
    HID_COMMA      = 0x36, /* , < */
    HID_PERIOD     = 0x37, /* . > */
    HID_SLASH      = 0x38, /* / ? */
    HID_CAPSLOCK   = 0x39,

    HID_F1  = 0x3A, HID_F2  = 0x3B, HID_F3  = 0x3C, HID_F4  = 0x3D,
    HID_F5  = 0x3E, HID_F6  = 0x3F, HID_F7  = 0x40, HID_F8  = 0x41,
    HID_F9  = 0x42, HID_F10 = 0x43, HID_F11 = 0x44, HID_F12 = 0x45,

    HID_PRINTSCREEN = 0x46,
    HID_SCROLLLOCK  = 0x47,
    HID_PAUSE       = 0x48,
    HID_INSERT      = 0x49,
    HID_HOME        = 0x4A,
    HID_PAGEUP      = 0x4B,
    HID_DELETE_FWD  = 0x4C, /* forward delete */
    HID_END         = 0x4D,
    HID_PAGEDOWN    = 0x4E,
    HID_RIGHT       = 0x4F,
    HID_LEFT        = 0x50,
    HID_DOWN        = 0x51,
    HID_UP          = 0x52,

    HID_NUMLOCK     = 0x53,
    HID_KP_SLASH    = 0x54,
    HID_KP_ASTERISK = 0x55,
    HID_KP_MINUS    = 0x56,
    HID_KP_PLUS     = 0x57,
    HID_KP_ENTER    = 0x58,
    HID_KP_1 = 0x59, HID_KP_2 = 0x5A, HID_KP_3 = 0x5B, HID_KP_4 = 0x5C,
    HID_KP_5 = 0x5D, HID_KP_6 = 0x5E, HID_KP_7 = 0x5F, HID_KP_8 = 0x60,
    HID_KP_9 = 0x61, HID_KP_0 = 0x62, HID_KP_PERIOD = 0x63,
    HID_KP_EQUAL = 0x67,

    HID_LCTRL  = 0xE0,
    HID_LSHIFT = 0xE1,
    HID_LALT   = 0xE2,
    HID_LMETA  = 0xE3,
    HID_RCTRL  = 0xE4,
    HID_RSHIFT = 0xE5,
    HID_RALT   = 0xE6,
    HID_RMETA  = 0xE7
};

/* Highest HID usage we index on; the evdev table is sized to cover it. */
#define UKVM_HID_MAX 256

/* ----------------------------------------------------------------------- */
/* macOS: Carbon virtual keycode -> USB HID usage                          */
/* ----------------------------------------------------------------------- */
/*
 * The index space is the 8-bit macOS virtual keycode (CGKeyCode). Values
 * are taken from <Carbon/Carbon.h> HIToolbox Events.h (kVK_*). Only the
 * standard ANSI layout plus modifiers, navigation, function and keypad
 * keys are populated; everything else stays zero and is not transmitted.
 *
 * Carbon virtual keycode constants, inlined so the table is readable and
 * does not require Carbon just to parse this header.
 */
enum {
    kVKX_ANSI_A = 0x00, kVKX_ANSI_S = 0x01, kVKX_ANSI_D = 0x02,
    kVKX_ANSI_F = 0x03, kVKX_ANSI_H = 0x04, kVKX_ANSI_G = 0x05,
    kVKX_ANSI_Z = 0x06, kVKX_ANSI_X = 0x07, kVKX_ANSI_C = 0x08,
    kVKX_ANSI_V = 0x09, kVKX_ANSI_B = 0x0B, kVKX_ANSI_Q = 0x0C,
    kVKX_ANSI_W = 0x0D, kVKX_ANSI_E = 0x0E, kVKX_ANSI_R = 0x0F,
    kVKX_ANSI_Y = 0x10, kVKX_ANSI_T = 0x11, kVKX_ANSI_1 = 0x12,
    kVKX_ANSI_2 = 0x13, kVKX_ANSI_3 = 0x14, kVKX_ANSI_4 = 0x15,
    kVKX_ANSI_6 = 0x16, kVKX_ANSI_5 = 0x17, kVKX_ANSI_Equal = 0x18,
    kVKX_ANSI_9 = 0x19, kVKX_ANSI_7 = 0x1A, kVKX_ANSI_Minus = 0x1B,
    kVKX_ANSI_8 = 0x1C, kVKX_ANSI_0 = 0x1D, kVKX_ANSI_RightBracket = 0x1E,
    kVKX_ANSI_O = 0x1F, kVKX_ANSI_U = 0x20, kVKX_ANSI_LeftBracket = 0x21,
    kVKX_ANSI_I = 0x22, kVKX_ANSI_P = 0x23, kVKX_ANSI_L = 0x25,
    kVKX_ANSI_J = 0x26, kVKX_ANSI_Quote = 0x27, kVKX_ANSI_K = 0x28,
    kVKX_ANSI_Semicolon = 0x29, kVKX_ANSI_Backslash = 0x2A,
    kVKX_ANSI_Comma = 0x2B, kVKX_ANSI_Slash = 0x2C, kVKX_ANSI_N = 0x2D,
    kVKX_ANSI_M = 0x2E, kVKX_ANSI_Period = 0x2F, kVKX_ANSI_Grave = 0x32,
    kVKX_ANSI_KeypadDecimal = 0x41, kVKX_ANSI_KeypadMultiply = 0x43,
    kVKX_ANSI_KeypadPlus = 0x45, kVKX_ANSI_KeypadClear = 0x47,
    kVKX_ANSI_KeypadDivide = 0x4B, kVKX_ANSI_KeypadEnter = 0x4C,
    kVKX_ANSI_KeypadMinus = 0x4E, kVKX_ANSI_KeypadEquals = 0x51,
    kVKX_ANSI_Keypad0 = 0x52, kVKX_ANSI_Keypad1 = 0x53,
    kVKX_ANSI_Keypad2 = 0x54, kVKX_ANSI_Keypad3 = 0x55,
    kVKX_ANSI_Keypad4 = 0x56, kVKX_ANSI_Keypad5 = 0x57,
    kVKX_ANSI_Keypad6 = 0x58, kVKX_ANSI_Keypad7 = 0x59,
    kVKX_ANSI_Keypad8 = 0x5B, kVKX_ANSI_Keypad9 = 0x5C,

    kVKX_Return = 0x24, kVKX_Tab = 0x30, kVKX_Space = 0x31,
    kVKX_Delete = 0x33, kVKX_Escape = 0x35, kVKX_Command = 0x37,
    kVKX_Shift = 0x38, kVKX_CapsLock = 0x39, kVKX_Option = 0x3A,
    kVKX_Control = 0x3B, kVKX_RightShift = 0x3C, kVKX_RightOption = 0x3D,
    kVKX_RightControl = 0x3E, kVKX_RightCommand = 0x36,
    kVKX_Function = 0x3F, kVKX_F17 = 0x40, kVKX_VolumeUp = 0x48,
    kVKX_VolumeDown = 0x49, kVKX_Mute = 0x4A, kVKX_F18 = 0x4F,
    kVKX_F19 = 0x50, kVKX_F20 = 0x5A, kVKX_F5 = 0x60, kVKX_F6 = 0x61,
    kVKX_F7 = 0x62, kVKX_F3 = 0x63, kVKX_F8 = 0x64, kVKX_F9 = 0x65,
    kVKX_F11 = 0x67, kVKX_F13 = 0x69, kVKX_F16 = 0x6A, kVKX_F14 = 0x6B,
    kVKX_F10 = 0x6D, kVKX_F12 = 0x6F, kVKX_F15 = 0x71, kVKX_Help = 0x72,
    kVKX_Home = 0x73, kVKX_PageUp = 0x74, kVKX_ForwardDelete = 0x75,
    kVKX_F4 = 0x76, kVKX_End = 0x77, kVKX_F2 = 0x78, kVKX_PageDown = 0x79,
    kVKX_F1 = 0x7A, kVKX_LeftArrow = 0x7B, kVKX_RightArrow = 0x7C,
    kVKX_DownArrow = 0x7D, kVKX_UpArrow = 0x7E
};

static const uint16_t mac_to_hid[256] = {
    [kVKX_ANSI_A] = HID_A, [kVKX_ANSI_B] = HID_B, [kVKX_ANSI_C] = HID_C,
    [kVKX_ANSI_D] = HID_D, [kVKX_ANSI_E] = HID_E, [kVKX_ANSI_F] = HID_F,
    [kVKX_ANSI_G] = HID_G, [kVKX_ANSI_H] = HID_H, [kVKX_ANSI_I] = HID_I,
    [kVKX_ANSI_J] = HID_J, [kVKX_ANSI_K] = HID_K, [kVKX_ANSI_L] = HID_L,
    [kVKX_ANSI_M] = HID_M, [kVKX_ANSI_N] = HID_N, [kVKX_ANSI_O] = HID_O,
    [kVKX_ANSI_P] = HID_P, [kVKX_ANSI_Q] = HID_Q, [kVKX_ANSI_R] = HID_R,
    [kVKX_ANSI_S] = HID_S, [kVKX_ANSI_T] = HID_T, [kVKX_ANSI_U] = HID_U,
    [kVKX_ANSI_V] = HID_V, [kVKX_ANSI_W] = HID_W, [kVKX_ANSI_X] = HID_X,
    [kVKX_ANSI_Y] = HID_Y, [kVKX_ANSI_Z] = HID_Z,

    [kVKX_ANSI_0] = HID_0, [kVKX_ANSI_1] = HID_1, [kVKX_ANSI_2] = HID_2,
    [kVKX_ANSI_3] = HID_3, [kVKX_ANSI_4] = HID_4, [kVKX_ANSI_5] = HID_5,
    [kVKX_ANSI_6] = HID_6, [kVKX_ANSI_7] = HID_7, [kVKX_ANSI_8] = HID_8,
    [kVKX_ANSI_9] = HID_9,

    [kVKX_Return]  = HID_ENTER,
    [kVKX_Escape]  = HID_ESCAPE,
    [kVKX_Delete]  = HID_BACKSPACE,
    [kVKX_Tab]     = HID_TAB,
    [kVKX_Space]   = HID_SPACE,

    [kVKX_ANSI_Minus]        = HID_MINUS,
    [kVKX_ANSI_Equal]        = HID_EQUAL,
    [kVKX_ANSI_LeftBracket]  = HID_LBRACKET,
    [kVKX_ANSI_RightBracket] = HID_RBRACKET,
    [kVKX_ANSI_Backslash]    = HID_BACKSLASH,
    [kVKX_ANSI_Semicolon]    = HID_SEMICOLON,
    [kVKX_ANSI_Quote]        = HID_QUOTE,
    [kVKX_ANSI_Grave]        = HID_GRAVE,
    [kVKX_ANSI_Comma]        = HID_COMMA,
    [kVKX_ANSI_Period]       = HID_PERIOD,
    [kVKX_ANSI_Slash]        = HID_SLASH,
    [kVKX_CapsLock]          = HID_CAPSLOCK,

    [kVKX_F1]  = HID_F1,  [kVKX_F2]  = HID_F2,  [kVKX_F3]  = HID_F3,
    [kVKX_F4]  = HID_F4,  [kVKX_F5]  = HID_F5,  [kVKX_F6]  = HID_F6,
    [kVKX_F7]  = HID_F7,  [kVKX_F8]  = HID_F8,  [kVKX_F9]  = HID_F9,
    [kVKX_F10] = HID_F10, [kVKX_F11] = HID_F11, [kVKX_F12] = HID_F12,

    [kVKX_Home]          = HID_HOME,
    [kVKX_PageUp]        = HID_PAGEUP,
    [kVKX_ForwardDelete] = HID_DELETE_FWD,
    [kVKX_End]           = HID_END,
    [kVKX_PageDown]      = HID_PAGEDOWN,
    [kVKX_Help]          = HID_INSERT, /* mac "Help" sits where Insert does */
    [kVKX_LeftArrow]     = HID_LEFT,
    [kVKX_RightArrow]    = HID_RIGHT,
    [kVKX_DownArrow]     = HID_DOWN,
    [kVKX_UpArrow]       = HID_UP,

    [kVKX_ANSI_KeypadDecimal]  = HID_KP_PERIOD,
    [kVKX_ANSI_KeypadMultiply] = HID_KP_ASTERISK,
    [kVKX_ANSI_KeypadPlus]     = HID_KP_PLUS,
    [kVKX_ANSI_KeypadClear]    = HID_NUMLOCK,
    [kVKX_ANSI_KeypadDivide]   = HID_KP_SLASH,
    [kVKX_ANSI_KeypadEnter]    = HID_KP_ENTER,
    [kVKX_ANSI_KeypadMinus]    = HID_KP_MINUS,
    [kVKX_ANSI_KeypadEquals]   = HID_KP_EQUAL,
    [kVKX_ANSI_Keypad0] = HID_KP_0, [kVKX_ANSI_Keypad1] = HID_KP_1,
    [kVKX_ANSI_Keypad2] = HID_KP_2, [kVKX_ANSI_Keypad3] = HID_KP_3,
    [kVKX_ANSI_Keypad4] = HID_KP_4, [kVKX_ANSI_Keypad5] = HID_KP_5,
    [kVKX_ANSI_Keypad6] = HID_KP_6, [kVKX_ANSI_Keypad7] = HID_KP_7,
    [kVKX_ANSI_Keypad8] = HID_KP_8, [kVKX_ANSI_Keypad9] = HID_KP_9,

    [kVKX_Control]      = HID_LCTRL,
    [kVKX_Shift]        = HID_LSHIFT,
    [kVKX_Option]       = HID_LALT,
    [kVKX_Command]      = HID_LMETA,
    [kVKX_RightControl] = HID_RCTRL,
    [kVKX_RightShift]   = HID_RSHIFT,
    [kVKX_RightOption]  = HID_RALT,
    [kVKX_RightCommand] = HID_RMETA
};

/* ----------------------------------------------------------------------- */
/* FreeBSD: USB HID usage -> evdev KEY_* / BTN_*                           */
/* ----------------------------------------------------------------------- */
/*
 * The index space is the HID usage ID. On FreeBSD the evdev KEY_* codes
 * come from <dev/evdev/input-event-codes.h>; that header is only present
 * on FreeBSD/Linux, so when it is unavailable (e.g. building the macOS
 * host or syntax-checking elsewhere) we fall back to the well-known
 * numeric values, which are stable ABI constants shared with Linux.
 */
#if defined(__FreeBSD__)
#include <dev/evdev/input-event-codes.h>
#define UKVM_HAVE_EVDEV_CODES 1
#elif defined(__linux__) && defined(UKVM_USE_LINUX_EVDEV_HEADER)
#include <linux/input-event-codes.h>
#define UKVM_HAVE_EVDEV_CODES 1
#endif

#ifndef UKVM_HAVE_EVDEV_CODES
/*
 * Minimal subset of evdev key codes (ABI-stable integers). These match the
 * values in <dev/evdev/input-event-codes.h>. Defined only when the system
 * header is absent so we never collide with it.
 */
#define KEY_ESC        1
#define KEY_1          2
#define KEY_2          3
#define KEY_3          4
#define KEY_4          5
#define KEY_5          6
#define KEY_6          7
#define KEY_7          8
#define KEY_8          9
#define KEY_9          10
#define KEY_0          11
#define KEY_MINUS      12
#define KEY_EQUAL      13
#define KEY_BACKSPACE  14
#define KEY_TAB        15
#define KEY_Q          16
#define KEY_W          17
#define KEY_E          18
#define KEY_R          19
#define KEY_T          20
#define KEY_Y          21
#define KEY_U          22
#define KEY_I          23
#define KEY_O          24
#define KEY_P          25
#define KEY_LEFTBRACE  26
#define KEY_RIGHTBRACE 27
#define KEY_ENTER      28
#define KEY_LEFTCTRL   29
#define KEY_A          30
#define KEY_S          31
#define KEY_D          32
#define KEY_F          33
#define KEY_G          34
#define KEY_H          35
#define KEY_J          36
#define KEY_K          37
#define KEY_L          38
#define KEY_SEMICOLON  39
#define KEY_APOSTROPHE 40
#define KEY_GRAVE      41
#define KEY_LEFTSHIFT  42
#define KEY_BACKSLASH  43
#define KEY_Z          44
#define KEY_X          45
#define KEY_C          46
#define KEY_V          47
#define KEY_B          48
#define KEY_N          49
#define KEY_M          50
#define KEY_COMMA      51
#define KEY_DOT        52
#define KEY_SLASH      53
#define KEY_RIGHTSHIFT 54
#define KEY_KPASTERISK 55
#define KEY_LEFTALT    56
#define KEY_SPACE      57
#define KEY_CAPSLOCK   58
#define KEY_F1         59
#define KEY_F2         60
#define KEY_F3         61
#define KEY_F4         62
#define KEY_F5         63
#define KEY_F6         64
#define KEY_F7         65
#define KEY_F8         66
#define KEY_F9         67
#define KEY_F10        68
#define KEY_NUMLOCK    69
#define KEY_SCROLLLOCK 70
#define KEY_KP7        71
#define KEY_KP8        72
#define KEY_KP9        73
#define KEY_KPMINUS    74
#define KEY_KP4        75
#define KEY_KP5        76
#define KEY_KP6        77
#define KEY_KPPLUS     78
#define KEY_KP1        79
#define KEY_KP2        80
#define KEY_KP3        81
#define KEY_KP0        82
#define KEY_KPDOT      83
#define KEY_F11        87
#define KEY_F12        88
#define KEY_KPENTER    96
#define KEY_RIGHTCTRL  97
#define KEY_KPSLASH    98
#define KEY_SYSRQ      99
#define KEY_RIGHTALT   100
#define KEY_HOME       102
#define KEY_UP         103
#define KEY_PAGEUP     104
#define KEY_LEFT       105
#define KEY_RIGHT      106
#define KEY_END        107
#define KEY_DOWN       108
#define KEY_PAGEDOWN   109
#define KEY_INSERT     110
#define KEY_DELETE     111
#define KEY_PAUSE      119
#define KEY_KPEQUAL    117
#define KEY_LEFTMETA   125
#define KEY_RIGHTMETA  126

#define BTN_LEFT       0x110
#define BTN_RIGHT      0x111
#define BTN_MIDDLE     0x112
#define BTN_SIDE       0x113
#define BTN_EXTRA      0x114
#endif /* !UKVM_HAVE_EVDEV_CODES */

static const uint16_t hid_to_evdev[UKVM_HID_MAX] = {
    [HID_A] = KEY_A, [HID_B] = KEY_B, [HID_C] = KEY_C, [HID_D] = KEY_D,
    [HID_E] = KEY_E, [HID_F] = KEY_F, [HID_G] = KEY_G, [HID_H] = KEY_H,
    [HID_I] = KEY_I, [HID_J] = KEY_J, [HID_K] = KEY_K, [HID_L] = KEY_L,
    [HID_M] = KEY_M, [HID_N] = KEY_N, [HID_O] = KEY_O, [HID_P] = KEY_P,
    [HID_Q] = KEY_Q, [HID_R] = KEY_R, [HID_S] = KEY_S, [HID_T] = KEY_T,
    [HID_U] = KEY_U, [HID_V] = KEY_V, [HID_W] = KEY_W, [HID_X] = KEY_X,
    [HID_Y] = KEY_Y, [HID_Z] = KEY_Z,

    [HID_1] = KEY_1, [HID_2] = KEY_2, [HID_3] = KEY_3, [HID_4] = KEY_4,
    [HID_5] = KEY_5, [HID_6] = KEY_6, [HID_7] = KEY_7, [HID_8] = KEY_8,
    [HID_9] = KEY_9, [HID_0] = KEY_0,

    [HID_ENTER]     = KEY_ENTER,
    [HID_ESCAPE]    = KEY_ESC,
    [HID_BACKSPACE] = KEY_BACKSPACE,
    [HID_TAB]       = KEY_TAB,
    [HID_SPACE]     = KEY_SPACE,
    [HID_MINUS]     = KEY_MINUS,
    [HID_EQUAL]     = KEY_EQUAL,
    [HID_LBRACKET]  = KEY_LEFTBRACE,
    [HID_RBRACKET]  = KEY_RIGHTBRACE,
    [HID_BACKSLASH] = KEY_BACKSLASH,
    [HID_SEMICOLON] = KEY_SEMICOLON,
    [HID_QUOTE]     = KEY_APOSTROPHE,
    [HID_GRAVE]     = KEY_GRAVE,
    [HID_COMMA]     = KEY_COMMA,
    [HID_PERIOD]    = KEY_DOT,
    [HID_SLASH]     = KEY_SLASH,
    [HID_CAPSLOCK]  = KEY_CAPSLOCK,

    [HID_F1]  = KEY_F1,  [HID_F2]  = KEY_F2,  [HID_F3]  = KEY_F3,
    [HID_F4]  = KEY_F4,  [HID_F5]  = KEY_F5,  [HID_F6]  = KEY_F6,
    [HID_F7]  = KEY_F7,  [HID_F8]  = KEY_F8,  [HID_F9]  = KEY_F9,
    [HID_F10] = KEY_F10, [HID_F11] = KEY_F11, [HID_F12] = KEY_F12,

    [HID_PRINTSCREEN] = KEY_SYSRQ,
    [HID_SCROLLLOCK]  = KEY_SCROLLLOCK,
    [HID_PAUSE]       = KEY_PAUSE,
    [HID_INSERT]      = KEY_INSERT,
    [HID_HOME]        = KEY_HOME,
    [HID_PAGEUP]      = KEY_PAGEUP,
    [HID_DELETE_FWD]  = KEY_DELETE,
    [HID_END]         = KEY_END,
    [HID_PAGEDOWN]    = KEY_PAGEDOWN,
    [HID_RIGHT]       = KEY_RIGHT,
    [HID_LEFT]        = KEY_LEFT,
    [HID_DOWN]        = KEY_DOWN,
    [HID_UP]          = KEY_UP,

    [HID_NUMLOCK]     = KEY_NUMLOCK,
    [HID_KP_SLASH]    = KEY_KPSLASH,
    [HID_KP_ASTERISK] = KEY_KPASTERISK,
    [HID_KP_MINUS]    = KEY_KPMINUS,
    [HID_KP_PLUS]     = KEY_KPPLUS,
    [HID_KP_ENTER]    = KEY_KPENTER,
    [HID_KP_1] = KEY_KP1, [HID_KP_2] = KEY_KP2, [HID_KP_3] = KEY_KP3,
    [HID_KP_4] = KEY_KP4, [HID_KP_5] = KEY_KP5, [HID_KP_6] = KEY_KP6,
    [HID_KP_7] = KEY_KP7, [HID_KP_8] = KEY_KP8, [HID_KP_9] = KEY_KP9,
    [HID_KP_0] = KEY_KP0, [HID_KP_PERIOD] = KEY_KPDOT,
    [HID_KP_EQUAL] = KEY_KPEQUAL,

    [HID_LCTRL]  = KEY_LEFTCTRL,
    [HID_LSHIFT] = KEY_LEFTSHIFT,
    [HID_LALT]   = KEY_LEFTALT,
    [HID_LMETA]  = KEY_LEFTMETA,
    [HID_RCTRL]  = KEY_RIGHTCTRL,
    [HID_RSHIFT] = KEY_RIGHTSHIFT,
    [HID_RALT]   = KEY_RIGHTALT,
    [HID_RMETA]  = KEY_RIGHTMETA
};

#endif /* UKVM_HID_KEYMAP_H */
