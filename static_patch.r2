# static_patch.r2 — optional static study patch (UNDERSTANDING-only, not robust).
# Run:  r2 -w -i static_patch.r2 libProject.so   (operates on a COPY!)
#
# WARNING: a static .so patch can make the main menu APPEAR but the login flow
# bootstraps the state the menu needs, so deeper UI may render blank/crash, and
# the runtime anti-tamper (maps scanners + fork/kill watchdog) is untouched.
# For a WORKING main menu use skip_login.js (Frida). This file is for studying
# the control flow only.

# 1) login/main gate: never branch to the login menu
wao nop @ 0x2522ec

# 2) in-render secondary key re-check: don't jump into the exit() cascade
wao nop @ 0x25232c
wao nop @ 0x25273c

# 3) validator: ignore "len != 2" and "OK" gate -> proceed to token path
wao nop @ 0x250f10
# force the "response == OK" branch to be taken unconditionally:
#   0x250f20  b.eq 0x250f68  ->  b 0x250f68   (40 02 00 54 -> 12 00 00 14)
wx 12000014 @ 0x250f20

# 4) validator: ignore token mismatch so g_isLoggedIn ends up 1
wao nop @ 0x251038

# verify
pd 2 @ 0x2522ec
pd 1 @ 0x250f20
