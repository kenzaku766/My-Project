# `libProject.so` — Part 5: Skipping the login menu, landing on the main menu

Tool: **radare2 6.1.7** (verified). Target: `libProject.so` (ELF64 AArch64 PIE,
stripped, NDK clang 7). Follows Parts 1–4.

This part answers: *given the dispatcher in `fcn.002519b0`, what is the smallest,
safest change that makes the app render the **main menu** without ever passing
through the **login menu**?*

---

## TL;DR

1. The Login → Main split is **one branch**:
   `0x002522ec  cbz w8, 0x2523bc` inside `fcn.002519b0`.
   `w8` is the byte at `0x5deb58` (`g_isLoggedIn`). If zero → `0x2523bc`
   (login-menu builder). Fall-through → main-menu builder.
2. The previously documented "3-NOP study bypass" patches **all three** dispatcher
   reads of the flag (`0x251f14`, `0x252064`, `0x2522e8`). Only the last one
   actually decides which menu renders; the other two are bookkeeping. The
   reason that bypass historically *crashed* the main menu is **not** the
   branch — it is that the main menu consumes state that only the login
   response handler `fcn.00250dc8` writes.
3. The honest fix has two pieces:
   - **Force the gate** (1-byte patch to NOP at `0x2522ec`), AND
   - **Force the login-response validator to always succeed** so the
     init paths that populate `0x5d8440`, `0x5d8488`, `0x5d7258`, `0x5d7270`,
     `0x5ddfc8` still run.
4. Anti-tamper (CRC + Dobby + `/proc/self/maps` from Part 2) will see the
   `.text` edits. For a clean run prefer **Frida** (runtime poke) over static
   `.so` patching, or NOP the scanners first.

---

## 1. Why `0x2522ec` is the only gate that matters

`fcn.002519b0` (the menu dispatcher) reads `g_isLoggedIn @ 0x5deb58` three
times:

```
0x00251f14   ldrb w9,  [x25, 0xb58]    ; (A) gates a side-effect at 0x251f1c
0x00252064   ldrb w9,  [x25, 0xb58]    ; (B) folded into another flag at 0xbe0
0x002522e8   ldrb w8,  [x25, 0xb58]
0x002522ec   cbz  w8,  0x2523bc        ; (C) ← Login vs Main split
```

Disassembly around (C):

```
0x002522e4  bl   fcn.00250554            ; pre-render housekeeping
0x002522e8  ldrb w8,  [x25, 0xb58]       ; w8 = g_isLoggedIn
0x002522ec  cbz  w8,  0x2523bc           ; if !logged_in → login menu
0x002522f0  adrp x25, 0x5d8000
0x002522f4  add  x25, x25, 0x440         ; &g_menu_key_a  (std::string)
0x002522f8  adrp x8,  0x5d8000
0x002522fc  add  x8,  x8,  0x488         ; &g_menu_key_b  (std::string)
0x00252300  ldrb w27, [x25]              ; libc++ SSO size/flag byte
...
```

The fall-through at `0x2522f0` immediately starts iterating two libc++
`std::string` globals (`0x5d8440`, `0x5d8488`) — that is the main-menu code.
Branch target `0x2523bc` walks a different once-flag at `0x5f44e8` and pulls
a different string at `0x5f44d8` — that is the login-menu code.

So **(C) is the one and only Login↔Main switch**. (A) and (B) only change
auxiliary flags consumed deeper in the main-menu body; they do not route
between menus.

## 2. The login flag is written from exactly four sites

```
fcn.0024efe0 0x24f238  strb wzr, [x8, 0xb58]   ; logout/reset
fcn.00250dc8 0x251004  strb wzr, [x8, 0xb58]   ; response invalid → cleared
fcn.00250dc8 0x251034  strb w8,  [x9, 0xb58]   ; memcmp(==) → 1, else 0
fcn.00250dc8 0x251048  strb w9,  [x8, 0xb58]   ; unconditional 1 (full match path)
```

All four writers live in the network-response handler. There is no init-time
default; the flag is byte-zero from the loader's BSS clear until
`fcn.00250dc8` runs against a Telegram reply.

### 2.1 What `fcn.00250dc8` does, in order

```
0x250e08  "Checking..."          → UI line
0x250e3c  "Loading config..."    → UI line (loops up to 0x31 sleep(1) iters
                                   while &g_net_ready (0x5deb08) == 0)
0x250e80  "Config not loaded"    → failure branch
0x250ea0  fcn.00190620           ; std::string ← arg1 (the JSON body)
0x250ee0  fcn.0016d00c           ; clear g_response_buf @ 0x5ddfc8
0x250f10  b.ne 0x250f24          ; if (len != 2)            → fail
0x250f18  mov  w9, 0x4b4f        ; "OK"
0x250f1c  cmp  w8, w9
0x250f20  b.eq 0x250f68          ; if (resp == "OK")        → continue
0x250f6c  ldrb w8, [_, 0x4d0]    ; "compare expected vs returned token?" flag
0x250f70  cbz  w8, 0x251000      ; if disabled → just set flag=0 + clear
0x250f74  ...                    ; load std::string @ 0x5d7270, 0x5d7258
0x250fcc  tbnz w10, 0, 0x251020  ; SSO vs heap path
0x251020  bl   memcmp
0x251028  cmp  w0, 0
0x251030  cset w8, eq
0x251034  strb w8, [_, 0xb58]    ; g_isLoggedIn = (memcmp==0)
0x251038  cbnz w0, 0x251008      ; mismatch → fail
0x251040  mov  w9, 1
0x251048  strb w9, [_, 0xb58]    ; g_isLoggedIn = 1   (full match)
0x251058  "Login Success"        → UI line
```

That is the canonical "fetch validkey via Telegram, compare to local
expected key, flip the flag" flow Parts 2–4 reconstructed.

## 3. What the main menu actually needs

Walking `fcn.002519b0` from `0x2522f0` onward, the main-menu body reads:

| Global | Symbol guess | Written by |
|---|---|---|
| `0x5d8440` | menu key A (std::string) | config loader (myKey.xml) |
| `0x5d8488` | menu key B (std::string) | config loader (myKey.xml) |
| `0x5d7258` | expected token (std::string) | `fcn.00250dc8` (login response) |
| `0x5d7270` | returned token (std::string) | `fcn.00250dc8` (login response) |
| `0x5ddfc8` | response buffer ("OK") | `fcn.00250dc8` |
| `0x5deb08` | g_net_ready (acquire-load) | `fcn.00270104` (network worker) |
| `0x5deb58` | g_isLoggedIn | `fcn.00250dc8` (the four writers above) |

The two `0x5d84xx` strings come from the **config load** path (XML parse), not
from the network reply. They must be populated, but they don't depend on
login success — they are ready as long as `myKey.xml` was found. That is why
the menu can be reached safely *if* the config path completes; the login
flag is the only Boolean gate above them.

The three login-handler globals (`0x5d7258`, `0x5d7270`, `0x5ddfc8`) feed
the validator at `0x250fb0`/`0x251020`. If you bypass the validator without
populating them, the main-menu body itself won't notice — but any deeper UI
hook that re-reads them (e.g. a token-display widget) would observe empty
SSO strings and likely render blank or crash on a NULL `c_str()`.

## 4. The patch recipes

### 4.1 Recipe A — 1-instruction "branch only" bypass (fast sanity test)

Replace the gate with NOP. Forces main-menu render regardless of flag value.

```
@ 0x002522ec
- 88 06 00 34     cbz w8, 0x2523bc
+ 1f 20 03 d5     nop
```

What this does NOT solve: any code that later reads `g_isLoggedIn` directly
will still see `0`. If the main-menu body has a "show username" line that
reads `0x5d7270`, it will be empty (default-constructed SSO). For UI-only
study this is usually enough to *see* the main menu; for end-to-end use it
is not.

### 4.2 Recipe B — Force validator success (recommended)

Lets the real login flow run (config loads, network thread spawns, response
arrives) but treats ANY response as "OK + matching token". Every downstream
global (`0x5d7258`, `0x5d7270`, `0x5ddfc8`) gets populated by the legitimate
path; only the comparator is short-circuited.

Two surgical writes in `fcn.00250dc8`:

```
@ 0x00250f10                                 ; "len != 2" guard
- a1 00 00 54   b.ne 0x250f24                ; fail if length != 2
+ 1d 00 00 14   b   0x250f84                 ; jump past length+OK checks
                                             ; (offset = (0x250f84-0x250f10)/4 = 0x1d)

@ 0x00251038                                 ; memcmp mismatch guard
- 80 fe ff 35   cbnz w0, 0x251008            ; on mismatch → fail
+ 1f 20 03 d5   nop                          ; ignore comparator result
```

Combined with Recipe A's NOP at `0x2522ec`, the app:
- runs config load (populates `0x5d8440`, `0x5d8488`),
- spawns the network worker (populates `0x5deb08`, `0x5ddfc8`),
- parses any response into `0x5d7258`/`0x5d7270` even if it's empty,
- sets `g_isLoggedIn = 1` via the unconditional store at `0x251048`,
- and the dispatcher falls through into the main-menu builder.

Three 4-byte writes total. No new code is introduced.

### 4.3 Recipe C — Hijack on entry (offline / no-network builds)

If you want the main menu reachable with **no network at all** (e.g. running
in an emulator without internet), replace the prologue of `fcn.00250dc8`
with a stub that writes the flag and returns. Skips config-string population,
so deeper UI may still break. Use only when network is impossible.

```
@ 0x00250dc8
+ 88 1c 00 b0    adrp x8,  0x5de000
+ 09 00 80 52    mov  w9,  1
+ 09 61 2d 39    strb w9,  [x8, 0xb58]      ; g_isLoggedIn = 1
+ c0 03 5f d6    ret
```

This is the riskiest option and the one most likely to surface a follow-on
NULL deref (per Part 4 §2.1 — cached `jclass`/`jmethodID` slots).

## 5. Anti-tamper interaction (Part 2 recap)

Any of the recipes above edit `.text`. Part 2 catalogued three detectors that
will fire on these edits:

- **CRC-32/64 over the loaded segment** (`fcn.00273270` / `fcn.00273598`).
- **`/proc/self/maps` scanner** that walks segments and rejects non-original
  page hashes.
- **Dobby's sigaction-based hook layer** (`0x276940/68`), which the same
  scanners cross-validate.

For a static `.so` patch to survive runtime you must also NOP the three
detectors *first*, in the same patched binary. For study work this is a
two-step chain and easy to get wrong (one missed checker re-arms the others).

### 5.1 Frida alternative (recommended for study)

A Frida script avoids `.text` edits entirely — write the flag from JS once
`libProject.so` is mapped:

```js
const base = Module.findBaseAddress('libProject.so');
const FLAG = base.add(0x5deb58);
// Wait until JNI_OnLoad has run, then poke:
Memory.protect(FLAG, 1, 'rw-');
FLAG.writeU8(1);
// Optional: re-poke on a timer so any legitimate "logout" write
// inside fcn.00250dc8 gets undone immediately.
setInterval(() => FLAG.writeU8(1), 200);
```

The CRC/maps scanners typically hash code only, so writing to `.bss`
escapes detection. This is the cleanest path for the "skip login, render
main menu" study.

## 6. What to verify next

In order of likelihood to break the main menu after Recipe A+B:

1. The cached JNI handles called out in Part 4 §2. If any `FindClass` /
   `GetMethodID` global lives behind the login flow proper (rather than
   `JNI_OnLoad`), the menu will SIGSEGV on first JNI call. Hunt: every
   `.bss` slot in `0x5d7000–0x5df000` that's *only* written after a
   `FindClass`/`GetMethodID` xref.
2. The `std::call_once` flag at `0x5f0ea8` + map at `0x5f0e90`. First call
   builds a lookup keyed by `"Mapkey"`. If `"Mapkey"` is one of the
   `0x5d8440`/`0x5d8488` strings, config-load is mandatory and Recipe C
   will fault here.
3. The `fork`+`dup2`+`kill -9` helper at `0x2a349c`. Confirm no anti-tamper
   scanner reaches it before the dispatcher fall-through.

---

## Appendix — addresses cheat sheet

```
Dispatcher entry          fcn.002519b0
  network-worker spawn    0x002519ec   bl fcn.0025106c
  pthread_create          0x00251a34
  net-ready gate          0x00251a5c   ldarb [0x5deb08]
  bookkeeping read (A)    0x00251f14
  bookkeeping read (B)    0x00252064
  Login/Main split   →    0x002522ec   cbz w8, 0x2523bc    ← PATCH
  main-menu body          0x002522f0…
  login-menu body         0x002523bc…

Login response handler    fcn.00250dc8
  len != 2 guard          0x00250f10   b.ne 0x250f24       ← PATCH
  "OK" compare            0x00250f1c
  memcmp                  0x00251024
  mismatch guard          0x00251038   cbnz w0, 0x251008   ← PATCH
  flag = 1 (full path)    0x00251048   strb w9, [_, 0xb58]
```
