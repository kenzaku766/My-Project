# `libProject.so` — Part 7: Skip the login menu → land on the MAIN menu (Frida, working)

Tool: **radare2 6.1.7** (re-verified this session, native `linux-arm_64`).
Target: `libProject.so` — ELF64 AArch64 PIE, **stripped**, NDK clang 7, C++/libc++, BoringSSL static.
Scope: authorized study of the user's OWN project (kenzaku766/My-Project). Follows Parts 1–6 + the verdict.

> Parts 1–6 reconstructed the control flow and concluded *"use Frida"* but never shipped a
> complete harness. **This part is that deliverable**, with every offset re-verified against the
> binary this session.

---

## TL;DR

The login menu and the main menu are split by a single branch; the trap is that the main menu
**consumes state that only the login/config flow builds**, plus there is a **second in-render key
re-check** that funnels into an `exit()` cascade, plus runtime **anti-tamper** (two
`/proc/self/maps` scanners + a `fork`+`kill -9` watchdog).

The clean route is **Frida**: let the real worker/validator run so state initialises, then
override only the *decision* and neutralise the *kill paths*. Ready-to-run script:
**`skip_login.js`**. Static study-only recipe: **`static_patch.r2`**.

---

## 1. Re-verified addresses (radare2 6.1.7, this session)

| What | Address | Bytes / insn (verified) |
|---|---|---|
| Login↔Main gate | `0x2522ec` | `88 06 00 34` `cbz w8, 0x2523bc` |
| g_isLoggedIn read feeding the gate | `0x2522e8` | `ldrb w8, [x25, 0xb58]` |
| In-render re-check: length mismatch → exit | `0x25232c` | `41 87 00 54` `b.ne 0x253414` |
| In-render re-check: memcmp | `0x252734` | `bl sym.imp.memcmp` |
| In-render re-check: match → success | `0x252738` | `cbz w0, 0x252778` |
| In-render re-check: mismatch → exit | `0x25273c` | `37 03 00 14` `b 0x253418` |
| `exit()` cascade (anti-tamper kill) | `0x253414+` | `strb wzr,[x22,0x9a8]` then ~10× `bl exit` |
| Validator (real login logic) | `fcn.00250dc8` | void fn(std::string* response) |
| Validator "len==2" guard | `0x250f10` | `a1 00 00 54` `b.ne 0x250f24` |
| Validator "OK" gate | `0x250f18/1c/20` | `mov w9,0x4b4f` (`'OK'`); `b.eq 0x250f68` |
| Validator token memcmp | `0x251024` | `bl sym.imp.memcmp` |
| Validator sets flag = (memcmp==0) | `0x251034` | `strb w8,[x9,0xb58]` |
| Validator mismatch guard | `0x251038` | `80 fe ff 35` `cbnz w0, 0x251008` |
| `JavaVM*` cache (JNI_OnLoad) | `0x257074` | `str x0,[x9,0x1b0]` → `0x5d71b0` (never NULL at runtime) |
| Network worker (sets g_net_ready) | `0x270104` | `…bl 0x18d250; and w8,w0,1; stlrb w8,[0x5deb08]` |
| maps scanner (line parser) | `0x273270` | indirect-called; returns int |
| maps scanner (ELF-magic hunt) | `0x273598` | scans mappings for `\x7fELF` |

Strings confirmed: `Login Success` `@0x4a3fd7`, `Auth Failed` `@0x4a3fe5`,
`Please Login! (Copy Key to Clipboard)` `@0x4a4043`, `Loading config...` `@0x4a3fb3`,
`https://api.telegram.org/bot` `@0x4a295b`, `myKey.xml` `@0x4a3855`.

## 2. Why a Frida override (and not just NOP the gate)

`g_isLoggedIn @ 0x5deb58` is in `.bss` (zero at load) and is only written by the validator
`fcn.00250dc8`, which itself waits on the **network worker** `fcn.00270104 → fcn.0018d250`
that populates the menu-key strings `0x5d8440`/`0x5d8488`. Therefore:

```
JNI_OnLoad (0x257074)   -> caches JavaVM* @0x5d71b0           [never NULL at runtime, Part 4]
dispatcher fcn.002519b0 -> pthread_create(worker fcn.00270104)
worker fcn.00270104     -> g_net_ready = fcn.0018d250() & 1   [fills 0x5d8440/0x5d8488]
validator fcn.00250dc8  -> spin g_net_ready; need resp=="OK"; token memcmp -> g_isLoggedIn
gate 0x2522ec (cbz)     -> g_isLoggedIn ? MAIN(0x2522f0) : LOGIN(0x2523bc)
MAIN body               -> uses JNI handles + the std::strings the login flow built
in-render re-check      -> 0x25232c / 0x25273c -> exit() cascade @0x253414 on mismatch
```

Skip the worker/validator and the menu strings stay empty → blank UI / NULL `c_str()` → crash
(Parts 2–4). So the harness **lets them run** and overrides only the boolean + the kill paths.

## 3. The harness — what `skip_login.js` does (in order)

1. **Wait** for `libProject.so` to be mapped (after `dlopen`/`JNI_OnLoad`).
2. **Blind the two `/proc/self/maps` scanners** (`0x273270`, `0x273598`) → `Interceptor.replace`
   returning `0`. Do this *first*, or the `fork`+`kill -9` watchdog can SIGKILL the process.
3. **Neutralise `exit()`** (safety net for the anti-tamper cascade).
4. **NOP the two in-render re-check branches** (`0x25232c`, `0x25273c`) so the main-menu body
   can never enter the `exit()` cascade at `0x253414`.
5. **NOP the gate** (`0x2522ec`) → dispatcher always falls through to the main menu.
6. **Hook the validator `fcn.00250dc8` `onLeave`** and force `g_isLoggedIn = 1`. Using `onLeave`
   (not entry) means the validator's **side effects already ran** (config strings, JNI handle
   caching) — we only flip the final decision, so the menu has valid state to render.
7. **Seed `0x5d73c0`** with `"2099-12-31 23:59:59"` (libc++ SSO write) so the expiry
   `sscanf`/`mktime` path can't route into an "Expired" branch. Optional if real config fills it.
8. **Hold the flag** on a 250 ms timer to undo any logout/reset writer.

Run:
```sh
frida -U -f <your.package.name> -l skip_login.js --no-pause   # spawn (preferred)
# or: frida -U -n <AppName> -l skip_login.js                  # attach
```

Why spawn: the gate/validator and the maps scanners can run early; spawning guarantees the
hooks are installed before those execute.

## 4. Static alternative — `static_patch.r2` (control-flow study only)

```sh
cp libProject.so libProject_study.so
r2 -w -i static_patch.r2 libProject_study.so
```
It applies six edits (verified to assemble this session):

| Addr | From | To | Purpose |
|---|---|---|---|
| `0x2522ec` | `cbz w8,0x2523bc` | `nop` | always main menu |
| `0x25232c` | `b.ne 0x253414` | `nop` | skip exit cascade (len) |
| `0x25273c` | `b 0x253418` | `nop` | skip exit cascade (memcmp) |
| `0x250f10` | `b.ne 0x250f24` | `nop` | ignore "len!=2" |
| `0x250f20` | `b.eq 0x250f68` | `b 0x250f68` (`12 00 00 14`) | force "OK" accepted |
| `0x251038` | `cbnz w0,0x251008` | `nop` | ignore token mismatch |

**Limits (why static is study-only):** the runtime anti-tamper (maps scanners, `fork`+`kill -9`
watchdog, Dobby/xDL layer) is untouched, and any deeper UI widget that re-reads login-produced
state can still render blank if the real network/config flow didn't run. The **menu renders, but
isn't guaranteed functional** — exactly the verdict from Parts 5–6. Use Frida for a working menu.

## 5. What is still NOT recoverable here

- The real `validkey` — delivered by the live **Telegram Bot API** reply (`@0x4a295b`), not in the
  binary. To capture it, additionally hook BoringSSL `SSL_read`/`SSL_write` and dump the JSON.
- The XOR-`0x7e` obfuscated symbol name xDL resolves at runtime into `0x5f4668` (Part 6).

## 6. Reproduce the verifications (radare2)

```sh
r2 -q -c "pd 4 @ 0x2522e8"  libProject.so      # gate
r2 -q -c "pd 6 @ 0x252730"  libProject.so      # in-render memcmp + exit branch
r2 -q -c "pd 6 @ 0x250f0c"  libProject.so      # validator OK gate
r2 -q -c "pd 8 @ 0x251020"  libProject.so      # validator token compare + flag store
r2 -q -c "pd 22 @ 0x270104" libProject.so      # worker -> g_net_ready
r2 -q -c "pd 12 @ 0x257074" libProject.so      # JNI_OnLoad JavaVM* cache
```

_Generated with radare2 6.1.7 — Part 7 of the authorized login study for the user's own project
(kenzaku766/My-Project). Delivers the working Frida harness Parts 1–6 pointed to._
