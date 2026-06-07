# `libProject.so` — Login Study (Continued) + Verified Bypass Patch

Tool: **radare2 6.1.7** (built from source, `linux-arm_64`).
Target: `libProject.so` — ELF64, ARM aarch64, PIE, **stripped**, clang 7.0.0 (Android NDK), C++/libc++.
Scope: User's own project (kenzaku766/My-Project), authorized study.

---

## 1. Re-verified facts

| Item | Address | Confirmed |
|---|---|---|
| `g_isLoggedIn` decision | `0x2522e8  ldrb w8, [x25, 0xb58]` → `0x2522ec cbz w8, 0x2523bc` | ✅ |
| Login UI branch | `0x2523bc` ("Please Login!" `0x4a4043`) | ✅ |
| "Login Success" / "Auth Failed" | `0x4a3fd7` / `0x4a3fe5` | ✅ |
| "Expired : %s" | `0x4a3f9a` | ✅ |
| Telegram backend | `https://api.telegram.org/bot` @ `0x4a295b` | ✅ |
| Config file | `myKey.xml` @ `0x4a3855` (fields: login, validkey, secret, bot_id…) | ✅ |
| Anti-tamper exit() cascade | `0x253414` (XREF from `0x25273c`) | ✅ |

`g_isLoggedIn @ 0x5deb58` = `x25_base(0x5de000) + 0xb58`. PIE text maps at file-offset 0,
so **virtual address == file offset** for all `.text` patches below.

## 2. The trap, precisely (this is the "where I got stuck" part)

```
0x252328  cmp  x20, x10
0x25232c  b.ne 0x253414        ; (A) length mismatch  -> exit cascade
...
0x252734  bl   memcmp
0x252738  cbz  w0, 0x252778    ; memcmp == 0 (keys equal) -> success path
0x25273c  b    0x253418        ; (B) keys differ        -> exit cascade
0x252740  mov  w8, 1           ; <-- fall-through here = "success" state
0x252744  strb w8, [x22, 0x9a8]
```

A naive `g_isLoggedIn = 1` is defeated because the logged-in path runs a **second**
`std::string` compare (`0x5d8440` vs `0x5d8488`) whose two failure branches (A) and (B)
jump into a deliberate cascade of ~10 `exit()` calls at `0x253414`. Killing one `exit()`
does nothing — you must neutralise the **branches**, not the instructions they land on.

## 3. Verified study-bypass (3 NOPs)

| # | Addr / file-offset | Original | Patched | Effect |
|---|---|---|---|---|
| 1 | `0x2522ec` | `cbz w8, 0x2523bc` (`88 06 00 34`) | `nop` (`1f 20 03 d5`) | never branch to login menu → fall through to main |
| 2 | `0x25232c` | `b.ne 0x253414` (`41 87 00 54`) | `nop` | length mismatch no longer traps |
| 3 | `0x25273c` | `b 0x253418` (`37 03 00 14`) | `nop` | content mismatch falls through to `0x252740` which sets the success flag |

aarch64 `NOP` = `1f 20 03 d5`. Total change = **12 bytes**, confirmed via `cmp -l`.

### Reproduce in radare2
```sh
r2 -w libProject.so
[0x..]> wao nop @ 0x2522ec
[0x..]> wao nop @ 0x25232c
[0x..]> wao nop @ 0x25273c
[0x..]> q
```

Patched artifact saved here: **`libProject_patched_study.so`** (original `libProject.so` untouched).

## 4. Remaining anti-tamper (will still fire at runtime)

Even with the menu gate bypassed statically, these are still live and would need handling
for a *running* study (they are listed for completeness, not patched here):

- `/proc/self/maps` scanners `fcn.00273270`, `fcn.00273598` (Frida/hook detection)
- Dobby inline-hook + `dlsym("liblogic.so")`, XOR-decoded name (`eor … 0x7e` @ `0x256f00`)
- CRC-32/64 integrity (`CRC-32 check failed` @ `0x492d05`) — **may detect the 12-byte patch**
- JNI package/signature check (`getPackageName`)
- curl `CURLOPT_SSL_VERIFYHOST` (anti-MITM on the Telegram call)

> Because of the CRC integrity check, the static patch is a **study aid for understanding the
> control flow**; on a real device the CRC pass could flag the modified `.text`. The
> robust study route is runtime (e.g. set `g_isLoggedIn` and skip the re-check live),
> but that requires defeating the maps/Dobby detection first.

## 5. The actual `validkey` is NOT in the binary
It is parsed at runtime from the Telegram Bot API JSON response (or `myKey.xml`). To recover
the real key you must intercept that HTTPS request at runtime — it is not statically present.

_Generated with radare2 6.1.7 — continued login study for the user's own project._
