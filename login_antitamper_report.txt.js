# `libProject.so` — Login-Skip Path & Anti-Tamper Map (radare2)

Target: `libProject.so` — ARM aarch64, ELF64, PIE, stripped, clang 7.0.0 (Android NDK), C++ / libc++.
Tool: radare2 6.1.7. Analysis: `aa; aae` + manual disasm.

---

## 1. The function that shows Login menu vs Main menu

**`fcn.002522e8`** (size **0x133C / 4924 bytes**) — the main ImGui render/UI loop.
This is the single function that decides whether to draw the **Login menu** or the **Main menu**.

### Decision point (read this first)
```
0x002522e8   ldrb w8, [x25, 0xb58]      ; w8 = g_isLoggedIn  (global @ 0x5deb58)
0x002522ec   cbz  w8, 0x2523bc          ; if NOT logged in -> jump to LOGIN menu
0x002522f0   ...                        ; else fall through -> MAIN menu path
```
- **Branch taken (g_isLoggedIn == 0) -> `0x2523bc`** : renders the login UI. At
  `0x002524a8` it draws the string **"Please Login! (Copy Key to Clipboard)"**
  (`0x4a4043`) and an InputText bound to the user-key buffer `0x5deb59` (width 0x80).
- **Fall-through (g_isLoggedIn != 0) -> MAIN menu** : but see the trap in section 2.

> Patch point A (skip login menu): NOP `0x2522ec` (`88 06 00 34`) so execution always
> falls through to the main-menu path. **By itself this is NOT enough** — the main path
> re-validates the key and kills the process (section 2).

---

## 2. Anti-Tamper layer woven INTO the menu router (the trap)

Right after the `g_isLoggedIn` check, the logged-in path performs a **second key
comparison** (`std::string` @ `0x5d8440` vs `0x5d8488`, SSO + byte-loop / memcmp,
same scheme as the validator `fcn.00250dc8`). On **mismatch** it branches to:

```
0x00253414   strb wzr, [x22, 0x9a8]     ; clear a state flag (0x5d89a8)
0x00253418   mov  w0, wzr
0x0025341c   bl   sym.imp.exit          ; exit(0)
0x00253420   mov  w0, wzr
0x00253424   bl   sym.imp.exit          ; exit(0)   <-- repeated ~10x on purpose
0x00253428   bl   sym.imp.exit          ; ... anti-patch: NOPing one won't help
   ... (cascade of exit() calls) ...
```

The repeated `exit()` calls are a deliberate **anti-patch / anti-tamper** measure:
defeating the gate requires neutralising the compare *branch*, not a single instr.

> Relevant compare branches that lead to `0x253414`:
> - `0x0025232c  b.ne 0x253414`  (length mismatch)
> - `0x0025273c  b.ne 0x253414`  (content mismatch, via memcmp path)
>
> Patch point B (study): force these `b.ne` to fall through (or fix the two
> `std::string`s @ `0x5d8440` / `0x5d8488` to be equal at runtime). Combined with
> Patch A, the UI then renders the Main menu directly.

### Cleanest single study-bypass
Force the global byte **`g_isLoggedIn @ 0x5deb58 = 1`** AND make the second pair of
strings equal — OR patch both compare branches. The decision state is centralised in
that one byte, but the **secondary re-check + exit() spam** is the protection around it.

---

## 3. Other Anti-Tamper / Integrity mechanisms found

| # | Mechanism | Evidence (addr) |
|---|---|---|
| 1 | **Self exit() cascade** on key re-check fail | `fcn.002522e8` @ `0x253414` |
| 2 | **`/proc/self/maps` scanner** (detect injected .so / Frida / hooks) | `fcn.00273270` (772 B), `fcn.00273598` (1024 B); symbol `get_process_map_with_proc_maps` (`0x4e872a`); err `"[!] /proc/self/maps parse failed!"` (`0x4e8707`); path string `0x491680` |
| 3 | **Dobby inline-hook framework** + dynamic symbol resolve | `DobbyInstrument` call @ `0x256f20`; `dlsym` @ `0x256f14`; loads `liblogic.so` (`0x4a40d7`) @ `0x256f38` |
| 4 | **XOR string obfuscation** | `eor w10, w10, 0x7e` @ `0x256f00` (decodes lib name before dlsym) |
| 5 | **Anti-debug timing loop** | retry+`sleep(1)` loop @ `0x256f38`–`0x256f50` |
| 6 | **CRC-32 / CRC-64 integrity** | `CrcGenerateTable` (`0x4917c2`), `Crc64GenerateTable` (`0x4917d3`), `"CRC-32 check failed"` (`0x492d05`, referenced via data table `0x5a9fb0`) |
| 7 | **Package / signature check (JNI)** | `getPackageName` referenced @ `0x171b78`, `0x18aeb8` |
| 8 | **Library presence / integrity** | scans `/libc.so` (`0x49172a`), `/libart.so` (`0x491733`), `/system/lib64/liblzma.so` (`0x4917a9`), `/Assets/library/libLibServer.so` (`0x4a2343`), `liblogic.so` |
| 9 | **TLS / SSL verification** (anti-MITM) | `CURLOPT_SSL_VERIFYHOST`, peer-cert checks (curl/OpenSSL in `.rodata`) |
| 10 | **`mapsaved` marker** | string `0x4a3741`, referenced @ `0x2291f4` |

> Note: the `/proc/self/maps` scanners (`fcn.00273270`, `fcn.00273598`) have **no direct
> call xrefs** — they are invoked **indirectly** (function pointer / thread / Dobby),
> which is itself an anti-static-analysis trait.

---

## 4. Key globals (login + anti-tamper)

| Address | Role |
|---|---|
| `0x5deb58` | **g_isLoggedIn** (1 byte) — central login state |
| `0x5deb59` | user-key buffer (C-string, InputText target) |
| `0x5de3d0` | login_enabled gate |
| `0x5d8440` / `0x5d8488` | std::string pair for the **2nd (anti-tamper) key re-check** |
| `0x5d89a8` / `0x5d89ac` | UI/anti-tamper state flags (gate before render) |
| `0x5d7270` / `0x5d7258` | validkey / userkey (validator `fcn.00250dc8`) |
| `0x5d8660` | login mode (1=Simple V1.0.0, 2=Full V1.0.0) |
| `0x5f44e8` / `0x5f44d8` | atomic UI-state used in login-menu branch |

---

## 5. Function index

| Function | Addr | Size | Purpose |
|---|---|---|---|
| `fcn.002522e8` | `0x2522e8` | 4924 B | **Main UI router**: login vs main menu + 2nd key re-check + exit() trap |
| `fcn.00250dc8` | `0x250dc8` | 672 B | Login validator (thread): memcmp validkey vs userkey -> g_isLoggedIn |
| `fcn.00251344` | `0x251344` | 636 B | Login trigger: spawns validator on detached thread |
| `fcn.00273270` | `0x273270` | 772 B | /proc/self/maps scanner #1 |
| `fcn.00273598` | `0x273598` | 1024 B | /proc/self/maps scanner #2 |
| `~0x256ef0` | `0x256ef0` | — | Dobby/dlsym loader for `liblogic.so` (XOR-decoded) |

---

## 6. Summary

- **Where the login menu is skipped / main menu shown**: `fcn.002522e8 @ 0x2522ec`,
  gated on `g_isLoggedIn (0x5deb58)`. Login UI at `0x2523bc` ("Please Login!" `0x2524a8`);
  main menu on the fall-through path.
- **Anti-tamper is real and layered**: a secondary in-render key re-check that calls
  `exit()` ~10× on failure, plus `/proc/self/maps` hook-detection, Dobby instrumentation,
  CRC-32/64 integrity, package-signature (JNI), library checks, XOR-obfuscated strings,
  and SSL verification.
- A naive single-byte patch of `g_isLoggedIn` is caught by the secondary re-check + exit()
  cascade; a study-bypass must also neutralise the `b.ne 0x253414` branches (or satisfy
  `0x5d8440 == 0x5d8488`).

_Generated with radare2 6.1.7 for study of the user's own project (kenzaku766/My-Project)._
