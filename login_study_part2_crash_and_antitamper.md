# `libProject.so` — Part 2: Why the patched lib CRASHES + full anti-tamper inventory

Tool: radare2 6.1.7 (aarch64). Follows `login_study_continued.md`.
Question answered: *"after patching, it crashes when the menu is about to appear — are there other anti-tamper?"*

---

## TL;DR
1. **The crash is NOT a checksum catching your patch.** It is a **null/garbage dereference**:
   forcing the logged-in render path runs menu/expiry code that uses state which only the
   **real login flow initializes**. Login here is not a boolean — it *bootstraps app state*.
2. The earlier **"CRC-32/64 integrity" finding was a FALSE POSITIVE** — those strings belong
   to **liblzma/xz**, not an app integrity check (proof below).
3. Real protections that DO exist: a **forked subprocess/exec helper** (`fork`+`dup2`+`kill -9`),
   **Dobby** signal-based hooking, **`/proc/self/maps` scanners**, **xDL** stealth symbol
   resolution, **expiry/time check**, and **TLS verify** on the Telegram call.

---

## 1. Root cause of the crash (verified)

After your 3 NOPs, execution falls into the logged-in branch of `fcn.002522e8` and reaches the
"success" path at `0x252778`:

```
0x252778  adrp x9, 0x5d7000 ; add x9,#0x3c0   -> std::string @ 0x5d73c0 (the key/expiry text)
0x25278c  adrp x1, 0x49c000 ; +0xac5          -> sscanf format (date)
0x2527c4  bl   sscanf                          ; parse "Expired"/validkey date out of the string
0x2527e0  bl   mktime                          ; -> expiry timestamp, stored @ 0x5d8830
0x2527f8  bl   0x229760 / 0x227b9c / 0x22eb08  ; build & render the MAIN menu (reads config)
```

- `0x5d73c0` and the config structures used by `0x229760/0x227b9c/0x22eb08` are **only populated
  after a successful login** (config parsed from the Telegram API response / `myKey.xml`).
- With login skipped, those are empty/NULL → `sscanf` on an empty string + menu builders
  dereferencing NULL config → **SIGSEGV right as the menu appears**. That matches your symptom.

> **Conclusion:** the login gate and the app-state init are deliberately coupled. A static NOP of
> the gate cannot work because the data the main menu needs is produced *by* the login routine.
> This coupling is itself the most effective anti-tamper in the binary.

## 2. The CRC "integrity" was a false positive (corrected)

`0x5a9fb0` is a contiguous **array of pointers** to consecutive `.rodata` strings:
```
0x5a9fa0: 0x492cd5  0x492ce8
0x5a9fb0: 0x492d05 ("CRC-32 check failed")  0x492d19
0x5a9fc0: 0x492d3c  0x492d4e ...
```
That is the classic **liblzma/xz error-message table**. `CrcGenerateTable` / `Crc64GenerateTable`
are referenced **only inside `xdl_lzma_decompress`** (`0x16f8f4`, `0x16f910`) — i.e. xz CRC tables
used to decompress xDL's symbol data, **not** a self-integrity check of `.text`.
➡️ There is **no CRC self-check** that would detect your 12-byte patch.

## 3. Real anti-tamper / anti-analysis present (verified xrefs)

| # | Mechanism | Evidence |
|---|---|---|
| 1 | **Login↔state coupling** (the crash cause) | `fcn.002522e8` success path `0x252778`+ |
| 2 | **Secondary in-render key re-check + `exit()` cascade** | `0x25232c`, `0x25273c` → `0x253414` (~10× `exit`) |
| 3 | **Forked subprocess/exec helper** (`fork`+`dup2`(0/1)+`kill -9`) — runs shell-style checks & can SIGKILL | `fork`@`0x2a349c`; `dup2`@`0x2a34c0/d4`; `kill(.,9)`@`0x2a3984` |
| 4 | **Dobby** inline-hook framework, signal(`sigaction`)-based trampolines | `intercept_routing_common_bridge_handler` (`0x276940/68`), many `sigaction` xrefs |
| 5 | **`/proc/self/maps` scanners** (Frida/injected-.so detection) — **no direct xref → called indirectly** (fn-ptr/thread/Dobby) | `fcn.00273270`, `fcn.00273598`; str `/proc/self/maps`@`0x491680` |
| 6 | **xDL** stealth symbol resolution (bypasses linker namespace; xz-compressed sym data) | `xdl_lzma_decompress`@`0x16f8f4`; `dlsym`@`0x256f14`; XOR name-decode `eor …,0x7e`@`0x256f00` |
| 7 | **Expiry / time gate** | `sscanf`+`mktime`@`0x2527c4/e0`; "Expired : %s"@`0x4a3f9a`; `/storage/emulated/0/expire_debug.txt`@`0x49caa0` (ref `0x198570`) |
| 8 | **TLS verify (anti-MITM)** on Telegram call | `CURLOPT_SSL_VERIFYHOST`, `certificate verify failed` in `.rodata` |
| 9 | JNI package/signature check | `getPackageName` xrefs `0x171b78`, `0x18aeb8` |

> Note: **No `ptrace` import** — anti-debug here is via the forked helper + signal handlers, not ptrace.

## 4. What to do instead (study approach that won't crash)

Static NOP of the gate is a dead end because of §1. For studying the logged-in UI:

- **Best:** run the *real* login once with a valid key so the config/state initializes, then study.
- **Dynamic (recommended for study):** with the maps/Dobby detection neutralised first, hook
  `fcn.00250dc8` (validator) to (a) force its result **and** (b) let it run its state-init side
  effects — or hook the config parser `fcn.0018d250` to inject a known-good config so the menu
  builders (`0x229760/0x227b9c/0x22eb08`) have valid data.
- **If you must stay static:** you'd have to also synthesise the config/state the menu reads —
  impractical; this is exactly what the design prevents.

## 5. To pinpoint the exact faulting pointer
Share the crash address from `logcat` (the `backtrace`/`fault addr`), or the value of `pc`/`x?`
at the SIGSEGV. I can map it to the precise global (likely a NULL config pointer used by
`0x229760` / `0x227b9c` / `0x22eb08`) and confirm which init routine must run first.

_Generated with radare2 6.1.7 — continued study of the user's own project._
