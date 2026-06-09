# `libProject.so` — Part 4: JNI_OnLoad correction + true crash hypothesis

Tool: **radare2 6.1.7** (verified independently in a clean sandbox).
Target: `libProject.so` — ELF64 AArch64 PIE, stripped, NDK clang 7, C++/libc++.
Follows Parts 1–3. **This part corrects Part 3 §4.**

---

## TL;DR

1. **`0x5d71b0` is the cached `JavaVM*`, not an "app/UI context object".** It is set unconditionally by the dynamic linker via `JNI_OnLoad` (`0x257074  str x0, [x9, 0x1b0]`). At runtime it is **never NULL**.
2. **The menu-builder prologue is a JNI `AttachCurrentThread` call**, not a generic C++ virtual call. The offset `+0x20` in `*JavaVM` (i.e. `JNIInvokeInterface_`) is `AttachCurrentThread` on AArch64.
3. **Part 3 §4's "NULL deref at `0x5d71b0`" diagnosis is therefore wrong.** That deref cannot fault. The real crash lives further down the menu-builder bodies (`fcn.00229760`, `fcn.00227b9c`, `fcn.0022eb08`).

## 1. Evidence

### 1.1 `JNI_OnLoad` writes its first argument to `0x5d71b0`

`axt @ 0x5d71b0` over the whole binary returns 66 reads and exactly **one write**:

```
sym.JNI_OnLoad 0x257074 [DATA:-w-] str x0, [x9, 0x1b0]
```

Disassembly around that store:
```
0x0025704c  sub  sp, sp, 0x30
0x00257060  ldr  x8, [x19, 0x28]     ; stack canary
0x00257064  adrp x9, 0x5d7000
0x00257068  mov  w2, 6               ; JNI_VERSION_1_6 low half
0x00257070  str  x8, [sp, 8]
0x00257074  str  x0, [x9, 0x1b0]     ; *(0x5d71b0) = arg1  -> JavaVM*
0x00257078  ldr  x8, [x0]            ; x8 = *vm           -> JNIInvokeInterface*
0x0025707c  movk w2, 1, lsl 16       ; w2 = 0x00010006 = JNI_VERSION_1_6
0x00257088  ldr  x8, [x8, 0x30]      ; vtable[+0x30] = GetEnv
0x0025708c  blr  x8                  ; (*vm)->GetEnv(vm, &env, JNI_VERSION_1_6)
```

This is the canonical Android NDK boilerplate:
```c
jint JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    g_vm = vm;                                  // -> 0x5d71b0
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, &env, JNI_VERSION_1_6) != JNI_OK) return -1;
    return JNI_VERSION_1_6;
}
```

The store happens before any application code runs — the Android linker invokes `JNI_OnLoad` synchronously during `dlopen()`. Therefore **`0x5d71b0 != NULL` for any code that observes it at runtime.**

### 1.2 The menu-builder prologue is `AttachCurrentThread`

`fcn.00229760` prologue (identical shape in `fcn.00227b9c` and `fcn.0022eb08`):
```
0x00229778  ldr  x8,  [x21, 0x28]     ; stack canary
0x0022977c  add  x1,  sp, 0x18        ; &env
0x00229780  mov  x2,  xzr             ; thr_args = NULL
0x00229788  adrp x8,  0x5d7000
0x0022978c  ldr  x0,  [x8, 0x1b0]     ; x0 = JavaVM* (always non-NULL)
0x00229790  str  xzr, [sp, var_18h]   ; env = NULL (out param init)
0x00229794  ldr  x8,  [x0]            ; x8 = JNIInvokeInterface* (vtable)
0x00229798  ldr  x8,  [x8, 0x20]      ; +0x20 = AttachCurrentThread
0x0022979c  blr  x8                   ; vm->AttachCurrentThread(vm, &env, NULL)
0x002297a8  ldr  x19, [sp, var_18h]   ; x19 = env (JNIEnv*)
```

`JNIInvokeInterface_` slot map (AArch64, sizeof(void*)=8):
| Offset | Slot |
|---:|---|
| 0x00 | reserved0/1/2 (3 ptrs) |
| 0x18 | DestroyJavaVM |
| **0x20** | **AttachCurrentThread** ✅ |
| 0x28 | DetachCurrentThread |
| 0x30 | GetEnv |
| 0x38 | AttachCurrentThreadAsDaemon |

So `vtable[+0x20]` is unambiguously `AttachCurrentThread`. Every menu builder begins by acquiring a `JNIEnv*` on the calling thread before invoking Java UI methods — standard Android JNI pattern, not a "logged-in context" call.

### 1.3 Why Part 3 §4 reached the wrong conclusion

Part 3 assumed `0x5d71b0` lived in `.bss` and therefore was zero-at-load. The address is in `.bss`, but `JNI_OnLoad` initializes it *before* any consumer runs — exactly because the JavaVM cache pattern is so common. Distinguishing "`.bss` and uninitialized by application logic" from "`.bss` and initialized by the dynamic linker callback" is the lesson.

## 2. Where the crash actually is

`AttachCurrentThread` succeeds (Java is alive; the .so wouldn't have loaded otherwise). The next instructions in `fcn.00229760` are:

```
0x002297a0  adrp x8, 0x5f0000
0x002297a4  add  x8, x8, 0xea8         ; &g_once_flag @ 0x5f0ea8
0x002297ac  ldarb w8, [x8]             ; acquire-load once flag (libc++ call_once)
0x002297b0  tbz   w8, 0, 0x229878      ; bit0 == 0 -> run the slow init path
...
0x002297b4  adrp x20, 0x5f0000
0x002297b8  add  x20, x20, 0xe90       ; &g_map @ 0x5f0e90
0x002297bc  mov  x0, x20
0x002297c0  bl   fcn.0025c064          ; map ctor / get-or-build
0x002297d4  bl   fcn.00189fa4          ; std::unordered_map<string,…>::operator[]
0x002297e0  add  x1, x1, 0x73a         ; key = "Mapkey" @ 0x4a373a
0x002297f4  bl   fcn.0018a294          ; std::string ctor for key
...
```

Reading without inferring too much:
- `0x5f0ea8` / `0x5f0e90` look like a **libc++ `std::call_once` flag + a function-local static** (likely a `std::unordered_map<std::string, …>` keyed by names like `"Mapkey"`). Local statics are thread-safely initialised on first use; this branch should not in itself crash.
- The crash must therefore come from one of:
  1. A **cached `jclass` / `jmethodID` global** (a `.bss` slot that the login path populates via `FindClass`/`GetMethodID`) being NULL when `(*env)->CallXxxMethod(env, NULL, …)` is invoked. JNI does not null-check `clazz`/`methodID`; ART will SIGSEGV.
  2. A **`std::string` global the menu reads** (e.g. `0x5d73c0`, the validkey/expiry text) being default-constructed (empty SSO). The `sscanf("%d-%d-%d %d:%d:%d", …)` matches 0 fields → `mktime` of a zeroed `struct tm` → epoch `0`, which the expiry comparator may treat as "expired" and route into a path that itself dereferences a NULL UI handle.
  3. A **deliberate kill from anti-tamper.** Part 2's `fork`+`dup2`+`kill -9` helper is a candidate — but only if the maps scanner has already flagged something. With *only* the 3 NOPs from Part 1 applied and Dobby/maps detection untouched, the static patch can be seen if any detector inspects `.text` around `0x252xxx`.

Without a logcat tombstone (`pc`, `fault addr`, `backtrace`) the exact instruction can't be pinned the way Part 3 claimed. The honest statement is: "crash is *after* `AttachCurrentThread`, in code that consumes login-produced state — either JNI handles or `std::string`/map data."

## 3. Updated globals table

| Global | Addr | Section | Real meaning | At load |
|---|---|---|---|---|
| **JavaVM* (cache)** | **`0x5d71b0`** | .bss | set by `JNI_OnLoad`, used for `AttachCurrentThread` | **set by linker → non-NULL** |
| expiry/validkey text | `0x5d73c0` | .bss | std::string parsed by `sscanf` | empty (SSO, but valid object) |
| expected token | `0x5d7258` | .bss | std::string compared in validator | empty |
| returned token | `0x5d7270` | .bss | std::string compared in validator | empty |
| response buffer | `0x5ddfc8` | .bss | last server response (must be `"OK"`) | empty |
| cfg_gate | `0x5d84d0` | .bss | boolean enabling the token compare | 0 |
| g_net_ready | `0x5deb08` | .bss | set by HTTP callback | 0 |
| g_isLoggedIn | `0x5deb58` | .bss | validator output | 0 |
| g_check_inprogress | `0x5d8628` | .bss | validator "busy" lock | 0 |
| g_expiry_ts | `0x5d8830` | .bss | mktime result | 0 |
| g_menu_built | `0x5de7f8` | .bss | one-shot menu build flag | 0 |
| call_once flag | `0x5f0ea8` | .bss | libc++ once_flag for the map below | 0 |
| local-static map | `0x5f0e90` | .bss | unordered_map<string,…>, key `"Mapkey"` | empty |

## 4. What to investigate next (queued)

In order of payoff for getting the menu to render without a real device run:

1. **Cached JNI handles.** Find every `.bss` slot that holds a `jclass` or `jmethodID` (look for writes after `FindClass` / `GetMethodID` / `NewGlobalRef`). The login path's "init side effects" almost certainly include these. Candidate xref starting points: any function that calls `sym.imp.NewGlobalRef` (if PLT-imported) or that builds class names like the package name visible at `getPackageName` xrefs (`0x171b78`, `0x18aeb8`).
2. **Network response handler.** Indirectly-called writer to `0x5deb08` and `0x5ddfc8`. Walk back from `0x5deb08` writes to find the curl/HTTP completion callback.
3. **`/proc/self/maps` scanners** `fcn.00273270`, `fcn.00273598` — required first hop for any future runtime-instrumentation study (Route B).
4. **Dobby signal-hook layer** around `intercept_routing_common_bridge_handler` `0x276940/68` — confirms the sigaction-based detection envelope.
5. **xDL XOR symbol-name table** — `eor …, 0x7e` @ `0x256f00` — decode the obfuscated symbol names xDL is resolving.
6. **The `fork`+`dup2`+`kill -9` helper** at `0x2a349c/c0/d4/0x2a3984` — verify what it execs and what triggers it.

## 5. Practical recommendation

The cleanest way to keep studying without fighting ghosts is still **Route A from Part 3**: run the binary on a real device with a valid `validkey` once so the login path populates all of the above, then re-attach with r2/lldb to study the live, fully-initialised state. Static patching is now confirmed to be a dead end **for a different reason than Part 3 stated** — not because `0x5d71b0` is NULL, but because login is the only thing that constructs the JNI handle cache and the `std::string` data the UI consumes.

_Generated with radare2 6.1.7 — Part 4 of the authorized login study for the user's own project (kenzaku766/My-Project)._
