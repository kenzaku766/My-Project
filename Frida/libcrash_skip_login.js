/*
 * libcrash_skip_login.js — Frida: skip login -> MAIN menu, for libCrash.so
 * running inside a VIRTUAL SPACE app (com.dualspace.multispace.androidx).
 *
 * Same binary as libProject.so (just renamed) -> ALL OFFSETS ARE IDENTICAL.
 * Verified against radare2 6.1.7 (kenzaku766/My-Project). Authorized study.
 *
 * VIRTUAL SPACE NOTES:
 *  - The game runs as a CHILD of the DualSpace container, not as its own real
 *    process, so `frida -f <container>` is useless. Use late-attach or the
 *    companion driver vspace_inject.py (child gating).
 *  - The native lib may be loaded from the virtual app's data dir via a custom
 *    loader; we therefore match the module by SUBSTRING ('libcrash'), not by an
 *    exact filename, and we keep polling until it appears.
 *
 * Termux run (after launching the game inside virtual space):
 *    frida -U -n <game_process_name> -l libcrash_skip_login.js
 *  or no-miss:
 *    python vspace_inject.py --match libcrash
 */

'use strict';

const LIB_MATCH = 'libcrash';   // case-insensitive substring of the mapped .so

// ---- verified offsets (UNCHANGED by the rename) ----------------------------
const OFF = {
  GATE_CBZ          : 0x2522ec,   // login vs main split (cbz w8,login)
  RECHECK_BNE       : 0x25232c,   // b.ne 0x253414 -> exit cascade
  RECHECK_B_FAIL    : 0x25273c,   // b    0x253418 -> exit cascade
  VALIDATOR         : 0x250dc8,   // void fcn(std::string* response)
  G_IS_LOGGED_IN    : 0x5deb58,   // byte flag
  G_EXPIRY_TEXT     : 0x5d73c0,   // std::string parsed by sscanf
  MAPS_SCAN_PARSE   : 0x273270,
  MAPS_SCAN_ELFHUNT : 0x273598,
};

const NOP = [0x1f, 0x20, 0x03, 0xd5];

function writeNop(addr) { Memory.protect(addr, 4, 'rwx'); addr.writeByteArray(NOP); }

function seedSsoString(addr, str) {            // libc++ short std::string (<=22)
  if (str.length > 22) throw new Error('SSO too long');
  Memory.protect(addr, 24, 'rw-');
  addr.writeU8(str.length << 1);
  for (let i = 0; i < str.length; i++) addr.add(1 + i).writeU8(str.charCodeAt(i));
  addr.add(1 + str.length).writeU8(0);
}

function findLib() {                            // substring match (virtual-space safe)
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    if (m.name.toLowerCase().indexOf(LIB_MATCH) !== -1 ||
        (m.path && m.path.toLowerCase().indexOf(LIB_MATCH) !== -1)) return m;
  }
  return null;
}

function arm(mod) {
  const base = mod.base;
  console.log('[*] ' + mod.name + ' @ ' + base + '  (path: ' + mod.path + ')');
  const A = (o) => base.add(o);

  // 1) blind the /proc/self/maps scanners FIRST (else fork+kill -9 watchdog fires)
  [OFF.MAPS_SCAN_PARSE, OFF.MAPS_SCAN_ELFHUNT].forEach((o) => {
    try {
      Interceptor.replace(A(o), new NativeCallback(function () { return 0; }, 'int', []));
      console.log('[+] maps scanner neutralised @ 0x' + o.toString(16));
    } catch (e) { console.log('[-] scanner 0x' + o.toString(16) + ': ' + e); }
  });

  // 2) neutralise exit() (safety net for anti-tamper cascade)
  const ex = Module.findExportByName(null, 'exit');
  if (ex) Interceptor.replace(ex, new NativeCallback(function (c) {
    console.log('[!] exit(' + c + ') swallowed'); }, 'void', ['int']));

  // 3) NOP in-render re-check branches so menu body can't enter exit cascade
  writeNop(A(OFF.RECHECK_BNE));
  writeNop(A(OFF.RECHECK_B_FAIL));

  // 4) NOP the gate -> always fall through to MAIN menu
  writeNop(A(OFF.GATE_CBZ));

  // 5) hook validator onLeave: side effects already ran -> just force the flag
  Interceptor.attach(A(OFF.VALIDATOR), {
    onLeave: function () {
      const f = A(OFF.G_IS_LOGGED_IN); Memory.protect(f, 1, 'rw-'); f.writeU8(1);
      console.log('[+] validator returned -> g_isLoggedIn = 1');
    }
  });

  // 6) seed far-future expiry (optional if real config fills 0x5d73c0)
  try { seedSsoString(A(OFF.G_EXPIRY_TEXT), '2099-12-31 23:59:59');
        console.log('[+] expiry seeded'); } catch (e) { console.log('[-] ' + e); }

  // 7) hold the flag against any logout/reset writer
  setInterval(function () {
    const f = A(OFF.G_IS_LOGGED_IN);
    if (f.readU8() !== 1) { Memory.protect(f, 1, 'rw-'); f.writeU8(1); }
  }, 250);

  console.log('[*] armed — login skipped, main menu should render.');
}

let tries = 0;
const wait = setInterval(function () {
  const mod = findLib();
  if (mod) { clearInterval(wait); arm(mod); }
  else if (++tries > 1200) { clearInterval(wait); console.log('[-] ' + LIB_MATCH + ' never mapped'); }
}, 50);
