#!/usr/bin/env python3
# vspace_inject.py — no-miss Frida injector for a game running in VIRTUAL SPACE
# (DualSpace / MultiSpace: com.dualspace.multispace.androidx).
#
# The game is a CHILD process of the virtual container, so `-f` is no good.
# This driver uses TWO strategies and picks whichever fires first:
#   (1) child gating on the container  -> catches the game the instant it spawns
#   (2) process polling by substring    -> attaches as soon as the proc appears
# It injects libcrash_skip_login.js, which itself waits for libCrash.so to map.
#
# Usage in Termux (frida-server running as root on the device):
#   python vspace_inject.py --match libcrash
#   # optional:  --container com.dualspace.multispace.androidx
#   #            --proc-match <substring of the game process name>
#   #            --script libcrash_skip_login.js
#
# Requires: pip install frida frida-tools
import argparse, sys, time, frida

def on_message(msg, data):
    if msg.get('type') == 'send':
        print('[js]', msg.get('payload'))
    elif msg.get('type') == 'error':
        print('[js-error]', msg.get('stack') or msg.get('description'))

def load(session, js):
    s = session.create_script(js)
    s.on('message', on_message)
    s.load()
    return s

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--container', default='com.dualspace.multispace.androidx')
    ap.add_argument('--proc-match', default=None,
                    help='substring of the GAME process name as shown by frida-ps -U')
    ap.add_argument('--match', default='libcrash', help='passed through; informational')
    ap.add_argument('--script', default='libcrash_skip_login.js')
    args = ap.parse_args()

    with open(args.script, 'r') as f:
        js = f.read()

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    print('[*] device:', dev)
    injected = {}

    # ---- strategy 1: child gating on the container -------------------------
    def on_child(child):
        try:
            print('[child] spawned pid=%s id=%s' % (child.pid, child.identifier))
            sess = dev.attach(child.pid)
            load(sess, js)
            injected[child.pid] = sess
            dev.resume(child.pid)
            print('[+] injected into child pid', child.pid)
        except Exception as e:
            print('[-] child inject failed:', e)
            try: dev.resume(child.pid)
            except Exception: pass

    try:
        dev.on('child-added', on_child)
        dev.enable_child_gating  # presence check
    except Exception:
        pass

    try:
        pid = dev.spawn([args.container])
        try: dev.enable_child_gating(pid)
        except Exception as e: print('[i] child gating unavailable:', e)
        dev.resume(pid)
        print('[*] container spawned pid', pid, '- now OPEN the game inside virtual space')
    except Exception as e:
        print('[i] could not spawn container (open it manually):', e)

    # ---- strategy 2: poll for the game process and attach ------------------
    print('[*] polling for game process... (Ctrl+C to stop)')
    seen = set()
    try:
        while True:
            for p in dev.enumerate_processes():
                key = p.pid
                if key in injected or key in seen:
                    continue
                name = (p.name or '').lower()
                want = args.proc_match.lower() if args.proc_match else None
                # attach to anything that isn't us/the shell; if --proc-match given, filter
                if want and want not in name:
                    continue
                if not want and name in ('frida-server', 'frida', 'python', 'sh', 'bash'):
                    continue
                try:
                    sess = dev.attach(p.pid)
                    load(sess, js)
                    injected[p.pid] = sess
                    seen.add(key)
                    print('[+] attached+injected:', p.name, p.pid)
                except Exception:
                    seen.add(key)
            time.sleep(1.0)
    except KeyboardInterrupt:
        print('\n[*] bye')

if __name__ == '__main__':
    main()
