#!/usr/bin/env python3
"""Generate fresh signatures and immediately test them with curl."""
import frida
import json
import subprocess
import sys
import time

sigs_received = None

def on_message(message, data):
    global sigs_received
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict) and payload.get('type') == 'sigs':
            sigs_received = payload
    elif message['type'] == 'error':
        print(f"[ERR] {message.get('description', '')}")

def run_curl(url, headers, label):
    cmd = ['curl', '-s', '-w', '\n%{http_code} %{size_download}', url]
    for k, v in headers.items():
        cmd.extend(['-H', f'{k}: {v}'])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    lines = result.stdout.strip().split('\n')
    status_line = lines[-1] if lines else "?"
    print(f"  {label}: {status_line}")
    return status_line

def main():
    device = frida.get_usb_device()
    pid = None
    for app in device.enumerate_applications(scope="full"):
        if app.identifier == "com.dragon.read" and app.pid:
            pid = app.pid
            break
    if not pid:
        print("App not running!")
        return

    session = device.attach(pid)
    js = open("scripts/instant_test.js").read()
    script = session.create_script(js)
    script.on('message', on_message)
    script.load()

    # Wait for signatures
    for _ in range(10):
        if sigs_received:
            break
        time.sleep(0.5)

    if not sigs_received:
        print("No signatures received!")
        session.detach()
        return

    s = sigs_received
    url = s['url']
    tsMs = s['tsMs']

    base_headers = {
        'User-Agent': 'com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)',
        'Accept': 'application/json',
        'Accept-Encoding': 'identity',
        'sdk-version': '2',
        'lc': '101',
        'passport-sdk-version': '5051451',
        'x-tt-store-region': 'cn-gd',
        'x-tt-store-region-src': 'did',
        'X-SS-REQ-TICKET': tsMs,
        'x-reading-request': f'{tsMs}-abcd1234',
    }

    all_sigs = {
        'X-Gorgon': s['gorgon'],
        'X-Khronos': s['khronos'],
        'X-Argus': s['argus'],
        'X-Ladon': s['ladon'],
        'X-Helios': s['helios'],
        'X-Medusa': s['medusa'],
    }

    print(f"\nFresh signatures (ts={s['khronos']}):")
    print(f"  Helios: {s['helios'][:40]}...")
    print(f"  Medusa: {s['medusa'][:40]}... ({len(s['medusa'])} chars)")
    print()

    # Test 1: ALL headers (should work)
    h1 = {**base_headers, **all_sigs}
    run_curl(url, h1, "T1: ALL headers")

    # Test 2: Only Helios + Medusa
    h2 = {**base_headers, 'X-Helios': s['helios'], 'X-Medusa': s['medusa']}
    run_curl(url, h2, "T2: Only Helios+Medusa")

    # Test 3: Only Medusa
    h3 = {**base_headers, 'X-Medusa': s['medusa']}
    run_curl(url, h3, "T3: Only Medusa")

    # Test 4: Only Helios
    h4 = {**base_headers, 'X-Helios': s['helios']}
    run_curl(url, h4, "T4: Only Helios")

    # Test 5: Helios+Medusa + Khronos
    h5 = {**base_headers, 'X-Helios': s['helios'], 'X-Medusa': s['medusa'], 'X-Khronos': s['khronos']}
    run_curl(url, h5, "T5: Helios+Medusa+Khronos")

    # Test 6: No signatures
    h6 = {**base_headers}
    run_curl(url, h6, "T6: No signatures")

    # Test 7: Different URL but same Helios/Medusa
    url2 = url.replace("book_id=7373660003258862617", "book_id=1234567890")
    h7 = {**base_headers, **all_sigs}
    run_curl(url2, h7, "T7: Different book_id, same sigs")

    # Test 8: Without x-reading-request
    h8 = dict(h1)
    del h8['x-reading-request']
    run_curl(url, h8, "T8: Without x-reading-request")

    # Test 9: Without X-SS-REQ-TICKET
    h9 = dict(h1)
    del h9['X-SS-REQ-TICKET']
    run_curl(url, h9, "T9: Without X-SS-REQ-TICKET")

    # Test 10: Minimal headers (no sdk-version, lc, etc)
    h10 = {
        'User-Agent': base_headers['User-Agent'],
        'Accept': 'application/json',
        'X-Helios': s['helios'],
        'X-Medusa': s['medusa'],
    }
    run_curl(url, h10, "T10: Minimal (UA+Accept+Helios+Medusa)")

    session.detach()
    print("\nDone!")

if __name__ == "__main__":
    main()
