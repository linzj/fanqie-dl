#!/usr/bin/env python3
"""Frida hook script for fanqie novel app signing."""
import frida
import sys
import time
import subprocess
import threading

SCRIPT_CODE = open("/Users/zuojianlin/src/crackfq/fanqie-dl/scripts/hook_all.js").read()

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[MSG] {message['payload']}", flush=True)
    elif message['type'] == 'error':
        print(f"[ERR] {message.get('description', '')}", flush=True)
        if 'stack' in message:
            print(message['stack'], flush=True)
    else:
        print(f"[???] {message}", flush=True)

def trigger_search():
    """Trigger a search in the app using adb."""
    time.sleep(3)
    print("\n[PY] Triggering search via adb...", flush=True)

    # Click search box
    subprocess.run(["adb", "shell", "input", "tap", "443", "182"], check=True)
    time.sleep(3)

    # Click input field
    subprocess.run(["adb", "shell", "input", "tap", "350", "115"], check=True)
    time.sleep(1)

    # Type query
    subprocess.run(["adb", "shell", "input", "text", "xuanhuan"], check=True)
    time.sleep(1)

    # Press enter/search
    subprocess.run(["adb", "shell", "input", "keyevent", "66"], check=True)
    print("[PY] Search triggered!", flush=True)

def main():
    device = frida.get_usb_device()

    # Find the main process
    pid = None
    for proc in device.enumerate_processes():
        if proc.name == "com.dragon.read" or "dragon.read" in proc.name:
            if ":" not in proc.name:  # Skip sub-processes
                pid = proc.pid
                print(f"[PY] Found main process: {proc.name} (PID {pid})", flush=True)
                break

    if pid is None:
        # Try by identifier
        for app in device.enumerate_applications():
            if app.identifier == "com.dragon.read":
                pid = app.pid
                print(f"[PY] Found app: {app.name} (PID {pid})", flush=True)
                break

    if pid is None:
        print("[PY] App not found, listing all processes...", flush=True)
        for proc in device.enumerate_processes():
            print(f"  {proc.pid}: {proc.name}", flush=True)
        return

    session = device.attach(pid)
    script = session.create_script(SCRIPT_CODE)
    script.on('message', on_message)
    script.load()

    print("[PY] Script loaded, triggering search...", flush=True)

    # Start search in background
    t = threading.Thread(target=trigger_search, daemon=True)
    t.start()

    # Wait for results
    print("[PY] Waiting 30s for API calls...", flush=True)
    time.sleep(30)

    print("[PY] Done.", flush=True)
    session.detach()

if __name__ == "__main__":
    main()
