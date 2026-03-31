#!/usr/bin/env python3
"""Dump libmetasec_ml.so from app memory using frida."""
import frida
import sys
import os

OUTPUT_PATH = "/Users/zuojianlin/src/crackfq/fanqie-dl/lib/libmetasec_ml_dumped.so"

def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    device = frida.get_usb_device()

    if pid is None:
        for proc in device.enumerate_processes():
            if proc.name == "com.dragon.read" or proc.name == "番茄免费小说":
                pid = proc.pid
                break

    if pid is None:
        print("App not found!")
        return

    print(f"Attaching to PID {pid}...")
    session = device.attach(pid)

    script_code = open("/Users/zuojianlin/src/crackfq/fanqie-dl/scripts/dump_so.js").read()

    module_size = 0
    dump_buffer = None
    dumped = 0
    skipped = 0

    def on_message(message, data):
        nonlocal module_size, dump_buffer, dumped, skipped

        if message['type'] == 'send':
            payload = message['payload']

            if isinstance(payload, dict):
                if payload.get('type') == 'meta':
                    module_size = payload['size']
                    dump_buffer = bytearray(module_size)
                    print(f"Module size: {module_size} bytes ({module_size/1024/1024:.2f} MB)")

                elif payload.get('type') == 'page':
                    offset = payload['offset']
                    size = payload['size']
                    if data and dump_buffer is not None:
                        dump_buffer[offset:offset+size] = data
                        dumped += 1

                elif payload.get('type') == 'skip':
                    skipped += 1

            elif isinstance(payload, str):
                print(f"[frida] {payload}")

        elif message['type'] == 'error':
            print(f"[ERR] {message.get('description', '')}")

    script = session.create_script(script_code, runtime='v8')
    script.on('message', on_message)
    script.load()

    import time
    # Wait for dump to complete
    time.sleep(15)

    if dump_buffer:
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, 'wb') as f:
            f.write(dump_buffer)
        print(f"\nDumped to: {OUTPUT_PATH}")
        print(f"Size: {len(dump_buffer)} bytes")
        print(f"Pages: {dumped} dumped, {skipped} skipped")

        # Verify ELF header
        if dump_buffer[:4] == b'\x7fELF':
            print("ELF header: OK")
        else:
            print(f"WARNING: No ELF header (first 4 bytes: {dump_buffer[:4].hex()})")
    else:
        print("No data received!")

    session.detach()

if __name__ == "__main__":
    main()
