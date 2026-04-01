#!/bin/bash
# Iterative dump loop: run emulator → collect missing pages → dump from device → repeat
# Usage: ./scripts/iterate.sh <PID> [max_iterations]

PID=${1:?Usage: iterate.sh <PID>}
MAX=${2:-50}

for i in $(seq 1 $MAX); do
    echo "=== Iteration $i ==="

    # Run emulator test (short timeout)
    cargo test test_signing -- --nocapture > /tmp/emu_test.log 2>&1

    # Check results
    strings /tmp/emu_test.log | grep -E '\[emu\].*Loaded|\[emu\].*Halted|\[emu\].*SVCs|\[SIG\]' | head -5

    # Check if we got signatures
    if strings /tmp/emu_test.log | grep -q '\[SIG\]'; then
        echo "*** SIGNATURES FOUND ***"
        strings /tmp/emu_test.log | grep '\[SIG\]'
        break
    fi

    # Check missing pages
    if [ ! -f lib/missing_pages.txt ]; then
        echo "No missing pages file — emulator may have completed or crashed"
        break
    fi

    PAGES=$(wc -l < lib/missing_pages.txt | tr -d ' ')
    if [ "$PAGES" -eq 0 ]; then
        echo "No missing pages"
        break
    fi

    echo "Dumping $PAGES missing pages..."

    # Dump pages using python frida (single session)
    python3 -u scripts/dump_pages.py $PID lib/missing_pages.txt 2>&1

    if [ $? -ne 0 ]; then
        echo "ERROR: dump_pages.py failed"
        break
    fi

    echo ""
done
