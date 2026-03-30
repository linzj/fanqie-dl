#!/usr/bin/env python3
"""Standalone signer - reads JSON from stdin, writes signed headers to stdout."""
import sys, json, time, hashlib
sys.path.insert(0, '.')
from signer.gorgon import get_xgorgon
from signer.argus import Argus
from signer.ladon import Ladon

def sign(params, body=None, aid=1967):
    ts = int(time.time())
    stub = hashlib.md5(body.encode()).hexdigest() if body else None
    h = {
        "X-Gorgon": get_xgorgon(params=params, ticket=ts, data=body or ""),
        "X-Khronos": str(ts),
        "X-SS-REQ-TICKET": str(ts * 1000),
    }
    if stub:
        h["X-SS-STUB"] = stub
    try:
        h["X-Argus"] = Argus.get_sign(queryhash=params, data=stub, timestamp=ts, aid=aid)
        h["X-Ladon"] = Ladon.encrypt(ts, 1611921764, aid)
    except:
        pass
    return h

if __name__ == "__main__":
    req = json.loads(sys.stdin.readline())
    result = sign(req.get("params", ""), req.get("body"), req.get("aid", 1967))
    print(json.dumps(result))
