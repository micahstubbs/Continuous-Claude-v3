#!/usr/bin/env python3
import json, sys, glob, os, tempfile

data = json.load(sys.stdin)
if data.get('stop_hook_active'):
    print('{}'); sys.exit(0)

tmp_dir = tempfile.gettempdir()
ctx_files = glob.glob(os.path.join(tmp_dir, 'claude-context-pct-*.txt'))
if ctx_files:
    try:
        pct = int(open(ctx_files[0]).read().strip())
        if pct >= 85:
            print(json.dumps({
                "decision": "block",
                "reason": f"Context at {pct}%. Run: /create_handoff"
            }))
            sys.exit(0)
    except: pass
print('{}')
